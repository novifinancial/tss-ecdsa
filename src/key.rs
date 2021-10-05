// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use crate::zkp::{
    piaffg::{PiAffgInput, PiAffgProof, PiAffgSecret},
    pienc::PiEncProof,
    pilog::{PiLogInput, PiLogProof, PiLogSecret},
    setup::ZkSetupParameters,
    Proof,
};
use crate::PairWithMultiplePublics;
use ecdsa::elliptic_curve::sec1::ToEncodedPoint;
use integer_encoding::VarInt;
use libpaillier::{unknown_order::BigNumber, *};
use rand::{CryptoRng, RngCore};
use utils::{bn_to_scalar, k256_order, random_bn_in_range};

use super::*;
use crate::errors::{InternalError, Result};

const COMPRESSED: bool = true;

#[derive(Debug)]
pub struct KeygenPrivate {
    pub(crate) sk: DecryptionKey,
    pub(crate) x: BigNumber, // in the range [1, q)
}

impl KeygenPrivate {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = self.sk.to_bytes();
        out.extend(self.x.to_bytes());
        out
    }

    pub fn from_slice<B: Clone + AsRef<[u8]>>(buf: B) -> Result<Self> {
        let sk =
            DecryptionKey::from_bytes(buf.clone()).map_err(|_| InternalError::Serialization)?;
        // TODO (ladi) We should upstream a serialized_size on libpaillier Key
        let sk_buf = sk.to_bytes();
        let x = BigNumber::from_slice(&buf.as_ref()[sk_buf.len()..]);
        Ok(Self { sk, x })
    }
}

#[derive(Debug, Clone)]
pub struct KeygenPublic {
    pub(crate) pk: EncryptionKey,
    pub(crate) X: k256::ProjectivePoint,
    pub(crate) params: ZkSetupParameters,
}

impl KeygenPublic {
    fn verify(&self) -> bool {
        self.pk.n() == &self.params.N && self.params.verify()
    }

    pub fn to_bytes(self) -> Result<Vec<u8>> {
        let buf_enc = self.pk.to_bytes();
        let buf_enc_len = buf_enc.len();

        let mut offset = 0;
        let mut out = (0..buf_enc_len.required_space())
            .map(|_| 0u8)
            .collect::<Vec<u8>>();
        offset += buf_enc_len.encode_var(&mut out[offset..]);
        out.extend(buf_enc);
        offset += buf_enc_len;

        let encoded_point = self.X.to_encoded_point(COMPRESSED);
        out.extend(encoded_point.to_bytes().to_vec());
        offset += 33;

        let buf_params = self.params.to_bytes()?;
        let buf_params_len = buf_params.len();
        out.extend(
            (0..buf_params_len.required_space())
                .map(|_| 0u8)
                .collect::<Vec<u8>>(),
        );
        let _ = buf_params_len.encode_var(&mut out[offset..]);
        out.extend(buf_params);

        Ok(out)
    }

    pub fn from_slice<B: AsRef<[u8]>>(buf: B) -> Result<Self> {
        let mut offset = 0;
        let buf = buf.as_ref();
        let (buf_pk_len, pk_len): (usize, usize) = VarInt::decode_var(&buf[offset..])
            .map(Ok)
            .unwrap_or(Err(InternalError::Serialization))?;

        offset += pk_len;
        let pk = EncryptionKey::from_bytes(&buf[offset..offset + buf_pk_len])
            .map_err(|_| InternalError::Serialization)?;
        offset += buf_pk_len;

        let X_opt: Option<_> = k256::ProjectivePoint::from_bytes(
            generic_array::GenericArray::from_slice(&buf[offset..offset + 33]),
        )
        .into();
        let X = X_opt.map(Ok).unwrap_or(Err(InternalError::Serialization))?;
        offset += 33;

        let (buf_proof_len, proof_len): (usize, usize) = VarInt::decode_var(&buf[offset..])
            .map(Ok)
            .unwrap_or(Err(InternalError::Serialization))?;
        offset += proof_len;
        let params = ZkSetupParameters::from_slice(&buf[offset..offset + buf_proof_len])?;

        let ret = Self { pk, X, params };
        ret.verify()
            .then(|| ret)
            .ok_or(InternalError::FailedToVerifyProof)
    }
}

pub struct KeyShare {
    pub(crate) public: KeygenPublic,
    pub(crate) private: KeygenPrivate,
}

impl KeyShare {
    pub fn new<R: RngCore + CryptoRng>(rng: &mut R, prime_bits: usize) -> Self {
        let p = BigNumber::safe_prime(prime_bits);
        let q = BigNumber::safe_prime(prime_bits);
        Self::from_safe_primes(rng, &p, &q)
    }

    #[cfg_attr(feature = "flame_it", flame("Keygen"))]
    pub fn from_safe_primes<R: RngCore + CryptoRng>(
        rng: &mut R,
        p: &BigNumber,
        q: &BigNumber,
    ) -> Self {
        let sk = DecryptionKey::with_safe_primes_unchecked(p, q).unwrap();
        let pk = EncryptionKey::from(&sk);

        let order = k256_order();
        let x = BigNumber::random(&order);
        let g = k256::ProjectivePoint::generator();
        let X = g * bn_to_scalar(&x).unwrap(); // public component

        let params = ZkSetupParameters::gen_from_primes(rng, &(p * q), p, q).unwrap();

        // Zk setup parameters should verify
        assert!(params.verify());

        Self {
            private: KeygenPrivate { sk, x },
            public: KeygenPublic { pk, X, params },
        }
    }

    /// Corresponds to pre-signing round 1 for party i
    ///
    /// Produces local shares k and gamma, along with their encrypted
    /// components K = enc(k) and G = enc(gamma).
    ///
    /// The public_keys parameter corresponds to a KeygenPublic for
    /// each of the other parties. Party i should be left as `None`
    #[cfg_attr(feature = "flame_it", flame)]
    pub fn round_one(
        &self,
        public_keys: &[Option<KeygenPublic>],
    ) -> Result<round_one::PairWithMultiplePublics> {
        let mut rng = rand::rngs::OsRng;
        let k = random_bn_in_range(&mut rng, ELL);
        let gamma = random_bn_in_range(&mut rng, ELL);

        let (K, rho) = self.public.pk.encrypt(&k.to_bytes(), None).unwrap();
        let (G, nu) = self.public.pk.encrypt(&gamma.to_bytes(), None).unwrap();
        public_keys
            .iter()
            .map(|v| {
                v.as_ref()
                    .map(|key| {
                        PiEncProof::prove(
                            &mut rng,
                            &crate::zkp::pienc::PiEncInput::new(
                                &key.params,
                                self.public.pk.n(),
                                &Ciphertext(K.clone()),
                            ),
                            &crate::zkp::pienc::PiEncSecret::new(&k, &rho),
                        )
                    })
                    .transpose()
            })
            .collect::<Result<Vec<_>>>()
            .map(|v| PairWithMultiplePublics {
                private: round_one::Private {
                    k,
                    rho,
                    gamma,
                    nu,
                    G: Ciphertext(G.clone()),
                    K: Ciphertext(K.clone()),
                },
                publics: v
                    .iter()
                    .map(|p| {
                        p.as_ref().map(|proof| round_one::Public {
                            K: Ciphertext(K.clone()),
                            G: Ciphertext(G.clone()),
                            proof: proof.clone(),
                        })
                    })
                    .collect(),
            })
    }

    /// Needs to be run once per party j != i
    ///
    /// Constructs a D = gamma * K and D_hat = x * K, and Gamma = g * gamma.
    ///
    #[cfg_attr(feature = "flame_it", flame)]
    pub fn round_two(
        &self,
        kg_pub_j: &KeygenPublic,
        r1_priv_i: &round_one::Private,
        r1_pub_j: &round_one::Public,
    ) -> round_two::Pair {
        // Picking betas as elements of [+- 2^384] here is like sampling them from the distribution
        // [1, 2^256], which is akin to 2^{ell + epsilon} where ell = epsilon = 384. Note that
        // we need q/2^epsilon to be negligible.
        let mut rng = rand::rngs::OsRng;
        let beta = random_bn_in_range(&mut rng, ELL);
        let beta_hat = random_bn_in_range(&mut rng, ELL);

        let (beta_ciphertext, s) = kg_pub_j.pk.encrypt(beta.to_bytes(), None).unwrap();
        let (beta_hat_ciphertext, s_hat) = kg_pub_j.pk.encrypt(beta_hat.to_bytes(), None).unwrap();

        let D = kg_pub_j
            .pk
            .add(
                &kg_pub_j.pk.mul(&r1_pub_j.K.0, &r1_priv_i.gamma).unwrap(),
                &beta_ciphertext,
            )
            .unwrap();

        let D_hat = kg_pub_j
            .pk
            .add(
                &kg_pub_j.pk.mul(&r1_pub_j.K.0, &self.private.x).unwrap(),
                &beta_hat_ciphertext,
            )
            .unwrap();

        let (F, r) = self.public.pk.encrypt(beta.to_bytes(), None).unwrap();
        let (F_hat, r_hat) = self.public.pk.encrypt(beta_hat.to_bytes(), None).unwrap();

        let g = k256::ProjectivePoint::generator();
        let Gamma = g * bn_to_scalar(&r1_priv_i.gamma).unwrap();

        // Generate three proofs

        let psi = PiAffgProof::prove(
            &mut rng,
            &PiAffgInput::new(
                &kg_pub_j.params,
                &g,
                kg_pub_j.pk.n(),
                self.public.pk.n(),
                &r1_pub_j.K.0,
                &D,
                &F,
                &Gamma,
            ),
            &PiAffgSecret::new(&r1_priv_i.gamma, &beta, &s, &r),
        )
        .unwrap();

        let psi_hat = PiAffgProof::prove(
            &mut rng,
            &PiAffgInput::new(
                &kg_pub_j.params,
                &g,
                kg_pub_j.pk.n(),
                self.public.pk.n(),
                &r1_pub_j.K.0,
                &D_hat,
                &F_hat,
                &self.public.X,
            ),
            &PiAffgSecret::new(&self.private.x, &beta_hat, &s_hat, &r_hat),
        )
        .unwrap();

        let psi_prime = PiLogProof::prove(
            &mut rng,
            &PiLogInput::new(
                &kg_pub_j.params,
                &g,
                self.public.pk.n(),
                &r1_priv_i.G.0,
                &Gamma,
            ),
            &PiLogSecret::new(&r1_priv_i.gamma, &r1_priv_i.nu),
        )
        .unwrap();

        Pair {
            private: round_two::Private { beta, beta_hat },
            public: round_two::Public {
                D: Ciphertext(D),
                D_hat: Ciphertext(D_hat),
                F: Ciphertext(F),
                F_hat: Ciphertext(F_hat),
                Gamma,
                psi,
                psi_hat,
                psi_prime,
            },
        }
    }

    /// From the perspective of party i
    /// r2_privs and r2_pubs don't include party i
    ///
    /// First computes alpha = dec(D), alpha_hat = dec(D_hat).
    /// Computes a delta = gamma * k
    #[cfg_attr(feature = "flame_it", flame)]
    pub fn round_three(
        &self,
        kg_pubs: &[Option<KeygenPublic>],
        r1_priv_i: &round_one::Private,
        r2_privs: &[Option<round_two::Private>],
        r2_pubs: &[Option<round_two::Public>],
    ) -> round_three::PairWithMultiplePublics {
        let order = k256_order();
        let mut delta: BigNumber = r1_priv_i.gamma.modmul(&r1_priv_i.k, &order);
        let mut chi: BigNumber = self.private.x.modmul(&r1_priv_i.k, &order);

        assert!(r2_privs.len() == r2_pubs.len(), "Should be same length");

        let g = k256::ProjectivePoint::generator();
        let mut Gamma = g * bn_to_scalar(&r1_priv_i.gamma).unwrap();

        for i in 0..r2_privs.len() {
            if r2_pubs[i].is_none() {
                assert!(
                    r2_privs[i].is_none(),
                    "Should both be None or neither are None"
                );
                continue;
            }
            let r2_pub_j = r2_pubs[i].clone().unwrap();
            let r2_priv_j = r2_privs[i].clone().unwrap();

            let alpha = BigNumber::from_slice(self.private.sk.decrypt(&r2_pub_j.D.0).unwrap());
            let alpha_hat =
                BigNumber::from_slice(self.private.sk.decrypt(&r2_pub_j.D_hat.0).unwrap());

            delta = delta.modadd(&alpha.modsub(&r2_priv_j.beta, &order), &order);
            chi = chi.modadd(&alpha_hat.modsub(&r2_priv_j.beta_hat, &order), &order);

            Gamma += r2_pub_j.Gamma;
        }

        let Delta = Gamma * bn_to_scalar(&r1_priv_i.k).unwrap();

        let delta_scalar = bn_to_scalar(&delta).unwrap();
        let chi_scalar = bn_to_scalar(&chi).unwrap();

        let mut rng = rand::rngs::OsRng;

        let publics = kg_pubs
            .iter()
            .map(|p| match p {
                None => None,
                Some(kg_pub_j) => {
                    let psi_double_prime = PiLogProof::prove(
                        &mut rng,
                        &PiLogInput::new(
                            &kg_pub_j.params,
                            &Gamma,
                            self.public.pk.n(),
                            &r1_priv_i.K.0,
                            &Delta,
                        ),
                        &PiLogSecret::new(&r1_priv_i.k, &r1_priv_i.rho),
                    )
                    .unwrap();
                    Some(round_three::Public {
                        delta: delta_scalar,
                        Delta,
                        psi_double_prime,
                    })
                }
            })
            .collect();

        PairWithMultiplePublics {
            private: round_three::Private {
                k: r1_priv_i.k.clone(),
                chi: chi_scalar,
                Gamma,
                // These last two fields can be public, but for convenience
                // are stored in this party's private component
                delta: delta_scalar,
                Delta,
            },
            publics,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    #[test]
    fn serialization_roundtrip() -> Result<()> {
        let mut rng = OsRng;
        let NUM_PARTIES = 3;
        for i in 0..NUM_PARTIES {
            let KeyShare { private, public } = KeyShare::from_safe_primes(
                &mut rng,
                &POOL_OF_PRIMES[2 * i],
                &POOL_OF_PRIMES[2 * i + 1],
            );
            let private_bytes = private.to_bytes();
            let X = public.X.clone();
            let pk = public.pk.clone();
            let public_bytes = public.to_bytes()?;

            let roundtrip_private = KeygenPrivate::from_slice(private_bytes.clone())
                .expect("Roundtrip deserialization should succeed. qed.");
            assert_eq!(private_bytes, roundtrip_private.to_bytes());
            let roundtrip_public = KeygenPublic::from_slice(&public_bytes)
                .expect("Roundtrip deserialization should succeed. qed.");
            assert_eq!(X, roundtrip_public.X);
            assert_eq!(pk.to_bytes(), roundtrip_public.pk.to_bytes());
            //assert_eq!(public_bytes, roundtrip_public.to_bytes());
        }
        Ok(())
    }
}
