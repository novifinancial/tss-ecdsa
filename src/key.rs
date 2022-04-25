// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use crate::protocol::ParticipantIdentifier;
use crate::zkp::{
    piaffg::{PiAffgInput, PiAffgProof, PiAffgSecret},
    pienc::PiEncProof,
    pilog::{PiLogInput, PiLogProof, PiLogSecret},
    setup::ZkSetupParameters,
    Proof,
};
use ecdsa::elliptic_curve::sec1::ToEncodedPoint;
use k256::ProjectivePoint;
use libpaillier::{unknown_order::BigNumber, *};
use rand::{CryptoRng, RngCore};
use std::collections::HashMap;
use utils::{bn_to_scalar, k256_order, random_bn_in_range};

use super::serialization::*;
use super::*;
use crate::errors::{InternalError, Result};

#[derive(Debug)]
pub struct KeygenPrivate {
    pub(crate) sk: DecryptionKey,
    pub(crate) x: BigNumber, // in the range [1, q)
}

impl KeygenPrivate {
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let result = [
            serialize(&self.sk.to_bytes(), 2)?,
            serialize(&self.x.to_bytes(), 2)?,
        ]
        .concat();
        Ok(result)
    }

    pub fn from_slice<B: Clone + AsRef<[u8]>>(input: B) -> Result<Self> {
        let (sk_bytes, input) = tokenize(input.as_ref(), 2)?;
        let (x_bytes, input) = tokenize(&input, 2)?;
        if !input.is_empty() {
            // Should not be encountering any more bytes
            return Err(InternalError::Serialization);
        }
        let sk = DecryptionKey::from_bytes(sk_bytes).map_err(|_| InternalError::Serialization)?;
        let x = BigNumber::from_slice(x_bytes);
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
    /// Verifies that the public key's modulus matches the ZKSetupParameters modulus
    /// N, and taht the parameters have appropriate s and t values.
    pub(crate) fn verify(&self) -> bool {
        self.pk.n() == &self.params.N && self.params.verify()
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let result = [
            serialize(&self.pk.to_bytes(), 2)?,
            serialize(&self.X.to_encoded_point(COMPRESSED).to_bytes(), 2)?,
            serialize(&self.params.to_bytes()?, 2)?,
        ]
        .concat();
        Ok(result)
    }

    pub fn from_slice<B: AsRef<[u8]>>(input: B) -> Result<Self> {
        let (pk_bytes, input) = tokenize(input.as_ref(), 2)?;
        let (X_bytes, input) = tokenize(&input, 2)?;
        let (params_bytes, input) = tokenize(&input, 2)?;
        if !input.is_empty() {
            // Should not be encountering any more bytes
            return Err(InternalError::Serialization);
        }
        let pk = EncryptionKey::from_bytes(pk_bytes).map_err(|_| InternalError::Serialization)?;
        let X_opt: Option<_> =
            k256::ProjectivePoint::from_bytes(generic_array::GenericArray::from_slice(&X_bytes))
                .into();
        let X = X_opt.map(Ok).unwrap_or(Err(InternalError::Serialization))?;
        let params = ZkSetupParameters::from_slice(&params_bytes)?;

        Ok(Self { pk, X, params })
    }
}

#[derive(Debug, Clone)]
pub struct KeyInit {
    x: BigNumber,
    pub(crate) X: ProjectivePoint,
}

impl KeyInit {
    pub fn new<R: RngCore + CryptoRng>(_rng: &mut R) -> Self {
        let order = k256_order();
        let x = BigNumber::random(&order);
        let g = k256::ProjectivePoint::generator();
        let X = g * bn_to_scalar(&x).unwrap(); // public component
        Self { x, X }
    }
}

pub struct KeyShare {
    pub public: KeygenPublic,
    pub private: KeygenPrivate,
}

impl KeyShare {
    pub fn new<R: RngCore + CryptoRng>(rng: &mut R, prime_bits: usize) -> Self {
        let p = BigNumber::safe_prime(prime_bits);
        let q = BigNumber::safe_prime(prime_bits);
        let key_init = KeyInit::new(rng);
        Self::from_safe_primes_and_init(rng, &p, &q, &key_init)
    }

    pub fn from(public: KeygenPublic, private: KeygenPrivate) -> Self {
        Self { public, private }
    }

    #[cfg_attr(feature = "flame_it", flame("Keygen"))]
    pub fn from_safe_primes_and_init<R: RngCore + CryptoRng>(
        rng: &mut R,
        p: &BigNumber,
        q: &BigNumber,
        key_init: &KeyInit,
    ) -> Self {
        let sk = DecryptionKey::with_safe_primes_unchecked(p, q).unwrap();
        let pk = EncryptionKey::from(&sk);
        let params = ZkSetupParameters::gen_from_primes(rng, &(p * q), p, q).unwrap();

        Self {
            private: KeygenPrivate {
                sk,
                x: key_init.x.clone(),
            },
            public: KeygenPublic {
                pk,
                X: key_init.X,
                params,
            },
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
        public_keys: &HashMap<ParticipantIdentifier, KeygenPublic>,
    ) -> Result<(
        round_one::Private,
        HashMap<ParticipantIdentifier, round_one::Public>,
    )> {
        let mut rng = rand::rngs::OsRng;
        let k = random_bn_in_range(&mut rng, ELL);
        let gamma = random_bn_in_range(&mut rng, ELL);

        let (K, rho) = self.public.pk.encrypt(&k.to_bytes(), None).unwrap();
        let (G, nu) = self.public.pk.encrypt(&gamma.to_bytes(), None).unwrap();

        let mut ret_publics = HashMap::new();
        for (id, keygen_public) in public_keys {
            let proof = PiEncProof::prove(
                &mut rng,
                &crate::zkp::pienc::PiEncInput::new(
                    &keygen_public.params,
                    self.public.pk.n(),
                    &Ciphertext(K.clone()),
                ),
                &crate::zkp::pienc::PiEncSecret::new(&k, &rho),
            )?;
            let r1_public = round_one::Public {
                K: Ciphertext(K.clone()),
                G: Ciphertext(G.clone()),
                proof: proof.clone(),
            };
            ret_publics.insert(id.clone(), r1_public);
        }

        let r1_private = round_one::Private {
            k,
            rho,
            gamma,
            nu,
            G: Ciphertext(G.clone()),
            K: Ciphertext(K.clone()),
        };

        return Ok((r1_private, ret_publics));
    }

    /// Needs to be run once per party j != i
    ///
    /// Constructs a D = gamma * K and D_hat = x * K, and Gamma = g * gamma.
    ///
    #[cfg_attr(feature = "flame_it", flame)]
    pub fn round_two(
        &self,
        receiver_kg_pub: &KeygenPublic,
        sender_r1_priv: &round_one::Private,
        receiver_r1_pub: &round_one::Public,
    ) -> round_two::Pair {
        // Picking betas as elements of [+- 2^384] here is like sampling them from the distribution
        // [1, 2^256], which is akin to 2^{ell + epsilon} where ell = epsilon = 384. Note that
        // we need q/2^epsilon to be negligible.
        let mut rng = rand::rngs::OsRng;
        let beta = random_bn_in_range(&mut rng, ELL);
        let beta_hat = random_bn_in_range(&mut rng, ELL);

        let (beta_ciphertext, s) = receiver_kg_pub.pk.encrypt(beta.to_bytes(), None).unwrap();
        let (beta_hat_ciphertext, s_hat) = receiver_kg_pub
            .pk
            .encrypt(beta_hat.to_bytes(), None)
            .unwrap();

        let D = receiver_kg_pub
            .pk
            .add(
                &receiver_kg_pub
                    .pk
                    .mul(&receiver_r1_pub.K.0, &sender_r1_priv.gamma)
                    .unwrap(),
                &beta_ciphertext,
            )
            .unwrap();

        let D_hat = receiver_kg_pub
            .pk
            .add(
                &receiver_kg_pub
                    .pk
                    .mul(&receiver_r1_pub.K.0, &self.private.x)
                    .unwrap(),
                &beta_hat_ciphertext,
            )
            .unwrap();

        let (F, r) = self.public.pk.encrypt(beta.to_bytes(), None).unwrap();
        let (F_hat, r_hat) = self.public.pk.encrypt(beta_hat.to_bytes(), None).unwrap();

        let g = k256::ProjectivePoint::generator();
        let Gamma = g * bn_to_scalar(&sender_r1_priv.gamma).unwrap();

        // Generate three proofs

        let psi = PiAffgProof::prove(
            &mut rng,
            &PiAffgInput::new(
                &receiver_kg_pub.params,
                &g,
                receiver_kg_pub.pk.n(),
                self.public.pk.n(),
                &receiver_r1_pub.K.0,
                &D,
                &F,
                &Gamma,
            ),
            &PiAffgSecret::new(&sender_r1_priv.gamma, &beta, &s, &r),
        )
        .unwrap();

        let psi_hat = PiAffgProof::prove(
            &mut rng,
            &PiAffgInput::new(
                &receiver_kg_pub.params,
                &g,
                receiver_kg_pub.pk.n(),
                self.public.pk.n(),
                &receiver_r1_pub.K.0,
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
                &receiver_kg_pub.params,
                &g,
                self.public.pk.n(),
                &sender_r1_priv.G.0,
                &Gamma,
            ),
            &PiLogSecret::new(&sender_r1_priv.gamma, &sender_r1_priv.nu),
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
        sender_r1_priv: &round_one::Private,
        other_participant_inputs: &HashMap<ParticipantIdentifier, round_three::RoundThreeInput>,
    ) -> Result<(
        round_three::Private,
        HashMap<ParticipantIdentifier, round_three::Public>,
    )> {
        let order = k256_order();
        let mut delta: BigNumber = sender_r1_priv.gamma.modmul(&sender_r1_priv.k, &order);
        let mut chi: BigNumber = self.private.x.modmul(&sender_r1_priv.k, &order);

        let g = k256::ProjectivePoint::generator();
        let mut Gamma = g * bn_to_scalar(&sender_r1_priv.gamma).unwrap();

        for (_, round_three_input) in other_participant_inputs {
            let r2_pub_j = round_three_input.r2_public.clone();
            let r2_priv_j = round_three_input.r2_private.clone();

            let alpha = BigNumber::from_slice(self.private.sk.decrypt(&r2_pub_j.D.0).unwrap());
            let alpha_hat =
                BigNumber::from_slice(self.private.sk.decrypt(&r2_pub_j.D_hat.0).unwrap());

            delta = delta.modadd(&alpha.modsub(&r2_priv_j.beta, &order), &order);
            chi = chi.modadd(&alpha_hat.modsub(&r2_priv_j.beta_hat, &order), &order);

            Gamma += r2_pub_j.Gamma;
        }

        let Delta = Gamma * bn_to_scalar(&sender_r1_priv.k).unwrap();

        let delta_scalar = bn_to_scalar(&delta).unwrap();
        let chi_scalar = bn_to_scalar(&chi).unwrap();

        let mut rng = rand::rngs::OsRng;

        let mut ret_publics = HashMap::new();
        for (other_id, round_three_input) in other_participant_inputs {
            let kg_pub_j = round_three_input.keygen_public.clone();
            let psi_double_prime = PiLogProof::prove(
                &mut rng,
                &PiLogInput::new(
                    &kg_pub_j.params,
                    &Gamma,
                    self.public.pk.n(),
                    &sender_r1_priv.K.0,
                    &Delta,
                ),
                &PiLogSecret::new(&sender_r1_priv.k, &sender_r1_priv.rho),
            )
            .unwrap();
            let val = round_three::Public {
                delta: delta_scalar,
                Delta,
                psi_double_prime,
            };
            ret_publics.insert(other_id.clone(), val);
        }

        let private = round_three::Private {
            k: sender_r1_priv.k.clone(),
            chi: chi_scalar,
            Gamma,
            // These last two fields can be public, but for convenience
            // are stored in this party's private component
            delta: delta_scalar,
            Delta,
        };

        Ok((private, ret_publics))
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
            let key_init = KeyInit::new(&mut rng);
            let KeyShare { private, public } = KeyShare::from_safe_primes_and_init(
                &mut rng,
                &POOL_OF_PRIMES[2 * i],
                &POOL_OF_PRIMES[2 * i + 1],
                &key_init,
            );
            let private_bytes = private.to_bytes()?;
            let X = public.X.clone();
            let pk = public.pk.clone();
            let public_bytes = public.to_bytes()?;

            let roundtrip_private = KeygenPrivate::from_slice(private_bytes.clone())
                .expect("Roundtrip deserialization should succeed. qed.");
            assert_eq!(private_bytes, roundtrip_private.to_bytes()?);
            let roundtrip_public = KeygenPublic::from_slice(&public_bytes)
                .expect("Roundtrip deserialization should succeed. qed.");
            assert_eq!(X, roundtrip_public.X);
            assert_eq!(pk.to_bytes(), roundtrip_public.pk.to_bytes());
            assert_eq!(public_bytes, roundtrip_public.to_bytes()?);
        }
        Ok(())
    }
}
