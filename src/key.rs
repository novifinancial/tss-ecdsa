// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use generic_array::GenericArray;
use k256::elliptic_curve::bigint::Encoding;
use k256::elliptic_curve::group::ff::PrimeField;
use k256::elliptic_curve::Curve;
use libpaillier::{unknown_order::BigNumber, *};
use rand::{CryptoRng, RngCore};

use super::*;

pub(crate) fn bn_to_scalar(x: &BigNumber) -> Option<k256::Scalar> {
    // Take (mod q)
    let order_bytes: [u8; 32] = k256::Secp256k1::ORDER.to_be_bytes();
    let order = BigNumber::from_slice(&order_bytes);

    let x_modded = x % order;

    let bytes = x_modded.to_bytes();

    let mut slice = vec![0u8; 32 - bytes.len()];
    slice.extend_from_slice(&bytes);
    k256::Scalar::from_repr(GenericArray::clone_from_slice(&slice))
}

#[derive(Debug)]
pub struct KeygenPrivate {
    pub(crate) sk: DecryptionKey,
    pub(crate) x: BigNumber, // in the range [1, q)
}
#[derive(Debug)]
pub struct KeygenPublic {
    pub(crate) pk: EncryptionKey,
    pub(crate) X: k256::ProjectivePoint,
    pub(crate) proof: PaillierBlumModulusProof,
}

impl KeygenPublic {
    fn verify(&self) -> bool {
        self.pk.n() == &self.proof.N && self.proof.verify()
    }
}

pub struct KeyShare {
    pub(crate) public: KeygenPublic,
    pub(crate) private: KeygenPrivate,
}

impl KeyShare {
    const ELL: usize = 384;
    const EPSILON: usize = 384;

    pub fn new<R: RngCore + CryptoRng>(rng: &mut R, prime_bits: usize) -> Self {
        let p = BigNumber::safe_prime(prime_bits);
        let q = BigNumber::safe_prime(prime_bits);
        Self::from_safe_primes(rng, &p, &q)
    }

    pub fn from_safe_primes<R: RngCore + CryptoRng>(
        _rng: &mut R,
        p: &BigNumber,
        q: &BigNumber,
    ) -> Self {
        let sk = DecryptionKey::with_safe_primes_unchecked(p, q).unwrap();
        let pk = EncryptionKey::from(&sk);

        let order = k256_order();
        let x = BigNumber::random(&order);
        let g = k256::ProjectivePoint::generator();
        let X = g * bn_to_scalar(&x).unwrap(); // public component

        let proof = PaillierBlumModulusProof::prove(&(p * q), p, q).unwrap();

        // Proof should verify
        assert!(proof.verify());

        Self {
            private: KeygenPrivate { sk, x },
            public: KeygenPublic { pk, X, proof },
        }
    }

    /// Corresponds to pre-signing round 1 for party i
    ///
    /// Produces local shares k and gamma, along with their encrypted
    /// components K = enc(k) and G = enc(gamma).
    ///
    pub fn round_one(&self) -> round_one::Pair {
        let k = BigNumber::random(&(BigNumber::one() << Self::ELL));
        let gamma = BigNumber::random(&(BigNumber::one() << Self::ELL));

        let (K, _) = self.public.pk.encrypt(&k.to_bytes(), None).unwrap();
        let (G, _) = self.public.pk.encrypt(&gamma.to_bytes(), None).unwrap();
        Pair {
            private: round_one::Private { k, gamma },
            public: round_one::Public {
                K: Ciphertext(K),
                G: Ciphertext(G),
            },
        }
    }

    /// Needs to be run once per party j != i
    ///
    /// Constructs a D = gamma * K and D_hat = x * K, and Gamma = g * gamma.
    ///
    pub fn round_two(
        &self,
        kg_pub_j: &KeygenPublic,
        r1_priv_i: &round_one::Private,
        r1_pub_j: &round_one::Public,
    ) -> round_two::Pair {
        // Verify KeygenPublic
        assert!(kg_pub_j.verify());

        // Picking betas as elements of [+- 2^384] here is like sampling them from the distribution
        // [1, 2^256], which is akin to 2^{ell + epsilon} where ell = epsilon = 384. Note that
        // we need q/2^epsilon to be negligible.
        // FIXME: allow for betas to also be negative
        let beta = BigNumber::random(&(BigNumber::one() << (Self::ELL + Self::EPSILON)));
        let beta_hat = BigNumber::random(&(BigNumber::one() << (Self::ELL + Self::EPSILON)));

        let (beta_ciphertext, _) = kg_pub_j.pk.encrypt(beta.to_bytes(), None).unwrap();
        let (beta_hat_ciphertext, _) = kg_pub_j.pk.encrypt(beta_hat.to_bytes(), None).unwrap();

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

        let (F, _) = self.public.pk.encrypt(beta.to_bytes(), None).unwrap();
        let (F_hat, _) = self.public.pk.encrypt(beta_hat.to_bytes(), None).unwrap();

        let g = k256::ProjectivePoint::generator();
        let Gamma = g * bn_to_scalar(&r1_priv_i.gamma).unwrap();

        Pair {
            private: round_two::Private { beta, beta_hat },
            public: round_two::Public {
                D: Ciphertext(D),
                D_hat: Ciphertext(D_hat),
                F: Ciphertext(F),
                F_hat: Ciphertext(F_hat),
                Gamma,
            },
        }
    }

    /// From the perspective of party i
    /// r2_privs and r2_pubs don't include party i
    ///
    /// First computes alpha = dec(D), alpha_hat = dec(D_hat).
    /// Computes a delta = gamma * k
    pub fn round_three(
        &self,
        r1_priv_i: &round_one::Private,
        r2_privs: &[Option<round_two::Private>],
        r2_pubs: &[Option<round_two::Public>],
    ) -> round_three::Pair {
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

        Pair {
            private: round_three::Private {
                k: r1_priv_i.k.clone(),
                chi: chi_scalar,
                Gamma,
            },
            public: round_three::Public {
                delta: delta_scalar,
                Delta,
            },
        }
    }
}

fn k256_order() -> BigNumber {
    // Set order = q
    let order_bytes: [u8; 32] = k256::Secp256k1::ORDER.to_be_bytes();
    BigNumber::from_slice(&order_bytes)
}
