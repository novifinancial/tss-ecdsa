// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use crate::utils::CurvePoint;
use crate::zkp::setup::ZkSetupParameters;
use libpaillier::{unknown_order::BigNumber, *};
use rand::{CryptoRng, RngCore};
use utils::{bn_to_scalar, k256_order};

use super::*;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct KeygenPrivate {
    pub(crate) sk: DecryptionKey,
    pub(crate) x: BigNumber, // in the range [1, q)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeygenPublic {
    pub(crate) pk: EncryptionKey,
    pub(crate) X: CurvePoint,
    pub(crate) params: ZkSetupParameters,
}

impl KeygenPublic {
    /// Verifies that the public key's modulus matches the ZKSetupParameters modulus
    /// N, and that the parameters have appropriate s and t values.
    pub(crate) fn verify(&self) -> bool {
        self.pk.n() == &self.params.N && self.params.verify()
    }
}

#[derive(Debug, Clone)]
pub struct KeyInit {
    pub(crate) x: BigNumber,
    pub(crate) X: CurvePoint,
}

impl KeyInit {
    pub fn new<R: RngCore + CryptoRng>(_rng: &mut R) -> Self {
        let order = k256_order();
        let x = BigNumber::random(&order);
        let g = k256::ProjectivePoint::GENERATOR;
        let X = CurvePoint(g * bn_to_scalar(&x).unwrap()); // public component
        Self { x, X }
    }
}

pub struct KeyShareAndInfo {
    pub public: KeygenPublic,
    pub private: KeygenPrivate,
}

impl KeyShareAndInfo {
    #[allow(dead_code)]
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    #[test]
    fn serialization_roundtrip() {
        let mut rng = OsRng;
        let NUM_PARTIES = 3;
        for i in 0..NUM_PARTIES {
            let key_init = KeyInit::new(&mut rng);
            let KeyShareAndInfo { private, public } = KeyShareAndInfo::from_safe_primes_and_init(
                &mut rng,
                &POOL_OF_PRIMES[2 * i],
                &POOL_OF_PRIMES[2 * i + 1],
                &key_init,
            );
            let private_bytes = bincode::serialize(&private).unwrap();
            let X = public.X;
            let pk = public.pk.clone();
            let public_bytes = bincode::serialize(&public).unwrap();

            let roundtrip_private: KeygenPrivate = bincode::deserialize(&private_bytes)
                .expect("Roundtrip deserialization should succeed. qed.");
            assert_eq!(
                private_bytes,
                bincode::serialize(&roundtrip_private).unwrap()
            );
            let roundtrip_public: KeygenPublic = bincode::deserialize(&public_bytes)
                .expect("Roundtrip deserialization should succeed. qed.");
            assert_eq!(X, roundtrip_public.X);
            assert_eq!(
                bincode::serialize(&pk).unwrap(),
                bincode::serialize(&roundtrip_public.pk).unwrap()
            );
            assert_eq!(public_bytes, bincode::serialize(&roundtrip_public).unwrap());
        }
    }
}
