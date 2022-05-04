// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use crate::zkp::setup::ZkSetupParameters;
use ecdsa::elliptic_curve::sec1::ToEncodedPoint;
use k256::ProjectivePoint;
use libpaillier::{unknown_order::BigNumber, *};
use rand::{CryptoRng, RngCore};
use utils::{bn_to_scalar, k256_order};

use super::serialization::*;
use super::*;
use crate::errors::{InternalError, Result};
use crate::parameters::COMPRESSED;

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
    /// N, and that the parameters have appropriate s and t values.
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
    pub(crate) x: BigNumber,
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
    fn serialization_roundtrip() -> Result<()> {
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
            let private_bytes = private.to_bytes()?;
            let X = public.X;
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
