// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

use generic_array::GenericArray;
use k256::elliptic_curve::bigint::Encoding;
use k256::elliptic_curve::group::ff::PrimeField;
use k256::elliptic_curve::AffinePoint;
use k256::elliptic_curve::Curve;
use k256::Secp256k1;
use libpaillier::unknown_order::BigNumber;
use merlin::Transcript;
use rand::Rng;
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

const MAX_ITER: usize = 50_000usize;

/// Wrapper around k256::ProjectivePoint so that we can define our own
/// serialization/deserialization for it
#[derive(Eq, PartialEq, Debug, Clone, Copy)]
pub struct CurvePoint(pub(crate) k256::ProjectivePoint);

impl CurvePoint {
    pub const GENERATOR: Self = CurvePoint(k256::ProjectivePoint::GENERATOR);
    pub const IDENTITY: Self = CurvePoint(k256::ProjectivePoint::IDENTITY);
}

impl From<k256::ProjectivePoint> for CurvePoint {
    fn from(p: k256::ProjectivePoint) -> Self {
        Self(p)
    }
}

impl Serialize for CurvePoint {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let afp = AffinePoint::<Secp256k1>::from(self.0);
        afp.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for CurvePoint {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let p = AffinePoint::<Secp256k1>::deserialize(deserializer)?;
        Ok(Self(p.into()))
    }
}

/// Computes a^e (mod n)
#[cfg_attr(feature = "flame_it", flame("utils"))]
pub(crate) fn modpow(a: &BigNumber, e: &BigNumber, n: &BigNumber) -> BigNumber {
    a.modpow(e, n)
}

/// Generate a random BigNumber in the range -n, ..., n
pub(crate) fn random_positive_bn<R: RngCore + CryptoRng>(_rng: &mut R, n: &BigNumber) -> BigNumber {
    BigNumber::random(n)
}

/// Generate a random BigNumber in the range -n, ..., n
pub(crate) fn random_bn_plusminus<R: RngCore + CryptoRng>(rng: &mut R, n: &BigNumber) -> BigNumber {
    let val = BigNumber::random(n);
    let is_positive: bool = rng.gen();
    match is_positive {
        true => val,
        false => -val,
    }
}

/// Generate a random BigNumber in the range -2^n, ..., 0, ..., 2^n
pub(crate) fn random_bn_in_range<R: RngCore + CryptoRng>(rng: &mut R, n: usize) -> BigNumber {
    let val = BigNumber::random(&(BigNumber::one() << n));
    let is_positive: bool = rng.gen();
    match is_positive {
        true => val,
        false => -val,
    }
}

/// Generate a random BigNumber x in the range -2^n, ..., 0, ..., 2^n, where |x| > 2^min_bound
#[cfg(test)]
pub(crate) fn random_bn_in_range_min<R: RngCore + CryptoRng>(
    rng: &mut R,
    n: usize,
    min_bound: usize,
) -> crate::errors::Result<BigNumber> {
    if min_bound >= n {
        return bail!("min_bound needs to be less than n");
    }
    let min_bound_bn = (BigNumber::one() << n) - (BigNumber::one() << min_bound);
    let val = BigNumber::random(&(min_bound_bn + (BigNumber::one() << min_bound)));
    let is_positive: bool = rng.gen();
    Ok(match is_positive {
        true => val,
        false => -val,
    })
}

/// Produces a random value in [-n, ..., 0, ..., n]
pub(crate) fn plusminus_bn_random_from_transcript(
    transcript: &mut Transcript,
    n: &BigNumber,
) -> BigNumber {
    let mut is_neg_byte = vec![0u8; 1];
    transcript.challenge_bytes(b"sampling negation bit", is_neg_byte.as_mut_slice());
    let is_neg: bool = is_neg_byte[0] & 1 == 1;

    let b = positive_bn_random_from_transcript(transcript, n);
    match is_neg {
        true => -b,
        false => b,
    }
}

/// Produces a random value in [0, ..., n]
pub(crate) fn positive_bn_random_from_transcript(
    transcript: &mut Transcript,
    n: &BigNumber,
) -> BigNumber {
    let len = n.to_bytes().len();
    let mut t = vec![0u8; len as usize];
    loop {
        transcript.challenge_bytes(b"sampling randomness", t.as_mut_slice());
        let b = BigNumber::from_slice(t.as_slice());
        if &b <= n {
            return b;
        }
    }
}

/// Generate a random BigNumber in the range 1..N-1 (Z_N^*) (non-zero)
pub(crate) fn random_bn_in_z_star<R: RngCore + CryptoRng>(
    _rng: &mut R,
    n: &BigNumber,
) -> BigNumber {
    for _ in 0..MAX_ITER {
        let bn = BigNumber::random(n);
        if bn != BigNumber::zero() {
            return bn;
        }
    }
    BigNumber::zero()
}

pub(crate) fn bn_to_scalar(x: &BigNumber) -> Option<k256::Scalar> {
    // Take (mod q)
    let order = k256_order();

    let x_modded = x % order;
    let bytes = x_modded.to_bytes();

    let mut slice = vec![0u8; 32 - bytes.len()];
    slice.extend_from_slice(&bytes);
    let mut ret: k256::Scalar = Option::from(k256::Scalar::from_repr(
        GenericArray::clone_from_slice(&slice),
    ))
    .unwrap();

    // Make sure to negate the scalar if the original input was negative
    if x < &BigNumber::zero() {
        ret = ret.negate();
    }

    Some(ret)
}

pub(crate) fn k256_order() -> BigNumber {
    // Set order = q
    let order_bytes: [u8; 32] = k256::Secp256k1::ORDER.to_be_bytes();
    BigNumber::from_slice(&order_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    #[test]
    fn test_random_bn_in_range() {
        // Statistical tests -- should generate random numbers that are long enough

        let mut max_len = 0;
        let num_bytes = 100;

        let mut rng = OsRng;
        for _ in 0..1000 {
            let bn = random_bn_in_range(&mut rng, num_bytes * 8);
            let len = bn.to_bytes().len();
            if max_len < len {
                max_len = len;
            }
        }

        assert!(max_len > num_bytes - 2);
    }

    #[test]
    fn test_bn_to_scalar_neg() {
        let neg1 = BigNumber::zero() - BigNumber::one();

        let scalar = bn_to_scalar(&neg1).unwrap();
        assert_eq!(k256::Scalar::ZERO, scalar.add(&k256::Scalar::ONE));
    }
}
