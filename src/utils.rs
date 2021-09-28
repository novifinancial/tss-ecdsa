// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use crate::errors::*;
use ecdsa::elliptic_curve::group::GroupEncoding;
use generic_array::GenericArray;
use k256::elliptic_curve::bigint::Encoding;
use k256::elliptic_curve::group::ff::PrimeField;
use k256::elliptic_curve::Curve;
use libpaillier::unknown_order::BigNumber;
use merlin::Transcript;
use rand::{CryptoRng, RngCore};

const MAX_ITER: usize = 50_000usize;

// Convert bytes into a k256::ProjectivePoint
pub(crate) fn point_from_bytes(bytes: &[u8]) -> Result<k256::ProjectivePoint> {
    Option::from(k256::ProjectivePoint::from_bytes(
        generic_array::GenericArray::from_slice(bytes),
    ))
    .ok_or(InternalError::Serialization)
}

/// Computes a^e (mod n)
#[cfg_attr(feature = "flame_it", flame("utils"))]
pub(crate) fn modpow(a: &BigNumber, e: &BigNumber, n: &BigNumber) -> BigNumber {
    a.modpow(e, n)
}

/// Generate a random positive BigNumber in the range 0..n
pub(crate) fn random_bn<R: RngCore + CryptoRng>(_rng: &mut R, n: &BigNumber) -> BigNumber {
    BigNumber::random(n)
}

/// Generate a random positive BigNumber in the range 0..2^{n+1}
pub(crate) fn random_bn_in_range<R: RngCore + CryptoRng>(_rng: &mut R, n: usize) -> BigNumber {
    BigNumber::random(&(BigNumber::one() << (n + 1)))
}

/// Generate a random value less than `2^{n+1}`
/// Taken from unknown_order crate (since they don't currently support an API)
/// that passes an rng for this function
pub(crate) fn bn_random_from_transcript(transcript: &mut Transcript, n: &BigNumber) -> BigNumber {
    let len = n.to_bytes().len();
    let mut t = vec![0u8; len as usize];
    loop {
        transcript.challenge_bytes(b"sampling randomness", t.as_mut_slice());
        let b = BigNumber::from_slice(t.as_slice());
        if &b < n {
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
    k256::Scalar::from_repr(GenericArray::clone_from_slice(&slice))
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
}
