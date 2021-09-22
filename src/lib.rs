// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

#![allow(non_snake_case)] // FIXME: To be removed in the future
#![cfg_attr(feature = "flame_it", feature(proc_macro_hygiene))]
#[cfg(feature = "flame_it")]
extern crate flame;
#[cfg(feature = "flame_it")]
#[macro_use]
extern crate flamer;

use ecdsa::hazmat::FromDigest;
use generic_array::GenericArray;
use k256::elliptic_curve::group::GroupEncoding;
use libpaillier::unknown_order::BigNumber;
use rand::Rng;

pub mod errors;
pub mod key;
pub mod serialization;
mod utils;
pub mod zkp;

#[cfg(test)]
mod tests;

// A note on sampling from +- 2^L, and mod N computations:
// In the paper (https://eprint.iacr.org/2021/060.pdf), ranges
// are sampled as from being positive/negative 2^L and (mod N)
// is taken to mean {-N/2, ..., N/2}. However, for the
// sake of convenience, we sample everything from
// + 2^{L+1} and use mod N to represent {0, ..., N-1}.

///////////////
// Constants //
// ========= //
///////////////

/// From the paper, needs to be 3 * security parameter
const ELL: usize = 384;
/// From the paper, needs to be 3 * security parameter
const EPSILON: usize = 384;

pub struct Pair<S, T> {
    pub(crate) private: S,
    pub(crate) public: T,
}

#[derive(Clone, Debug)]
struct Ciphertext(libpaillier::Ciphertext);

pub mod round_one {
    use crate::zkp::pienc::PaillierEncryptionInRangeProof;

    use super::BigNumber;
    use super::Ciphertext;

    #[derive(Debug)]
    pub struct Private {
        pub(crate) k: BigNumber,
        pub(crate) gamma: BigNumber,
    }

    #[derive(Debug)]
    pub struct Public {
        pub(crate) K: Ciphertext,
        pub(crate) G: Ciphertext,
        pub(crate) encryption_proofs: Vec<Option<PaillierEncryptionInRangeProof>>,
    }

    pub type Pair = super::Pair<Private, Public>;
}

pub mod round_two {
    use super::BigNumber;
    use super::Ciphertext;

    #[derive(Clone)]
    pub struct Private {
        pub(crate) beta: BigNumber,
        pub(crate) beta_hat: BigNumber,
    }

    #[derive(Clone)]
    pub struct Public {
        pub(crate) D: Ciphertext,
        pub(crate) D_hat: Ciphertext,
        pub(crate) F: Ciphertext,
        pub(crate) F_hat: Ciphertext,
        pub(crate) Gamma: k256::ProjectivePoint,
    }

    pub type Pair = super::Pair<Private, Public>;
}

pub mod round_three {
    use super::BigNumber;

    pub struct Private {
        pub(crate) k: BigNumber,
        pub(crate) chi: k256::Scalar,
        pub(crate) Gamma: k256::ProjectivePoint,
    }

    #[derive(Clone)]
    pub struct Public {
        pub(crate) delta: k256::Scalar,
        pub(crate) Delta: k256::ProjectivePoint,
    }

    pub type Pair = super::Pair<Private, Public>;
}

pub type PresignCouncil = Vec<round_three::Public>;

pub type RecordPair = Pair<round_three::Private, PresignCouncil>;

pub struct PresignRecord {
    R: k256::ProjectivePoint,
    k: BigNumber,
    chi: k256::Scalar,
}

impl From<RecordPair> for PresignRecord {
    fn from(RecordPair { private, public }: RecordPair) -> Self {
        let mut delta = k256::Scalar::zero();
        let mut Delta = k256::ProjectivePoint::identity();
        for p in public {
            delta += &p.delta;
            Delta += p.Delta;
        }

        let g = k256::ProjectivePoint::generator();
        if g * delta != Delta {
            // Error, failed to validate
            panic!("Error, failed to validate");
        }

        let R = private.Gamma * delta.invert().unwrap();

        PresignRecord {
            R,
            k: private.k,
            chi: private.chi,
        }
    }
}

impl PresignRecord {
    fn x_from_point(p: &k256::ProjectivePoint) -> k256::Scalar {
        let r = &p.to_affine().to_bytes()[1..32 + 1];
        k256::Scalar::from_bytes_reduced(&GenericArray::clone_from_slice(r))
    }

    pub fn sign(&self, d: sha2::Sha256) -> (k256::Scalar, k256::Scalar) {
        let r = Self::x_from_point(&self.R);
        let m = k256::Scalar::from_digest(d);
        let s = key::bn_to_scalar(&self.k).unwrap() * m + r * self.chi;

        (r, s)
    }
}

// Generate safe primes from a file. Usually, generating safe primes takes
// awhile (0-5 minutes per 512-bit safe prime on my laptop, average 50 seconds)
lazy_static::lazy_static! {
    static ref POOL_OF_PRIMES: Vec<BigNumber> = get_safe_primes();
}

pub(crate) fn get_safe_primes() -> Vec<BigNumber> {
    let file_contents = std::fs::read_to_string("src/safe_primes_512.txt").unwrap();
    let mut safe_primes_str: Vec<&str> = file_contents.split('\n').collect();
    safe_primes_str = safe_primes_str[0..safe_primes_str.len() - 1].to_vec(); // Remove the last element which is empty
    let safe_primes: Vec<BigNumber> = safe_primes_str
        .into_iter()
        .map(|s| BigNumber::from_slice(&hex::decode(&s).unwrap()))
        .collect();
    safe_primes
}

pub(crate) fn get_random_safe_prime_512() -> BigNumber {
    // FIXME: should just return BigNumber::safe_prime(PRIME_BITS);
    POOL_OF_PRIMES[rand::thread_rng().gen_range(0..POOL_OF_PRIMES.len())].clone()
}
