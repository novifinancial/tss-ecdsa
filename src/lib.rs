// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

#![allow(non_snake_case)] // FIXME: To be removed in the future

use ecdsa::hazmat::FromDigest;
use generic_array::GenericArray;
use k256::elliptic_curve::bigint::Encoding;
use k256::elliptic_curve::group::GroupEncoding;
use k256::elliptic_curve::Curve;
use libpaillier::unknown_order::BigNumber;

pub mod errors;
pub mod zkp;

use crate::zkp::pbmod::PaillierBlumModulusProof;

mod key;
mod tests;

#[derive(Clone, Debug)]
struct Ciphertext(libpaillier::Ciphertext);

pub mod round_one {
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
    }

    pub type Pair = super::key::Pair<Private, Public>;
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

    pub type Pair = super::key::Pair<Private, Public>;
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

    pub type Pair = super::key::Pair<Private, Public>;
}

pub type PresignCouncil = Vec<round_three::Public>;

pub type RecordPair = key::Pair<round_three::Private, PresignCouncil>;

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

fn k256_order() -> BigNumber {
    // Set order = q
    let order_bytes: [u8; 32] = k256::Secp256k1::ORDER.to_be_bytes();
    BigNumber::from_slice(&order_bytes)
}
