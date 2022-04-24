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

use crate::zkp::Proof;

pub mod errors;
pub mod key;
pub mod messages;
pub mod protocol;
pub mod serialization;
mod utils;
pub mod zkp;

#[cfg(test)]
mod tests;

use errors::{InternalError, Result};
use serialization::*;

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
/// Convenience constant
const COMPRESSED: bool = true;

pub struct Pair<S, T> {
    pub(crate) private: S,
    pub(crate) public: T,
}

pub struct PairWithMultiplePublics<S, T> {
    pub private: S,
    pub publics: Vec<Option<T>>,
}

#[derive(Clone, Debug)]
struct Ciphertext(libpaillier::Ciphertext);

pub mod round_one {
    use super::*;
    use crate::zkp::pienc::PiEncProof;

    #[derive(Debug)]
    pub struct Private {
        pub(crate) k: BigNumber,
        pub(crate) rho: BigNumber,
        pub(crate) gamma: BigNumber,
        pub(crate) nu: BigNumber,
        pub(crate) G: Ciphertext, // Technically can be public but is only one per party
        pub(crate) K: Ciphertext, // Technically can be public but is only one per party
    }

    impl Private {
        pub fn to_bytes(&self) -> Result<Vec<u8>> {
            let result = [
                serialize(&self.k.to_bytes(), 2)?,
                serialize(&self.rho.to_bytes(), 2)?,
                serialize(&self.gamma.to_bytes(), 2)?,
                serialize(&self.nu.to_bytes(), 2)?,
                serialize(&self.G.0.to_bytes(), 2)?,
                serialize(&self.K.0.to_bytes(), 2)?,
            ]
            .concat();
            Ok(result)
        }

        pub fn from_slice<B: Clone + AsRef<[u8]>>(input: B) -> Result<Self> {
            let (k_bytes, input) = tokenize(input.as_ref(), 2)?;
            let (rho_bytes, input) = tokenize(input.as_ref(), 2)?;
            let (gamma_bytes, input) = tokenize(input.as_ref(), 2)?;
            let (nu_bytes, input) = tokenize(input.as_ref(), 2)?;
            let (G_bytes, input) = tokenize(input.as_ref(), 2)?;
            let (K_bytes, input) = tokenize(&input, 2)?;
            if !input.is_empty() {
                // Should not be encountering any more bytes
                return Err(InternalError::Serialization);
            }
            let k = BigNumber::from_slice(k_bytes);
            let rho = BigNumber::from_slice(rho_bytes);
            let gamma = BigNumber::from_slice(gamma_bytes);
            let nu = BigNumber::from_slice(nu_bytes);
            let G = Ciphertext(libpaillier::Ciphertext::from_slice(G_bytes));
            let K = Ciphertext(libpaillier::Ciphertext::from_slice(K_bytes));
            Ok(Self {
                k,
                rho,
                gamma,
                nu,
                G,
                K,
            })
        }
    }

    #[derive(Debug)]
    pub struct Public {
        pub(crate) K: Ciphertext,
        pub(crate) G: Ciphertext,
        pub(crate) proof: PiEncProof,
    }

    impl Public {
        pub fn to_bytes(&self) -> Result<Vec<u8>> {
            let result = [
                serialize(&self.K.0.to_bytes(), 2)?,
                serialize(&self.G.0.to_bytes(), 2)?,
                serialize(&self.proof.to_bytes()?, 2)?,
            ]
            .concat();
            Ok(result)
        }

        pub fn from_slice<B: Clone + AsRef<[u8]>>(input: B) -> Result<Self> {
            let (K_bytes, input) = tokenize(input.as_ref(), 2)?;
            let (G_bytes, input) = tokenize(&input, 2)?;
            let (proof_bytes, input) = tokenize(&input, 2)?;
            if !input.is_empty() {
                // Should not be encountering any more bytes
                return Err(InternalError::Serialization);
            }
            let K = Ciphertext(libpaillier::Ciphertext::from_slice(K_bytes));
            let G = Ciphertext(libpaillier::Ciphertext::from_slice(G_bytes));
            let proof = PiEncProof::from_slice(&proof_bytes)?;
            Ok(Self { K, G, proof })
        }
    }

    pub type PairWithMultiplePublics = super::PairWithMultiplePublics<Private, Public>;
}

pub mod round_two {
    use ecdsa::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
    use elliptic_curve::sec1::EncodedPoint;
    use k256::ProjectivePoint;

    use super::*;

    use crate::zkp::piaffg::PiAffgProof;
    use crate::zkp::pilog::PiLogProof;

    #[derive(Clone)]
    pub struct Private {
        pub(crate) beta: BigNumber,
        pub(crate) beta_hat: BigNumber,
    }

    impl Private {
        pub fn to_bytes(&self) -> Result<Vec<u8>> {
            let result = [
                serialize(&self.beta.to_bytes(), 2)?,
                serialize(&self.beta_hat.to_bytes(), 2)?,
            ]
            .concat();
            Ok(result)
        }

        pub fn from_slice<B: Clone + AsRef<[u8]>>(input: B) -> Result<Self> {
            let (beta_bytes, input) = tokenize(input.as_ref(), 2)?;
            let (beta_hat_bytes, input) = tokenize(&input, 2)?;
            if !input.is_empty() {
                // Should not be encountering any more bytes
                return Err(InternalError::Serialization);
            }
            let beta = BigNumber::from_slice(beta_bytes);
            let beta_hat = BigNumber::from_slice(beta_hat_bytes);
            Ok(Self { beta, beta_hat })
        }
    }

    #[derive(Clone)]
    pub struct Public {
        pub(crate) D: Ciphertext,
        pub(crate) D_hat: Ciphertext,
        pub(crate) F: Ciphertext,
        pub(crate) F_hat: Ciphertext,
        pub(crate) Gamma: ProjectivePoint,
        pub(crate) psi: PiAffgProof,
        pub(crate) psi_hat: PiAffgProof,
        pub(crate) psi_prime: PiLogProof,
    }

    impl Public {
        pub fn to_bytes(&self) -> Result<Vec<u8>> {
            let result = [
                serialize(&self.D.0.to_bytes(), 2)?,
                serialize(&self.D_hat.0.to_bytes(), 2)?,
                serialize(&self.F.0.to_bytes(), 2)?,
                serialize(&self.F_hat.0.to_bytes(), 2)?,
                serialize(self.Gamma.to_encoded_point(COMPRESSED).as_bytes(), 2)?,
                serialize(&self.psi.to_bytes()?, 2)?,
                serialize(&self.psi_hat.to_bytes()?, 2)?,
                serialize(&self.psi_prime.to_bytes()?, 2)?,
            ]
            .concat();
            Ok(result)
        }

        pub fn from_slice<B: Clone + AsRef<[u8]>>(input: B) -> Result<Self> {
            let (D_bytes, input) = tokenize(input.as_ref(), 2)?;
            let (D_hat_bytes, input) = tokenize(&input, 2)?;
            let (F_bytes, input) = tokenize(&input, 2)?;
            let (F_hat_bytes, input) = tokenize(&input, 2)?;
            let (Gamma_bytes, input) = tokenize(&input, 2)?;
            let (psi_bytes, input) = tokenize(&input, 2)?;
            let (psi_hat_bytes, input) = tokenize(&input, 2)?;
            let (psi_prime_bytes, input) = tokenize(&input, 2)?;
            if !input.is_empty() {
                // Should not be encountering any more bytes
                return Err(InternalError::Serialization);
            }
            let D = Ciphertext(libpaillier::Ciphertext::from_slice(D_bytes));
            let D_hat = Ciphertext(libpaillier::Ciphertext::from_slice(D_hat_bytes));
            let F = Ciphertext(libpaillier::Ciphertext::from_slice(F_bytes));
            let F_hat = Ciphertext(libpaillier::Ciphertext::from_slice(F_hat_bytes));
            let Gamma = ProjectivePoint::from_encoded_point(
                &EncodedPoint::from_bytes(Gamma_bytes).map_err(|_| InternalError::Serialization)?,
            )
            .ok_or(InternalError::Serialization)?;
            let psi = PiAffgProof::from_slice(&psi_bytes)?;
            let psi_hat = PiAffgProof::from_slice(&psi_hat_bytes)?;
            let psi_prime = PiLogProof::from_slice(&psi_prime_bytes)?;
            Ok(Self {
                D,
                D_hat,
                F,
                F_hat,
                Gamma,
                psi,
                psi_hat,
                psi_prime,
            })
        }
    }

    pub type Pair = super::Pair<Private, Public>;
}

pub mod round_three {
    use ecdsa::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
    use elliptic_curve::sec1::EncodedPoint;
    use k256::{ProjectivePoint, Scalar};

    use super::*;

    use crate::zkp::pilog::PiLogProof;

    pub struct Private {
        pub(crate) k: BigNumber,
        pub(crate) chi: Scalar,
        pub(crate) Gamma: ProjectivePoint,
        pub(crate) delta: Scalar,
        pub(crate) Delta: ProjectivePoint,
    }

    impl Private {
        pub fn to_bytes(&self) -> Result<Vec<u8>> {
            let result = [
                serialize(&self.k.to_bytes(), 2)?,
                serialize(&self.chi.to_bytes(), 2)?,
                serialize(self.Gamma.to_encoded_point(COMPRESSED).as_bytes(), 2)?,
                serialize(&self.delta.to_bytes(), 2)?,
                serialize(self.Delta.to_encoded_point(COMPRESSED).as_bytes(), 2)?,
            ]
            .concat();
            Ok(result)
        }

        pub fn from_slice<B: Clone + AsRef<[u8]>>(input: B) -> Result<Self> {
            let (k_bytes, input) = tokenize(input.as_ref(), 2)?;
            let (chi_bytes, input) = tokenize(&input, 2)?;
            let (Gamma_bytes, input) = tokenize(&input, 2)?;
            let (delta_bytes, input) = tokenize(&input, 2)?;
            let (Delta_bytes, input) = tokenize(&input, 2)?;
            if !input.is_empty() {
                // Should not be encountering any more bytes
                return Err(InternalError::Serialization);
            }
            let k = BigNumber::from_slice(&k_bytes);
            let chi = Scalar::from_bytes_reduced(&GenericArray::clone_from_slice(&chi_bytes));
            let Gamma = ProjectivePoint::from_encoded_point(
                &EncodedPoint::from_bytes(Gamma_bytes).map_err(|_| InternalError::Serialization)?,
            )
            .ok_or(InternalError::Serialization)?;
            let delta = Scalar::from_bytes_reduced(&GenericArray::clone_from_slice(&delta_bytes));
            let Delta = ProjectivePoint::from_encoded_point(
                &EncodedPoint::from_bytes(Delta_bytes).map_err(|_| InternalError::Serialization)?,
            )
            .ok_or(InternalError::Serialization)?;
            Ok(Self {
                k,
                chi,
                Gamma,
                delta,
                Delta,
            })
        }
    }

    #[derive(Clone)]
    pub struct Public {
        pub(crate) delta: Scalar,
        pub(crate) Delta: ProjectivePoint,
        pub(crate) psi_double_prime: PiLogProof,
    }

    impl Public {
        pub fn to_bytes(&self) -> Result<Vec<u8>> {
            let result = [
                serialize(&self.delta.to_bytes(), 2)?,
                serialize(self.Delta.to_encoded_point(COMPRESSED).as_bytes(), 2)?,
                serialize(&self.psi_double_prime.to_bytes()?, 2)?,
            ]
            .concat();
            Ok(result)
        }

        pub fn from_slice<B: Clone + AsRef<[u8]>>(input: B) -> Result<Self> {
            let (delta_bytes, input) = tokenize(input.as_ref(), 2)?;
            let (Delta_bytes, input) = tokenize(&input, 2)?;
            let (psi_double_prime_bytes, input) = tokenize(&input, 2)?;
            if !input.is_empty() {
                // Should not be encountering any more bytes
                return Err(InternalError::Serialization);
            }
            let delta = Scalar::from_bytes_reduced(&GenericArray::clone_from_slice(&delta_bytes));
            let Delta = ProjectivePoint::from_encoded_point(
                &EncodedPoint::from_bytes(Delta_bytes).map_err(|_| InternalError::Serialization)?,
            )
            .ok_or(InternalError::Serialization)?;
            let psi_double_prime = PiLogProof::from_slice(&psi_double_prime_bytes)?;
            Ok(Self {
                delta,
                Delta,
                psi_double_prime,
            })
        }
    }

    pub type PairWithMultiplePublics = super::PairWithMultiplePublics<Private, Public>;
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
        let mut delta = private.delta;
        let mut Delta = private.Delta;
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
        let s = utils::bn_to_scalar(&self.k).unwrap() * m + r * self.chi;

        (r, s)
    }
}

// Generate safe primes from a file. Usually, generating safe primes takes
// awhile (0-5 minutes per 512-bit safe prime on my laptop, average 50 seconds)
lazy_static::lazy_static! {
    static ref POOL_OF_PRIMES: Vec<BigNumber> = get_safe_primes();
}

/// FIXME: Should only expose this for testing purposes
pub fn get_safe_primes() -> Vec<BigNumber> {
    let file_contents = std::fs::read_to_string("src/safe_primes_512.txt").unwrap();
    let mut safe_primes_str: Vec<&str> = file_contents.split('\n').collect();
    safe_primes_str = safe_primes_str[0..safe_primes_str.len() - 1].to_vec(); // Remove the last element which is empty
    let safe_primes: Vec<BigNumber> = safe_primes_str
        .into_iter()
        .map(|s| BigNumber::from_slice(&hex::decode(&s).unwrap()))
        .collect();
    safe_primes
}

/// We sample safe primes that are 512 bits long. This comes from the security parameter
/// setting of κ = 128, and safe primes being of length 4κ (Figure 6, Round 1 of the CGGMP'21 paper)
pub(crate) fn get_random_safe_prime_512() -> BigNumber {
    // FIXME: should just return BigNumber::safe_prime(PRIME_BITS);
    POOL_OF_PRIMES[rand::thread_rng().gen_range(0..POOL_OF_PRIMES.len())].clone()
}
