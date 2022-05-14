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

use libpaillier::unknown_order::BigNumber;
use rand::Rng;

#[macro_use]
pub mod errors;

mod auxinfo;
mod keygen;
pub mod messages;
mod paillier;
mod parameters;
mod presign;
pub mod protocol;
mod storage;
mod utils;
mod zkp;

use crate::presign::*;

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
