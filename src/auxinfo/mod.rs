// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

//! Creates an [AuxInfoPublic] and [AuxInfoPrivate]

use crate::zkp::setup::ZkSetupParameters;
use anyhow::{Context, Result};
use libpaillier::{unknown_order::BigNumber, *};
use rand::{CryptoRng, RngCore};

pub(crate) struct AuxInfoPrivate {
    pub(crate) sk: DecryptionKey,
}

pub(crate) struct AuxInfoPublic {
    pub(crate) pk: EncryptionKey,
    pub(crate) params: ZkSetupParameters,
}

pub(crate) fn new_auxinfo<R: RngCore + CryptoRng>(
    rng: &mut R,
    prime_bits: usize,
) -> Result<(AuxInfoPrivate, AuxInfoPublic)> {
    let p = BigNumber::safe_prime(prime_bits);
    let q = BigNumber::safe_prime(prime_bits);
    let sk = DecryptionKey::with_safe_primes_unchecked(&p, &q)
        .context("Could not generate AuxInfoPrivate")?;

    let pk = EncryptionKey::from(&sk);
    let params = ZkSetupParameters::gen_from_primes(rng, &(&p * &q), &p, &q)?;

    Ok((AuxInfoPrivate { sk }, AuxInfoPublic { pk, params }))
}
