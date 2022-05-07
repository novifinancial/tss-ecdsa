// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

//! Creates an [AuxInfoPublic] and [AuxInfoPrivate]

use crate::errors::Result;
use crate::zkp::setup::ZkSetupParameters;
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
        .ok_or_else(|| bail_context!("Could not generate decryption key"))?;

    let pk = EncryptionKey::from(&sk);
    let params = ZkSetupParameters::gen_from_primes(rng, &(&p * &q), &p, &q)?;

    Ok((AuxInfoPrivate { sk }, AuxInfoPublic { pk, params }))
}
