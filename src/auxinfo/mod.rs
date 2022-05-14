// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

//! Creates an [AuxInfoPublic] and [AuxInfoPrivate]

use crate::errors::Result;
use crate::paillier::{PaillierDecryptionKey, PaillierEncryptionKey};
use crate::zkp::setup::ZkSetupParameters;
use libpaillier::{DecryptionKey, EncryptionKey};
use rand::{prelude::IteratorRandom, CryptoRng, RngCore};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub(crate) struct AuxInfoPrivate {
    pub(crate) sk: PaillierDecryptionKey,
}

#[derive(Serialize, Deserialize)]
pub(crate) struct AuxInfoPublic {
    pub(crate) pk: PaillierEncryptionKey,
    pub(crate) params: ZkSetupParameters,
}

pub(crate) fn new_auxinfo<R: RngCore + CryptoRng>(
    rng: &mut R,
    _prime_bits: usize,
) -> Result<(AuxInfoPrivate, AuxInfoPublic)> {
    // Pull in pre-generated safe primes from text file (not a safe operation!).
    // This is meant to save on the time needed to generate these primes, but
    // should not be done in a production environment!
    let safe_primes = crate::get_safe_primes();
    let two_safe_primes = safe_primes.iter().choose_multiple(rng, 2);

    // FIXME: do proper safe prime generation
    //let p = BigNumber::safe_prime(prime_bits);
    //let q = BigNumber::safe_prime(prime_bits);

    let p = two_safe_primes[0].clone();
    let q = two_safe_primes[1].clone();

    let sk = PaillierDecryptionKey(
        DecryptionKey::with_safe_primes_unchecked(&p, &q)
            .ok_or_else(|| bail_context!("Could not generate decryption key"))?,
    );

    let pk = PaillierEncryptionKey(EncryptionKey::from(&sk.0));
    let params = ZkSetupParameters::gen_from_primes(rng, &(&p * &q), &p, &q)?;

    Ok((AuxInfoPrivate { sk }, AuxInfoPublic { pk, params }))
}

impl AuxInfoPublic {
    /// Verifies that the public key's modulus matches the ZKSetupParameters modulus
    /// N, and that the parameters have appropriate s and t values.
    pub(crate) fn verify(&self) -> Result<()> {
        if self.pk.n() != &self.params.N {
            return verify_err!("Mismatch with pk.n() and params.N");
        }
        self.params.verify()
    }
}
