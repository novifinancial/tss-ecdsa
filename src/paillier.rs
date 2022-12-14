// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

use crate::errors::{InternalError, Result};
use crate::utils::random_bn_in_z_star;
use libpaillier::unknown_order::BigNumber;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Paillier-specific errors
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PaillierError {
    #[error("Failed to create a Paillier decryption key from inputs")]
    CouldNotCreateKey,
    #[error("The inputs to a homomorphic operation on a Paillier ciphertext were malformed")]
    InvalidOperation,
    #[error("The attemped decryption of a Pailler ciphertext failed")]
    DecryptionFailed,
}

/// TODO: Remove this once `InternalError` is instantiated with thiserror.
impl From<PaillierError> for InternalError {
    fn from(err: PaillierError) -> Self {
        InternalError::PaillierError(err)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct PaillierCiphertext(pub(crate) BigNumber);

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct PaillierEncryptionKey(pub(crate) libpaillier::EncryptionKey);

impl PaillierEncryptionKey {
    pub(crate) fn n(&self) -> &BigNumber {
        self.0.n()
    }

    pub(crate) fn encrypt(&self, x: &BigNumber) -> (BigNumber, BigNumber) {
        let mut rng = rand::rngs::OsRng;
        let nonce = random_bn_in_z_star(&mut rng, self.0.n());

        let one = BigNumber::one();
        let base = one + self.n();
        let a = base.modpow(x, self.0.nn());
        let b = nonce.modpow(self.n(), self.0.nn());
        let c = a.modmul(&b, self.0.nn());
        (c, nonce)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct PaillierDecryptionKey(libpaillier::DecryptionKey);

impl PaillierDecryptionKey {
    pub(crate) fn decrypt(&self, c: &BigNumber) -> Result<Vec<u8>> {
        Ok(self.0.decrypt(c).ok_or(PaillierError::DecryptionFailed)?)
    }

    /// Generate a new [`PaillierDecryptionKey`] from two primes.
    ///
    /// The inputs `p` and `q` are checked for primality but not for _safe_ primality.
    /// TODO #56: Check prime size and output size.
    pub(crate) fn from_primes(p: &BigNumber, q: &BigNumber) -> Result<Self> {
        Ok(PaillierDecryptionKey(
            libpaillier::DecryptionKey::with_primes(p, q)
                .ok_or(PaillierError::CouldNotCreateKey)?,
        ))
    }

    /// Retrieve the public [`PaillierEncryptionKey`] corresponding to this secret
    /// [`PaillierDecryptionKey`].
    pub fn encryption_key(&self) -> PaillierEncryptionKey {
        PaillierEncryptionKey(libpaillier::EncryptionKey::from(&self.0))
    }
}
