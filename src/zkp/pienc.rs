// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

//! Implements the ZKP from Figure 14 of https://eprint.iacr.org/2021/060.pdf

use crate::{Ciphertext, errors::*};
use libpaillier::unknown_order::BigNumber;
use merlin::Transcript;


#[derive(Debug)]
pub struct PaillierEncryptionInRangeProof {
    pub(crate) N: BigNumber,
    w: BigNumber,
    // (x, a, b, z),
    elements: Vec<PaillierBlumModulusProofElements>,
}

impl PaillierEncryptionInRangeProof {
    // N: modulus, K: Paillier ciphertext
    pub(crate) fn prove(N: BigNumber, K: Ciphertext) -> Result<Self, InternalError> {

    }
}
