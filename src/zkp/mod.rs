// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

//pub(crate) mod piaffg;
pub(crate) mod pienc;
pub(crate) mod pimod;
pub(crate) mod piprm;
pub(crate) mod setup;

use crate::errors::Result;
use rand::{CryptoRng, RngCore};

pub(crate) trait Proof: Sized {
    type CommonInput;
    type ProverSecret;

    fn prove<R: RngCore + CryptoRng>(
        rng: &mut R,
        input: &Self::CommonInput,
        secret: &Self::ProverSecret,
    ) -> Result<Self>;

    fn verify(&self, input: &Self::CommonInput) -> bool;
}
