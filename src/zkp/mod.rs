// Copyright (c) Facebook, Inc. and its affiliates.
// Modifications Copyright (c) 2023 Bolt Labs, Inc.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

//! Implements a trait for zero-knowledge proofs.
//!
//! In more detail, this module provides a trait [`Proof`] for constructing a
//! (non-interactive) zero knowledge proof. The trait provides two methods,
//! [`Proof::prove`] and [`Proof::verify`]. The former builds a proof and the
//! latter verifies the proof was constructed correctly.

pub(crate) mod piaffg;
pub(crate) mod pienc;
pub(crate) mod pifac;
pub(crate) mod pilog;
pub(crate) mod pimod;
pub(crate) mod piprm;
pub(crate) mod pisch;

use crate::errors::Result;
use merlin::Transcript;
use rand::{CryptoRng, RngCore};
use serde::{de::DeserializeOwned, Serialize};

/// A trait for constructing arbitrary system context.
///
/// This context can be turned into bytes and appended to a [`Transcript`].
pub(crate) trait ProofContext {
    fn as_bytes(&self) -> &[u8];
}

/// This is a temporary preliminary implementation that will be modified by
/// issue #240.
impl ProofContext for () {
    fn as_bytes(&self) -> &[u8] {
        &[]
    }
}

#[cfg(test)]
struct BadContext {}
#[cfg(test)]
impl ProofContext for BadContext {
    fn as_bytes(&self) -> &[u8] {
        &[8u8]
    }
}

/// A trait for constructing zero knowledge proofs.
///
/// The associated type [`Proof::CommonInput`] denotes the data known the both
/// the prover and verifier, and the associated type [`Proof::ProverSecret`]
/// denotes the data known only to the prover.
pub(crate) trait Proof: Sized + Serialize + DeserializeOwned {
    type CommonInput;
    type ProverSecret;
    /// Constructs a zero knowledge proof over [`Proof::ProverSecret`] and
    /// [`Proof::CommonInput`] using the provided [`Transcript`].
    fn prove<R: RngCore + CryptoRng>(
        input: &Self::CommonInput,
        secret: &Self::ProverSecret,
        context: &impl ProofContext,
        transcript: &mut Transcript,
        rng: &mut R,
    ) -> Result<Self>;
    /// Verifies a zero knowledge proof using the provided
    /// [`Proof::CommonInput`] and [`Transcript`].
    fn verify(
        &self,
        input: &Self::CommonInput,
        context: &impl ProofContext,
        transcript: &mut Transcript,
    ) -> Result<()>;
}
