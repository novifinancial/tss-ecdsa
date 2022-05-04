// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

//! Creates a [KeySharePublic] and [KeySharePrivate]

use crate::key::{KeyInit, KeygenPrivate, KeygenPublic};
use crate::zkp::setup::ZkSetupParameters;
use anyhow::{Context, Result};
use libpaillier::{unknown_order::BigNumber, *};
use rand::{CryptoRng, RngCore};

#[derive(Debug, Clone)]
pub(crate) struct KeySharePrivate {
    pub(crate) x: BigNumber,
}

#[derive(Debug, Clone)]
pub(crate) struct KeySharePublic {
    pub(crate) X: k256::ProjectivePoint,
}

/// Generates a new [KeySharePrivate] and [KeySharePublic]
pub(crate) fn new_keyshare<R: RngCore + CryptoRng>(
    _rng: &mut R,
) -> Result<(KeySharePrivate, KeySharePublic)> {
    let order = crate::utils::k256_order();
    let x = BigNumber::random(&order);
    let g = k256::ProjectivePoint::generator();
    let X = g * crate::utils::bn_to_scalar(&x).context("Could not generate public component")?;

    Ok((KeySharePrivate { x }, KeySharePublic { X }))
}
