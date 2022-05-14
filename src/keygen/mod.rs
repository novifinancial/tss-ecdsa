// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

//! Creates a [KeySharePublic] and [KeySharePrivate]

use crate::{errors::Result, utils::CurvePoint};
use libpaillier::unknown_order::BigNumber;
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct KeySharePrivate {
    pub(crate) x: BigNumber, // in the range [1, q)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct KeySharePublic {
    pub(crate) X: CurvePoint,
}

impl KeySharePublic {
    pub(crate) fn verify(&self) -> Result<()> {
        // FIXME: add actual verification logic
        Ok(())
    }
}

/// Generates a new [KeySharePrivate] and [KeySharePublic]
pub(crate) fn new_keyshare<R: RngCore + CryptoRng>(
    _rng: &mut R,
) -> Result<(KeySharePrivate, KeySharePublic)> {
    let order = crate::utils::k256_order();
    let x = BigNumber::random(&order);
    let g = CurvePoint::GENERATOR;
    let X = CurvePoint(
        g.0 * crate::utils::bn_to_scalar(&x)
            .ok_or_else(|| bail_context!("Could not generate public component"))?,
    );

    Ok((KeySharePrivate { x }, KeySharePublic { X }))
}
