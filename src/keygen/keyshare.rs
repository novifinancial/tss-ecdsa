// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

use crate::{
    errors::Result,
    messages::{KeygenMessageType, MessageType},
    utils::CurvePoint,
    Message,
};
use libpaillier::unknown_order::BigNumber;
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

    pub(crate) fn from_message(message: &Message) -> Result<Self> {
        if message.message_type() != MessageType::Keygen(KeygenMessageType::PublicKeyshare) {
            return bail!("Wrong message type, expected MessageType::PublicKeyshare");
        }
        let keyshare_public: KeySharePublic = deserialize!(&message.unverified_bytes)?;

        match keyshare_public.verify() {
            Ok(()) => Ok(keyshare_public),
            Err(e) => bail!("Failed to verify keyshare public: {}", e),
        }
    }
}
