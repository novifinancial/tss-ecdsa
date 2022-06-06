// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

use crate::errors::Result;
use crate::messages::{AuxinfoMessageType, MessageType};
use crate::paillier::{PaillierDecryptionKey, PaillierEncryptionKey};
use crate::zkp::setup::ZkSetupParameters;
use crate::Message;
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

impl AuxInfoPublic {
    /// Verifies that the public key's modulus matches the ZKSetupParameters modulus
    /// N, and that the parameters have appropriate s and t values.
    pub(crate) fn verify(&self) -> Result<()> {
        if self.pk.n() != &self.params.N {
            return verify_err!("Mismatch with pk.n() and params.N");
        }
        self.params.verify()
    }

    pub(crate) fn from_message(message: &Message) -> Result<Self> {
        if message.message_type() != MessageType::Auxinfo(AuxinfoMessageType::Public) {
            return bail!(
                "Wrong message type, expected MessageTypeAuxinfo::(AuxinfoMessageType::Public)"
            );
        }
        let aux_info_public: AuxInfoPublic = deserialize!(&message.unverified_bytes)?;

        match aux_info_public.verify() {
            Ok(()) => Ok(aux_info_public),
            Err(e) => bail!("Failed to verify auxinfo public: {}", e),
        }
    }
}
