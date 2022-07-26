// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

use crate::errors::Result;
use crate::messages::{AuxinfoMessageType, MessageType};
use crate::zkp::pimod::{PiModInput, PiModProof, PiModSecret};
use crate::zkp::Proof;
use crate::Message;
use libpaillier::unknown_order::BigNumber;
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone)]
pub(crate) struct AuxInfoProof {
    pub pimod: PiModProof,
    //pub pifac: PiFacProof,
}

impl AuxInfoProof {
    pub(crate) fn from_message(message: &Message) -> Result<Self> {
        if message.message_type() != MessageType::Auxinfo(AuxinfoMessageType::R3Proof) {
            return bail!("Wrong message type, expected MessageType::Auxinfo(AuxinfoMessageType::R1CommitHash)");
        }
        let auxinfo_proof: AuxInfoProof = deserialize!(&message.unverified_bytes)?;
        Ok(auxinfo_proof)
    }

    pub(crate) fn prove<R: RngCore + CryptoRng>(
        rng: &mut R,
        N: &BigNumber,
        p: &BigNumber,
        q: &BigNumber,
    ) -> Result<Self> {
        let pimod = PiModProof::prove(rng, &PiModInput::new(N), &PiModSecret::new(p, q))?;
        Ok(Self { pimod })
    }

    pub(crate) fn verify(&self, N: &BigNumber) -> Result<()> {
        self.pimod.verify(&PiModInput::new(N))?;
        Ok(())
    }
}
