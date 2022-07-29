// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

use crate::errors::Result;
use crate::messages::{AuxinfoMessageType, MessageType};
use crate::zkp::pimod::{PiModInput, PiModProof, PiModSecret};
use crate::Identifier;
use crate::Message;
use libpaillier::unknown_order::BigNumber;
use merlin::Transcript;
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
        sid: Identifier,
        rho: [u8; 32],
        N: &BigNumber,
        p: &BigNumber,
        q: &BigNumber,
    ) -> Result<Self> {
        let mut transcript = Transcript::new(b"PaillierBlumModulusProof");
        transcript.append_message(b"Session Id", &serialize!(&sid)?);
        transcript.append_message(b"rho", &rho);
        let pimod = PiModProof::prove_with_transcript(
            rng,
            &PiModInput::new(N),
            &PiModSecret::new(p, q),
            &mut transcript,
        )?;
        Ok(Self { pimod })
    }

    pub(crate) fn verify(&self, sid: Identifier, rho: [u8; 32], N: &BigNumber) -> Result<()> {
        let mut transcript = Transcript::new(b"PaillierBlumModulusProof");
        transcript.append_message(b"Session Id", &serialize!(&sid)?);
        transcript.append_message(b"rho", &rho);
        self.pimod
            .verify_with_transcript(&PiModInput::new(N), &mut transcript)?;
        Ok(())
    }
}
