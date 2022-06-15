// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

use crate::errors::Result;
use crate::keygen::keygen_commit::{KeygenCommit, KeygenDecommit};
use crate::keygen::keyshare::KeySharePrivate;
use crate::keygen::keyshare::KeySharePublic;
use crate::messages::KeygenMessageType;
use crate::messages::{Message, MessageType};
use crate::protocol::ParticipantIdentifier;
use crate::storage::StorableType;
use crate::storage::Storage;
use crate::utils::{k256_order, process_ready_message};
use crate::zkp::pisch::{PiSchInput, PiSchPrecommit, PiSchProof, PiSchSecret};
use crate::CurvePoint;
use libpaillier::unknown_order::BigNumber;
use merlin::Transcript;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone)]
pub(crate) struct KeygenParticipant {
    /// A unique identifier for this participant
    id: ParticipantIdentifier,
    /// A list of all other participant identifiers participating in the protocol
    other_participant_ids: Vec<ParticipantIdentifier>,
    /// Local storage for this participant to store secrets
    storage: Storage,
}

impl KeygenParticipant {
    pub(crate) fn from_ids(
        id: ParticipantIdentifier,
        other_participant_ids: Vec<ParticipantIdentifier>,
    ) -> Self {
        Self {
            id,
            other_participant_ids,
            storage: Storage::new(),
        }
    }

    /// Processes the incoming message given the storage from the protocol participant
    /// (containing auxinfo and keygen artifacts). Optionally produces a [KeysharePrivate]
    /// and [KeysharePublic] once keygen is complete.
    pub(crate) fn process_message(
        &mut self,
        message: &Message,
        main_storage: &mut Storage,
    ) -> Result<Vec<Message>> {
        match message.message_type() {
            MessageType::Keygen(KeygenMessageType::Ready) => {
                let messages = self.handle_ready_msg(message)?;
                Ok(messages)
            }
            MessageType::Keygen(KeygenMessageType::R1CommitHash) => {
                let messages = self.handle_round_one_msg(message)?;
                Ok(messages)
            }
            MessageType::Keygen(KeygenMessageType::R2Decommit) => {
                let messages = self.handle_round_two_msg(message)?;
                Ok(messages)
            }
            MessageType::Keygen(KeygenMessageType::R3Proof) => {
                let messages = self.handle_round_three_msg(message, main_storage)?;
                Ok(messages)
            }
            _ => {
                return bail!(
                    "Attempting to process a non-keygen message with a keygen participant"
                );
            }
        }
    }
    //fn do_round_one<R: RngCore + CryptoRng>(&mut self, rng: &mut R, message: &Message, main_storage: &mut Storage) -> Result<Vec<Message>> {
    fn handle_ready_msg(
        &mut self,
        message: &Message,
    ) -> Result<Vec<Message>> {
        let (mut messages, is_ready) = process_ready_message(
            self.id,
            &self.other_participant_ids,
            &mut self.storage,
            message,
            StorableType::KeygenReady,
        )?;

        //todo: only send once
        if is_ready {
            let more_messages = self.gen_round_one_msgs(message)?;
            messages.extend_from_slice(&more_messages);
        }
        Ok(messages)
    }
    //fn gen_round_one_msgs<R: RngCore + CryptoRng>(&mut self, rng: &mut R, message: &Message, main_storage: &mut Storage) -> Result<Vec<Message>> {
    fn gen_round_one_msgs(
        &mut self,
        message: &Message,
    ) -> Result<Vec<Message>> {
        //todo: add check here that this hasn't happened yet
        let mut rng = rand::rngs::OsRng;
        let (keyshare_private, keyshare_public) = new_keyshare()?;
        self.storage.store(
            StorableType::PrivateKeyshare,
            message.id(),
            self.id,
            &serialize!(&keyshare_private)?,
        )?;
        self.storage.store(
            StorableType::PublicKeyshare,
            message.id(),
            self.id,
            &serialize!(&keyshare_public)?,
        )?;

        let q = crate::utils::k256_order();
        let g = CurvePoint(k256::ProjectivePoint::GENERATOR);
        let X = keyshare_public.X;

        //todo: maybe there should be a function for generating a PiSchInput
        let input = PiSchInput::new(&g, &q, &X);
        let sch_precom = PiSchProof::precommit(&mut rng, &input)?;
        let decom = KeygenDecommit::new(&message.id(), &self.id, &keyshare_public, &sch_precom);
        let com = decom.commit()?;
        let com_bytes = &serialize!(&com)?;

        self.storage.store(
            StorableType::KeygenCommit,
            message.id(),
            self.id,
            &com_bytes,
        )?;
        self.storage.store(
            StorableType::KeygenDecommit,
            message.id(),
            self.id,
            &serialize!(&decom)?,
        )?;
        self.storage.store(
            StorableType::KeygenSchnorrPrecom,
            message.id(),
            self.id,
            &serialize!(&sch_precom)?,
        )?;

        let messages: Vec<Message> = self
            .other_participant_ids
            .iter()
            .map(|&other_participant_id| {
                Message::new(
                    MessageType::Keygen(KeygenMessageType::R1CommitHash),
                    message.id(),
                    self.id,
                    other_participant_id,
                    &com_bytes,
                )
            })
            .collect();
        Ok(messages)
    }
    fn handle_round_one_msg(
        &mut self,
        message: &Message,
    ) -> Result<Vec<Message>> {
        let message_bytes = serialize!(&KeygenCommit::from_message(message)?)?;
        self.storage.store(
            StorableType::KeygenCommit,
            message.id(),
            message.from(),
            &message_bytes,
        )?;

        //check if we've received all the commits
        let r1_done = self.storage.contains_for_all_ids(StorableType::KeygenCommit, message.id(), &[self.other_participant_ids.clone(), vec![self.id]].concat()).is_ok();
        let mut messages = vec![];

        //todo: only send once
        if r1_done {
            let more_messages = self.gen_round_two_msgs(message)?;
            messages.extend_from_slice(&more_messages);
        }
        Ok(messages)
    }
    fn gen_round_two_msgs(
        &mut self,
        message: &Message,
    ) -> Result<Vec<Message>> {
        //check that we've generated our keyshare before trying to retrieve it
        let mut fetch = vec![];
        fetch.push((StorableType::PublicKeyshare, message.id(), self.id));
        let public_keyshare_generated = self.storage.contains_batch(&fetch).is_ok();
        let mut messages = vec![];
        if !public_keyshare_generated {
            let more_messages = self.gen_round_one_msgs(message)?;
            messages.extend_from_slice(&more_messages);
        }

        //retreive your decom from storage
        let decom_bytes =
            self.storage
                .retrieve(StorableType::KeygenDecommit, message.id(), self.id)?;
        let more_messages: Vec<Message> = self
            .other_participant_ids
            .iter()
            .map(|&other_participant_id| {
                Message::new(
                    MessageType::Keygen(KeygenMessageType::R2Decommit),
                    message.id(),
                    self.id,
                    other_participant_id,
                    &decom_bytes,
                )
            })
            .collect();
        messages.extend_from_slice(&more_messages);
        Ok(messages)
    }
    fn handle_round_two_msg(
        &mut self,
        message: &Message,
    ) -> Result<Vec<Message>> {
        let decom = KeygenDecommit::from_message(message)?;
        let com_bytes =
            self.storage
                .retrieve(StorableType::KeygenCommit, message.id(), message.from())?;
        let com: KeygenCommit = deserialize!(&com_bytes)?;
        if !decom.verify(&message.id(), &message.from(), &com)? {
            return bail!("Decommitment Check Failed!");
        }
        self.storage.store(StorableType::KeygenDecommit, message.id(), message.from(), &serialize!(&decom)?)?;

        //check if we've received all the decommits
        let r2_done = self.storage.contains_for_all_ids(StorableType::KeygenDecommit, message.id(), &[self.other_participant_ids.clone(), vec![self.id]].concat()).is_ok();
        let mut messages = vec![];

        //todo: only send once
        if r2_done {
            let more_messages = self.gen_round_three_msgs(message)?;
            messages.extend_from_slice(&more_messages);
        }
        Ok(messages)
    }
    fn gen_round_three_msgs(
        &mut self,
        message: &Message,
    ) -> Result<Vec<Message>> {
        let rids: Vec<[u8; 32]> = self
            .other_participant_ids
            .iter()
            .map(|&other_participant_id| {
                let decom: KeygenDecommit = deserialize!(&self.storage.retrieve(StorableType::KeygenDecommit, message.id(), other_participant_id).unwrap()).unwrap();
                decom.rid
            })
            .collect();
        let my_decom: KeygenDecommit = deserialize!(&self.storage.retrieve(StorableType::KeygenDecommit, message.id(), self.id)?)?;
        let mut global_rid = my_decom.rid.clone();
        // xor all the rids together. In principle, many different options for combining these should be okay
        for rid in rids.iter(){
            for i in 0..32{
                global_rid[i] = global_rid[i] ^ rid[i];
            }
        }
        self.storage.store(StorableType::KeygenGlobalRid, message.id(), self.id, &serialize!(&global_rid)?)?;

        let mut transcript = Transcript::new(b"keygen schnorr");
        transcript.append_message(b"rid", &serialize!(&global_rid)?);
        let precom: PiSchPrecommit = deserialize!(&self.storage.retrieve(StorableType::KeygenSchnorrPrecom, message.id(), self.id)?)?;

        let q = crate::utils::k256_order();
        let g = CurvePoint(k256::ProjectivePoint::GENERATOR);
        let my_pk: KeySharePublic = deserialize!(&self.storage.retrieve(StorableType::PublicKeyshare, message.id(), self.id)?)?;
        let input = PiSchInput::new(&g, &q, &my_pk.X);

        let my_sk: KeySharePrivate = deserialize!(&self.storage.retrieve(StorableType::PrivateKeyshare, message.id(), self.id)?)?;

        let proof = PiSchProof::resume_proof(precom, &input, &PiSchSecret::new(&my_sk.x), &transcript)?;
        let proof_bytes = serialize!(&proof)?;

        let more_messages: Vec<Message> = self
            .other_participant_ids
            .iter()
            .map(|&other_participant_id| {
                Message::new(
                    MessageType::Keygen(KeygenMessageType::R3Proof),
                    message.id(),
                    self.id,
                    other_participant_id,
                    &proof_bytes,
                )
            })
            .collect();

        Ok(more_messages)
    }
    fn handle_round_three_msg(
        &mut self,
        message: &Message,
        main_storage: &mut Storage,
    ) -> Result<Vec<Message>> {
        let proof = PiSchProof::from_message(message)?;
        let global_rid: [u8;32] = deserialize!(&self.storage.retrieve(StorableType::KeygenGlobalRid, message.id(), self.id)?)?;
        let decom: KeygenDecommit = deserialize!(&self.storage.retrieve(StorableType::KeygenDecommit, message.id(), message.from())?)?;

        let q = crate::utils::k256_order();
        let g = CurvePoint(k256::ProjectivePoint::GENERATOR);
        let input = PiSchInput::new(&g, &q, &decom.pk.X);

        let mut transcript = Transcript::new(b"keygen schnorr");
        transcript.append_message(b"rid", &serialize!(&global_rid)?);

        proof.verify_with_transcript(&input, &transcript)?;
        let keyshare = decom.get_keyshare();
        self.storage.store(
            StorableType::PublicKeyshare,
            message.id(),
            message.from(),
            &serialize!(&keyshare)?,
        )?;

        //check if we've stored all the public keyshares
        let keyshare_done = self.storage.contains_for_all_ids(StorableType::PublicKeyshare, message.id(), &[self.other_participant_ids.clone(), vec![self.id]].concat()).is_ok();

        //todo: only do once
        if keyshare_done {
            for oid in self.other_participant_ids.iter(){
                let keyshare_bytes = self.storage.retrieve(StorableType::PublicKeyshare, message.id(), *oid)?;
                main_storage.store(StorableType::PublicKeyshare, message.id(), *oid, &keyshare_bytes)?;
            }
            let my_pk_bytes = self.storage.retrieve(StorableType::PublicKeyshare, message.id(), self.id)?;
            let my_sk_bytes = self.storage.retrieve(StorableType::PrivateKeyshare, message.id(), self.id)?;
            main_storage.store(StorableType::PublicKeyshare, message.id(), self.id, &my_pk_bytes)?;
            main_storage.store(StorableType::PrivateKeyshare, message.id(), self.id, &my_sk_bytes)?;
        }
        Ok(vec![])
    }
}

/// Generates a new [KeySharePrivate] and [KeySharePublic]
fn new_keyshare() -> Result<(KeySharePrivate, KeySharePublic)> {
    let order = k256_order();
    let x = BigNumber::random(&order);
    let g = CurvePoint::GENERATOR;
    let X = CurvePoint(
        g.0 * crate::utils::bn_to_scalar(&x)
            .ok_or_else(|| bail_context!("Could not generate public component"))?,
    );

    Ok((KeySharePrivate { x }, KeySharePublic { X }))
}
