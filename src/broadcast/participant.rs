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
use crate::broadcast::BroadcastData;
use crate::message_queue::MessageQueue;
use crate::messages::KeygenMessageType;
use crate::messages::{Message, MessageType};
use crate::protocol::ParticipantIdentifier;
use crate::storage::StorableType;
use crate::storage::Storage;
use crate::utils::{k256_order, process_ready_message};
use crate::zkp::pisch::{PiSchInput, PiSchPrecommit, PiSchProof, PiSchSecret};
use crate::{CurvePoint, Identifier};
use crate::participant::ProtocolParticipant;
use crate::run_only_once;
use libpaillier::unknown_order::BigNumber;
use merlin::Transcript;
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone)]
pub(crate) struct BroadcastParticipant {
    /// A unique identifier for this participant
    id: ParticipantIdentifier,
    /// A list of all other participant identifiers participating in the protocol
    other_participant_ids: Vec<ParticipantIdentifier>,
    /// Local storage for this participant to store secrets
    storage: Storage,
}

impl ProtocolParticipant for BroadcastParticipant{
    fn storage(&self) -> &Storage{
        &self.storage
    }

    fn storage_mut(&mut self) -> &mut Storage{
        &mut self.storage
    }

    fn id(&self) -> ParticipantIdentifier{
        self.id
    }
}

impl BroadcastParticipant {
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

    pub(crate) fn process_message<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
        message: &Message,
        main_storage: &mut Storage,
    ) -> Result<Vec<Message>> {
        match message.message_type() {
            MessageType::Keygen(BroadcastMessageType::Disperse) => {
                let messages = self.handle_round_one_msg(rng, message, main_storage)?;
                Ok(messages)
            }
            MessageType::Keygen(BroadcastMessageType::ReDisperse) => {
                let messages = self.handle_round_two_msg(rng, message, main_storage)?;
                Ok(messages)
            }
            _ => {
                return bail!(
                    "Attempting to process a non-broadcast message with a broadcast participant"
                );
            }
        }
    }

    fn handle_ready_msg<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
        message: &Message,
    ) -> Result<Vec<Message>> {

        // [ [data, votes], [data, votes], ...]
        // for a given tag and sid, only run once
        let data =  BroadcastData::from_message(message);
        let messages = run_only_once_per_tag!(self.gen_round_one_msgs(rng, message))?;
            let _ = run_only_once!(self.gen_round_one_msgs(rng, message))?;
            //let more_messages = self.gen_round_one_msgs(rng, message)?;
            messages.extend_from_slice(&more_messages);
        }
        Ok(messages)
    }

    fn gen_round_one_msgs<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
        message: &Message,
    ) -> Result<Vec<Message>> {
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

        // todo: maybe there should be a function for generating a PiSchInput
        let input = PiSchInput::new(&g, &q, &X);
        let sch_precom = PiSchProof::precommit(rng, &input)?;
        let decom = KeygenDecommit::new(&message.id(), &self.id, &keyshare_public, &sch_precom);
        let com = decom.commit()?;
        let com_bytes = &serialize!(&com)?;

        self.storage
            .store(StorableType::KeygenCommit, message.id(), self.id, com_bytes)?;
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
                    com_bytes,
                )
            })
            .collect();
        Ok(messages)
    }

    fn handle_round_one_msg<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
        message: &Message,
        main_storage: &mut Storage,
    ) -> Result<Vec<Message>> {
        let message_bytes = serialize!(&KeygenCommit::from_message(message)?)?;
        self.storage.store(
            StorableType::KeygenCommit,
            message.id(),
            message.from(),
            &message_bytes,
        )?;

        // check if we've received all the commits.
        let r1_done = self
            .storage
            .contains_for_all_ids(
                StorableType::KeygenCommit,
                message.id(),
                &self.other_participant_ids.clone(),
            )
            .is_ok();
        let mut messages = vec![];

        if r1_done {
            let more_messages = run_only_once!(self.gen_round_two_msgs(rng, message))?;
            messages.extend_from_slice(&more_messages);
            // process any round 2 messages we may have received early
            for msg in self
                .fetch_messages(
                    MessageType::Keygen(KeygenMessageType::R2Decommit),
                    message.id(),
                )?
                .iter()
            {
                messages.extend_from_slice(&self.handle_round_two_msg(rng, msg, main_storage)?);
            }
        }
        Ok(messages)
    }
    fn gen_round_two_msgs<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
        message: &Message,
    ) -> Result<Vec<Message>> {
        // check that we've generated our keyshare before trying to retrieve it
        let fetch = vec![(StorableType::PublicKeyshare, message.id(), self.id)];
        let public_keyshare_generated = self.storage.contains_batch(&fetch).is_ok();
        let mut messages = vec![];
        if !public_keyshare_generated {
            let more_messages = run_only_once!(self.gen_round_one_msgs(rng, message))?;
            messages.extend_from_slice(&more_messages);
        }

        // retreive your decom from storage
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

    fn handle_round_two_msg<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
        message: &Message,
        main_storage: &mut Storage,
    ) -> Result<Vec<Message>> {
        // We must receive all commitments in round 1 before we start processing decommits in round 2.
        let r1_done = self
            .storage
            .contains_for_all_ids(
                StorableType::KeygenCommit,
                message.id(),
                &[self.other_participant_ids.clone(), vec![self.id]].concat(),
            )
            .is_ok();
        if !r1_done {
            // store any early round2 messages
            self.stash_message(message)?;
            return Ok(vec![]);
        }
        let decom = KeygenDecommit::from_message(message)?;
        let com_bytes =
            self.storage
                .retrieve(StorableType::KeygenCommit, message.id(), message.from())?;
        let com: KeygenCommit = deserialize!(&com_bytes)?;
        if !decom.verify(&message.id(), &message.from(), &com)? {
            return bail!("Decommitment Check Failed!");
        }
        self.storage.store(
            StorableType::KeygenDecommit,
            message.id(),
            message.from(),
            &serialize!(&decom)?,
        )?;

        // check if we've received all the decommits
        let r2_done = self
            .storage
            .contains_for_all_ids(
                StorableType::KeygenDecommit,
                message.id(),
                &self.other_participant_ids.clone(),
            )
            .is_ok();
        let mut messages = vec![];

        if r2_done {
            let more_messages = run_only_once!(self.gen_round_three_msgs(rng, message))?;
            messages.extend_from_slice(&more_messages);
            for msg in self
                .fetch_messages(
                    MessageType::Keygen(KeygenMessageType::R3Proof),
                    message.id(),
                )?
                .iter()
            {
                messages.extend_from_slice(&self.handle_round_three_msg(rng, msg, main_storage)?);
            }
        }
        Ok(messages)
    }
}
