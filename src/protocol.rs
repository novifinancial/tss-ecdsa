// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

//! Contains the main protocol that is executed through a [Participant]

use crate::auxinfo::AuxInfoPublic;
use crate::errors::Result;
use crate::keygen::KeySharePublic;
use crate::messages::*;
use crate::presign::PresignKeyShareAndInfo;
use crate::presign::PresignRecord;
use crate::round_three::RoundThreeInput;
use crate::storage::*;
use crate::utils::CurvePoint;
use k256::elliptic_curve::Field;
use k256::elliptic_curve::IsHigh;
use rand::{CryptoRng, Rng, RngCore};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt::Debug;

/////////////////////
// Participant API //
/////////////////////

/// Each participant has an inbox which can contain messages.
#[derive(Serialize, Deserialize, Clone)]
pub struct Participant {
    /// A unique identifier for this participant
    pub id: ParticipantIdentifier,
    /// A list of all other participant identifiers participating in the protocol
    pub other_participant_ids: Vec<ParticipantIdentifier>,
    /// An inbox for this participant containing messages sent from other participants
    inbox: Vec<Vec<u8>>,
    /// Local storage for this participant to store secrets
    storage: Storage,
    /// presign -> {keyshare, auxinfo} map
    presign_map: HashMap<Identifier, (Identifier, Identifier)>,
}

impl Participant {
    /// Initialized the participant from a [ParticipantConfig]
    pub fn from_config(config: ParticipantConfig) -> Result<Self> {
        Ok(Participant {
            id: config.id,
            other_participant_ids: config.other_ids,
            inbox: vec![],
            storage: Storage::new(),
            presign_map: HashMap::new(),
        })
    }

    /// Instantiate a new quorum of participants of a specified size. Random identifiers
    /// are selected
    pub fn new_quorum<R: RngCore + CryptoRng>(
        quorum_size: usize,
        rng: &mut R,
    ) -> Result<Vec<Self>> {
        let mut participant_ids = vec![];
        for _ in 0..quorum_size {
            participant_ids.push(ParticipantIdentifier::random(rng));
        }
        let participants = participant_ids
            .iter()
            .map(|&participant_id| -> Result<Participant> {
                // Filter out current participant id from list of other ids
                let mut other_ids = vec![];
                for &id in participant_ids.iter() {
                    if id != participant_id {
                        other_ids.push(id);
                    }
                }

                Self::from_config(ParticipantConfig {
                    id: participant_id,
                    other_ids,
                })
            })
            .collect::<Result<Vec<Participant>>>()?;
        Ok(participants)
    }

    fn process_ready_message(
        &mut self,
        message: &Message,
        storable_type: StorableType,
    ) -> Result<(Vec<Message>, bool)> {
        self.storage
            .store(storable_type, &message.identifier, &message.from, &[])?;

        let mut messages = vec![];

        // If message is coming from self, then tell the other participants that we are ready
        if message.from == self.id {
            for other_id in self.other_participant_ids.clone() {
                messages.push(Message::new(
                    message.message_type,
                    message.identifier,
                    self.id,
                    other_id,
                    &[],
                ));
            }
        }

        // Make sure that all parties are ready before proceeding
        let mut fetch = vec![];
        for participant in self.other_participant_ids.clone() {
            fetch.push((storable_type, message.identifier, participant));
        }
        fetch.push((storable_type, message.identifier, self.id));
        let is_ready = self.storage.contains_batch(&fetch).is_ok();

        Ok((messages, is_ready))
    }

    /// Pulls the first message from the participant's inbox, and then potentially
    /// outputs a bunch of messages that need to be delivered to other participants'
    /// inboxes.
    #[cfg_attr(feature = "flame_it", flame)]
    pub fn process_single_message<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
    ) -> Result<Vec<Message>> {
        let message: Message = deserialize!(&self.inbox.remove(0))?;

        println!(
            "processing participant: {}, with message type: {:?}",
            &self.id, &message.message_type,
        );

        match message.message_type {
            MessageType::AuxInfoReady => {
                let (mut messages, is_ready) =
                    self.process_ready_message(&message, StorableType::AuxInfoReady)?;
                if is_ready {
                    let more_messages = self.do_auxinfo_gen(rng, &message)?;
                    messages.extend_from_slice(&more_messages);
                }
                Ok(messages)
            }
            MessageType::KeygenReady => {
                let (mut messages, is_ready) =
                    self.process_ready_message(&message, StorableType::KeygenReady)?;
                if is_ready {
                    let more_messages = self.do_keygen(rng, &message)?;
                    messages.extend_from_slice(&more_messages);
                }
                Ok(messages)
            }
            MessageType::PresignReady => {
                let (mut messages, is_ready) =
                    self.process_ready_message(&message, StorableType::PresignReady)?;
                if is_ready {
                    let more_messages = self.do_round_one(&message)?;
                    messages.extend_from_slice(&more_messages);
                }
                Ok(messages)
            }
            MessageType::AuxInfoPublic => {
                // First, verify the bytes of the public auxinfo, and then
                // store it locally
                let message_bytes = serialize!(&message.validate_to_auxinfo_public()?)?;
                self.storage.store(
                    StorableType::AuxInfoPublic,
                    &message.identifier,
                    &message.from,
                    &message_bytes,
                )?;

                Ok(vec![])
            }
            MessageType::PublicKeyshare => {
                // First, verify the bytes of the public keyshare, and then
                // store it locally
                let message_bytes = serialize!(&message.validate_to_keyshare_public()?)?;

                self.storage.store(
                    StorableType::PublicKeyshare,
                    &message.identifier,
                    &message.from,
                    &message_bytes,
                )?;

                Ok(vec![])
            }
            MessageType::PresignRoundOne => self.do_round_two(&message),
            MessageType::PresignRoundTwo => {
                let (auxinfo_identifier, keyshare_identifier) =
                    self.get_associated_identifiers_for_presign(&message.identifier)?;

                // First, verify the bytes of the round two value, and then
                // store it locally. In order to v
                self.validate_and_store_round_two_public(
                    &message,
                    auxinfo_identifier,
                    keyshare_identifier,
                )?;

                // Since we are in round 2, it should certainly be the case that all
                // public auxinfo for other participants have been stored, since
                // this was a requirement to proceed for round 1.
                assert!(self.has_collected_all_of_others(
                    StorableType::AuxInfoPublic,
                    auxinfo_identifier
                )?);

                // Check if storage has all of the other participants' round two values (both
                // private and public), and call do_round_three() if so
                match self.has_collected_all_of_others(
                    StorableType::RoundTwoPrivate,
                    message.identifier,
                )? && self
                    .has_collected_all_of_others(StorableType::RoundTwoPublic, message.identifier)?
                {
                    true => self.do_round_three(&message),
                    false => Ok(vec![]),
                }
            }
            MessageType::PresignRoundThree => {
                let (auxinfo_identifier, _) =
                    self.get_associated_identifiers_for_presign(&message.identifier)?;

                // First, verify and store the round three value locally
                self.validate_and_store_round_three_public(&message, auxinfo_identifier)?;

                if self.has_collected_all_of_others(
                    StorableType::RoundThreePublic,
                    message.identifier,
                )? {
                    self.do_presign_finish(&message)?;
                }

                // No messages to return
                Ok(vec![])
            }
        }
    }

    /// Produces a message to signal to this participant that auxinfo generation is
    /// ready for the specified identifier
    pub fn initialize_auxinfo_message(&self, auxinfo_identifier: Identifier) -> Message {
        Message::new(
            MessageType::AuxInfoReady,
            auxinfo_identifier,
            self.id,
            self.id,
            &[],
        )
    }

    /// Produces a message to signal to this participant that keyshare generation is
    /// ready for the specified identifier
    pub fn initialize_keygen_message(&self, keygen_identifier: Identifier) -> Message {
        Message::new(
            MessageType::KeygenReady,
            keygen_identifier,
            self.id,
            self.id,
            &[],
        )
    }

    /// Produces a message to signal to this participant that presignature generation is
    /// ready for the specified identifier. This also requires supplying the associated
    /// auxinfo identifier and keyshare identifier.
    pub fn initialize_presign_message(
        &mut self,
        auxinfo_identifier: Identifier,
        keyshare_identifier: Identifier,
        identifier: Identifier,
    ) -> Message {
        // Set the presign map internally
        self.presign_map
            .insert(identifier, (auxinfo_identifier, keyshare_identifier));

        Message::new(MessageType::PresignReady, identifier, self.id, self.id, &[])
    }

    fn get_associated_identifiers_for_presign(
        &self,
        presign_identifier: &Identifier,
    ) -> Result<(Identifier, Identifier)> {
        let (id1, id2) = self.presign_map.get(presign_identifier).ok_or_else(
            || bail_context!("Could not find associated auxinfo and keyshare identifiers for this presign identifier")
        )?;

        Ok((*id1, *id2))
    }

    /// Aux Info Generation
    ///
    ///
    #[cfg_attr(feature = "flame_it", flame)]
    fn do_auxinfo_gen<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
        message: &Message,
    ) -> Result<Vec<Message>> {
        let (auxinfo_private, auxinfo_public) = crate::auxinfo::new_auxinfo(rng, 512)?;
        let auxinfo_public_bytes = serialize!(&auxinfo_public)?;

        // Store private and public keyshares locally
        self.storage.store(
            StorableType::AuxInfoPrivate,
            &message.identifier,
            &self.id,
            &serialize!(&auxinfo_private)?,
        )?;
        self.storage.store(
            StorableType::AuxInfoPublic,
            &message.identifier,
            &self.id,
            &auxinfo_public_bytes,
        )?;

        // Publish public keyshare to all other participants on the channel
        Ok(self
            .other_participant_ids
            .iter()
            .map(|&other_participant_id| {
                Message::new(
                    MessageType::AuxInfoPublic,
                    message.identifier,
                    self.id,
                    other_participant_id,
                    &auxinfo_public_bytes,
                )
            })
            .collect())
    }

    /// Key Generation
    ///
    /// During keygen, each participant produces and stores their own secret values, and then
    /// publishes the same public component to every other participant.
    #[cfg_attr(feature = "flame_it", flame)]
    fn do_keygen<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
        message: &Message,
    ) -> Result<Vec<Message>> {
        let (keyshare_private, keyshare_public) = crate::keygen::new_keyshare(rng)?;
        let keyshare_public_bytes = serialize!(&keyshare_public)?;

        // Store private and public keyshares locally
        self.storage.store(
            StorableType::PrivateKeyshare,
            &message.identifier,
            &self.id,
            &serialize!(&keyshare_private)?,
        )?;
        self.storage.store(
            StorableType::PublicKeyshare,
            &message.identifier,
            &self.id,
            &keyshare_public_bytes,
        )?;

        // Publish public keyshare to all other participants on the channel
        Ok(self
            .other_participant_ids
            .iter()
            .map(|&other_participant_id| {
                Message::new(
                    MessageType::PublicKeyshare,
                    message.identifier,
                    self.id,
                    other_participant_id,
                    &keyshare_public_bytes,
                )
            })
            .collect())
    }

    /// Presign: Round One
    ///
    /// During round one, each participant produces and stores their own secret values, and then
    /// stores a round one secret, and publishes a unique public component to every other participant.
    ///
    /// This can only be run after all participants have finished with key generation.
    #[cfg_attr(feature = "flame_it", flame)]
    fn do_round_one(&mut self, message: &Message) -> Result<Vec<Message>> {
        let (auxinfo_identifier, keyshare_identifier) =
            self.get_associated_identifiers_for_presign(&message.identifier)?;

        // Reconstruct keyshare and other participants' public keyshares from local storage
        let keyshare = self.get_keyshare(auxinfo_identifier, keyshare_identifier)?;
        let other_public_auxinfo =
            self.get_other_participants_public_auxinfo(auxinfo_identifier)?;

        // Run Round One
        let (private, r1_publics) = keyshare.round_one(&other_public_auxinfo)?;

        // Store private r1 value locally
        self.storage.store(
            StorableType::RoundOnePrivate,
            &message.identifier,
            &self.id,
            &serialize!(&private)?,
        )?;

        // Publish public r1 to all other participants on the channel
        let mut ret_messages = vec![];
        for (other_id, r1_public) in r1_publics {
            ret_messages.push(Message::new(
                MessageType::PresignRoundOne,
                message.identifier,
                self.id,
                other_id,
                &serialize!(&r1_public)?,
            ));
        }

        Ok(ret_messages)
    }

    /// Presign: Round Two
    ///
    /// During round two, each participant retrieves the public keyshares for each other participant from the
    /// key generation phase, the round 1 public values from each other participant, its own round 1 private
    /// value, and its own round one keyshare from key generation, and produces per-participant
    /// round 2 public and private values.
    ///
    /// This can be run as soon as each round one message to this participant has been published.
    /// These round two messages are returned in response to the sender, without having to
    /// rely on any other round one messages from other participants aside from the sender.
    #[cfg_attr(feature = "flame_it", flame)]
    fn do_round_two(&mut self, message: &Message) -> Result<Vec<Message>> {
        let (auxinfo_identifier, keyshare_identifier) =
            self.get_associated_identifiers_for_presign(&message.identifier)?;

        // Reconstruct keyshare and other participants' public keyshares from local storage
        let keyshare = self.get_keyshare(auxinfo_identifier, keyshare_identifier)?;
        let other_public_keyshares =
            self.get_other_participants_public_auxinfo(auxinfo_identifier)?;

        assert_eq!(message.to, self.id);

        // Find the keyshare corresponding to the "from" participant
        let keyshare_from = other_public_keyshares.get(&message.from).ok_or_else(|| {
            bail_context!("Could not find corresponding public keyshare for participant in round 2")
        })?;

        // Get this participant's round 1 private value
        let r1_priv = deserialize!(&self.storage.retrieve(
            StorableType::RoundOnePrivate,
            message.identifier,
            message.to
        )?)?;

        let r1_public =
            message.validate_to_round_one_public(&keyshare.aux_info_public, keyshare_from)?;

        // Store the round 1 public value as well
        self.storage.store(
            StorableType::RoundOnePublic,
            &message.identifier,
            &message.from,
            &serialize!(&r1_public)?,
        )?;

        let (r2_priv_ij, r2_pub_ij) = keyshare.round_two(keyshare_from, &r1_priv, &r1_public);

        // Store the private value for this round 2 pair
        self.storage.store(
            StorableType::RoundTwoPrivate,
            &message.identifier,
            &message.from,
            &serialize!(&r2_priv_ij)?,
        )?;

        // Only a single message to be output here
        let message = Message::new(
            MessageType::PresignRoundTwo,
            message.identifier,
            self.id,
            message.from, // This is a essentially response to that sender
            &serialize!(&r2_pub_ij)?,
        );
        Ok(vec![message])
    }

    /// Presign: Round Three
    ///
    /// During round three, to process all round 3 messages from a sender, the participant
    /// must first wait for round 2 to be completely finished for all participants.
    /// Then, the participant retrieves:
    /// - all participants' public keyshares,
    /// - its own round 1 private value,
    /// - all round 2 per-participant private values,
    /// - all round 2 per-participant public values,
    ///
    /// and produces a set of per-participant round 3 public values and one private value.
    ///
    /// Each participant is only going to run round three once.
    #[cfg_attr(feature = "flame_it", flame)]
    fn do_round_three(&mut self, message: &Message) -> Result<Vec<Message>> {
        let (auxinfo_identifier, keyshare_identifier) =
            self.get_associated_identifiers_for_presign(&message.identifier)?;

        // Reconstruct keyshare from local storage
        let keyshare = self.get_keyshare(auxinfo_identifier, keyshare_identifier)?;

        let round_three_hashmap =
            self.get_other_participants_round_three_values(message.identifier, auxinfo_identifier)?;

        // Get this participant's round 1 private value
        let r1_priv = deserialize!(&self.storage.retrieve(
            StorableType::RoundOnePrivate,
            message.identifier,
            self.id
        )?)?;

        let (r3_private, r3_publics_map) = keyshare.round_three(&r1_priv, &round_three_hashmap)?;

        // Store round 3 private value
        self.storage.store(
            StorableType::RoundThreePrivate,
            &message.identifier,
            &self.id,
            &serialize!(&r3_private)?,
        )?;

        // Publish public r3 values to all other participants on the channel
        let mut ret_messages = vec![];
        for (id, r3_public) in r3_publics_map {
            ret_messages.push(Message::new(
                MessageType::PresignRoundThree,
                message.identifier,
                self.id,
                id,
                &serialize!(&r3_public)?,
            ));
        }

        Ok(ret_messages)
    }

    /// Presign: Finish
    ///
    /// In this step, the participant simply collects all r3 public values and its r3
    /// private value, and assembles them into a PresignRecord.
    #[cfg_attr(feature = "flame_it", flame)]
    fn do_presign_finish(&mut self, message: &Message) -> Result<()> {
        let r3_pubs = self.get_other_participants_round_three_publics(message.identifier)?;

        // Get this participant's round 3 private value
        let r3_private: crate::round_three::Private = deserialize!(&self.storage.retrieve(
            StorableType::RoundThreePrivate,
            message.identifier,
            self.id
        )?)?;

        // Check consistency across all Gamma values
        for r3_pub in r3_pubs.iter() {
            if r3_pub.Gamma != r3_private.Gamma {
                return bail!("Inconsistency in presign finish -- Gamma mismatch");
            }
        }

        let presign_record: PresignRecord = crate::RecordPair {
            private: r3_private,
            publics: r3_pubs,
        }
        .into();

        self.storage.store(
            StorableType::PresignRecord,
            &message.identifier,
            &self.id,
            &serialize!(&presign_record)?,
        )?;

        Ok(())
    }

    /// Consumer can use this function to "give" a message to this participant
    pub fn accept_message(&mut self, message: &Message) -> Result<()> {
        if message.to != self.id {
            return bail!(
                "Attempting to deliver to recipient {:?} the message:\n {}",
                self.id,
                message,
            );
        }

        self.inbox.push(serialize!(&message)?);

        Ok(())
    }

    /// Returns whether or not auxinfo generation has completed for this identifier
    pub fn is_auxinfo_done(&self, auxinfo_identifier: &Identifier) -> Result<()> {
        let mut fetch = vec![];
        for participant in self.other_participant_ids.clone() {
            fetch.push((
                StorableType::AuxInfoPublic,
                *auxinfo_identifier,
                participant,
            ));
        }
        fetch.push((StorableType::AuxInfoPublic, *auxinfo_identifier, self.id));
        fetch.push((StorableType::AuxInfoPrivate, *auxinfo_identifier, self.id));

        self.storage.contains_batch(&fetch)
    }

    /// Returns whether or not keyshare generation has completed for this identifier
    pub fn is_keygen_done(&self, keygen_identifier: &Identifier) -> Result<()> {
        let mut fetch = vec![];
        for participant in self.other_participant_ids.clone() {
            fetch.push((
                StorableType::PublicKeyshare,
                *keygen_identifier,
                participant,
            ));
        }
        fetch.push((StorableType::PublicKeyshare, *keygen_identifier, self.id));
        fetch.push((StorableType::PrivateKeyshare, *keygen_identifier, self.id));

        self.storage.contains_batch(&fetch)
    }

    /// Returns whether or not presignature generation has completed for this identifier
    pub fn is_presigning_done(&self, presign_identifier: &Identifier) -> Result<()> {
        self.storage
            .contains_batch(&[(StorableType::PresignRecord, *presign_identifier, self.id)])
    }

    /// Retrieves this participant's associated public keyshare for this identifier
    pub fn get_public_keyshare(&self, identifier: Identifier) -> Result<CurvePoint> {
        let keyshare_public: KeySharePublic = deserialize!(&self.storage.retrieve(
            StorableType::PublicKeyshare,
            identifier,
            self.id,
        )?)?;
        Ok(keyshare_public.X)
    }

    /// If presign record is populated, then this participant is ready to issue
    /// a signature
    pub fn sign(
        &self,
        presign_identifier: Identifier,
        digest: sha2::Sha256,
    ) -> Result<SignatureShare> {
        let presign_record: PresignRecord = deserialize!(&self.storage.retrieve(
            StorableType::PresignRecord,
            presign_identifier,
            self.id
        )?)?;
        let (r, s) = presign_record.sign(digest);
        let ret = SignatureShare { r: Some(r), s };

        // FIXME: Need to clear the presign record after being used once

        Ok(ret)
    }

    //////////////////////
    // Helper functions //
    //////////////////////

    #[cfg(test)]
    pub(crate) fn has_messages(&self) -> bool {
        !self.inbox.is_empty()
    }

    fn get_keyshare(
        &self,
        auxinfo_identifier: Identifier,
        keyshare_identifier: Identifier,
    ) -> Result<PresignKeyShareAndInfo> {
        // Reconstruct keyshare from local storage
        let id = self.id;
        let keyshare_and_info = PresignKeyShareAndInfo {
            aux_info_private: deserialize!(&self.storage.retrieve(
                StorableType::AuxInfoPrivate,
                auxinfo_identifier,
                id
            )?)?,
            aux_info_public: deserialize!(&self.storage.retrieve(
                StorableType::AuxInfoPublic,
                auxinfo_identifier,
                id
            )?)?,
            keyshare_private: deserialize!(&self.storage.retrieve(
                StorableType::PrivateKeyshare,
                keyshare_identifier,
                id
            )?)?,
            keyshare_public: deserialize!(&self.storage.retrieve(
                StorableType::PublicKeyshare,
                keyshare_identifier,
                id
            )?)?,
        };
        Ok(keyshare_and_info)
    }

    /// Aggregate the other participants' public keyshares from storage. But don't remove them
    /// from storage.
    ///
    /// This returns a HashMap with the key as the participant id and the value as the KeygenPublic
    fn get_other_participants_public_auxinfo(
        &self,
        identifier: Identifier,
    ) -> Result<HashMap<ParticipantIdentifier, AuxInfoPublic>> {
        if !self.has_collected_all_of_others(StorableType::AuxInfoPublic, identifier)? {
            return bail!("Not ready to get other participants public auxinfo just yet!");
        }

        let mut hm = HashMap::new();
        for other_participant_id in self.other_participant_ids.clone() {
            let val = self.storage.retrieve(
                StorableType::AuxInfoPublic,
                identifier,
                other_participant_id,
            )?;
            hm.insert(other_participant_id, deserialize!(&val)?);
        }
        Ok(hm)
    }

    /// Aggregate the other participants' round three public values from storage. But don't remove them
    /// from storage.
    ///
    /// This returns a Vec with the values
    fn get_other_participants_round_three_publics(
        &self,
        identifier: Identifier,
    ) -> Result<Vec<crate::round_three::Public>> {
        if !self.has_collected_all_of_others(StorableType::RoundThreePublic, identifier)? {
            return bail!("Not ready to get other participants round three publics just yet!");
        }

        let mut ret_vec = vec![];
        for other_participant_id in self.other_participant_ids.clone() {
            let val = self.storage.retrieve(
                StorableType::RoundThreePublic,
                identifier,
                other_participant_id,
            )?;
            ret_vec.push(deserialize!(&val)?);
        }
        Ok(ret_vec)
    }

    /// Aggregate the other participants' values needed for round three from storage. This includes:
    /// - public keyshares
    /// - round two private values
    /// - round two public values
    ///
    /// This returns a HashMap with the key as the participant id and these values being mapped
    fn get_other_participants_round_three_values(
        &self,
        identifier: Identifier,
        auxinfo_identifier: Identifier,
    ) -> Result<HashMap<ParticipantIdentifier, RoundThreeInput>> {
        if !self.has_collected_all_of_others(StorableType::AuxInfoPublic, auxinfo_identifier)?
            || !self.has_collected_all_of_others(StorableType::RoundTwoPrivate, identifier)?
            || !self.has_collected_all_of_others(StorableType::RoundTwoPublic, identifier)?
        {
            return bail!("Not ready to get other participants round three values just yet!");
        }

        let mut hm = HashMap::new();
        for other_participant_id in self.other_participant_ids.clone() {
            let auxinfo_public = self.storage.retrieve(
                StorableType::AuxInfoPublic,
                auxinfo_identifier,
                other_participant_id,
            )?;
            let round_two_private = self.storage.retrieve(
                StorableType::RoundTwoPrivate,
                identifier,
                other_participant_id,
            )?;
            let round_two_public = self.storage.retrieve(
                StorableType::RoundTwoPublic,
                identifier,
                other_participant_id,
            )?;
            hm.insert(
                other_participant_id,
                RoundThreeInput {
                    auxinfo_public: deserialize!(&auxinfo_public)?,
                    r2_private: deserialize!(&round_two_private)?,
                    r2_public: deserialize!(&round_two_public)?,
                },
            );
        }
        Ok(hm)
    }

    /// Returns true if in storage, there is one storable_type for each other
    /// participant in the quorum.
    fn has_collected_all_of_others(
        &self,
        storable_type: StorableType,
        identifier: Identifier,
    ) -> Result<bool> {
        let indices: Vec<(StorableType, Identifier, ParticipantIdentifier)> = self
            .other_participant_ids
            .iter()
            .map(|participant_id| (storable_type, identifier, *participant_id))
            .collect();
        Ok(self.storage.contains_batch(&indices).is_ok())
    }

    fn validate_and_store_round_two_public(
        &mut self,
        message: &Message,
        auxinfo_identifier: Identifier,
        keyshare_identifier: Identifier,
    ) -> Result<()> {
        let receiver_auxinfo_public = deserialize!(&self.storage.retrieve(
            StorableType::AuxInfoPublic,
            auxinfo_identifier,
            message.to
        )?)?;
        let sender_auxinfo_public = deserialize!(&self.storage.retrieve(
            StorableType::AuxInfoPublic,
            auxinfo_identifier,
            message.from
        )?)?;
        let sender_keyshare_public = deserialize!(&self.storage.retrieve(
            StorableType::PublicKeyshare,
            keyshare_identifier,
            message.from
        )?)?;
        let receiver_r1_private = deserialize!(&self.storage.retrieve(
            StorableType::RoundOnePrivate,
            message.identifier,
            message.to
        )?)?;
        let sender_r1_public = deserialize!(&self.storage.retrieve(
            StorableType::RoundOnePublic,
            message.identifier,
            message.from,
        )?)?;

        let message_bytes = serialize!(&message.validate_to_round_two_public(
            &receiver_auxinfo_public,
            &sender_auxinfo_public,
            &sender_keyshare_public,
            &receiver_r1_private,
            &sender_r1_public,
        )?)?;

        self.storage.store(
            StorableType::RoundTwoPublic,
            &message.identifier,
            &message.from,
            &message_bytes,
        )?;

        Ok(())
    }

    fn validate_and_store_round_three_public(
        &mut self,
        message: &Message,
        auxinfo_identifier: Identifier,
    ) -> Result<()> {
        let receiver_auxinfo_public = deserialize!(&self.storage.retrieve(
            StorableType::AuxInfoPublic,
            auxinfo_identifier,
            message.to
        )?)?;
        let sender_auxinfo_public = deserialize!(&self.storage.retrieve(
            StorableType::AuxInfoPublic,
            auxinfo_identifier,
            message.from
        )?)?;
        let sender_r1_public = deserialize!(&self.storage.retrieve(
            StorableType::RoundOnePublic,
            message.identifier,
            message.from
        )?)?;

        let message_bytes = serialize!(&message.validate_to_round_three_public(
            &receiver_auxinfo_public,
            &sender_auxinfo_public,
            &sender_r1_public,
        )?)?;

        self.storage.store(
            StorableType::RoundThreePublic,
            &message.identifier,
            &message.from,
            &message_bytes,
        )?;

        Ok(())
    }
}

/// Simple wrapper around the signature share output
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct SignatureShare {
    /// The r-scalar associated with an ECDSA signature
    pub r: Option<k256::Scalar>,
    /// The s-scalar associated with an ECDSA signature
    pub s: k256::Scalar,
}

impl Default for SignatureShare {
    fn default() -> Self {
        Self::new()
    }
}

impl SignatureShare {
    fn new() -> Self {
        Self {
            r: None,
            s: k256::Scalar::zero(),
        }
    }

    /// Can be used to combine [SignatureShare]s
    pub fn chain(&self, share: Self) -> Result<Self> {
        let r = match (self.r, share.r) {
            (_, None) => bail!("Invalid format for share, r scalar = 0"),
            (Some(prev_r), Some(new_r)) => {
                if prev_r != new_r {
                    return bail!("Cannot chain as r values don't match");
                }
                Ok(prev_r)
            }
            (None, Some(new_r)) => Ok(new_r),
        }?;

        // Keep the same r, add in the s value
        Ok(Self {
            r: Some(r),
            s: self.s + share.s,
        })
    }

    /// Converts the [SignatureShare] into a signature
    pub fn finish(&self) -> Result<k256::ecdsa::Signature> {
        let mut s = self.s;
        if s.is_high().unwrap_u8() == 1 {
            s = s.negate();
        }

        let sig = match self.r {
            Some(r) => Ok(k256::ecdsa::Signature::from_scalars(r, s)
                .map_err(|_| bail_context!("Could not construct signature from scalars"))?),
            None => bail!("Cannot produce a signature without including shares"),
        }?;

        Ok(sig)
    }
}

/// The configuration for the participant, including the identifiers
/// corresponding to the other participants of the quorum
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParticipantConfig {
    /// The identifier for this participant
    pub id: ParticipantIdentifier,
    /// The identifiers for the other participants of the quorum
    pub other_ids: Vec<ParticipantIdentifier>,
}

/// An identifier corresponding to a [Participant]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ParticipantIdentifier(Identifier);

impl ParticipantIdentifier {
    /// Generates a random [ParticipantIdentifier]
    pub fn random<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        ParticipantIdentifier(Identifier::random(rng))
    }
}

impl std::fmt::Display for ParticipantIdentifier {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "ParticipantId({})",
            hex::encode(&self.0 .0.to_be_bytes()[..4])
        )
    }
}

/// A generic identifier
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Identifier(u128);

impl Identifier {
    /// Produces a random [Identifier]
    pub fn random<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        // Sample random 32 bytes and convert to hex
        let random_bytes = rng.gen::<u128>();
        Self(random_bytes)
    }
}

impl std::fmt::Display for Identifier {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "Id({})", hex::encode(&self.0.to_be_bytes()[..4]))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use k256::ecdsa::signature::DigestVerifier;
    use rand::rngs::OsRng;
    use sha2::{Digest, Sha256};

    /// Delivers a message into a participant's inbox
    fn deliver_one(message: &Message, recipient: &mut Participant) -> Result<()> {
        recipient.accept_message(message)
    }

    /// Delivers all messages into their respective participant's inboxes
    fn deliver_all(messages: &[Message], quorum: &mut Vec<Participant>) -> Result<()> {
        for message in messages {
            for participant in &mut *quorum {
                if participant.id == message.to {
                    deliver_one(message, &mut *participant)?;
                    break;
                }
            }
        }
        Ok(())
    }

    fn is_presigning_done(quorum: &[Participant], presign_identifier: &Identifier) -> Result<()> {
        for participant in quorum {
            if participant.is_presigning_done(presign_identifier).is_err() {
                return bail!("Presign not done");
            }
        }
        Ok(())
    }

    fn is_auxinfo_done(quorum: &[Participant], auxinfo_identifier: &Identifier) -> Result<()> {
        for participant in quorum {
            if participant.is_auxinfo_done(auxinfo_identifier).is_err() {
                return bail!("Auxinfo not done");
            }
        }
        Ok(())
    }

    fn is_keygen_done(quorum: &[Participant], keygen_identifier: &Identifier) -> Result<()> {
        for participant in quorum {
            if participant.is_keygen_done(keygen_identifier).is_err() {
                return bail!("Keygen not done");
            }
        }
        Ok(())
    }

    fn process_messages<R: RngCore + CryptoRng>(
        quorum: &mut Vec<Participant>,
        rng: &mut R,
    ) -> Result<()> {
        // Pick a random participant to process
        let index = rng.gen_range(0..quorum.len());

        if !quorum[index].has_messages() {
            // No messages to process for this participant, so pick another participant
            return Ok(());
        }

        let messages = quorum[index].process_single_message(rng)?;
        deliver_all(&messages, quorum)?;

        Ok(())
    }

    #[cfg_attr(feature = "flame_it", flame)]
    #[test]
    fn test_run_protocol() -> Result<()> {
        let mut rng = OsRng;
        let mut quorum = Participant::new_quorum(3, &mut rng)?;

        let auxinfo_identifier = Identifier::random(&mut rng);
        let keyshare_identifier = Identifier::random(&mut rng);
        let presign_identifier = Identifier::random(&mut rng);

        for participant in &mut quorum {
            participant
                .accept_message(&participant.initialize_auxinfo_message(auxinfo_identifier))?;
        }
        while is_auxinfo_done(&quorum, &auxinfo_identifier).is_err() {
            process_messages(&mut quorum, &mut rng)?;
        }

        for participant in &mut quorum {
            participant
                .accept_message(&participant.initialize_keygen_message(keyshare_identifier))?;
        }
        while is_keygen_done(&quorum, &keyshare_identifier).is_err() {
            process_messages(&mut quorum, &mut rng)?;
        }

        for participant in &mut quorum {
            let message = participant.initialize_presign_message(
                auxinfo_identifier,
                keyshare_identifier,
                presign_identifier,
            );
            participant.accept_message(&message)?;
        }
        while is_presigning_done(&quorum, &presign_identifier).is_err() {
            process_messages(&mut quorum, &mut rng)?;
        }

        // Now, produce a valid signature
        let mut hasher = Sha256::new();
        hasher.update(b"some test message");

        let mut aggregator = SignatureShare::default();
        for participant in &mut quorum {
            let signature_share = participant.sign(presign_identifier, hasher.clone())?;
            aggregator = aggregator.chain(signature_share)?;
        }
        let signature = aggregator.finish()?;

        // Initialize all participants and get their public keyshares to construct the
        // final signature verification key
        let mut vk_point = CurvePoint::IDENTITY;
        for participant in &mut quorum {
            let X = participant.get_public_keyshare(keyshare_identifier)?;
            vk_point = CurvePoint(vk_point.0 + X.0);
        }
        let verification_key =
            k256::ecdsa::VerifyingKey::from_encoded_point(&vk_point.0.to_affine().into())
                .map_err(|_| bail_context!("Could not construct verification key"))?;

        // Moment of truth, does the signature verify?
        assert!(verification_key.verify_digest(hasher, &signature).is_ok());

        #[cfg(feature = "flame_it")]
        flame::dump_html(&mut std::fs::File::create("stats/flame-graph.html").unwrap()).unwrap();

        Ok(())
    }
}
