// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

//! Contains the main protocol that is executed through a [Participant]

use crate::errors::Result;
use crate::keygen::KeySharePublic;
use crate::messages::*;
use crate::presign::participant::PresignParticipant;
use crate::presign::record::PresignRecord;
use crate::storage::*;
use crate::utils::process_ready_message;
use crate::utils::CurvePoint;
use k256::elliptic_curve::Field;
use k256::elliptic_curve::IsHigh;
use rand::{CryptoRng, Rng, RngCore};
use serde::{Deserialize, Serialize};
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
    /// Local storage for this participant to store finalized auxinfo, keygen, and presign
    /// values. This storage is not responsible for storing round-specific material.
    main_storage: Storage,
    /// Participant subprotocol for handling presign messages
    presign_participant: PresignParticipant,
}

impl Participant {
    /// Initialized the participant from a [ParticipantConfig]
    pub fn from_config(config: ParticipantConfig) -> Result<Self> {
        Ok(Participant {
            id: config.id,
            other_participant_ids: config.other_ids.clone(),
            inbox: vec![],
            main_storage: Storage::new(),
            presign_participant: PresignParticipant::from_ids(config.id, config.other_ids),
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
            &self.id,
            &message.message_type(),
        );

        match message.message_type() {
            MessageType::AuxInfoReady => {
                let (mut messages, is_ready) = process_ready_message(
                    self.id,
                    &self.other_participant_ids,
                    &mut self.main_storage,
                    &message,
                    StorableType::AuxInfoReady,
                )?;
                if is_ready {
                    let more_messages = self.do_auxinfo_gen(rng, &message)?;
                    messages.extend_from_slice(&more_messages);
                }
                Ok(messages)
            }
            MessageType::AuxInfoPublic => {
                // First, verify the bytes of the public auxinfo, and then
                // store it locally
                let message_bytes = serialize!(&message.validate_to_auxinfo_public()?)?;
                self.main_storage.store(
                    StorableType::AuxInfoPublic,
                    message.id(),
                    message.from(),
                    &message_bytes,
                )?;

                Ok(vec![])
            }
            MessageType::KeygenReady => {
                let (mut messages, is_ready) = process_ready_message(
                    self.id,
                    &self.other_participant_ids,
                    &mut self.main_storage,
                    &message,
                    StorableType::KeygenReady,
                )?;
                if is_ready {
                    let more_messages = self.do_keygen(rng, &message)?;
                    messages.extend_from_slice(&more_messages);
                }
                Ok(messages)
            }
            MessageType::PublicKeyshare => {
                // First, verify the bytes of the public keyshare, and then
                // store it locally
                let message_bytes = serialize!(&message.validate_to_keyshare_public()?)?;

                self.main_storage.store(
                    StorableType::PublicKeyshare,
                    message.id(),
                    message.from(),
                    &message_bytes,
                )?;

                Ok(vec![])
            }
            MessageType::Presign(_) => {
                // Send presign message and existing storage containing auxinfo and
                // keyshare values that presign needs to operate
                let (optional_presign_record, messages) = self
                    .presign_participant
                    .process_message(&message, &self.main_storage)?;

                if let Some(presign_record) = optional_presign_record {
                    self.main_storage.store(
                        StorableType::PresignRecord,
                        message.id(),
                        self.id,
                        &serialize!(&presign_record)?,
                    )?;
                }

                Ok(messages)
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
        self.presign_participant.initialize_presign_message(
            auxinfo_identifier,
            keyshare_identifier,
            identifier,
        )
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
        self.main_storage.store(
            StorableType::AuxInfoPrivate,
            message.id(),
            self.id,
            &serialize!(&auxinfo_private)?,
        )?;
        self.main_storage.store(
            StorableType::AuxInfoPublic,
            message.id(),
            self.id,
            &auxinfo_public_bytes,
        )?;

        // Publish public keyshare to all other participants on the channel
        Ok(self
            .other_participant_ids
            .iter()
            .map(|&other_participant_id| {
                Message::new(
                    MessageType::AuxInfoPublic,
                    message.id(),
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
        self.main_storage.store(
            StorableType::PrivateKeyshare,
            message.id(),
            self.id,
            &serialize!(&keyshare_private)?,
        )?;
        self.main_storage.store(
            StorableType::PublicKeyshare,
            message.id(),
            self.id,
            &keyshare_public_bytes,
        )?;

        // Publish public keyshare to all other participants on the channel
        Ok(self
            .other_participant_ids
            .iter()
            .map(|&other_participant_id| {
                Message::new(
                    MessageType::PublicKeyshare,
                    message.id(),
                    self.id,
                    other_participant_id,
                    &keyshare_public_bytes,
                )
            })
            .collect())
    }

    /// Consumer can use this function to "give" a message to this participant
    pub fn accept_message(&mut self, message: &Message) -> Result<()> {
        if message.to() != self.id {
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

        self.main_storage.contains_batch(&fetch)
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

        self.main_storage.contains_batch(&fetch)
    }

    /// Returns whether or not presignature generation has completed for this identifier
    pub fn is_presigning_done(&self, presign_identifier: Identifier) -> Result<()> {
        self.main_storage.contains_batch(&[(
            StorableType::PresignRecord,
            presign_identifier,
            self.id,
        )])
    }

    /// Retrieves this participant's associated public keyshare for this identifier
    pub fn get_public_keyshare(&self, identifier: Identifier) -> Result<CurvePoint> {
        let keyshare_public: KeySharePublic = deserialize!(&self.main_storage.retrieve(
            StorableType::PublicKeyshare,
            identifier,
            self.id,
        )?)?;
        Ok(keyshare_public.X)
    }

    /// If presign record is populated, then this participant is ready to issue
    /// a signature
    pub fn sign(
        &mut self,
        presign_identifier: Identifier,
        digest: sha2::Sha256,
    ) -> Result<SignatureShare> {
        let presign_record: PresignRecord = deserialize!(&self.main_storage.retrieve(
            StorableType::PresignRecord,
            presign_identifier,
            self.id
        )?)?;
        let (r, s) = presign_record.sign(digest);
        let ret = SignatureShare { r: Some(r), s };

        // Clear the presign record after being used once
        self.main_storage
            .delete(StorableType::PresignRecord, presign_identifier, self.id)?;

        Ok(ret)
    }

    //////////////////////
    // Helper functions //
    //////////////////////

    #[cfg(test)]
    pub(crate) fn has_messages(&self) -> bool {
        !self.inbox.is_empty()
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
                if participant.id == message.to() {
                    deliver_one(message, &mut *participant)?;
                    break;
                }
            }
        }
        Ok(())
    }

    fn is_presigning_done(quorum: &[Participant], presign_identifier: Identifier) -> Result<()> {
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
        while is_presigning_done(&quorum, presign_identifier).is_err() {
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
