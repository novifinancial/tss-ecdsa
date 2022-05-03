// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use crate::key::{KeyInit, KeyShare, KeygenPrivate, KeygenPublic};
use crate::messages::*;
use crate::round_three::RoundThreeInput;
use anyhow::Error;
use k256::Secp256k1;
use rand::prelude::IteratorRandom;
use rand::{CryptoRng, Rng, RngCore};
use std::collections::HashMap;
use std::fmt::{Debug, Display, Formatter};
use std::str::FromStr;

/////////////////////
// Participant API //
/////////////////////

/// Each participant has an inbox which can contain messages.
pub struct Participant {
    /// A unique identifier for this participant
    id: ParticipantIdentifier,
    /// A list of all other participant identifiers participating in the protocol
    other_participant_ids: Vec<ParticipantIdentifier>,
    /// An inbox for this participant containing messages sent from other participants
    inbox: Vec<String>,
    /// Local storage for this participant to store secrets
    storage: HashMap<(StorableType, ParticipantIdentifier), String>,
    /// Contains the private and public keyshares that don't get rotated
    key_init: Option<KeyInit>,
    /// The presign record, starting out as None, but gets populated after
    /// the presign phase completes
    presign_record: Option<crate::PresignRecord>,
}

impl Participant {
    /// Instantiate a new quorum of participants of a specified size. Random identifiers
    /// are selected
    #[cfg_attr(feature = "flame_it", flame)]
    pub fn new_quorum<R: RngCore + CryptoRng>(
        quorum_size: usize,
        rng: &mut R,
    ) -> Result<Vec<Self>, Error> {
        let mut participant_ids = vec![];
        for _ in 0..quorum_size {
            participant_ids.push(ParticipantIdentifier::random(rng));
        }
        let participants = participant_ids
            .iter()
            .map(|participant_id| {
                // Filter out current participant id from list of other ids
                let mut other_ids = vec![];
                for id in participant_ids.iter() {
                    if id.clone() != participant_id.clone() {
                        other_ids.push(id.clone());
                    }
                }

                Participant {
                    id: participant_id.clone(),
                    other_participant_ids: other_ids,
                    // Initialize a single message for begin key generation in each
                    // participant's inbox
                    inbox: vec![(Message {
                        message_type: MessageType::BeginKeyGeneration,
                        from: ParticipantIdentifier("".to_string()), // No "from" for this message
                        to: ParticipantIdentifier("".to_string()),   // No "to" for this message
                        unverified_bytes: vec![],
                    })
                    .to_string()],
                    storage: HashMap::new(),
                    key_init: None,
                    presign_record: None,
                }
            })
            .collect();
        Ok(participants)
    }

    /// Pulls the first message from the participant's inbox, and then potentially
    /// outputs a bunch of messages that need to be delivered to other participants'
    /// inboxes.
    #[cfg_attr(feature = "flame_it", flame)]
    pub fn process_single_message<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
    ) -> Result<Vec<Message>, Error> {
        let message = Message::from_str(&self.inbox.remove(0))?;

        println!(
            "processing participant: {}, with message type: {}",
            &self.id.0[0..4],
            &message.message_type,
        );

        match message.message_type {
            MessageType::BeginKeyGeneration => self.do_keygen(rng),
            MessageType::PublicKeyshare => {
                // First, verify the bytes of the public keyshare, and then
                // store it locally
                let message_bytes = message.validate_to_keygen_public()?.to_bytes()?;

                self.store(Storable {
                    associated_participant_id: message.from,
                    storable_type: StorableType::PublicKeyshare,
                    bytes: message_bytes,
                });

                // Check if storage has all of the other participants' public keyshares,
                // and call do_round_one() if so
                match self.has_collected_all_of_others(StorableType::PublicKeyshare)? {
                    true => self.do_round_one(),
                    false => Ok(vec![]),
                }
            }
            MessageType::RoundOne => self.do_round_two(&message),
            MessageType::RoundTwo => {
                // First, verify the bytes of the round two value, and then
                // store it locally. In order to v
                self.validate_and_store_round_two_public(&message)?;

                // Since we are in round 2, it should certainly be the case that all
                // public keyshares for other participants have been stored, since
                // this was a requirement to proceed for round 1.
                assert!(self.has_collected_all_of_others(StorableType::PublicKeyshare)?);

                // Check if storage has all of the other participants' round two values (both
                // private and public), and call do_round_three() if so
                match self.has_collected_all_of_others(StorableType::RoundTwoPrivate)?
                    && self.has_collected_all_of_others(StorableType::RoundTwoPublic)?
                {
                    true => self.do_round_three(),
                    false => Ok(vec![]),
                }
            }
            MessageType::RoundThree => {
                // First, verify and store the round three value locally
                self.validate_and_store_round_three_public(&message)?;

                if self.has_collected_all_of_others(StorableType::RoundThreePublic)? {
                    self.do_presign_finish()?;
                }

                // No messages to return
                Ok(vec![])
            }
        }
    }

    /// Key Init
    ///
    /// Produces the private x and public X shares corresponding to the actual ECDSA key
    #[cfg_attr(feature = "flame_it", flame)]
    pub fn do_init<R: RngCore + CryptoRng>(&mut self, rng: &mut R) -> Result<(), Error> {
        if self.key_init.is_some() {
            bail!("Attempting to initialize key shares when they were already initialized");
        }
        self.key_init = Some(KeyInit::new(rng));
        Ok(())
    }

    /// Key Generation
    ///
    /// During keygen, each participant produces and stores their own secret values, and then
    /// publishes the same public component to every other participant.
    #[cfg_attr(feature = "flame_it", flame)]
    fn do_keygen<R: RngCore + CryptoRng>(&mut self, rng: &mut R) -> Result<Vec<Message>, Error> {
        // Pull in pre-generated safe primes from text file (not a safe operation!).
        // This is meant to save on the time needed to generate these primes, but
        // should not be done in a production environment!
        let safe_primes = crate::get_safe_primes();
        let two_safe_primes = safe_primes.iter().choose_multiple(rng, 2);

        let keyshare = match self.key_init.clone() {
            Some(key_init) => Ok(KeyShare::from_safe_primes_and_init(
                rng,
                two_safe_primes[0],
                two_safe_primes[1],
                &key_init,
            )),
            None => Err(anyhow!(
                "Cannot do keygen before calling init on key shares"
            )),
        }?;

        let public_keyshare_bytes = keyshare.public.to_bytes()?;

        // Store private and public keyshares locally
        self.store(Storable {
            storable_type: StorableType::PrivateKeyshare,
            associated_participant_id: self.id.clone(),
            bytes: keyshare.private.to_bytes()?,
        });
        self.store(Storable {
            storable_type: StorableType::PublicKeyshare,
            associated_participant_id: self.id.clone(),
            bytes: public_keyshare_bytes.clone(),
        });

        // Publish public keyshare to all other participants on the channel
        Ok(self
            .other_participant_ids
            .iter()
            .map(|other_participant_id| Message {
                message_type: MessageType::PublicKeyshare,
                from: self.id.clone(),
                to: other_participant_id.clone(),
                unverified_bytes: public_keyshare_bytes.clone(),
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
    fn do_round_one(&mut self) -> Result<Vec<Message>, Error> {
        // Reconstruct keyshare and other participants' public keyshares from local storage
        let keyshare = self.get_keyshare()?;
        let other_public_keyshares = self.get_other_participants_public_keyshares()?;

        // Run Round One
        let (private, r1_publics) = keyshare.round_one(&other_public_keyshares)?;

        // Store private r1 value locally
        self.store(Storable {
            storable_type: StorableType::RoundOnePrivate,
            associated_participant_id: self.id.clone(),
            bytes: private.to_bytes()?,
        });

        // Publish public r1 to all other participants on the channel
        let mut ret_messages = vec![];
        for (other_id, r1_public) in r1_publics {
            ret_messages.push(Message {
                message_type: MessageType::RoundOne,
                from: self.id.clone(),
                to: other_id.clone(),
                unverified_bytes: r1_public.to_bytes()?,
            });
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
    fn do_round_two(&mut self, message: &Message) -> Result<Vec<Message>, Error> {
        // Reconstruct keyshare and other participants' public keyshares from local storage
        let keyshare = self.get_keyshare()?;
        let other_public_keyshares = self.get_other_participants_public_keyshares()?;

        assert_eq!(message.to, self.id);

        // Find the keyshare corresponding to the "from" participant
        let keyshare_from = other_public_keyshares.get(&message.from).ok_or_else(|| {
            anyhow!("Could not find corresponding public keyshare for participant in round 2")
        })?;

        // Get this participant's round 1 private value
        let r1_priv = crate::round_one::Private::from_slice(
            &self
                .retrieve(StorableType::RoundOnePrivate, &message.to, false)?
                .bytes,
        )?;

        let r1_public = message.validate_to_round_one_public(&keyshare.public, keyshare_from)?;

        // Store the round 1 public value as well
        self.store(Storable {
            storable_type: StorableType::RoundOnePublic,
            associated_participant_id: message.from.clone(),
            bytes: r1_public.to_bytes()?,
        });

        let crate::round_two::Pair {
            private: r2_priv_ij,
            public: r2_pub_ij,
        } = keyshare.round_two(keyshare_from, &r1_priv, &r1_public);

        // Store the private value for this round 2 pair
        self.store(Storable {
            storable_type: StorableType::RoundTwoPrivate,
            associated_participant_id: message.from.clone(),
            bytes: r2_priv_ij.to_bytes()?,
        });

        // Only a single message to be output here
        let message = Message {
            message_type: MessageType::RoundTwo,
            from: self.id.clone(),
            to: message.from.clone(), // This is a essentially response to that sender
            unverified_bytes: r2_pub_ij.to_bytes()?,
        };
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
    fn do_round_three(&mut self) -> Result<Vec<Message>, Error> {
        // Reconstruct keyshare from local storage
        let keyshare = self.get_keyshare()?;

        let round_three_hashmap = self.get_other_participants_round_three_values()?;

        // Get this participant's round 1 private value
        let r1_priv = crate::round_one::Private::from_slice(
            &self
                .retrieve(StorableType::RoundOnePrivate, &self.id.clone(), false)?
                .bytes,
        )?;

        let (r3_private, r3_publics_map) = keyshare.round_three(&r1_priv, &round_three_hashmap)?;

        // Store round 3 private value
        self.store(Storable {
            storable_type: StorableType::RoundThreePrivate,
            associated_participant_id: self.id.clone(),
            bytes: r3_private.to_bytes()?,
        });

        // Publish public r3 values to all other participants on the channel
        let mut ret_messages = vec![];
        for (id, r3_public) in r3_publics_map {
            ret_messages.push(Message {
                message_type: MessageType::RoundThree,
                from: self.id.clone(),
                to: id.clone(),
                unverified_bytes: r3_public.to_bytes()?,
            });
        }

        Ok(ret_messages)
    }

    /// Presign: Finish
    ///
    /// In this step, the participant simply collects all r3 public values and its r3
    /// private value, and assembles them into a PresignRecord.
    #[cfg_attr(feature = "flame_it", flame)]
    fn do_presign_finish(&mut self) -> Result<(), Error> {
        let r3_pubs = self.get_other_participants_round_three_publics()?;

        // Get this participant's round 3 private value
        let r3_private = crate::round_three::Private::from_slice(
            &self
                .retrieve(StorableType::RoundThreePrivate, &self.id.clone(), false)?
                .bytes,
        )?;

        // Check consistency across all Gamma values
        for r3_pub in r3_pubs.iter() {
            if r3_pub.Gamma != r3_private.Gamma {
                bail!("Inconsistency in presign finish -- Gamma mismatch");
            }
        }

        self.presign_record = Some(
            crate::RecordPair {
                private: r3_private,
                public: r3_pubs,
            }
            .into(),
        );

        Ok(())
    }

    /// Consumer can use this function to "give" a message to this participant
    pub fn accept_message(&mut self, message: &Message) -> Result<(), Error> {
        if message.to != self.id {
            return Err(Error::msg(format!(
                "Attempting to deliver to recipient {} the message:\n {}",
                self.id, message,
            )));
        }

        self.inbox.push(message.to_string());

        Ok(())
    }

    /// Caller can use this to check if the participant is ready to issue a signature
    /// (meaning that the presigning phase has completed)
    pub fn is_ready_to_sign(&self) -> Result<bool, Error> {
        if self.presign_record.is_some() {
            return Ok(true);
        }
        Ok(false)
    }

    pub fn has_messages(&self) -> bool {
        !self.inbox.is_empty()
    }

    pub fn get_public_share(&self) -> Result<k256::ProjectivePoint, Error> {
        match &self.key_init {
            Some(key_init) => Ok(key_init.X),
            None => bail!("Need to call init first before trying to get public share"),
        }
    }

    /// If presign record is populated, then this participant is ready to issue
    /// a signature
    pub fn sign(&mut self, digest: sha2::Sha256) -> Result<SignatureShare, Error> {
        match &self.presign_record {
            Some(record) => {
                let (r, s) = record.sign(digest);
                let ret = SignatureShare { r: Some(r), s };

                // Clear the presign record after being used once
                self.presign_record = None;

                Ok(ret)
            }
            None => bail!("No presign record, not ready to sign yet"),
        }
    }

    //////////////////////
    // Helper functions //
    //////////////////////

    fn store(&mut self, storable: Storable) {
        let val = storable.to_string();
        self.storage.insert(
            (storable.storable_type, storable.associated_participant_id),
            val,
        );
    }

    fn retrieve(
        &mut self,
        storable_type: StorableType,
        associated_participant_id: &ParticipantIdentifier,
        should_delete: bool,
    ) -> Result<Storable, Error> {
        let key = (storable_type.clone(), associated_participant_id.clone());
        let ret = Storable::from_str(self.storage.get(&key).ok_or_else(|| {
            anyhow!("Could not find {} when getting from storage", storable_type)
        })?)?;

        if should_delete {
            self.storage.remove(&key).ok_or_else(|| {
                anyhow!(
                    "Could not find {} when removing from storage",
                    storable_type
                )
            })?;
        }

        Ok(ret)
    }

    fn get_keyshare(&mut self) -> Result<KeyShare, Error> {
        // Reconstruct keyshare from local storage
        let id = self.id.clone();
        let keyshare = KeyShare::from(
            KeygenPublic::from_slice(
                &self
                    .retrieve(StorableType::PublicKeyshare, &id, false)?
                    .bytes,
            )?,
            KeygenPrivate::from_slice(
                &self
                    .retrieve(StorableType::PrivateKeyshare, &id, false)?
                    .bytes,
            )?,
        );
        Ok(keyshare)
    }

    /// Aggregate the other participants' public keyshares from storage. But don't remove them
    /// from storage.
    ///
    /// This returns a HashMap with the key as the participant id and the value as the KeygenPublic
    fn get_other_participants_public_keyshares(
        &mut self,
    ) -> Result<HashMap<ParticipantIdentifier, KeygenPublic>, Error> {
        if !self.has_collected_all_of_others(StorableType::PublicKeyshare)? {
            bail!("Not ready to get other participants public keyshares just yet!");
        }

        let mut hm = HashMap::new();
        for other_participant_id in self.other_participant_ids.clone() {
            let val = self.retrieve(StorableType::PublicKeyshare, &other_participant_id, false)?;
            hm.insert(other_participant_id, KeygenPublic::from_slice(val.bytes)?);
        }
        Ok(hm)
    }

    /// Aggregate the other participants' round three public values from storage. But don't remove them
    /// from storage.
    ///
    /// This returns a Vec with the values
    fn get_other_participants_round_three_publics(
        &mut self,
    ) -> Result<Vec<crate::round_three::Public>, Error> {
        if !self.has_collected_all_of_others(StorableType::RoundThreePublic)? {
            bail!("Not ready to get other participants round three publics just yet!");
        }

        let mut ret_vec = vec![];
        for other_participant_id in self.other_participant_ids.clone() {
            let val =
                self.retrieve(StorableType::RoundThreePublic, &other_participant_id, false)?;
            ret_vec.push(crate::round_three::Public::from_slice(val.bytes)?);
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
        &mut self,
    ) -> Result<HashMap<ParticipantIdentifier, RoundThreeInput>, Error> {
        if !self.has_collected_all_of_others(StorableType::PublicKeyshare)?
            || !self.has_collected_all_of_others(StorableType::RoundTwoPrivate)?
            || !self.has_collected_all_of_others(StorableType::RoundTwoPublic)?
        {
            bail!("Not ready to get other participants round three values just yet!");
        }

        let mut hm = HashMap::new();
        for other_participant_id in self.other_participant_ids.clone() {
            let public_keyshare =
                self.retrieve(StorableType::PublicKeyshare, &other_participant_id, false)?;
            let round_two_private =
                self.retrieve(StorableType::RoundTwoPrivate, &other_participant_id, false)?;
            let round_two_public =
                self.retrieve(StorableType::RoundTwoPublic, &other_participant_id, false)?;
            hm.insert(
                other_participant_id.clone(),
                RoundThreeInput {
                    keygen_public: KeygenPublic::from_slice(public_keyshare.bytes)?,
                    r2_private: crate::round_two::Private::from_slice(round_two_private.bytes)?,
                    r2_public: crate::round_two::Public::from_slice(round_two_public.bytes)?,
                },
            );
        }
        Ok(hm)
    }

    /// Returns true if in storage, there is one storable_type for each other
    /// participant in the quorum.
    fn has_collected_all_of_others(&mut self, storable_type: StorableType) -> Result<bool, Error> {
        for other_participant_id in self.other_participant_ids.clone() {
            if self
                .retrieve(storable_type.clone(), &other_participant_id, false)
                .is_err()
            {
                return Ok(false);
            }
        }
        Ok(true)
    }

    fn validate_and_store_round_two_public(&mut self, message: &Message) -> Result<(), Error> {
        let receiver_keygen_public = KeygenPublic::from_slice(
            &self
                .retrieve(StorableType::PublicKeyshare, &message.to, false)?
                .bytes,
        )?;
        let sender_keygen_public = KeygenPublic::from_slice(
            &self
                .retrieve(StorableType::PublicKeyshare, &message.from, false)?
                .bytes,
        )?;
        let receiver_r1_private = crate::round_one::Private::from_slice(
            &self
                .retrieve(StorableType::RoundOnePrivate, &message.to, false)?
                .bytes,
        )?;
        let sender_r1_public = crate::round_one::Public::from_slice(
            &self
                .retrieve(StorableType::RoundOnePublic, &message.from, false)?
                .bytes,
        )?;

        let message_bytes = message
            .validate_to_round_two_public(
                &receiver_keygen_public,
                &sender_keygen_public,
                &receiver_r1_private,
                &sender_r1_public,
            )?
            .to_bytes()?;

        self.store(Storable {
            storable_type: StorableType::RoundTwoPublic,
            associated_participant_id: message.from.clone(),
            bytes: message_bytes,
        });

        Ok(())
    }

    fn validate_and_store_round_three_public(&mut self, message: &Message) -> Result<(), Error> {
        let receiver_keygen_public = KeygenPublic::from_slice(
            &self
                .retrieve(StorableType::PublicKeyshare, &message.to, false)?
                .bytes,
        )?;
        let sender_keygen_public = KeygenPublic::from_slice(
            &self
                .retrieve(StorableType::PublicKeyshare, &message.from, false)?
                .bytes,
        )?;
        let sender_r1_public = crate::round_one::Public::from_slice(
            &self
                .retrieve(StorableType::RoundOnePublic, &message.from, false)?
                .bytes,
        )?;

        let message_bytes = message
            .validate_to_round_three_public(
                &receiver_keygen_public,
                &sender_keygen_public,
                &sender_r1_public,
            )?
            .to_bytes()?;

        self.store(Storable {
            storable_type: StorableType::RoundThreePublic,
            associated_participant_id: message.from.clone(),
            bytes: message_bytes,
        });

        Ok(())
    }
}

/// Simple wrapper around the signature share output
pub struct SignatureShare {
    r: Option<k256::Scalar>,
    s: k256::Scalar,
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

    pub fn chain(&self, share: Self) -> Result<Self, Error> {
        let r = match (self.r, share.r) {
            (_, None) => Err(anyhow::anyhow!("Invalid format for share, r scalar = 0")),
            (Some(prev_r), Some(new_r)) => {
                if prev_r != new_r {
                    return Err(anyhow::anyhow!("Cannot chain as r values don't match"));
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

    pub fn finish(&self) -> Result<ecdsa::Signature<Secp256k1>, Error> {
        let mut s = self.s;
        if s.is_high().unwrap_u8() == 1 {
            s = s.negate();
        }

        let sig = match self.r {
            Some(r) => Ok(ecdsa::Signature::from_scalars(r, s)?),
            None => Err(anyhow::anyhow!(
                "Cannot produce a signature without including shares"
            )),
        }?;

        Ok(sig)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ParticipantIdentifier(String);

impl ParticipantIdentifier {
    pub fn random<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        // Sample random 32 bytes and convert to hex
        let random_bytes = rng.gen::<[u8; 32]>();
        Self(hex::encode(random_bytes))
    }
}

impl Display for ParticipantIdentifier {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl FromStr for ParticipantIdentifier {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self(s.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ecdsa::signature::DigestVerifier;
    use rand::rngs::OsRng;
    use sha2::{Digest, Sha256};

    /// Delivers a message into a participant's inbox
    fn deliver_one(message: &Message, recipient: &mut Participant) -> Result<(), Error> {
        recipient.accept_message(message)
    }

    /// Delivers all messages into their respective participant's inboxes
    fn deliver_all(messages: &[Message], quorum: &mut Vec<Participant>) -> Result<(), Error> {
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

    fn is_presigning_done(quorum: &[Participant]) -> Result<bool, Error> {
        for participant in quorum {
            if !(participant.is_ready_to_sign()?) {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// For N participants, a typical flow for a single participant looks like:
    ///
    /// Step 0. 1 keygen
    /// Step 1. 1 round one, only after all keygens are done
    ///         Each round one produces N-1 public components
    /// Step 2. N-1 round twos, one for each sender. Each round
    ///         two only relies on that sender's round one
    ///         information, and produces a single public value
    ///         for round two as well.
    ///
    #[cfg_attr(feature = "flame_it", flame)]
    #[test]
    fn test_run_protocol() -> Result<(), Error> {
        let mut rng = OsRng;
        let mut quorum = Participant::new_quorum(3, &mut rng)?;

        // Initialize all participants and get their public keyshares to construct the
        // final signature verification key
        let mut vk_point = k256::ProjectivePoint::identity();
        for participant in quorum.iter_mut() {
            participant.do_init(&mut rng)?;
            let X = participant.get_public_share()?;
            vk_point += X;
        }
        let verification_key =
            ecdsa::VerifyingKey::from_encoded_point(&vk_point.to_affine().into())?;

        while !is_presigning_done(&quorum)? {
            // Pick a random participant to process
            let index = rng.gen_range(0..quorum.len());

            if !quorum[index].has_messages() {
                // No messages to process for this participant, so pick another participant
                continue;
            }

            let messages = quorum[index].process_single_message(&mut rng)?;
            deliver_all(&messages, &mut quorum)?;
        }

        // Now, produce a valid signature
        let mut hasher = Sha256::new();
        hasher.update(b"some test message");

        let mut aggregator = SignatureShare::default();
        for participant in quorum.iter_mut() {
            let signature_share = participant.sign(hasher.clone())?;
            aggregator = aggregator.chain(signature_share)?;
        }
        let signature = aggregator.finish()?;

        // Moment of truth, does the signature verify?
        assert!(verification_key.verify_digest(hasher, &signature).is_ok());

        #[cfg(feature = "flame_it")]
        flame::dump_html(&mut std::fs::File::create("stats/flame-graph.html").unwrap()).unwrap();

        Ok(())
    }
}
