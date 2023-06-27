//! Types and functions related to the key generation sub-protocol Participant.

// Copyright (c) Facebook, Inc. and its affiliates.
// Modifications Copyright (c) 2022-2023 Bolt Labs Holdings, Inc
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

use crate::{
    broadcast::participant::{BroadcastOutput, BroadcastParticipant, BroadcastTag},
    errors::{CallerError, InternalError, Result},
    keygen::{
        keygen_commit::{KeygenCommit, KeygenDecommit},
        keyshare::{KeySharePrivate, KeySharePublic},
    },
    local_storage::LocalStorage,
    messages::{KeygenMessageType, Message, MessageType},
    participant::{Broadcast, InnerProtocolParticipant, ProcessOutcome, ProtocolParticipant},
    protocol::{ParticipantIdentifier, ProtocolType, SharedContext},
    run_only_once,
    utils::{k256_order, CurvePoint},
    zkp::{
        pisch::{CommonInput, PiSchPrecommit, PiSchProof, ProverSecret},
        Proof2,
    },
    Identifier,
};

use k256::ecdsa::VerifyingKey;
use merlin::Transcript;
use rand::{CryptoRng, RngCore};
use tracing::{error, info, instrument, warn};

mod storage {
    use super::*;
    use crate::local_storage::TypeTag;

    pub(super) struct Ready;
    impl TypeTag for Ready {
        type Value = ();
    }
    pub(super) struct Commit;
    impl TypeTag for Commit {
        type Value = KeygenCommit;
    }
    pub(super) struct Decommit;
    impl TypeTag for Decommit {
        type Value = KeygenDecommit;
    }
    pub(super) struct SchnorrPrecom;
    impl TypeTag for SchnorrPrecom {
        type Value = PiSchPrecommit;
    }
    pub(super) struct GlobalRid;
    impl TypeTag for GlobalRid {
        type Value = [u8; 32];
    }
    pub(super) struct PrivateKeyshare;
    impl TypeTag for PrivateKeyshare {
        type Value = KeySharePrivate;
    }
    pub(super) struct PublicKeyshare;
    impl TypeTag for PublicKeyshare {
        type Value = KeySharePublic;
    }
}

/// Protocol status for [`KeygenParticipant`].
#[derive(Debug, PartialEq)]
pub enum Status {
    /// The protocol has been initialized.
    Initialized,
    /// The protocol has terminated successfully.
    TerminatedSuccessfully,
}

/// A [`ProtocolParticipant`] that runs the key generation protocol[^cite].
///
/// # Protocol input
/// The protocol takes no input.
///
/// # Protocol output
/// Upon successful completion, the participant produces [`Output`], which
/// includes:
/// - A list of public key shares, one for each participant (including this
///   participant);
/// - A single private key share for this participant; and
/// - A random value, agreed on by all participants.
///
/// # 🔒 Storage requirements
/// The [private key share](KeySharePrivate) in the output requires secure
/// persistent storage.
///
/// # High-level protocol description
/// The key generation protocol runs in four rounds:
/// - In the first round, each participant broadcasts a commitment to (1) its
///   public key share and (2) a "precommitment" to a Schnorr proof.
/// - Once all commitment broadcasts have been received, the second round
///   proceeds by each participant opening its commitment to all other
///   participants.
/// - In the third round, each participant (1) checks the validity of all the
///   commitments, and (2) produces a Schnorr proof that it knows the private
///   key corresponding to its public keyshare, and sends this proof to all
///   other participants.
/// - Finally, in the last round each participant checks the validity of all
///   other participants' Schnorr proofs. If that succeeds, each participant
///   outputs all the public key shares alongside its own private key share and
///   a global random value, produced with contributory randomness from all
///   parties.
///
/// [^cite]: Ran Canetti, Rosario Gennaro, Steven Goldfeder, Nikolaos
/// Makriyannis, and Udi Peled. UC Non-Interactive, Proactive, Threshold ECDSA
/// with Identifiable Aborts. [EPrint archive,
/// 2021](https://eprint.iacr.org/2021/060.pdf). Figure 5.
#[derive(Debug)]
pub struct KeygenParticipant {
    /// The current session identifier
    sid: Identifier,
    /// A unique identifier for this participant.
    id: ParticipantIdentifier,
    /// A list of all other participant identifiers participating in the
    /// protocol
    other_participant_ids: Vec<ParticipantIdentifier>,
    /// Local storage for this participant to store secrets
    local_storage: LocalStorage,
    /// Broadcast subprotocol handler
    broadcast_participant: BroadcastParticipant,
    /// Status of the protocol execution.
    status: Status,
    /// Whether or not the participant is Ready
    ready: bool
}

/// Output type from key generation, including all parties' public key shares,
/// this party's private key share, and a bit of global randomness.
#[derive(Debug, Clone)]
pub struct Output {
    public_key_shares: Vec<KeySharePublic>,
    private_key_share: KeySharePrivate,
    #[allow(unused)]
    rid: [u8; 32],
}

impl Output {
    /// Construct the generated public key.
    pub fn public_key(&self) -> Result<VerifyingKey> {
        // Add up all the key shares
        let public_key_point = self
            .public_key_shares
            .iter()
            .fold(CurvePoint::IDENTITY, |sum, share| sum + *share.as_ref());

        VerifyingKey::from_encoded_point(&public_key_point.0.to_affine().into()).map_err(|_| {
            error!("Keygen output does not produce a valid public key.");
            InternalError::InternalInvariantFailed
        })
    }

    pub(crate) fn public_key_shares(&self) -> &[KeySharePublic] {
        &self.public_key_shares
    }

    pub(crate) fn private_key_share(&self) -> &KeySharePrivate {
        &self.private_key_share
    }

    /// Simulate the output of a keygen run with the given participants.
    ///
    /// This should __never__ be called outside of tests!
    #[cfg(test)]
    pub(crate) fn simulate(
        pids: &[ParticipantIdentifier],
        rng: &mut (impl CryptoRng + RngCore),
    ) -> Self {
        use rand::Rng;

        let (mut private_key_shares, public_key_shares): (Vec<_>, Vec<_>) = pids
            .iter()
            .map(|&pid| {
                // TODO #340: Replace with KeyShare methods once they exist.
                let secret = KeySharePrivate::random(rng);
                let public = secret.public_share().unwrap();
                (secret, KeySharePublic::new(pid, public))
            })
            .unzip();

        let rid = rng.gen();

        Self {
            private_key_share: private_key_shares.pop().unwrap(),
            public_key_shares,
            rid,
        }
    }
}

impl ProtocolParticipant for KeygenParticipant {
    type Input = ();
    type Output = Output;
    type Status = Status;

    fn new(
        sid: Identifier,
        id: ParticipantIdentifier,
        other_participant_ids: Vec<ParticipantIdentifier>,
        input: Self::Input,
    ) -> Result<Self> {
        Ok(Self {
            sid,
            id,
            other_participant_ids: other_participant_ids.clone(),
            local_storage: Default::default(),
            broadcast_participant: BroadcastParticipant::new(
                sid,
                id,
                other_participant_ids,
                input,
            )?,
            status: Status::Initialized,
            ready: false
        })
    }

    fn ready_type() -> MessageType {
        MessageType::Keygen(KeygenMessageType::Ready)
    }

    fn protocol_type() -> ProtocolType {
        ProtocolType::Keygen
    }

    fn id(&self) -> ParticipantIdentifier {
        self.id
    }

    fn other_ids(&self) -> &[ParticipantIdentifier] {
        &self.other_participant_ids
    }

    fn sid(&self) -> Identifier {
        self.sid
    }

    fn input(&self) -> &Self::Input {
        &()
    }

    #[cfg_attr(feature = "flame_it", flame("keygen"))]
    #[instrument(skip_all)]
    fn process_message<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
        message: &Message,
        input: &Self::Input,
    ) -> Result<ProcessOutcome<Self::Output>> {
        info!("KEYGEN: Player {}: received {:?} from {}", self.id(), message.message_type(), message.from());

        if *self.status() == Status::TerminatedSuccessfully {
            Err(CallerError::ProtocolAlreadyTerminated)?;
        }

        if !self.is_ready() && message.message_type() != MessageType::Keygen(KeygenMessageType::Ready){
            self.stash_message(message)?;
            return Ok(ProcessOutcome::Incomplete);
        }

        match message.message_type() {
            MessageType::Keygen(KeygenMessageType::Ready) => self.handle_ready_msg(rng, message, input),
            MessageType::Keygen(KeygenMessageType::R1CommitHash) => {
                let broadcast_outcome = self.handle_broadcast(rng, message)?;

                // Handle the broadcasted message if all parties have agreed on it
                broadcast_outcome.convert(self, Self::handle_round_one_msg, rng, input)
            }
            MessageType::Keygen(KeygenMessageType::R2Decommit) => {
                self.handle_round_two_msg(message)
            }
            MessageType::Keygen(KeygenMessageType::R3Proof) => self.handle_round_three_msg(message),
            message_type => {
                error!(
                    "Incorrect MessageType given to KeygenParticipant. Got: {:?}",
                    message_type
                );
                Err(InternalError::InternalInvariantFailed)
            }
        }
    }

    fn status(&self) -> &Self::Status {
        &self.status
    }

    fn is_ready(&self) -> bool{
        self.ready
    }
}

impl InnerProtocolParticipant for KeygenParticipant {
    type Context = SharedContext;

    fn retrieve_context(&self) -> <Self as InnerProtocolParticipant>::Context {
        SharedContext::collect(self)
    }

    fn local_storage(&self) -> &LocalStorage {
        &self.local_storage
    }

    fn local_storage_mut(&mut self) -> &mut LocalStorage {
        &mut self.local_storage
    }

    fn set_ready(&mut self) {
        self.ready = true;
    }
}

impl Broadcast for KeygenParticipant {
    fn broadcast_participant(&mut self) -> &mut BroadcastParticipant {
        &mut self.broadcast_participant
    }
}

impl KeygenParticipant {
    /// Handle "Ready" messages from the protocol participants.
    ///
    /// Once "Ready" messages have been received from all participants, this
    /// method will trigger this participant to generate its round one message.
    #[cfg_attr(feature = "flame_it", flame("keygen"))]
    #[instrument(skip_all, err(Debug))]
    fn handle_ready_msg<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
        message: &Message,
        input: &<KeygenParticipant as crate::participant::ProtocolParticipant>::Input,
    ) -> Result<ProcessOutcome<<Self as ProtocolParticipant>::Output>> {
        info!("Handling ready keygen message.");

        let (ready_outcome, is_ready) = self.process_ready_message::<R, storage::Ready>(rng, message, input)?;

        if is_ready {
            let round_one_messages = run_only_once!(self.gen_round_one_msgs(rng, message.id()))?;
            // extend the output with r1 messages (if they hadn't already been generated)
            Ok(ready_outcome.with_messages(round_one_messages))
        } else {
            Ok(ready_outcome)
        }
    }

    /// Generate the protocol's round one message.
    ///
    /// The outcome is a broadcast message containing a commitment to: (1) this
    /// participant's [`KeySharePublic`] and (2) a "pre-commitment" to a Schnorr
    /// proof.
    #[cfg_attr(feature = "flame_it", flame("keygen"))]
    #[instrument(skip_all, err(Debug))]
    fn gen_round_one_msgs<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
        sid: Identifier,
    ) -> Result<Vec<Message>> {
        info!("Generating round one keygen messages.");

        let (keyshare_private, keyshare_public) = KeySharePublic::new_keyshare(self.id(), rng)?;

        let q = k256_order();
        let g = CurvePoint::GENERATOR;
        let X = keyshare_public.as_ref();

        let input = CommonInput::new(&g, &q, X);
        // This corresponds to `A_i` in the paper.
        let sch_precom = PiSchProof::precommit(rng, &input)?;
        let decom = KeygenDecommit::new(rng, &sid, &self.id, &keyshare_public, &sch_precom);
        // This corresponds to `V_i` in the paper.
        let com = decom.commit()?;
        let com_bytes = serialize!(&com)?;

        self.local_storage.store::<storage::Commit>(self.id, com);
        self.local_storage
            .store::<storage::Decommit>(self.id, decom);
        self.local_storage
            .store::<storage::SchnorrPrecom>(self.id, sch_precom);

        self.local_storage
            .store::<storage::PrivateKeyshare>(self.id, keyshare_private);
        self.local_storage
            .store::<storage::PublicKeyshare>(self.id, keyshare_public);

        let messages = self.broadcast(
            rng,
            MessageType::Keygen(KeygenMessageType::R1CommitHash),
            com_bytes,
            sid,
            BroadcastTag::KeyGenR1CommitHash,
        )?;
        Ok(messages)
    }

    /// Handle round one messages from the protocol participants.
    ///
    /// In round one, each participant broadcasts its commitment to its public
    /// key share and a "precommitment" to a Schnorr proof. Once all such
    /// commitments have been received, this participant will send an opening of
    /// its own commitment to all other parties.
    #[cfg_attr(feature = "flame_it", flame("keygen"))]
    #[instrument(skip_all, err(Debug))]
    fn handle_round_one_msg<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
        broadcast_message: BroadcastOutput,
        _input: &(),
    ) -> Result<ProcessOutcome<<Self as ProtocolParticipant>::Output>> {
        info!("Handling round one keygen message.");

        // XXX should we have a check that we haven't recieved a round one
        // message _after_ round one is complete? Likewise for all other rounds.

        let message = broadcast_message.into_message(BroadcastTag::KeyGenR1CommitHash)?;
        let keygen_commit = KeygenCommit::from_message(&message)?;
        self.local_storage
            .store::<storage::Commit>(message.from(), keygen_commit);

        // Check if we've received all the commits, which signals an end to
        // round one.
        //
        // Note: This does _not_ check `self.all_participants` on purpose. There
        // could be a setting where we've received all the round one messages
        // from all other participants, yet haven't ourselves generated our
        // round one message. If we switched to `self.all_participants` here
        // then the result would be `false`, causing the execution to hang.
        //
        // The "right" solution would be to only process the message once the
        // "Ready" round is complete, and stashing messages if it is not yet
        // complete (a la how we do it in `handle_round_two_msg`).
        // Unfortunately, this does not work given the current API because we
        // are dealing with a [`BroadcastOutput`] type instead of a [`Message`]
        // type.
        let r1_done = self
            .local_storage
            .contains_for_all_ids::<storage::Commit>(&self.other_participant_ids);

        if r1_done {
            // Finish round 1 by generating messages for round 2
            let round_one_messages = run_only_once!(self.gen_round_two_msgs(rng, message.id()))?;

            // Process any round 2 messages we may have received early
            let round_two_outcomes = self
                .fetch_messages(MessageType::Keygen(KeygenMessageType::R2Decommit))?
                .iter()
                .map(|msg| self.handle_round_two_msg(msg))
                .collect::<Result<Vec<_>>>()?;

            ProcessOutcome::collect_with_messages(round_two_outcomes, round_one_messages)
        } else {
            // Otherwise, wait for more round 1 messages
            Ok(ProcessOutcome::Incomplete)
        }
    }

    /// Generate the protocol's round two messages.
    ///
    /// The outcome is an opening to the commitment generated in round one.
    #[cfg_attr(feature = "flame_it", flame("keygen"))]
    #[instrument(skip_all, err(Debug))]
    fn gen_round_two_msgs<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
        sid: Identifier,
    ) -> Result<Vec<Message>> {
        info!("Generating round two keygen messages.");

        let mut messages = vec![];
        // Check that we've generated our keyshare before trying to retrieve it.
        //
        // Because we are not checking `self.all_participants` in
        // `handle_round_one_msg`, we may reach this point and not actually have
        // generated round one messages for ourselves (in particular,
        // `PublicKeyshare` and `Decommit`). This check forces that behavior.
        // Without it we'll get a `InternalInvariantFailed` error when trying to
        // retrieve `Decommit` below.
        if !self
            .local_storage
            .contains::<storage::PublicKeyshare>(self.id)
        {
            let more_messages = run_only_once!(self.gen_round_one_msgs(rng, sid))?;
            messages.extend_from_slice(&more_messages);
        }

        let decom = self.local_storage.retrieve::<storage::Decommit>(self.id)?;
        let more_messages = self.message_for_other_participants(
            MessageType::Keygen(KeygenMessageType::R2Decommit),
            sid,
            decom,
        )?;
        messages.extend_from_slice(&more_messages);
        Ok(messages)
    }

    /// Handle the protocol's round two messages.
    ///
    /// Here we check that the decommitments from each participant are valid.
    #[cfg_attr(feature = "flame_it", flame("keygen"))]
    #[instrument(skip_all, err(Debug))]
    fn handle_round_two_msg(
        &mut self,
        message: &Message,
    ) -> Result<ProcessOutcome<<Self as ProtocolParticipant>::Output>> {
        info!("Handling round two keygen message.");
        // We must receive all commitments in round 1 before we start processing
        // decommits in round 2.
        let r1_done = self
            .local_storage
            .contains_for_all_ids::<storage::Commit>(&self.all_participants());
        if !r1_done {
            // Store any early round 2 messages
            self.stash_message(message)?;
            return Ok(ProcessOutcome::Incomplete);
        }
        // Check that the decommitment contained in the message is valid for the
        // previously received commitment.
        let decom = KeygenDecommit::from_message(message)?;
        let com = self
            .local_storage
            .retrieve::<storage::Commit>(message.from())?;
        decom.verify(&message.id(), &message.from(), com)?;
        self.local_storage
            .store::<storage::Decommit>(message.from(), decom);

        // Check if we've received all the decommits
        let r2_done = self
            .local_storage
            .contains_for_all_ids::<storage::Decommit>(&self.all_participants());

        if r2_done {
            // Generate messages for round 3...
            let round_three_messages = run_only_once!(self.gen_round_three_msgs(message.id()))?;

            // ...and handle any messages that other participants have sent for round 3.
            let round_three_outcomes = self
                .fetch_messages(MessageType::Keygen(KeygenMessageType::R3Proof))?
                .iter()
                .map(|msg| self.handle_round_three_msg(msg))
                .collect::<Result<Vec<_>>>()?;
            ProcessOutcome::collect_with_messages(round_three_outcomes, round_three_messages)
        } else {
            // Otherwise, wait for more round 2 messages.
            Ok(ProcessOutcome::Incomplete)
        }
    }

    /// Generate the protocol's round three messages.
    ///
    /// At this point, we have validated each participant's commitment, and can
    /// now proceed to constructing a Schnorr proof that this participant knows
    /// the private value corresponding to its public key share.
    #[cfg_attr(feature = "flame_it", flame("keygen"))]
    #[instrument(skip_all, err(Debug))]
    fn gen_round_three_msgs(&mut self, sid: Identifier) -> Result<Vec<Message>> {
        info!("Generating round three keygen messages.");

        // Construct `global rid` out of each participant's `rid`s.
        let rids: Vec<[u8; 32]> = self
            .other_participant_ids
            .iter()
            .map(|&other_participant_id| {
                let decom = self
                    .local_storage
                    .retrieve::<storage::Decommit>(other_participant_id)?;
                Ok(decom.rid)
            })
            .collect::<Result<Vec<[u8; 32]>>>()?;
        let my_decom = self.local_storage.retrieve::<storage::Decommit>(self.id)?;
        let mut global_rid = my_decom.rid;
        // xor all the rids together. In principle, many different options for combining
        // these should be okay
        for rid in rids.iter() {
            for i in 0..32 {
                global_rid[i] ^= rid[i];
            }
        }
        self.local_storage
            .store::<storage::GlobalRid>(self.id, global_rid);
        let transcript = schnorr_proof_transcript(&global_rid)?;

        let precom = self
            .local_storage
            .retrieve::<storage::SchnorrPrecom>(self.id)?;

        let q = k256_order();
        let g = CurvePoint::GENERATOR;
        let my_pk = self
            .local_storage
            .retrieve::<storage::PublicKeyshare>(self.id)?;
        let input = CommonInput::new(&g, &q, my_pk.as_ref());

        let my_sk = self
            .local_storage
            .retrieve::<storage::PrivateKeyshare>(self.id)?;

        let proof = PiSchProof::prove_from_precommit(
            &self.retrieve_context(),
            precom,
            &input,
            &ProverSecret::new(my_sk.as_ref()),
            &transcript,
        )?;
        let messages = self.message_for_other_participants(
            MessageType::Keygen(KeygenMessageType::R3Proof),
            sid,
            proof,
        )?;
        Ok(messages)
    }

    /// Handle the protocol's round three messages.
    ///
    /// Here we validate the Schnorr proofs from each participant. If these
    /// pass, then we are assured that all public key shares are valid, and we
    /// can terminate the protocol by outputting these alongside this
    /// participant's own private key share.
    #[cfg_attr(feature = "flame_it", flame("keygen"))]
    #[instrument(skip_all, err(Debug))]
    fn handle_round_three_msg(
        &mut self,
        message: &Message,
    ) -> Result<ProcessOutcome<<Self as ProtocolParticipant>::Output>> {
        info!("Handling round three keygen message.");

        if !self.local_storage.contains::<storage::GlobalRid>(self.id) {
            self.stash_message(message)?;
            return Ok(ProcessOutcome::Incomplete);
        }
        let proof = PiSchProof::from_message(message)?;
        let global_rid = *self.local_storage.retrieve::<storage::GlobalRid>(self.id)?;
        let decom = self
            .local_storage
            .retrieve::<storage::Decommit>(message.from())?;

        let q = k256_order();
        let g = CurvePoint::GENERATOR;
        let input = CommonInput::new(&g, &q, decom.pk.as_ref());

        let mut transcript = schnorr_proof_transcript(&global_rid)?;
        proof.verify(input, &self.retrieve_context(), &mut transcript)?;

        // Only if the proof verifies do we store the participant's public key
        // share. This signals the end of the protocol for the participant.
        let keyshare = decom.get_keyshare();
        self.local_storage
            .store::<storage::PublicKeyshare>(message.from(), keyshare.clone());

        //check if we've stored all the public keyshares
        let keyshare_done = self
            .local_storage
            .contains_for_all_ids::<storage::PublicKeyshare>(&self.all_participants());

        // If so, we completed the protocol! Return the outputs.
        if keyshare_done {
            let public_key_shares = self
                .all_participants()
                .iter()
                .map(|pid| self.local_storage.remove::<storage::PublicKeyshare>(*pid))
                .collect::<Result<Vec<_>>>()?;
            let private_key_share = self
                .local_storage
                .remove::<storage::PrivateKeyshare>(self.id)?;
            self.status = Status::TerminatedSuccessfully;

            let output = Output {
                public_key_shares,
                private_key_share,
                rid: global_rid,
            };
            Ok(ProcessOutcome::Terminated(output))
        } else {
            // Otherwise, we'll have to wait for more round three messages.
            Ok(ProcessOutcome::Incomplete)
        }
    }
}

/// Generate a [`Transcript`] for [`PiSchProof`].
fn schnorr_proof_transcript(global_rid: &[u8; 32]) -> Result<Transcript> {
    let mut transcript = Transcript::new(b"keygen schnorr");
    transcript.append_message(b"rid", &serialize!(global_rid)?);
    Ok(transcript)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{utils::testing::{init_testing, init_testing_with_seed}, Identifier, ParticipantConfig};
    use rand::{CryptoRng, Rng, RngCore};
    use std::collections::HashMap;
    use tracing::debug;

    impl KeygenParticipant {
        pub fn new_quorum<R: RngCore + CryptoRng>(
            sid: Identifier,
            quorum_size: usize,
            rng: &mut R,
        ) -> Result<Vec<Self>> {
            ParticipantConfig::random_quorum(quorum_size, rng)?
                .into_iter()
                .map(|config| Self::new(sid, config.id(), config.other_ids().to_vec(), ()))
                .collect::<Result<Vec<_>>>()
        }
        pub fn initialize_keygen_message(&self, keygen_identifier: Identifier) -> Result<Message> {
            let empty: [u8; 0] = [];
            Message::new(
                MessageType::Keygen(KeygenMessageType::Ready),
                keygen_identifier,
                self.id,
                self.id,
                &empty,
            )
        }
    }

    /// Delivers all messages into their respective participant's inboxes.
    fn deliver_all(
        messages: &[Message],
        inboxes: &mut HashMap<ParticipantIdentifier, Vec<Message>>,
    ) -> Result<()> {
        for message in messages {
            for (&id, inbox) in &mut *inboxes {
                if id == message.to() {
                    inbox.push(message.clone());
                    break;
                }
            }
        }
        Ok(())
    }

    fn is_keygen_done(quorum: &[KeygenParticipant]) -> bool {
        for participant in quorum {
            if *participant.status() != Status::TerminatedSuccessfully {
                return false;
            }
        }
        true
    }

    #[allow(clippy::type_complexity)]
    fn process_messages<R: RngCore + CryptoRng>(
        quorum: &mut Vec<KeygenParticipant>,
        inboxes: &mut HashMap<ParticipantIdentifier, Vec<Message>>,
        rng: &mut R,
    ) -> Option<(usize, ProcessOutcome<Output>)> {
        // Pick a random participant to process
        let index = rng.gen_range(0..quorum.len());
        let participant = quorum.get_mut(index).unwrap();

        let inbox = inboxes.get_mut(&participant.id).unwrap();
        if inbox.is_empty() {
            // No messages to process for this participant, so pick another participant
            return None;
        }
        let message = inbox.remove(rng.gen_range(0..inbox.len()));
        debug!(
            "processing participant: {}, with message type: {:?} from {}",
            &participant.id,
            &message.message_type(),
            &message.from(),
        );
        Some((
            index,
            participant.process_message(rng, &message, &()).unwrap(),
        ))
    }

    #[cfg_attr(feature = "flame_it", flame)]
    #[test]
    // This test is cheap. Try a bunch of message permutations to decrease error
    // likelihood
    fn keygen_always_produces_valid_outputs() -> Result<()> {
        let _rng = init_testing();

        for i in 0..20000 {
            println!("{}", i);
            keygen_produces_valid_outputs()?;
        }
        Ok(())
    }

    #[test]
    fn keygen_produces_valid_outputs() -> Result<()> {
        let QUORUM_SIZE = 3;
        let mut rng = init_testing();
        //let seed = [96, 40, 124, 150, 39, 16, 10, 93, 146, 79, 137, 119, 66, 234, 89, 188, 248, 190, 156, 60, 111, 146, 252, 23, 77, 194, 70, 59, 226, 151, 162, 242];
        //let mut rng = init_testing_with_seed(seed);
        let sid = Identifier::random(&mut rng);
        let mut quorum = KeygenParticipant::new_quorum(sid, QUORUM_SIZE, &mut rng)?;
        let mut inboxes = HashMap::new();
        for participant in &quorum {
            let _ = inboxes.insert(participant.id, vec![]);
        }
        let mut outputs = std::iter::repeat_with(|| None)
            .take(QUORUM_SIZE)
            .collect::<Vec<_>>();

        let keyshare_identifier = Identifier::random(&mut rng);

        for participant in &quorum {
            let inbox = inboxes.get_mut(&participant.id).unwrap();
            inbox.push(participant.initialize_keygen_message(keyshare_identifier)?);
        }

        while !is_keygen_done(&quorum) {
            let (index, outcome) = match process_messages(&mut quorum, &mut inboxes, &mut rng) {
                None => continue,
                Some(x) => x,
            };

            // Deliver messages and save outputs
            match outcome {
                ProcessOutcome::Incomplete => {}
                ProcessOutcome::Processed(messages) => deliver_all(&messages, &mut inboxes)?,
                ProcessOutcome::Terminated(output) => outputs[index] = Some(output),
                ProcessOutcome::TerminatedForThisParticipant(output, messages) => {
                    deliver_all(&messages, &mut inboxes)?;
                    outputs[index] = Some(output);
                }
            }
        }

        // Make sure every player got an output
        let outputs: Vec<_> = outputs.into_iter().flatten().collect();
        assert!(outputs.len() == QUORUM_SIZE);

        // Check returned outputs
        //
        // Every participant should have a public output from every other participant
        // and, for a given participant, they should be the same in every output
        for party in quorum.iter_mut() {
            let pid = party.id;

            // Collect the KeySharePublic associated with pid from every output
            let mut publics_for_pid = vec![];
            for output in &outputs {
                let key_share = output
                    .public_key_shares
                    .iter()
                    .find(|key_share| key_share.participant() == pid);

                // Make sure every participant had a key share for this pid
                assert!(key_share.is_some());
                publics_for_pid.push(key_share.unwrap());
            }

            // Make sure they're all equal
            assert!(publics_for_pid.windows(2).all(|pks| pks[0] == pks[1]));

            // Check that each participant fully completed its broadcast portion.
            if let crate::broadcast::participant::Status::ParticipantCompletedBroadcast(
                participants,
            ) = party.broadcast_participant().status()
            {
                assert_eq!(participants.len(), party.other_participant_ids.len());
            } else {
                panic!("Broadcast not completed!");
            }
        }

        // Check that each participant's own `PublicKeyshare` corresponds to their
        // `PrivateKeyshare`
        for (output, pid) in outputs
            .iter()
            .zip(quorum.iter().map(ProtocolParticipant::id))
        {
            let public_share = output
                .public_key_shares
                .iter()
                .find(|public_share| public_share.participant() == pid);
            assert!(public_share.is_some());

            let expected_public_share =
                CurvePoint::GENERATOR.multiply_by_scalar(output.private_key_share.as_ref())?;
            assert_eq!(public_share.unwrap().as_ref(), &expected_public_share);
        }

        // Check that every participant has the same `rid` value
        assert!(outputs
            .windows(2)
            .all(|outputs| outputs[0].rid == outputs[1].rid));

        Ok(())
    }
}
