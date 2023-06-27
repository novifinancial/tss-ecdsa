//! Types and functions related to generate auxiliary information sub-protocol
//! Participant.

// Copyright (c) Facebook, Inc. and its affiliates.
// Modifications Copyright (c) 2022-2023 Bolt Labs Holdings, Inc
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

use crate::{
    auxinfo::{
        auxinfo_commit::{Commitment, CommitmentScheme},
        info::{AuxInfoPrivate, AuxInfoPublic, AuxInfoWitnesses},
        proof::AuxInfoProof,
        Output,
    },
    broadcast::participant::{BroadcastOutput, BroadcastParticipant, BroadcastTag},
    errors::{CallerError, InternalError, Result},
    local_storage::LocalStorage,
    messages::{AuxinfoMessageType, Message, MessageType},
    paillier::DecryptionKey,
    participant::{Broadcast, InnerProtocolParticipant, ProcessOutcome, ProtocolParticipant},
    protocol::{Identifier, ParticipantIdentifier, ProtocolType, SharedContext},
    ring_pedersen::VerifiedRingPedersen,
    run_only_once,
};
use rand::{CryptoRng, RngCore};
use tracing::{debug, error, info, instrument};

// Local storage data types.
mod storage {
    use super::*;
    use crate::local_storage::TypeTag;

    pub(super) struct Ready;
    impl TypeTag for Ready {
        type Value = ();
    }
    pub(super) struct Private;
    impl TypeTag for Private {
        type Value = AuxInfoPrivate;
    }
    pub(super) struct Public;
    impl TypeTag for Public {
        type Value = AuxInfoPublic;
    }
    pub(super) struct Commit;
    impl TypeTag for Commit {
        type Value = Commitment;
    }
    pub(super) struct Decommit;
    impl TypeTag for Decommit {
        type Value = CommitmentScheme;
    }
    pub(super) struct GlobalRid;
    impl TypeTag for GlobalRid {
        type Value = [u8; 32];
    }
    pub(super) struct Witnesses;
    impl TypeTag for Witnesses {
        type Value = AuxInfoWitnesses;
    }
}

/// Protocol status for [`AuxInfoParticipant`].
#[derive(Debug, PartialEq)]
pub enum Status {
    /// Protocol has initialized successfully.
    Initialized,
    /// Protocol has terminated successfully.
    TerminatedSuccessfully,
}

/// A [`ProtocolParticipant`] that runs the auxiliary information
/// protocol[^cite].
///
/// # Protocol input
/// The protocol takes no input.
///
/// # Protocol output
/// Upon succesful completion, the participant outputs the following:
/// - A [`Vec`] of [`AuxInfoPublic`]s, which correspond to the public auxiliary
///   information of each participant (including this participant), and
/// - A single [`AuxInfoPrivate`], which corresponds to the **private**
///   auxiliary information of this participant.
///
/// # 🔒 Storage requirements
/// The [`AuxInfoPrivate`] output requires secure persistent storage.
///
/// # High-level protocol description
/// The auxinfo protocol runs in four rounds:
/// - In the first round, we generate an RSA modulus `N = pq`, alongside
///   ring-Pedersen parameters `(s, t, λ)` such that `s = t^λ mod N`. We then
///   produce a zero-knowledge proof `𝚷[prm]` that the ring-Pedersen parameters
///   are correct. Finally, we commit to the tuple `(N, s, t, 𝚷[prm])` and
///   broadcast this commitment.
/// - Once we have received all broadcasted commitments, in the second round we
///   send a decommitment to the commited value in round one to all other
///   participants.
/// - In the third round, we (1) check the validity of all the commitments plus
///   the validity of the committed `𝚷[prm]` proof, and (2) generate the
///   following proofs about our RSA modulus `N`: `𝚷[mod]`, which asserts the
///   validity of `N` as a product of two primes, and a version of `𝚷[fac]` _for
///   each other participant_ which asserts that neither factor of `N` is "too
///   small". (The security of the `𝚷[fac]` proof depends on the correctness of
///   the commitment parameters used to create it, so each other party requires
///   it to be created with the parameters they provided in round two.) We then
///   send `𝚷[mod]` alongside the appropriate `𝚷[fac]` to each other
///   participant.
/// - Finally, in the last round we check the validity of the proofs from round
///   three. If everything passes, we output the `(N, s, t)` tuples from all
///   participants (including ourselves), alongside our own secret primes `(p,
///   q)`.
///
/// [^cite]: Ran Canetti, Rosario Gennaro, Steven Goldfeder, Nikolaos
/// Makriyannis, and Udi Peled. UC Non-Interactive, Proactive, Threshold ECDSA
/// with Identifiable Aborts. [EPrint archive,
/// 2021](https://eprint.iacr.org/2021/060.pdf). Figure 6. Note that this does
/// not include the key-refresh steps included in Figure 6.

#[derive(Debug)]
pub struct AuxInfoParticipant {
    /// The current session identifier
    sid: Identifier,
    /// The current protocol input
    input: (),
    /// A unique identifier for this participant
    id: ParticipantIdentifier,
    /// A list of all other participant identifiers participating in the
    /// protocol
    other_participant_ids: Vec<ParticipantIdentifier>,
    /// Local storage for this participant to store secrets
    local_storage: LocalStorage,
    /// Broadcast subprotocol handler
    broadcast_participant: BroadcastParticipant,
    /// The status of the protocol execution
    status: Status,
    /// Whether or not the participant is Ready
    ready: bool
}

impl ProtocolParticipant for AuxInfoParticipant {
    type Input = ();
    // The output type includes `AuxInfoPublic` material for all participants
    // (including ourselves) and `AuxInfoPrivate` for ourselves.
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
            input,
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
        MessageType::Auxinfo(AuxinfoMessageType::Ready)
    }

    fn protocol_type() -> ProtocolType {
        ProtocolType::AuxInfo
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
        &self.input
    }

    #[cfg_attr(feature = "flame_it", flame("auxinfo"))]
    #[instrument(skip_all, err(Debug))]
    fn process_message<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
        message: &Message,
        input: &Self::Input,
    ) -> Result<ProcessOutcome<Self::Output>> {
        info!("Processing auxinfo message.");

        if *self.status() == Status::TerminatedSuccessfully {
            Err(CallerError::ProtocolAlreadyTerminated)?;
        }

        match message.message_type() {
            MessageType::Auxinfo(AuxinfoMessageType::Ready) => self.handle_ready_msg(rng, message, input),
            MessageType::Auxinfo(AuxinfoMessageType::R1CommitHash) => {
                let broadcast_outcome = self.handle_broadcast(rng, message)?;

                // Handle the broadcasted message if all parties have agreed on it
                broadcast_outcome.convert(self, Self::handle_round_one_msg, rng, input)
            }
            MessageType::Auxinfo(AuxinfoMessageType::R2Decommit) => {
                self.handle_round_two_msg(rng, message)
            }
            MessageType::Auxinfo(AuxinfoMessageType::R3Proof) => {
                self.handle_round_three_msg(message)
            }
            message_type => {
                error!(
                    "Incorrect MessageType given to AuxInfoParticipant. Got: {:?}",
                    message_type
                );
                Err(InternalError::InternalInvariantFailed)
            }
        }
    }

    fn status(&self) -> &Self::Status {
        &self.status
    }

    fn is_ready(&self) -> bool {
        self.ready
    }
}

impl InnerProtocolParticipant for AuxInfoParticipant {
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

impl Broadcast for AuxInfoParticipant {
    fn broadcast_participant(&mut self) -> &mut BroadcastParticipant {
        &mut self.broadcast_participant
    }
}

impl AuxInfoParticipant {
    /// Handle "Ready" messages from the protocol participants.
    ///
    /// Once "Ready" messages have been received from all participants, this
    /// method will trigger this participant to generate its round one message.
    #[cfg_attr(feature = "flame_it", flame("auxinfo"))]
    #[instrument(skip_all, err(Debug))]
    fn handle_ready_msg<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
        message: &Message,
        input: &<AuxInfoParticipant as crate::participant::ProtocolParticipant>::Input,
    ) -> Result<ProcessOutcome<<Self as ProtocolParticipant>::Output>> {
        info!("Handling auxinfo ready message.");

        let (ready_outcome, is_ready) = self.process_ready_message::<R, storage::Ready>(rng, message, input)?;

        if is_ready {
            let round_one_messages = run_only_once!(self.gen_round_one_msgs(rng, message.id()))?;
            Ok(ready_outcome.with_messages(round_one_messages))
        } else {
            Ok(ready_outcome)
        }
    }

    /// Generate the participant's round one message.
    ///
    /// This corresponds to the following lines in Round 1 of Figure 6:
    /// - Line 1: Sampling safe primes `p` and `q`.
    /// - Line 4: Generating the `𝚷[prm]` proof `\hat{ψ}_i`.
    /// - Line 6: Producing the hash commitment `V_i` on the above values.
    #[cfg_attr(feature = "flame_it", flame("auxinfo"))]
    #[instrument(skip_all, err(Debug))]
    fn gen_round_one_msgs<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
        sid: Identifier,
    ) -> Result<Vec<Message>> {
        info!("Generating round one auxinfo messages.");

        let (auxinfo_private, auxinfo_public, auxinfo_witnesses) = self.new_auxinfo(rng)?;
        self.local_storage
            .store::<storage::Private>(self.id, auxinfo_private);
        self.local_storage
            .store::<storage::Public>(self.id, auxinfo_public.clone());
        self.local_storage
            .store::<storage::Witnesses>(self.id, auxinfo_witnesses);

        let scheme = CommitmentScheme::new(sid, self, auxinfo_public, rng)?;
        let com = scheme.commit()?;

        self.local_storage
            .store::<storage::Commit>(self.id, com.clone());
        self.local_storage
            .store::<storage::Decommit>(self.id, scheme);

        let messages = self.broadcast(
            rng,
            MessageType::Auxinfo(AuxinfoMessageType::R1CommitHash),
            serialize!(&com)?,
            sid,
            BroadcastTag::AuxinfoR1CommitHash,
        )?;
        Ok(messages)
    }

    /// Handle other participants' round one message.
    ///
    /// This message is a broadcast message containing the other participant's
    /// commitment to its [`AuxInfoPublic`] data. Once all such commitments have
    /// been received, we generate a round two message.
    #[cfg_attr(feature = "flame_it", flame("auxinfo"))]
    #[instrument(skip_all, err(Debug))]
    fn handle_round_one_msg<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
        broadcast_message: BroadcastOutput,
        _input: &(),
    ) -> Result<ProcessOutcome<<Self as ProtocolParticipant>::Output>> {
        info!("Handling round one auxinfo message.");

        let message = broadcast_message.into_message(BroadcastTag::AuxinfoR1CommitHash)?;

        self.local_storage
            .store::<storage::Commit>(message.from(), Commitment::from_message(&message)?);

        // Check if we've received all the commitments.
        //
        // Note that we only check whether we've recieved the commitments from
        // the other participants, as there could be a case where we've handled
        // all the other participants' round one message before we've generated
        // _this_ participant's round one message.
        let r1_done = self
            .local_storage
            .contains_for_all_ids::<storage::Commit>(&self.other_participant_ids);

        if r1_done {
            // Generate messages for round two...
            let round_two_messages = run_only_once!(self.gen_round_two_msgs(rng, message.id()))?;

            // ...and process any round two messages we may have received early.
            let round_two_outcomes = self
                .fetch_messages(MessageType::Auxinfo(AuxinfoMessageType::R2Decommit))?
                .iter()
                .map(|msg| self.handle_round_two_msg(rng, msg))
                .collect::<Result<Vec<_>>>()?;

            ProcessOutcome::collect_with_messages(round_two_outcomes, round_two_messages)
        } else {
            // Round 1 isn't done, so we have neither outputs nor new messages to send.
            Ok(ProcessOutcome::Incomplete)
        }
    }

    /// Generate this participant's round two message.
    ///
    /// This message is simply the decommitment to the commitment sent in round
    /// one.
    #[cfg_attr(feature = "flame_it", flame("auxinfo"))]
    #[instrument(skip_all, err(Debug))]
    fn gen_round_two_msgs<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
        sid: Identifier,
    ) -> Result<Vec<Message>> {
        info!("Generating round two auxinfo messages.");

        let mut messages = vec![];
        // Check that we've generated this participant's public info before trying to
        // retrieve it.
        let public_keyshare_generated = self.local_storage.contains::<storage::Public>(self.id);
        if !public_keyshare_generated {
            // If not, we need to generate the round one messages, which will
            // produce the necessary public info we were looking for above.
            let more_messages = run_only_once!(self.gen_round_one_msgs(rng, sid))?;
            messages.extend_from_slice(&more_messages);
        }

        let decom = self.local_storage.retrieve::<storage::Decommit>(self.id)?;
        let more_messages = self.message_for_other_participants(
            MessageType::Auxinfo(AuxinfoMessageType::R2Decommit),
            sid,
            decom,
        )?;
        messages.extend(more_messages);
        Ok(messages)
    }

    /// Handle other participants' round two message.
    ///
    /// The message should correspond to a decommitment to the committed value
    /// from round one. This method checks the validity of that decommitment.
    /// Once (valid) decommitments from all other participants have been
    /// received, we proceed to generating round three messages.
    #[cfg_attr(feature = "flame_it", flame("auxinfo"))]
    #[instrument(skip_all, err(Debug))]
    fn handle_round_two_msg<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
        message: &Message,
    ) -> Result<ProcessOutcome<<Self as ProtocolParticipant>::Output>> {
        info!("Handling round two auxinfo message.");

        // We must receive all commitments in round 1 before we start processing
        // decommitments in round 2.
        let r1_done = self
            .local_storage
            .contains_for_all_ids::<storage::Commit>(&self.all_participants());
        if !r1_done {
            // store any early round 2 messages
            self.stash_message(message)?;
            return Ok(ProcessOutcome::Incomplete);
        }
        // Convert the message into the decommitment value.
        //
        // Note: `AuxInfoDecommit::from_message` checks the validity of all its
        // messages, which includes validating the `𝚷[prm]` proof.
        let scheme = CommitmentScheme::from_message(message, &self.retrieve_context())?;
        let com = self
            .local_storage
            .retrieve::<storage::Commit>(message.from())?;
        scheme.verify(&message.id(), &message.from(), com)?;
        self.local_storage
            .store::<storage::Decommit>(message.from(), scheme);

        // Check if we've received all the decommitments.
        //
        // Note: This does _not_ check `self.all_participants()` on purpose. We
        // could be in the setting where we've received round two messages from
        // all other participants but haven't yet generated our own round one
        // message.
        let r2_done = self
            .local_storage
            .contains_for_all_ids::<storage::Decommit>(&self.other_participant_ids);
        if r2_done {
            // Generate messages for round 3...
            let round_three_messages =
                run_only_once!(self.gen_round_three_msgs(rng, message.id()))?;

            // ...and handle any messages that other participants have sent for round 3.
            let round_three_outcomes = self
                .fetch_messages(MessageType::Auxinfo(AuxinfoMessageType::R3Proof))?
                .iter()
                .map(|msg| self.handle_round_three_msg(msg))
                .collect::<Result<Vec<_>>>()?;

            ProcessOutcome::collect_with_messages(round_three_outcomes, round_three_messages)
        } else {
            Ok(ProcessOutcome::Incomplete)
        }
    }

    /// Generate the participant's round three message.
    ///
    /// This corresponds to the following lines of Round 3 in Figure 6:
    ///
    /// - Step 2, Lines 1-2: Generate the `𝚷[mod]` and `𝚷[fac]` proofs.
    ///
    /// Note that Step 1 is handled in `handle_round_two_msg`.
    #[cfg_attr(feature = "flame_it", flame("auxinfo"))]
    #[instrument(skip_all, err(Debug))]
    fn gen_round_three_msgs<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
        sid: Identifier,
    ) -> Result<Vec<Message>> {
        info!("Generating round three auxinfo messages.");

        // Extract all the `rid` values from all other participants.
        let rids: Vec<[u8; 32]> = self
            .other_participant_ids
            .iter()
            .map(|&other_participant_id| {
                let decom = self
                    .local_storage
                    .retrieve::<storage::Decommit>(other_participant_id)?;
                Ok(decom.rid())
            })
            .collect::<Result<Vec<[u8; 32]>>>()?;
        let my_decom = self.local_storage.retrieve::<storage::Decommit>(self.id)?;

        let mut global_rid = my_decom.rid();
        // xor all the rids together. In principle, many different options for combining
        // these should be okay
        for rid in rids.iter() {
            for i in 0..32 {
                global_rid[i] ^= rid[i];
            }
        }
        self.local_storage
            .store::<storage::GlobalRid>(self.id, global_rid);

        let witness = self.local_storage.retrieve::<storage::Witnesses>(self.id)?;
        let product = &witness.p * &witness.q;

        self.other_participant_ids
            .iter()
            .map(|&pid| {
                // Grab the other participant's decommitment record from storage...
                let verifier_decommit = self.local_storage.retrieve::<storage::Decommit>(pid)?;
                // ... and use its setup parameters in the proof.
                let proof = AuxInfoProof::prove(
                    rng,
                    &self.retrieve_context(),
                    sid,
                    global_rid,
                    verifier_decommit.clone().into_public().params(),
                    &product,
                    &witness.p,
                    &witness.q,
                )?;
                Message::new(
                    MessageType::Auxinfo(AuxinfoMessageType::R3Proof),
                    sid,
                    self.id,
                    pid,
                    &proof,
                )
            })
            .collect::<Result<Vec<_>>>()
    }

    /// Handle other participants' round three messages.
    ///
    /// This corresponds to the following lines in Output of Figure 6:
    ///
    /// - Step 1, Line 2: Verify the `𝚷[mod]` and `𝚷[fac]` proofs.
    ///
    /// - Step 2: Output the `(N, s, t)` tuple of each participant once all
    ///   participants' proofs verify.
    #[cfg_attr(feature = "flame_it", flame("auxinfo"))]
    #[instrument(skip_all, err(Debug))]
    fn handle_round_three_msg(
        &mut self,
        message: &Message,
    ) -> Result<ProcessOutcome<<Self as ProtocolParticipant>::Output>> {
        info!("Handling round three auxinfo message.");

        // We can't handle this message unless we already calculated the global_rid
        if !self.local_storage.contains::<storage::GlobalRid>(self.id) {
            self.stash_message(message)?;
            return Ok(ProcessOutcome::Incomplete);
        }

        let global_rid = self.local_storage.retrieve::<storage::GlobalRid>(self.id)?;
        let decom = self
            .local_storage
            .retrieve::<storage::Decommit>(message.from())?;

        let auxinfo_pub = decom.clone().into_public();
        let my_public = self.local_storage.retrieve::<storage::Public>(self.id)?;

        let proof = AuxInfoProof::from_message(message)?;
        // Verify the public parameters for the given participant. Note that
        // this verification verifies _both_ the `𝚷[mod]` and `𝚷[fac]` proofs.
        proof.verify(
            &self.retrieve_context(),
            message.id(),
            *global_rid,
            my_public.params(),
            auxinfo_pub.pk().modulus(),
        )?;

        self.local_storage
            .store::<storage::Public>(message.from(), auxinfo_pub);

        // Check if we've stored all the `AuxInfoPublic`s.
        let done = self
            .local_storage
            .contains_for_all_ids::<storage::Public>(&self.all_participants());

        // If so, we completed the protocol! Return the outputs.
        if done {
            let auxinfo_public = self
                .all_participants()
                .iter()
                .map(|pid| self.local_storage.remove::<storage::Public>(*pid))
                .collect::<Result<Vec<_>>>()?;
            let auxinfo_private = self.local_storage.remove::<storage::Private>(self.id)?;

            // The normal error type of this method is `CallerError::BadInput` because it's
            // external-facing, but in this case we somehow borked the protocol, so throw
            // the correct error.
            let output = Output::from_parts(auxinfo_public, auxinfo_private)
                .map_err(|_| InternalError::InternalInvariantFailed)?;

            self.status = Status::TerminatedSuccessfully;

            Ok(ProcessOutcome::Terminated(output))
        } else {
            // Otherwise, we'll have to wait for more round three messages.
            Ok(ProcessOutcome::Incomplete)
        }
    }

    #[cfg_attr(feature = "flame_it", flame("auxinfo"))]
    #[instrument(skip_all, err(Debug))]
    fn new_auxinfo<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
    ) -> Result<(AuxInfoPrivate, AuxInfoPublic, AuxInfoWitnesses)> {
        debug!("Creating new auxinfo.");

        let (decryption_key, p, q) = DecryptionKey::new(rng).map_err(|_| {
            error!("Failed to create DecryptionKey");
            InternalError::InternalInvariantFailed
        })?;
        let params = VerifiedRingPedersen::extract(&decryption_key, &self.retrieve_context(), rng)?;
        let encryption_key = decryption_key.encryption_key();

        Ok((
            decryption_key.into(),
            AuxInfoPublic::new(&self.retrieve_context(), self.id(), encryption_key, params)?,
            AuxInfoWitnesses { p, q },
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{utils::testing::init_testing, Identifier, ParticipantConfig};
    use rand::{CryptoRng, Rng, RngCore};
    use std::collections::HashMap;

    impl AuxInfoParticipant {
        pub fn new_quorum<R: RngCore + CryptoRng>(
            sid: Identifier,
            input: (),
            quorum_size: usize,
            rng: &mut R,
        ) -> Result<Vec<Self>> {
            ParticipantConfig::random_quorum(quorum_size, rng)?
                .into_iter()
                .map(|config| Self::new(sid, config.id(), config.other_ids().to_vec(), input))
                .collect::<Result<Vec<_>>>()
        }

        pub fn initialize_auxinfo_message(
            &self,
            auxinfo_identifier: Identifier,
        ) -> Result<Message> {
            let empty: [u8; 0] = [];
            Message::new(
                MessageType::Auxinfo(AuxinfoMessageType::Ready),
                auxinfo_identifier,
                self.id,
                self.id,
                &empty,
            )
        }
    }

    /// Delivers all messages into their respective participant's inboxes
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

    fn is_auxinfo_done(quorum: &[AuxInfoParticipant]) -> bool {
        for participant in quorum {
            if *participant.status() != Status::TerminatedSuccessfully {
                return false;
            }
        }
        true
    }

    /// Pick a random participant and process one of the messages in their
    /// inbox.
    ///
    /// Returns None if there are no messages for the selected participant.
    fn process_messages<R: RngCore + CryptoRng>(
        quorum: &mut Vec<AuxInfoParticipant>,
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
        // Pick a random message to process
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
    #[ignore = "slow"]
    // This test is cheap. Try a bunch of message permutations to decrease error
    // likelihood
    fn test_run_auxinfo_protocol_many_times() -> Result<()> {
        let _rng = init_testing();

        for _ in 0..20 {
            test_run_auxinfo_protocol()?;
        }
        Ok(())
    }

    #[test]
    fn test_run_auxinfo_protocol() -> Result<()> {
        let QUORUM_SIZE = 3;
        let mut rng = init_testing();
        let sid = Identifier::random(&mut rng);
        let mut quorum = AuxInfoParticipant::new_quorum(sid, (), QUORUM_SIZE, &mut rng)?;
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
            inbox.push(participant.initialize_auxinfo_message(keyshare_identifier)?);
        }

        while !is_auxinfo_done(&quorum) {
            // Try processing a message
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

        let participant_ids = quorum[0].all_participants();
        let context = SharedContext::fill_context(participant_ids, sid);
        // Check returned outputs
        //
        // Every participant should have a public output from every other participant
        // and, for a given participant, they should be the same in every output
        for party in quorum.iter_mut() {
            let pid = party.id;

            // Collect the AuxInfoPublic associated with pid from every output
            let mut publics_for_pid = vec![];
            for output in &outputs {
                let public_key = output.find_public(pid);
                assert!(public_key.is_some());
                // Check that it's valid while we're here.
                assert!(public_key.unwrap().verify(&context).is_ok());
                publics_for_pid.push(public_key.unwrap());
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

        // Check that private outputs are consistent
        for (output, pid) in outputs.iter().zip(quorum.iter().map(|p| p.id())) {
            let public_key = output.find_public(pid);
            assert!(public_key.is_some());
            assert_eq!(
                *public_key.unwrap().pk(),
                output.private_auxinfo().encryption_key()
            );
        }

        Ok(())
    }
}
