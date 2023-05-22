//! ## Example usage of [`tss_ecdsa`] crate.
//!
//! Each [`Participant`] is represented by a worker thread. A main coordinator
//! is used to drive sub-protocols and route messages between workers.
//!
//! This example uses
//! [`std::sync::mpsc`] channels to communicate [`Message`]s
//! amongst the workers and coordinator.
//!
//! # Warning: Trust Model
//! This example does not implement sender authentication, which is required for
//! a secure deployment.
//!
//! This means that the coordinator is trusted to route messages correctly.
//! The workers and coordinator are trusted to not forge messages from other
//! participants.
//!
//! Sender authentication is omitted from this code for brevity.

use anyhow::{self};
use clap::{command, Parser};
use rand::{rngs::StdRng, thread_rng, SeedableRng};
use sha2::{Digest, Sha256};
use std::{
    any::Any,
    collections::HashMap,
    sync::mpsc::{channel, Receiver, Sender},
    thread,
};

use tracing::{debug, info, instrument, span, trace, Level};
use tracing_subscriber::{self, EnvFilter};
use tss_ecdsa::{
    keygen::Output, AuxInfoParticipant, Identifier, KeygenParticipant, Message, Participant,
    ParticipantConfig, ParticipantIdentifier, PresignInput, PresignParticipant,
    ProtocolParticipant,
};
use uuid::Uuid;

mod utils;
use utils::{MessageFromWorker, SubProtocol};

#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
struct SessionId(Identifier);
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
struct KeyId(Uuid);

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct CommandLineArgs {
    /// Number of participant worker threads to use.
    #[arg(short, long)]
    number_of_workers: usize,
    /// Number of times to perform each sub-protocol of tss-ecdsa.
    /// protocol_executions > 1 useful for computing meaningful average
    /// execution times.
    #[arg(short, long)]
    protocol_executions: usize,
}

/// Generic Storage for outputs of protocols. Indexed by a `KeyId`
struct StoredOutput<P: ProtocolParticipant> {
    stored_output: HashMap<KeyId, P::Output>,
}

impl<P: ProtocolParticipant> StoredOutput<P> {
    fn new() -> Self {
        StoredOutput {
            stored_output: Default::default(),
        }
    }

    fn store(&mut self, id: KeyId, store: P::Output) {
        self.stored_output.insert(id, store);
    }

    fn retrieve(&mut self, id: &KeyId) -> &P::Output {
        self.stored_output.get(id).unwrap()
    }

    fn take(&mut self, id: &KeyId) -> P::Output {
        self.stored_output.remove(id).unwrap()
    }
}

/// Storage for all participants.
#[derive(Default)]
struct StoredParticipant {
    storage: HashMap<SessionId, (Box<dyn Any + 'static>, KeyId)>,
}

impl StoredParticipant {
    fn new() -> Self {
        StoredParticipant {
            storage: Default::default(),
        }
    }

    fn get_mut<T: ProtocolParticipant + 'static>(
        &mut self,
        id: &SessionId,
    ) -> (&mut Participant<T>, KeyId) {
        let (dynamic, key_id) = self.storage.get_mut(id).unwrap();
        (dynamic.downcast_mut().unwrap(), *key_id)
    }

    fn insert<P: ProtocolParticipant + 'static>(
        &mut self,
        id: SessionId,
        participant: Participant<P>,
        key_id: KeyId,
    ) {
        self.storage.insert(id, (Box::new(participant), key_id));
    }
}

/// Message from the coordinator instructing the worker on the next action.
enum MessageFromCoordinator {
    /// Message from another worker delivering a protocol message.
    SubProtocolMessage(Message),
    /// Message from coordinator asking worker to start new subprotocol.
    NewSubProtocol(SubProtocol, KeyId, SessionId),
}

/// Maps [`ParticipantIdentifier`] to [`Sender`] channels for routing message to
/// the correct participant.
type WorkerChannels = HashMap<ParticipantIdentifier, Sender<MessageFromCoordinator>>;

/// 1) Set up logging.
/// 2) Create MPSC channels for communication between the workers and main
/// thread.
/// 3) Spawns N participant/worker threads ensuring the channels are
/// "connected" properly.
/// 4) Main thread executes the entire [`tss_ecdsa`]
/// protocol to sign a message.
fn main() -> anyhow::Result<()> {
    let cli = CommandLineArgs::parse();
    // Set up logging.
    let filter = EnvFilter::from_default_env();
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .without_time()
        .compact()
        .init();
    let span = span!(Level::INFO, "main");
    let _enter = span.entered();

    let num_workers = cli.number_of_workers;
    let rng = &mut StdRng::from_entropy();

    // Channel from workers to main thread (workers use MPSC).
    let (outgoing_tx, workers_rx) = channel::<MessageFromWorker>();
    let mut worker_messages: WorkerChannels = HashMap::new();

    // Assign a unique identifier to each participant to uniquely identify them
    // through the sub-protocols.
    let participants: Vec<ParticipantConfig> = ParticipantConfig::random_quorum(num_workers, rng)?;
    info!("Spawning {num_workers} worker threads");

    // Spawn worker threads. Link worker to main thread with channels.
    for config in participants {
        let (from_coordinator_tx, from_coordinator_rx) = channel::<MessageFromCoordinator>();
        worker_messages.insert(config.id, from_coordinator_tx);

        let outgoing = outgoing_tx.clone();
        thread::spawn(|| participant_worker(config, from_coordinator_rx, outgoing));
    }

    // Main thread executes entire protocol.
    let runner = SubProtocolRunner::new(worker_messages, workers_rx, num_workers);
    do_tss_ecdsa(runner, cli.protocol_executions)?;

    Ok(())
}

/// Helper type for running sub-protocols for the coordinator.
struct SubProtocolRunner {
    /// Channels to send messages to our workers.
    send_to_workers: WorkerChannels,
    /// Receive messages from worker threads to route to other workers.
    from_workers: Receiver<MessageFromWorker>,
    /// Total number of Participants/worker threads participating in our
    /// sub-protocol.
    total_workers: usize,
}

impl SubProtocolRunner {
    /// Initialize `SubProtocolRunner` with the given channels for sending
    /// messages to worker threads.
    pub fn new(
        send_to_workers: WorkerChannels,
        from_workers: Receiver<MessageFromWorker>,
        total_workers: usize,
    ) -> Self {
        Self {
            send_to_workers,
            from_workers,
            total_workers,
        }
    }

    /// Runs an entire sub-protocol from start to end. Records statistics about
    /// sub-protocol execution time from main thread's point of view.
    fn do_sub_protocol(&mut self, sub_protocol: SubProtocol, key_id: KeyId) -> anyhow::Result<()> {
        info!(
            "Starting sub-protocol: {:?} for {:?}.",
            sub_protocol, key_id
        );

        self.start_new_subprotocol(sub_protocol, key_id)?;
        self.route_worker_messages()?;

        info!("Finished sub-protocol: {:?}.", sub_protocol);
        Ok(())
    }

    /// (Helper Method) Start the specified `sub_protocol` by sending a message
    /// to all worker threads.
    fn start_new_subprotocol(
        &self,
        sub_protocol: SubProtocol,
        key_id: KeyId,
    ) -> anyhow::Result<()> {
        debug!("Starting sub-protocol: {:?}", sub_protocol);
        let rng = &mut thread_rng();
        let sid = SessionId(Identifier::random(rng));

        for worker in self.send_to_workers.values() {
            worker.send(MessageFromCoordinator::NewSubProtocol(
                sub_protocol,
                key_id,
                sid,
            ))?;
        }

        Ok(())
    }

    /// (Helper Method) Receives messages from workers via our
    /// `self.from_workers` field and routes messages to the correct worker
    /// thread via our `self.send_to_workers` map.
    ///
    /// Warning: No sender authentication is done while routing messages!
    /// This function trusts workers not to forge messages.
    fn route_worker_messages(&self) -> anyhow::Result<()> {
        // # of workers who finished the current sub_protocol.
        let mut sub_protocol_ended = 0;

        for message in &self.from_workers {
            debug!("Received messages from a worker.");

            match message {
                MessageFromWorker::FinishedRound(messages) => {
                    // Empty messages are awkward...
                    if messages.is_empty() {
                        trace!("Received empty messages...");
                    }
                    for m in messages {
                        trace!("Routing message: {:?}", m);
                        let recipient = m.to();
                        self.send_to_workers
                            .get(&recipient)
                            .unwrap()
                            .send(MessageFromCoordinator::SubProtocolMessage(m))?;
                    }
                }
                MessageFromWorker::SubProtocolEnded => {
                    trace!("Worker finished sub-protocol.");
                    // TODO: Finish handling multiple in-flight sub-protocols here #382.
                    sub_protocol_ended += 1;
                    if sub_protocol_ended == self.total_workers {
                        debug!("All workers finished sub-protocol. Entire sub-protocol ended.");
                        break;
                    }
                }
            }
        }

        Ok(())
    }
}

/// Execute each sub-protocol of tss-ecdsa.
///
/// Prints average execution time to the log.
fn do_tss_ecdsa(mut runner: SubProtocolRunner, execution_times: usize) -> anyhow::Result<()> {
    info!("Starting key generation.");
    let runner = &mut runner;

    for i in 0..execution_times {
        let key_id = KeyId(Uuid::new_v4());
        info!("Running all sub-protocols. ({i}/{execution_times}).");
        runner.do_sub_protocol(SubProtocol::KeyGeneration, key_id)?;
        runner.do_sub_protocol(SubProtocol::AuxInfo, key_id)?;
        runner.do_sub_protocol(SubProtocol::Presign, key_id)?;
        runner.do_sub_protocol(SubProtocol::Sign, key_id)?;
    }

    Ok(())
}

/// Helper struct encapsulating all state needed for workers to drive
/// sub-protocols.
struct WorkerRunner {
    config: ParticipantConfig,
    participants: StoredParticipant,
    key_gen_outputs: StoredOutput<KeygenParticipant>,
    aux_info_outputs: StoredOutput<AuxInfoParticipant>,
    presign_outputs: StoredOutput<PresignParticipant>,
    outgoing: Sender<MessageFromWorker>,
}

impl WorkerRunner {
    fn new(config: ParticipantConfig, outgoing: Sender<MessageFromWorker>) -> Self {
        WorkerRunner {
            config,
            participants: StoredParticipant::new(),
            key_gen_outputs: StoredOutput::new(),
            aux_info_outputs: StoredOutput::new(),
            presign_outputs: StoredOutput::new(),
            outgoing,
        }
    }

    fn new_keygen(&mut self, sid: SessionId, key_id: KeyId) -> anyhow::Result<()> {
        debug!("Starting KeyGeneration sub-protocol.");
        self.new_sub_protocol::<KeygenParticipant>(sid, (), key_id)
    }

    fn new_auxinfo(&mut self, sid: SessionId, key_id: KeyId) -> anyhow::Result<()> {
        // Note: Missing inputs to aux-info see issues
        // #242 and #243.
        let _output: &Output = self.key_gen_outputs.retrieve(&key_id);
        self.new_sub_protocol::<AuxInfoParticipant>(sid, (), key_id)
    }

    fn new_presign(&mut self, sid: SessionId, key_id: KeyId) -> anyhow::Result<()> {
        let key_shares = self.key_gen_outputs.take(&key_id);
        let (aux_info_public, aux_info_private) = self.aux_info_outputs.retrieve(&key_id);

        let inputs: PresignInput = PresignInput::new(
            aux_info_public.clone(),
            aux_info_private.clone(),
            key_shares,
        )?;
        self.new_sub_protocol::<PresignParticipant>(sid, inputs, key_id)
    }

    #[instrument(skip_all)]
    fn new_sub_protocol<P: ProtocolParticipant + 'static>(
        &mut self,
        sid: SessionId,
        inputs: P::Input,
        key_id: KeyId,
    ) -> anyhow::Result<()> {
        let rng = &mut thread_rng();

        let mut participant: Participant<P> =
            Participant::from_config(&self.config, sid.0, inputs)?;
        let init_message = participant.initialize_message();

        // Output will be None.
        let (_output, messages) = participant.process_single_message(&init_message, rng)?;
        self.outgoing
            .send(MessageFromWorker::FinishedRound(messages))?;
        self.participants.insert(sid, participant, key_id);

        Ok(())
    }

    fn process_keygen(&mut self, sid: SessionId, incoming: Message) -> anyhow::Result<()> {
        let (p, key_id) = self.participants.get_mut::<KeygenParticipant>(&sid);
        Self::process_message(
            p,
            key_id,
            incoming,
            &mut self.key_gen_outputs,
            &self.outgoing,
        )
    }

    fn process_auxinfo(&mut self, sid: SessionId, incoming: Message) -> anyhow::Result<()> {
        let (p, key_id) = self.participants.get_mut::<AuxInfoParticipant>(&sid);
        Self::process_message(
            p,
            key_id,
            incoming,
            &mut self.aux_info_outputs,
            &self.outgoing,
        )
    }

    fn process_presign(&mut self, sid: SessionId, incoming: Message) -> anyhow::Result<()> {
        let (p, key_id) = self.participants.get_mut::<PresignParticipant>(&sid);
        Self::process_message(
            p,
            key_id,
            incoming,
            &mut self.presign_outputs,
            &self.outgoing,
        )
    }

    fn sign(&mut self, key_id: KeyId) -> anyhow::Result<()> {
        let presign_record = self.presign_outputs.take(&key_id);
        let signature = presign_record.sign(message_to_sign())?;
        info!("Computed signature: {:?}", signature);
        self.outgoing.send(MessageFromWorker::SubProtocolEnded)?;
        Ok(())
    }

    // This is an associated function instead of a method (does not take `self`) to
    // make borrow checker happy. As Rust cannot determine I'm borrowing
    // disjoint fields as &mut and &.
    #[instrument(skip_all)]
    fn process_message<P: ProtocolParticipant + 'static>(
        participant: &mut Participant<P>,
        key_id: KeyId,
        incoming: Message,
        stored_output: &mut StoredOutput<P>,
        outgoing: &Sender<MessageFromWorker>,
    ) -> anyhow::Result<()> {
        let (output, messages) =
            participant.process_single_message(&incoming, &mut thread_rng())?;
        if !messages.is_empty() {
            outgoing.send(MessageFromWorker::FinishedRound(messages))?;
        }

        // Note: `output` is `Some(_)` only when sub-protocol is done.
        if let Some(output) = output {
            debug!("Completed subprotocol successfully. Storing outputs.!");
            stored_output.store(key_id, output);
            outgoing.send(MessageFromWorker::SubProtocolEnded)?;
        }
        Ok(())
    }
}

/// Main function to drive work for the workers. These workers execute in their
/// own thread.
#[instrument(skip_all)]
fn participant_worker(
    config: ParticipantConfig,
    from_coordinator: Receiver<MessageFromCoordinator>,
    outgoing: Sender<MessageFromWorker>,
) -> anyhow::Result<()> {
    info!("Worker thread started.");
    let mut runner = WorkerRunner::new(config, outgoing);
    let mut current_subprotocol: HashMap<SessionId, SubProtocol> = Default::default();

    for incoming in from_coordinator {
        match incoming {
            MessageFromCoordinator::SubProtocolMessage(message) => {
                let sid = SessionId(message.id());
                let sub_protocol = current_subprotocol.get(&sid).unwrap();

                match sub_protocol {
                    SubProtocol::KeyGeneration => {
                        runner.process_keygen(sid, message)?;
                    }
                    SubProtocol::AuxInfo => {
                        runner.process_auxinfo(sid, message)?;
                    }
                    SubProtocol::Presign => runner.process_presign(sid, message)?,
                    SubProtocol::Sign => {
                        panic!("Unexpected sign message.");
                    }
                }
            }
            MessageFromCoordinator::NewSubProtocol(sub_protocol, key_id, sid) => {
                current_subprotocol.insert(sid, sub_protocol);

                match sub_protocol {
                    SubProtocol::KeyGeneration => {
                        runner.new_keygen(sid, key_id)?;
                    }
                    SubProtocol::AuxInfo => {
                        runner.new_auxinfo(sid, key_id)?;
                    }
                    SubProtocol::Presign => {
                        runner.new_presign(sid, key_id)?;
                    }
                    SubProtocol::Sign => {
                        runner.sign(key_id)?;
                    }
                }
            }
        }
    }

    Ok(())
}

fn message_to_sign() -> Sha256 {
    let mut hasher = Sha256::new();
    hasher.update(b"hello world");
    hasher
}
