use criterion::{criterion_group, criterion_main, Criterion};

use rand::{prelude::IteratorRandom, rngs::OsRng, CryptoRng, Rng, RngCore};
use std::collections::HashMap;
use tss_ecdsa::{
    errors::Result, AuxInfoParticipant, Identifier, KeygenParticipant, Message, Participant,
    ParticipantConfig, ParticipantIdentifier, PresignInput, PresignParticipant,
    ProtocolParticipant,
};

/// Delivers all messages into their respective participant's inboxes
fn deliver_all(
    messages: &[Message],
    inboxes: &mut HashMap<ParticipantIdentifier, Vec<Message>>,
) -> Result<()> {
    for message in messages {
        for (id, inbox) in inboxes.iter_mut() {
            if *id == message.to() {
                inbox.push(message.clone());
                break;
            }
        }
    }
    Ok(())
}

/// Process a single message for a single participant, randomly chosen. If that
/// participant completes the protocol, return their output.
fn process_messages<R: RngCore + CryptoRng, P: ProtocolParticipant>(
    quorum: &mut [Participant<P>],
    inboxes: &mut HashMap<ParticipantIdentifier, Vec<Message>>,
    rng: &mut R,
) -> Result<Option<P::Output>> {
    // Pick a random participant to process
    let participant = quorum.iter_mut().choose(rng).unwrap();

    let inbox = inboxes.get_mut(&participant.id()).unwrap();
    if inbox.is_empty() {
        // No messages to process for this participant, so pick another participant
        return Ok(None);
    }

    // Process a random message in the participant's inbox
    // This is done to simulate arbitrary message arrival ordering
    let index = rng.gen_range(0..inbox.len());
    let message = inbox.remove(index);
    let (output, messages) = participant.process_single_message(&message, rng)?;
    deliver_all(&messages, inboxes)?;

    Ok(output)
}

fn run_subprotocol<P: ProtocolParticipant>(
    quorum: &mut [Participant<P>],
    inboxes: &mut HashMap<ParticipantIdentifier, Vec<Message>>,
) -> Result<Vec<P::Output>> {
    let mut rng = rand::thread_rng();
    for participant in quorum.iter() {
        let inbox = inboxes.get_mut(&participant.id()).unwrap();
        inbox.push(participant.initialize_message());
    }

    let mut outputs = Vec::with_capacity(quorum.len());
    while outputs.len() < quorum.len() {
        if let Some(output) = process_messages(quorum, inboxes, &mut rng)? {
            outputs.push(output)
        }
    }
    Ok(outputs)
}

fn init_new_player_set<P: ProtocolParticipant>(
    num_players: usize,
    sid: Identifier,
    inputs: Vec<P::Input>,
) -> (
    Vec<Participant<P>>,
    HashMap<ParticipantIdentifier, Vec<Message>>,
) {
    let mut rng = rand::thread_rng();

    // Get the sets of mine/other ids for each party
    let ids = std::iter::repeat_with(|| ParticipantIdentifier::random(&mut rng))
        .take(num_players)
        .collect::<Vec<_>>();

    let configs = (0..num_players)
        .map(|i| {
            let mut other_ids = ids.clone();
            let id = other_ids.remove(i);
            ParticipantConfig { id, other_ids }
        })
        .collect::<Vec<_>>();

    // Instantiate participants
    let quorum: Vec<Participant<P>> = configs
        .iter()
        .zip(inputs)
        .map(|(config, input)| Participant::from_config(config, sid, input))
        .collect();

    // Instantiate inboxes
    let mut inboxes = HashMap::new();
    for participant in &quorum {
        let _ = inboxes.insert(participant.id(), vec![]);
    }
    (quorum, inboxes)
}

fn run_benchmarks_for_given_size(c: &mut Criterion, num_players: usize) {
    let mut rng = OsRng;

    // Note: Inboxes are specifically created out here so we don't benchmark the
    // allocation time to make them.

    // Benchmark keygen
    let keygen_identifier = Identifier::random(&mut rng);
    let keygen_inputs = std::iter::repeat(()).take(num_players).collect();
    let (mut players, mut inboxes) =
        init_new_player_set(num_players, keygen_identifier, keygen_inputs);
    c.bench_function(&format!("Keygen with {num_players} nodes"), |b| {
        b.iter(|| run_subprotocol::<KeygenParticipant>(&mut players, &mut inboxes))
    });

    // Benchmark auxinfo
    let auxinfo_identifier = Identifier::random(&mut rng);
    let auxinfo_inputs = std::iter::repeat(()).take(num_players).collect();
    let (mut players, mut inboxes) =
        init_new_player_set(num_players, auxinfo_identifier, auxinfo_inputs);
    c.bench_function(&format!("Auxinfo with {num_players} nodes"), |b| {
        b.iter(|| run_subprotocol::<AuxInfoParticipant>(&mut players, &mut inboxes))
    });

    // Prepare to benchmark presign:
    // 1. Run keygen and get outputs
    let keygen_inputs = std::iter::repeat(()).take(num_players).collect();
    let (mut players, mut inboxes) =
        init_new_player_set(num_players, keygen_identifier, keygen_inputs);
    let keygen_outputs = run_subprotocol::<KeygenParticipant>(&mut players, &mut inboxes).unwrap();

    // 2. Run auxinfo and get outputs
    let auxinfo_inputs = std::iter::repeat(()).take(num_players).collect();
    let (mut players, mut inboxes) =
        init_new_player_set(num_players, auxinfo_identifier, auxinfo_inputs);
    let auxinfo_outputs =
        run_subprotocol::<AuxInfoParticipant>(&mut players, &mut inboxes).unwrap();

    // 3. Assemble presign input from keygen and auxinfo.
    let presign_inputs = auxinfo_outputs
        .into_iter()
        .zip(keygen_outputs)
        .map(|((aux_pub, aux_priv), (key_pub, key_priv))| {
            PresignInput::new(aux_pub, aux_priv, key_pub, key_priv).unwrap()
        })
        .collect::<Vec<_>>();

    // Benchmark presign
    let presign_identifier = Identifier::random(&mut rng);
    let (mut players, mut inboxes) =
        init_new_player_set(num_players, presign_identifier, presign_inputs);
    c.bench_function(&format!("Presign with {num_players} nodes"), |b| {
        b.iter(|| run_subprotocol::<PresignParticipant>(&mut players, &mut inboxes))
    });
}

fn criterion_benchmark(c: &mut Criterion) {
    run_benchmarks_for_given_size(c, 3);
    run_benchmarks_for_given_size(c, 6);
    run_benchmarks_for_given_size(c, 9);
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
