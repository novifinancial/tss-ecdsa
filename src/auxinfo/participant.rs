// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

use crate::auxinfo::info::AuxInfoPrivate;
use crate::auxinfo::info::AuxInfoPublic;
use crate::errors::Result;
use crate::messages::AuxinfoMessageType;
use crate::messages::{Message, MessageType};
use crate::paillier::PaillierDecryptionKey;
use crate::paillier::PaillierEncryptionKey;
use crate::parameters::PRIME_BITS;
use crate::protocol::ParticipantIdentifier;
use crate::storage::StorableType;
use crate::storage::Storage;
use crate::utils::process_ready_message;
use crate::zkp::setup::ZkSetupParameters;
use libpaillier::DecryptionKey;
use libpaillier::EncryptionKey;
use rand::prelude::IteratorRandom;
use rand::rngs::OsRng;
use rand::CryptoRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone)]
pub(crate) struct AuxinfoParticipant {
    /// A unique identifier for this participant
    id: ParticipantIdentifier,
    /// A list of all other participant identifiers participating in the protocol
    other_participant_ids: Vec<ParticipantIdentifier>,
    /// Local storage for this participant to store secrets
    storage: Storage,
}

impl AuxinfoParticipant {
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
            MessageType::Auxinfo(AuxinfoMessageType::Ready) => {
                let (mut messages, is_ready) = process_ready_message(
                    self.id,
                    &self.other_participant_ids,
                    &mut self.storage,
                    message,
                    StorableType::AuxInfoReady,
                )?;
                if is_ready {
                    let mut rng = OsRng;
                    let (auxinfo_private, auxinfo_public) = new_auxinfo(&mut rng, PRIME_BITS)?;
                    let auxinfo_public_bytes = serialize!(&auxinfo_public)?;

                    let more_messages: Vec<Message> = self
                        .other_participant_ids
                        .iter()
                        .map(|&other_participant_id| {
                            Message::new(
                                MessageType::Auxinfo(AuxinfoMessageType::Public),
                                message.id(),
                                self.id,
                                other_participant_id,
                                &auxinfo_public_bytes,
                            )
                        })
                        .collect();
                    messages.extend_from_slice(&more_messages);

                    main_storage.store(
                        StorableType::AuxInfoPrivate,
                        message.id(),
                        self.id,
                        &serialize!(&auxinfo_private)?,
                    )?;
                    main_storage.store(
                        StorableType::AuxInfoPublic,
                        message.id(),
                        self.id,
                        &auxinfo_public_bytes,
                    )?;
                }
                Ok(messages)
            }
            MessageType::Auxinfo(AuxinfoMessageType::Public) => {
                // First, verify the bytes of the public keyshare, and then
                // store it locally
                let message_bytes = serialize!(&AuxInfoPublic::from_message(message)?)?;

                main_storage.store(
                    StorableType::AuxInfoPublic,
                    message.id(),
                    message.from(),
                    &message_bytes,
                )?;

                Ok(vec![])
            }
            _ => {
                return bail!(
                    "Attempting to process a non-auxinfo message with an auxinfo participant"
                );
            }
        }
    }
}

fn new_auxinfo<R: RngCore + CryptoRng>(
    rng: &mut R,
    _prime_bits: usize,
) -> Result<(AuxInfoPrivate, AuxInfoPublic)> {
    // Pull in pre-generated safe primes from text file (not a safe operation!).
    // This is meant to save on the time needed to generate these primes, but
    // should not be done in a production environment!
    let safe_primes = crate::utils::get_safe_primes();
    let two_safe_primes = safe_primes.iter().choose_multiple(rng, 2);

    // FIXME: do proper safe prime generation
    //let p = BigNumber::safe_prime(prime_bits);
    //let q = BigNumber::safe_prime(prime_bits);

    let p = two_safe_primes[0].clone();
    let q = two_safe_primes[1].clone();

    let sk = PaillierDecryptionKey(
        DecryptionKey::with_safe_primes_unchecked(&p, &q)
            .ok_or_else(|| bail_context!("Could not generate decryption key"))?,
    );

    let pk = PaillierEncryptionKey(EncryptionKey::from(&sk.0));
    let params = ZkSetupParameters::gen_from_primes(rng, &(&p * &q), &p, &q)?;

    Ok((AuxInfoPrivate { sk }, AuxInfoPublic { pk, params }))
}
