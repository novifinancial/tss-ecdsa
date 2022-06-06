// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

use crate::errors::Result;
use crate::keygen::keyshare::KeySharePrivate;
use crate::keygen::keyshare::KeySharePublic;
use crate::messages::KeygenMessageType;
use crate::messages::{Message, MessageType};
use crate::protocol::ParticipantIdentifier;
use crate::storage::StorableType;
use crate::storage::Storage;
use crate::utils::{k256_order, process_ready_message};
use crate::CurvePoint;
use libpaillier::unknown_order::BigNumber;
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
                let (mut messages, is_ready) = process_ready_message(
                    self.id,
                    &self.other_participant_ids,
                    &mut self.storage,
                    message,
                    StorableType::KeygenReady,
                )?;

                if is_ready {
                    let (keyshare_private, keyshare_public) = new_keyshare()?;
                    let keyshare_public_bytes = serialize!(&keyshare_public)?;

                    // Publish public keyshare to all other participants on the channel
                    let more_messages: Vec<Message> = self
                        .other_participant_ids
                        .iter()
                        .map(|&other_participant_id| {
                            Message::new(
                                MessageType::Keygen(KeygenMessageType::PublicKeyshare),
                                message.id(),
                                self.id,
                                other_participant_id,
                                &keyshare_public_bytes,
                            )
                        })
                        .collect();
                    messages.extend_from_slice(&more_messages);

                    main_storage.store(
                        StorableType::PrivateKeyshare,
                        message.id(),
                        self.id,
                        &serialize!(&keyshare_private)?,
                    )?;
                    main_storage.store(
                        StorableType::PublicKeyshare,
                        message.id(),
                        self.id,
                        &serialize!(&keyshare_public)?,
                    )?;
                }
                Ok(messages)
            }
            MessageType::Keygen(KeygenMessageType::PublicKeyshare) => {
                // First, verify the bytes of the public keyshare, and then
                // store it locally
                let message_bytes = serialize!(&KeySharePublic::from_message(message)?)?;

                main_storage.store(
                    StorableType::PublicKeyshare,
                    message.id(),
                    message.from(),
                    &message_bytes,
                )?;

                Ok(vec![])
            }
            _ => {
                return bail!(
                    "Attempting to process a non-keygen message with a keygen participant"
                );
            }
        }
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
