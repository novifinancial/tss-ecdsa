// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

use crate::errors::Result;
use crate::messages::{BroadcastMessageType, KeygenMessageType, Message, MessageType};
use crate::ParticipantIdentifier;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub(crate) struct BroadcastData {
    pub(crate) leader: ParticipantIdentifier,
    pub(crate) tag: String,
    pub(crate) message_type: MessageType,
    pub(crate) data: Vec<u8>,
}

impl BroadcastData {
    pub(crate) fn from_message(message: &Message) -> Result<Self> {
        if message.message_type()
            != MessageType::Keygen(KeygenMessageType::Broadcast(BroadcastMessageType::Disperse))
            && message.message_type()
                != MessageType::Keygen(KeygenMessageType::Broadcast(
                    BroadcastMessageType::Redisperse,
                ))
        {
            return bail!("Wrong message type, expected MessageType::Keygen(KeygenMessageType::Broadcast(BroadcastMessageType::Disperse) or ...Redisperse");
        }
        let broadcast_data: BroadcastData = deserialize!(&message.unverified_bytes)?;
        Ok(broadcast_data)
    }
}
