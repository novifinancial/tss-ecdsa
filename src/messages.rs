// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

//! Contains the functions and definitions for dealing with messages that are
//! passed between participants

use crate::auxinfo::AuxInfoPublic;
use crate::errors::Result;
use crate::protocol::Identifier;
use crate::protocol::ParticipantIdentifier;
use displaydoc::Display;
use serde::{Deserialize, Serialize};

/////////////////
// Message API //
/////////////////

/// An enum consisting of all message types
#[derive(Debug, Copy, Clone, PartialEq, Serialize, Deserialize)]
pub enum MessageType {
    /// Signals that auxinfo generation is ready
    AuxInfoReady,
    /// The public auxinfo parameters for a participant
    AuxInfoPublic,
    /// Keygen messages
    Keygen(KeygenMessageType),
    /// Presign messages
    Presign(PresignMessageType),
}

/// An enum consisting of all keygen message types
#[derive(Debug, Copy, Clone, PartialEq, Serialize, Deserialize)]
pub enum KeygenMessageType {
    /// Signals that keyshare generation is ready
    Ready,
    /// Public keyshare produced by keygen for a participant
    PublicKeyshare,
}

/// An enum consisting of all presign message types
#[derive(Debug, Copy, Clone, PartialEq, Serialize, Deserialize)]
pub enum PresignMessageType {
    /// Signals that presigning is ready
    Ready,
    /// First round of presigning
    RoundOne,
    /// Second round of presigning
    RoundTwo,
    /// Third round of presigning
    RoundThree,
}

/// A message that can be posted to (and read from) the broadcast channel
#[derive(Debug, Clone, Display, Serialize, Deserialize)]
pub struct Message {
    /// The type of the message
    message_type: MessageType,
    /// The unique identifier corresponding to the object carried by the message
    identifier: Identifier,
    /// Which participant this message is coming from
    from: ParticipantIdentifier,
    /// Which participant this message is addressed to
    to: ParticipantIdentifier,
    /// The raw bytes for the message, which need to be verified.
    /// This should be a private member of the struct, so that
    /// we require consumers to call the verify() function in
    /// order to extract bytes
    pub(crate) unverified_bytes: Vec<u8>,
}

impl Message {
    /// Creates a new instance of [Message]
    pub fn new(
        message_type: MessageType,
        identifier: Identifier,
        from: ParticipantIdentifier,
        to: ParticipantIdentifier,
        unverified_bytes: &[u8],
    ) -> Self {
        Self {
            message_type,
            identifier,
            from,
            to,
            unverified_bytes: unverified_bytes.to_vec(),
        }
    }

    /// The message type associated with the message
    pub fn message_type(&self) -> MessageType {
        self.message_type
    }

    /// The identifier associated with the message
    pub fn id(&self) -> Identifier {
        self.identifier
    }

    /// The participant that sent this message
    pub fn from(&self) -> ParticipantIdentifier {
        self.from
    }

    /// That participant that should receive this message
    pub fn to(&self) -> ParticipantIdentifier {
        self.to
    }
}

/// This is where the verification logic happens when pulling messages off of
/// the wire
impl Message {
    pub(crate) fn validate_to_auxinfo_public(&self) -> Result<AuxInfoPublic> {
        if self.message_type != MessageType::AuxInfoPublic {
            return bail!("Wrong message type, expected MessageType::AuxInfoPublic");
        }
        let aux_info_public: AuxInfoPublic = deserialize!(&self.unverified_bytes)?;

        match aux_info_public.verify() {
            Ok(()) => Ok(aux_info_public),
            Err(e) => bail!("Failed to verify auxinfo public: {}", e),
        }
    }
}
