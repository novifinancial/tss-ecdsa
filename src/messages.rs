// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

//! Contains the functions and definitions for dealing with messages that are
//! passed between participants

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
    /// Auxinfo messages
    Auxinfo(AuxinfoMessageType),
    /// Keygen messages
    Keygen(KeygenMessageType),
    /// Presign messages
    Presign(PresignMessageType),
    /// Broadcast messages
    Broadcast(BroadcastMessageType),
}

/// An enum consisting of all auxinfo message types
#[derive(Debug, Copy, Clone, PartialEq, Serialize, Deserialize)]
pub enum AuxinfoMessageType {
    /// Signals that auxinfo generation is ready
    Ready,
    /// Public auxinfo produced by auxinfo generation for a participant
    Public,
    /// A hash commitment to the public keyshare and associated proofs
    R1CommitHash,
    /// The information committed to in Round 1
    R2Decommit,
    /// A proof of knowledge of the discrete log of the value decommitted in Round 2
    R3Proof,
}

/// An enum consisting of all keygen message types
#[derive(Debug, Copy, Clone, PartialEq, Serialize, Deserialize)]
pub enum KeygenMessageType {
    /// Signals that keyshare generation is ready
    Ready,
    /// Public keyshare produced by keygen for a participant
    PublicKeyshare,
    /// A hash commitment to the public keyshare and associated proofs
    R1CommitHash,
    /// The information committed to in Round 1
    R2Decommit,
    /// A proof of knowledge of the discrete log of the value decommitted in Round 2
    R3Proof,
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

#[derive(Debug, Copy, Clone, PartialEq, Serialize, Deserialize)]
pub enum BroadcastMessageType {
    /// First round: sender sends their message to everyone
    Disperse,
    /// Second round: everyone reflects the message to everyone else
    Redisperse,
}

/// A message that can be posted to (and read from) the broadcast channel
#[derive(Debug, Clone, Display, Serialize, Deserialize)]
pub struct Message {
    /// The type of the message
    pub(crate) message_type: MessageType,
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
