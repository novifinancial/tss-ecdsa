// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use crate::errors::Result;
use crate::key::KeygenPublic;
use crate::protocol::ParticipantIdentifier;
use crate::round_one::Private as RoundOnePrivate;
use crate::round_one::Public as RoundOnePublic;
use crate::round_three::Public as RoundThreePublic;
use crate::round_two::Public as RoundTwoPublic;
use displaydoc::Display;
use serde::{Deserialize, Serialize};

/////////////////
// Message API //
/////////////////

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub(crate) enum MessageType {
    BeginKeyGeneration,
    PublicKeyshare,
    RoundOne,
    RoundTwo,
    RoundThree,
}

/// A message that can be posted to (and read from) the broadcast channel
#[derive(Debug, Display, Serialize, Deserialize)]
pub struct Message {
    pub(crate) message_type: MessageType,
    pub(crate) from: ParticipantIdentifier,
    pub(crate) to: ParticipantIdentifier,
    /// The raw bytes for the message, which need to be verified.
    /// This should be a private member of the struct, so that
    /// we require consumers to call the verify() function in
    /// order to extract bytes
    pub(crate) unverified_bytes: Vec<u8>,
}

/// This is where the verification logic happens when pulling messages off of
/// the wire
impl Message {
    pub(crate) fn validate_to_keygen_public(&self) -> Result<KeygenPublic> {
        if self.message_type != MessageType::PublicKeyshare {
            return bail!("Wrong message type, expected MessageType::PublicKeyshare");
        }
        let keygen_public: KeygenPublic = deserialize!(&self.unverified_bytes)?;

        match keygen_public.verify() {
            Ok(()) => Ok(keygen_public),
            Err(e) => bail!("Failed to verify keygen public: {}", e),
        }
    }

    pub(crate) fn validate_to_round_one_public(
        &self,
        receiver_keygen_public: &KeygenPublic,
        sender_keygen_public: &KeygenPublic,
    ) -> Result<RoundOnePublic> {
        if self.message_type != MessageType::RoundOne {
            return bail!("Wrong message type, expected MessageType::RoundOne");
        }
        let round_one_public: RoundOnePublic = deserialize!(&self.unverified_bytes)?;

        match round_one_public.verify(&receiver_keygen_public.params, sender_keygen_public.pk.n()) {
            Ok(()) => Ok(round_one_public),
            Err(e) => bail!("Failed to verify round one public: {}", e),
        }
    }

    pub(crate) fn validate_to_round_two_public(
        &self,
        receiver_keygen_public: &KeygenPublic,
        sender_keygen_public: &KeygenPublic,
        receiver_r1_private: &RoundOnePrivate,
        sender_r1_public: &RoundOnePublic,
    ) -> Result<RoundTwoPublic> {
        if self.message_type != MessageType::RoundTwo {
            return bail!("Wrong message type, expected MessageType::RoundTwo");
        }
        let round_two_public: RoundTwoPublic = deserialize!(&self.unverified_bytes)?;

        match round_two_public.verify(
            receiver_keygen_public,
            sender_keygen_public,
            receiver_r1_private,
            sender_r1_public,
        ) {
            Ok(()) => Ok(round_two_public),
            Err(e) => bail!("Failed to verify round two public: {}", e),
        }
    }

    pub(crate) fn validate_to_round_three_public(
        &self,
        receiver_keygen_public: &KeygenPublic,
        sender_keygen_public: &KeygenPublic,
        sender_r1_public: &RoundOnePublic,
    ) -> Result<RoundThreePublic> {
        if self.message_type != MessageType::RoundThree {
            return bail!("Wrong message type, expected MessageType::RoundThree");
        }

        let round_three_public: RoundThreePublic = deserialize!(&self.unverified_bytes)?;

        match round_three_public.verify(
            receiver_keygen_public,
            sender_keygen_public,
            sender_r1_public,
        ) {
            Ok(()) => Ok(round_three_public),
            Err(e) => bail!("Failed to verify round three public: {}", e),
        }
    }
}
