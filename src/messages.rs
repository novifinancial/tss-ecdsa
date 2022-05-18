// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use crate::auxinfo::AuxInfoPublic;
use crate::errors::Result;
use crate::keygen::KeySharePublic;
use crate::protocol::Identifier;
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
    AuxInfoPublic,
    BeginKeyGeneration,
    BeginAuxInfoGeneration,
    BeginPresign,
    PublicKeyshare,
    PresignRoundOne,
    PresignRoundTwo,
    PresignRoundThree,
}

/// A message that can be posted to (and read from) the broadcast channel
#[derive(Debug, Display, Serialize, Deserialize)]
pub struct Message {
    pub(crate) message_type: MessageType,
    pub(crate) identifier: Identifier,
    pub(crate) from: ParticipantIdentifier,
    pub(crate) to: ParticipantIdentifier,
    /// The raw bytes for the message, which need to be verified.
    /// This should be a private member of the struct, so that
    /// we require consumers to call the verify() function in
    /// order to extract bytes
    unverified_bytes: Vec<u8>,
}

impl Message {
    pub(crate) fn new(
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

    pub(crate) fn validate_to_keyshare_public(&self) -> Result<KeySharePublic> {
        if self.message_type != MessageType::PublicKeyshare {
            return bail!("Wrong message type, expected MessageType::PublicKeyshare");
        }
        let keyshare_public: KeySharePublic = deserialize!(&self.unverified_bytes)?;

        match keyshare_public.verify() {
            Ok(()) => Ok(keyshare_public),
            Err(e) => bail!("Failed to verify keyshare public: {}", e),
        }
    }

    pub(crate) fn validate_to_round_one_public(
        &self,
        receiver_keygen_public: &AuxInfoPublic,
        sender_keygen_public: &AuxInfoPublic,
    ) -> Result<RoundOnePublic> {
        if self.message_type != MessageType::PresignRoundOne {
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
        receiver_auxinfo_public: &AuxInfoPublic,
        sender_auxinfo_public: &AuxInfoPublic,
        sender_keyshare_public: &KeySharePublic,
        receiver_r1_private: &RoundOnePrivate,
        sender_r1_public: &RoundOnePublic,
    ) -> Result<RoundTwoPublic> {
        if self.message_type != MessageType::PresignRoundTwo {
            return bail!("Wrong message type, expected MessageType::RoundTwo");
        }
        let round_two_public: RoundTwoPublic = deserialize!(&self.unverified_bytes)?;

        match round_two_public.verify(
            receiver_auxinfo_public,
            sender_auxinfo_public,
            sender_keyshare_public,
            receiver_r1_private,
            sender_r1_public,
        ) {
            Ok(()) => Ok(round_two_public),
            Err(e) => bail!("Failed to verify round two public: {}", e),
        }
    }

    pub(crate) fn validate_to_round_three_public(
        &self,
        receiver_auxinfo_public: &AuxInfoPublic,
        sender_auxinfo_public: &AuxInfoPublic,
        sender_r1_public: &RoundOnePublic,
    ) -> Result<RoundThreePublic> {
        if self.message_type != MessageType::PresignRoundThree {
            return bail!("Wrong message type, expected MessageType::RoundThree");
        }

        let round_three_public: RoundThreePublic = deserialize!(&self.unverified_bytes)?;

        match round_three_public.verify(
            receiver_auxinfo_public,
            sender_auxinfo_public,
            sender_r1_public,
        ) {
            Ok(()) => Ok(round_three_public),
            Err(e) => bail!("Failed to verify round three public: {}", e),
        }
    }
}
