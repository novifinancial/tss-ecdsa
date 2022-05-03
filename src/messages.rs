// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use crate::key::KeygenPublic;
use crate::protocol::ParticipantIdentifier;
use crate::round_one::Private as RoundOnePrivate;
use crate::round_one::Public as RoundOnePublic;
use crate::round_three::Public as RoundThreePublic;
use crate::round_two::Public as RoundTwoPublic;
use anyhow::Error;
use regex::Regex;
use std::fmt::{Debug, Display, Formatter};
use std::str::FromStr;

/////////////////////////
// Private Storage API //
/////////////////////////

#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub(crate) enum StorableType {
    PrivateKeyshare,
    PublicKeyshare,
    RoundOnePrivate,
    RoundOnePublic,
    RoundTwoPrivate,
    RoundTwoPublic,
    RoundThreePrivate,
    RoundThreePublic,
}

impl std::fmt::Display for StorableType {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Self::PrivateKeyshare => write!(f, "PrivateKeyshare"),
            Self::PublicKeyshare => write!(f, "PublicKeyshare"),
            Self::RoundOnePrivate => write!(f, "RoundOnePrivate"),
            Self::RoundOnePublic => write!(f, "RoundOnePublic"),
            Self::RoundTwoPrivate => write!(f, "RoundTwoPrivate"),
            Self::RoundTwoPublic => write!(f, "RoundTwoPublic"),
            Self::RoundThreePrivate => write!(f, "RoundThreePrivate"),
            Self::RoundThreePublic => write!(f, "RoundThreePublic"),
        }
    }
}

impl FromStr for StorableType {
    type Err = Error;
    fn from_str(input: &str) -> Result<Self, Self::Err> {
        match input {
            "PrivateKeyshare" => Ok(Self::PrivateKeyshare),
            "PublicKeyshare" => Ok(Self::PublicKeyshare),
            "RoundOnePrivate" => Ok(Self::RoundOnePrivate),
            "RoundOnePublic" => Ok(Self::RoundOnePublic),
            "RoundTwoPrivate" => Ok(Self::RoundTwoPrivate),
            "RoundTwoPublic" => Ok(Self::RoundTwoPublic),
            "RoundThreePrivate" => Ok(Self::RoundThreePrivate),
            "RoundThreePublic" => Ok(Self::RoundThreePublic),
            _ => bail!("Could not parse message type: {}", input),
        }
    }
}

/// A message that can be posted to (and read from) the broadcast channel
#[derive(Debug)]
pub(crate) struct Storable {
    pub(crate) storable_type: StorableType,
    // The participant identifier that this storable is associated with
    pub(crate) associated_participant_id: ParticipantIdentifier,
    pub(crate) bytes: Vec<u8>,
}

impl std::fmt::Display for Storable {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "storable_type:{},associated_participant_id:{},bytes:{}",
            self.storable_type,
            self.associated_participant_id,
            hex::encode(self.bytes.clone()),
        )
    }
}

impl FromStr for Storable {
    type Err = Error;
    // Used for searching for storables in the per-participant private storage
    fn from_str(input: &str) -> Result<Self, Self::Err> {
        lazy_static::lazy_static! {
            static ref RE: Regex = Regex::new(r"storable_type:([0-9a-zA-Z]+),associated_participant_id:([0-9a-fA-F]+),bytes:([0-9a-fA-F]+)").unwrap();
        }
        if let Some(capture) = RE.captures_iter(input).next() {
            return Ok(Self {
                storable_type: StorableType::from_str(&capture[1].parse::<String>()?)?,
                associated_participant_id: ParticipantIdentifier::from_str(
                    &capture[2].parse::<String>()?,
                )?,
                bytes: hex::decode(capture[3].parse::<String>()?)?,
            });
        }

        bail!("Could not parse Storable string: {}", input)
    }
}

/////////////////
// Message API //
/////////////////

#[derive(Debug, PartialEq)]
pub(crate) enum MessageType {
    BeginKeyGeneration,
    PublicKeyshare,
    RoundOne,
    RoundTwo,
    RoundThree,
}

impl std::fmt::Display for MessageType {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            MessageType::BeginKeyGeneration => write!(f, "BeginKeyGeneration"),
            MessageType::PublicKeyshare => write!(f, "PublicKeyshare"),
            MessageType::RoundOne => write!(f, "RoundOne"),
            MessageType::RoundTwo => write!(f, "RoundTwo"),
            MessageType::RoundThree => write!(f, "RoundThree"),
        }
    }
}

impl FromStr for MessageType {
    type Err = Error;
    fn from_str(input: &str) -> Result<Self, Self::Err> {
        match input {
            "BeginKeyGeneration" => Ok(Self::BeginKeyGeneration),
            "PublicKeyshare" => Ok(Self::PublicKeyshare),
            "RoundOne" => Ok(Self::RoundOne),
            "RoundTwo" => Ok(Self::RoundTwo),
            "RoundThree" => Ok(Self::RoundThree),
            _ => bail!("Could not parse message type: {}", input),
        }
    }
}

// Used for searching for messages in the broadcast channel
const MESSAGE_REGEX: &str =
    r"message_type:([0-9a-zA-Z]+),from:([0-9a-fA-F]*),to:([0-9a-fA-F]*),bytes:([0-9a-fA-F]*)";

/// A message that can be posted to (and read from) the broadcast channel
#[derive(Debug)]
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
    pub(crate) fn validate_to_keygen_public(&self) -> Result<KeygenPublic, Error> {
        if self.message_type != MessageType::PublicKeyshare {
            bail!("Wrong message type, expected MessageType::PublicKeyshare");
        }
        let keygen_public = KeygenPublic::from_slice(&self.unverified_bytes)?;

        match keygen_public.verify() {
            true => Ok(keygen_public),
            false => bail!("Failed to verify keygen public"),
        }
    }

    pub(crate) fn validate_to_round_one_public(
        &self,
        receiver_keygen_public: &KeygenPublic,
        sender_keygen_public: &KeygenPublic,
    ) -> Result<RoundOnePublic, Error> {
        if self.message_type != MessageType::RoundOne {
            bail!("Wrong message type, expected MessageType::RoundOne");
        }
        let round_one_public = RoundOnePublic::from_slice(&self.unverified_bytes)?;

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
    ) -> Result<RoundTwoPublic, Error> {
        if self.message_type != MessageType::RoundTwo {
            bail!("Wrong message type, expected MessageType::RoundTwo");
        }
        let round_two_public = RoundTwoPublic::from_slice(&self.unverified_bytes)?;

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
    ) -> Result<RoundThreePublic, Error> {
        if self.message_type != MessageType::RoundThree {
            bail!("Wrong message type, expected MessageType::RoundThree");
        }

        let round_three_public = RoundThreePublic::from_slice(&self.unverified_bytes)?;

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

impl Display for Message {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        write!(
            f,
            "message_type:{},from:{},to:{},bytes:{}",
            self.message_type,
            self.from,
            self.to,
            hex::encode(self.unverified_bytes.clone()),
        )
    }
}

impl FromStr for Message {
    type Err = Error;
    fn from_str(input: &str) -> Result<Self, Self::Err> {
        let re = regex::Regex::new(MESSAGE_REGEX).unwrap();
        if let Some(capture) = re.captures_iter(input).next() {
            return Ok(Self {
                message_type: MessageType::from_str(&capture[1].parse::<String>()?)?,
                from: ParticipantIdentifier::from_str(&capture[2].parse::<String>()?)?,
                to: ParticipantIdentifier::from_str(&capture[3].parse::<String>()?)?,
                unverified_bytes: hex::decode(capture[4].parse::<String>()?)?,
            });
        }

        Err(Error::msg(format!(
            "Could not parse Message string: {}",
            input
        )))
    }
}
