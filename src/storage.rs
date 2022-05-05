// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use crate::protocol::ParticipantIdentifier;
use anyhow::Error;
use regex::Regex;
use std::fmt::Debug;
use std::hash::Hash;
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

#[derive(Debug)]
pub(crate) struct StorableKey {
    pub(crate) storable_type: StorableType,
    // The participant identifier that this storable is associated with
    pub(crate) associated_participant_id: ParticipantIdentifier,
}

impl std::fmt::Display for StorableKey {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "storable_type:{},associated_participant_id:{}",
            self.storable_type, self.associated_participant_id,
        )
    }
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
