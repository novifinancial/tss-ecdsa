use crate::protocol::PartyIdentifier;
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
            Self::RoundTwoPrivate => write!(f, "RoundTwoPrivate"),
            Self::RoundTwoPublic => write!(f, "RoundTwoPublic"),
            Self::RoundThreePrivate => write!(f, "RoundThreePrivate"),
            Self::RoundThreePublic => write!(f, "RoundThreePublic"),
        }
    }
}

impl FromStr for StorableType {
    type Err = anyhow::Error;
    fn from_str(input: &str) -> Result<Self, Self::Err> {
        match input {
            "PrivateKeyshare" => Ok(Self::PrivateKeyshare),
            "PublicKeyshare" => Ok(Self::PublicKeyshare),
            "RoundOnePrivate" => Ok(Self::RoundOnePrivate),
            "RoundTwoPrivate" => Ok(Self::RoundTwoPrivate),
            "RoundTwoPublic" => Ok(Self::RoundTwoPublic),
            "RoundThreePrivate" => Ok(Self::RoundThreePrivate),
            "RoundThreePublic" => Ok(Self::RoundThreePublic),
            _ => Err(anyhow::Error::msg(format!(
                "Could not parse message type: {}",
                input
            ))),
        }
    }
}

/// A message that can be posted to (and read from) the broadcast channel
#[derive(Debug)]
pub(crate) struct Storable {
    pub(crate) storable_type: StorableType,
    // The party identifier that this storable is associated with
    pub(crate) associated_party_id: PartyIdentifier,
    pub(crate) bytes: Vec<u8>,
}

impl std::fmt::Display for Storable {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "storable_type:{},associated_party_id:{},bytes:{}",
            self.storable_type,
            self.associated_party_id,
            hex::encode(self.bytes.clone()),
        )
    }
}

impl FromStr for Storable {
    type Err = anyhow::Error;
    // Used for searching for storables in the per-party private storage
    fn from_str(input: &str) -> Result<Self, Self::Err> {
        lazy_static::lazy_static! {
            static ref RE: Regex = Regex::new(r"storable_type:([0-9a-zA-Z]+),associated_party_id:([0-9a-fA-F]+),bytes:([0-9a-fA-F]+)").unwrap();
        }
        if let Some(capture) = RE.captures_iter(input).next() {
            return Ok(Self {
                storable_type: StorableType::from_str(&capture[1].parse::<String>()?)?,
                associated_party_id: PartyIdentifier::from_str(&capture[2].parse::<String>()?)?,
                bytes: hex::decode(capture[3].parse::<String>()?)?,
            });
        }

        Err(anyhow::anyhow!(format!(
            "Could not parse Storable string: {}",
            input
        )))
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
    type Err = anyhow::Error;
    fn from_str(input: &str) -> Result<Self, Self::Err> {
        match input {
            "BeginKeyGeneration" => Ok(Self::BeginKeyGeneration),
            "PublicKeyshare" => Ok(Self::PublicKeyshare),
            "RoundOne" => Ok(Self::RoundOne),
            "RoundTwo" => Ok(Self::RoundTwo),
            "RoundThree" => Ok(Self::RoundThree),
            _ => Err(anyhow::Error::msg(format!(
                "Could not parse message type: {}",
                input
            ))),
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
    pub(crate) from: PartyIdentifier,
    pub(crate) to: PartyIdentifier,
    pub(crate) bytes: Vec<u8>,
}

impl Display for Message {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        write!(
            f,
            "message_type:{},from:{},to:{},bytes:{}",
            self.message_type,
            self.from,
            self.to,
            hex::encode(self.bytes.clone()),
        )
    }
}

impl FromStr for Message {
    type Err = anyhow::Error;
    fn from_str(input: &str) -> Result<Self, Self::Err> {
        let re = regex::Regex::new(MESSAGE_REGEX).unwrap();
        if let Some(capture) = re.captures_iter(input).next() {
            return Ok(Self {
                message_type: MessageType::from_str(&capture[1].parse::<String>()?)?,
                from: PartyIdentifier::from_str(&capture[2].parse::<String>()?)?,
                to: PartyIdentifier::from_str(&capture[3].parse::<String>()?)?,
                bytes: hex::decode(capture[4].parse::<String>()?)?,
            });
        }

        Err(anyhow::Error::msg(format!(
            "Could not parse Message string: {}",
            input
        )))
    }
}
