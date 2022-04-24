use crate::key::{KeyInit, KeyShare, KeygenPrivate, KeygenPublic};
use crate::messages::*;
use k256::Secp256k1;
use rand::prelude::IteratorRandom;
use rand::{CryptoRng, Rng, RngCore};
use std::collections::HashMap;
use std::fmt::{Debug, Display, Formatter};
use std::str::FromStr;

///////////////
// Party API //
///////////////

/// Each party has an inbox which can contain messages.
pub struct Party {
    /// A unique identifier for this party
    id: PartyIdentifier,
    /// A list of all other party identifiers participating in the protocol
    other_party_ids: Vec<PartyIdentifier>,
    /// An inbox for this party containing messages sent from other parties
    inbox: Vec<String>,
    /// Local storage for this party to store secrets
    storage: HashMap<(StorableType, PartyIdentifier), String>,
    /// Contains the private and public keyshares that don't get rotated
    key_init: Option<KeyInit>,
    /// The presign record, starting out as None, but gets populated after
    /// the presign phase completes
    presign_record: Option<crate::PresignRecord>,
}

impl Party {
    /// Instantiate a new quorum of parties of a specified size. Random identifiers
    /// are selected
    pub fn new_quorum<R: RngCore + CryptoRng>(
        quorum_size: usize,
        rng: &mut R,
    ) -> Result<Vec<Self>, anyhow::Error> {
        let mut party_ids = vec![];
        for _ in 0..quorum_size {
            party_ids.push(PartyIdentifier::random(rng));
        }
        let parties = party_ids
            .iter()
            .map(|party_id| {
                // Filter out current party id from list of other ids
                let mut other_ids = vec![];
                for id in party_ids.iter() {
                    if id.clone() != party_id.clone() {
                        other_ids.push(id.clone());
                    }
                }

                Party {
                    id: party_id.clone(),
                    other_party_ids: other_ids,
                    // Initialize a single message for begin key generation in each
                    // party's inbox
                    inbox: vec![(Message {
                        message_type: MessageType::BeginKeyGeneration,
                        from: PartyIdentifier("".to_string()), // No "from" for this message
                        to: PartyIdentifier("".to_string()),   // No "to" for this message
                        bytes: vec![],
                    })
                    .to_string()],
                    storage: HashMap::new(),
                    key_init: None,
                    presign_record: None,
                }
            })
            .collect();
        Ok(parties)
    }

    /// Pulls the first message from the party's inbox, and then potentially
    /// outputs a bunch of messages that need to be delivered to other parties'
    /// inboxes.
    pub fn process_one<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
    ) -> Result<Vec<Message>, anyhow::Error> {
        let message = Message::from_str(&self.inbox.remove(0))?;

        println!(
            "processing party: {}, with message type: {}",
            &self.id.0[0..4],
            &message.message_type
        );

        match message.message_type {
            MessageType::BeginKeyGeneration => self.do_keygen(rng),
            MessageType::PublicKeyshare => {
                // First, store the public keyshare locally
                self.store(Storable {
                    associated_party_id: message.from,
                    storable_type: StorableType::PublicKeyshare,
                    bytes: message.bytes,
                });

                // Check if storage has all of the other parties' public keyshares,
                // and call do_round_one() if so
                match self.has_collected_all_of_others(StorableType::PublicKeyshare)? {
                    true => self.do_round_one(),
                    false => Ok(vec![]),
                }
            }
            MessageType::RoundOne => self.do_round_two(&message),
            MessageType::RoundTwo => {
                // First, store the round two value locally
                self.store(Storable {
                    storable_type: StorableType::RoundTwoPublic,
                    associated_party_id: message.from,
                    bytes: message.bytes,
                });

                // Since we are in round 2, it should certainly be the case that all
                // public keyshares for other parties have been stored, since
                // this was a requirement to proceed for round 1.
                assert!(self.has_collected_all_of_others(StorableType::PublicKeyshare)?);

                // Check if storage has all of the other parties' round two values (both
                // private and public), and call do_round_three() if so
                match self.has_collected_all_of_others(StorableType::RoundTwoPrivate)?
                    && self.has_collected_all_of_others(StorableType::RoundTwoPublic)?
                {
                    true => self.do_round_three(),
                    false => Ok(vec![]),
                }
            }
            MessageType::RoundThree => {
                // First, store the round three value locally
                self.store(Storable {
                    storable_type: StorableType::RoundThreePublic,
                    associated_party_id: message.from,
                    bytes: message.bytes,
                });

                if self.has_collected_all_of_others(StorableType::RoundThreePublic)? {
                    self.do_presign_finish()?;
                }

                // No messages to return
                Ok(vec![])
            }
        }
    }

    /// Key Init
    ///
    /// Produces the private x and public X shares corresponding to the actual ECDSA key
    pub fn do_init<R: RngCore + CryptoRng>(&mut self, rng: &mut R) -> Result<(), anyhow::Error> {
        if self.key_init.is_some() {
            return Err(anyhow::anyhow!(
                "Attempting to initialize key shares when they were already initialized"
            ));
        }
        self.key_init = Some(KeyInit::new(rng));
        Ok(())
    }

    /// Key Generation
    ///
    /// During keygen, each party produces and stores their own secret values, and then
    /// publishes the same public component to every other party.
    fn do_keygen<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
    ) -> Result<Vec<Message>, anyhow::Error> {
        // Pull in pre-generated safe primes from text file (not a safe operation!).
        // This is meant to save on the time needed to generate these primes, but
        // should not be done in a production environment!
        let safe_primes = crate::get_safe_primes();
        let two_safe_primes = safe_primes.iter().choose_multiple(rng, 2);

        let keyshare = match self.key_init.clone() {
            Some(key_init) => Ok(KeyShare::from_safe_primes_and_init(
                rng,
                two_safe_primes[0],
                two_safe_primes[1],
                &key_init,
            )),
            None => Err(anyhow::anyhow!(
                "Cannot do keygen before calling init on key shares"
            )),
        }?;

        let public_keyshare_bytes = keyshare.public.to_bytes()?;

        // Store private and public keyshares locally
        self.store(Storable {
            storable_type: StorableType::PrivateKeyshare,
            associated_party_id: self.id.clone(),
            bytes: keyshare.private.to_bytes()?,
        });
        self.store(Storable {
            storable_type: StorableType::PublicKeyshare,
            associated_party_id: self.id.clone(),
            bytes: public_keyshare_bytes.clone(),
        });

        // Publish public keyshare to all other parties on the channel
        Ok(self
            .other_party_ids
            .iter()
            .map(|other_party_id| Message {
                message_type: MessageType::PublicKeyshare,
                from: self.id.clone(),
                to: other_party_id.clone(),
                bytes: public_keyshare_bytes.clone(),
            })
            .collect())
    }

    /// Presign: Round One
    ///
    /// During round one, each party produces and stores their own secret values, and then
    /// stores a round one secret, and publishes a unique public component to every other party.
    ///
    /// This can only be run after all parties have finished with key generation.
    fn do_round_one(&mut self) -> Result<Vec<Message>, anyhow::Error> {
        // Reconstruct keyshare and other parties' public keyshares from local storage
        let keyshare = self.get_keyshare()?;
        let other_public_keyshares = self.get_other_parties_public_keyshares()?;

        let keyshares_list: Vec<Option<KeygenPublic>> = other_public_keyshares
            .values()
            .map(|x| Some(x.clone()))
            .collect();

        // Run Round One
        let crate::round_one::PairWithMultiplePublics { private, publics } =
            keyshare.round_one(&keyshares_list)?;

        // Store private r1 value locally
        self.store(Storable {
            storable_type: StorableType::RoundOnePrivate,
            associated_party_id: self.id.clone(),
            bytes: private.to_bytes()?,
        });

        // Publish public r1 to all other parties on the channel
        let mut ret_messages = vec![];
        #[allow(clippy::needless_range_loop)]
        for i in 0..self.other_party_ids.len() {
            match &publics[i] {
                Some(public) => {
                    ret_messages.push(Message {
                        message_type: MessageType::RoundOne,
                        from: self.id.clone(),
                        to: self.other_party_ids[i].clone(),
                        bytes: public.to_bytes()?,
                    });
                }
                None => (),
            };
        }

        Ok(ret_messages)
    }

    /// Presign: Round Two
    ///
    /// During round two, each party retrieves the public keyshares for each other party from the
    /// key generation phase, the round 1 public values from each other party, its own round 1 private
    /// value, and its own round one keyshare from key generation, and produces per-party
    /// round 2 public and private values.
    ///
    /// This can be run as soon as each round one message to this party has been published.
    /// These round two messages are returned in response to the sender, without having to
    /// rely on any other round one messages from other parties aside from the sender.
    fn do_round_two(&mut self, message: &Message) -> Result<Vec<Message>, anyhow::Error> {
        // Reconstruct keyshare and other parties' public keyshares from local storage
        let keyshare = self.get_keyshare()?;
        let other_public_keyshares = self.get_other_parties_public_keyshares()?;

        assert_eq!(message.to, self.id);

        // Find the keyshare corresponding to the "from" party
        let keyshare_from = other_public_keyshares.get(&message.from).ok_or_else(|| {
            anyhow::anyhow!("Could not find corresponding public keyshare for party in round 2")
        })?;

        // Get this party's round 1 private value
        let r1_priv = crate::round_one::Private::from_slice(
            &self
                .retrieve(StorableType::RoundOnePrivate, &message.to, false)?
                .bytes,
        )?;

        let crate::round_two::Pair {
            private: r2_priv_ij,
            public: r2_pub_ij,
        } = keyshare.round_two(
            keyshare_from,
            &r1_priv,
            &crate::round_one::Public::from_slice(&message.bytes)?,
        );

        // Store the private value for this round 2 pair
        self.store(Storable {
            storable_type: StorableType::RoundTwoPrivate,
            associated_party_id: message.from.clone(),
            bytes: r2_priv_ij.to_bytes()?,
        });

        // Only a single message to be output here
        let message = Message {
            message_type: MessageType::RoundTwo,
            from: self.id.clone(),
            to: message.from.clone(), // This is a essentially response to that sender
            bytes: r2_pub_ij.to_bytes()?,
        };
        Ok(vec![message])
    }

    /// Presign: Round Three
    ///
    /// During round three, to process all round 3 messages from a sender, the party
    /// must first wait for round 2 to be completely finished for all parties.
    /// Then, the party retrieves:
    /// - all parties' public keyshares,
    /// - its own round 1 private value,
    /// - all round 2 per-party private values,
    /// - all round 2 per-party public values,
    ///
    /// and produces a set of per-party round 3 public values and one private value.
    ///
    /// Each party is only going to run round three once.
    fn do_round_three(&mut self) -> Result<Vec<Message>, anyhow::Error> {
        // Reconstruct keyshare from local storage
        let keyshare = self.get_keyshare()?;

        let round_three_hashmap = self.get_other_parties_round_three_values()?;
        let round_three_values: Vec<_> = round_three_hashmap.values().collect();

        // Get this party's round 1 private value
        let r1_priv = crate::round_one::Private::from_slice(
            &self
                .retrieve(StorableType::RoundOnePrivate, &self.id.clone(), false)?
                .bytes,
        )?;

        let crate::round_three::PairWithMultiplePublics {
            private: r3_priv,
            publics,
        } = keyshare.round_three(
            &round_three_values
                .iter()
                .map(|r3v| Some(r3v.keygen_public.clone()))
                .collect::<Vec<_>>(),
            &r1_priv,
            &round_three_values
                .iter()
                .map(|r3v| Some(r3v.round_two_private.clone()))
                .collect::<Vec<_>>(),
            &round_three_values
                .iter()
                .map(|r3v| Some(r3v.round_two_public.clone()))
                .collect::<Vec<_>>(),
        );

        // Store round 3 private value
        self.store(Storable {
            storable_type: StorableType::RoundThreePrivate,
            associated_party_id: self.id.clone(),
            bytes: r3_priv.to_bytes()?,
        });

        // Publish public r3 values to all other parties on the channel
        let mut ret_messages = vec![];
        for i in 0..round_three_values.len() {
            match &publics[i] {
                Some(public) => {
                    ret_messages.push(Message {
                        message_type: MessageType::RoundThree,
                        from: self.id.clone(),
                        to: round_three_values[i].party_id.clone(),
                        bytes: public.to_bytes()?,
                    });
                }
                None => (),
            };
        }

        Ok(ret_messages)
    }

    /// Presign: Finish
    ///
    /// In this step, the party simply collects all r3 public values and its r3
    /// private value, and assembles them into a PresignRecord.
    fn do_presign_finish(&mut self) -> Result<(), anyhow::Error> {
        let r3_pubs = self.get_other_parties_round_three_publics()?;

        // Get this party's round 3 private value
        let r3_private = crate::round_three::Private::from_slice(
            &self
                .retrieve(StorableType::RoundThreePrivate, &self.id.clone(), false)?
                .bytes,
        )?;

        self.presign_record = Some(
            crate::RecordPair {
                private: r3_private,
                public: r3_pubs,
            }
            .into(),
        );

        Ok(())
    }

    /// Consumer can use this function to "give" a message to this party
    pub fn accept_message(&mut self, message: &Message) -> Result<(), anyhow::Error> {
        if message.to != self.id {
            return Err(anyhow::Error::msg(format!(
                "Attempting to deliver to recipient {} the message:\n {}",
                self.id, message,
            )));
        }

        self.inbox.push(message.to_string());

        Ok(())
    }

    /// Caller can use this to check if the party is ready to issue a signature
    /// (meaning that the presigning phase has completed)
    pub fn is_ready_to_sign(&self) -> Result<bool, anyhow::Error> {
        if self.presign_record.is_some() {
            return Ok(true);
        }
        Ok(false)
    }

    pub fn has_messages(&self) -> bool {
        !self.inbox.is_empty()
    }

    pub fn get_public_share(&self) -> Result<k256::ProjectivePoint, anyhow::Error> {
        match &self.key_init {
            Some(key_init) => Ok(key_init.X),
            None => Err(anyhow::anyhow!(
                "Need to call init first before trying to get public share"
            )),
        }
    }

    /// If presign record is populated, then this party is ready to issue
    /// a signature
    pub fn sign(&mut self, digest: sha2::Sha256) -> Result<SignatureShare, anyhow::Error> {
        match &self.presign_record {
            Some(record) => {
                let (r, s) = record.sign(digest);
                let ret = SignatureShare { r: Some(r), s };

                // Clear the presign record after being used once
                self.presign_record = None;

                Ok(ret)
            }
            None => Err(anyhow::anyhow!("No presign record, not ready to sign yet")),
        }
    }

    //////////////////////
    // Helper functions //
    //////////////////////

    fn store(&mut self, storable: Storable) {
        let val = storable.to_string();
        self.storage
            .insert((storable.storable_type, storable.associated_party_id), val);
    }

    fn retrieve(
        &mut self,
        storable_type: StorableType,
        associated_party_id: &PartyIdentifier,
        should_delete: bool,
    ) -> Result<Storable, anyhow::Error> {
        let key = (storable_type.clone(), associated_party_id.clone());
        let ret = Storable::from_str(self.storage.get(&key).ok_or_else(|| {
            anyhow::anyhow!("Could not find {} when getting from storage", storable_type)
        })?)?;

        if should_delete {
            self.storage.remove(&key).ok_or_else(|| {
                anyhow::anyhow!(
                    "Could not find {} when removing from storage",
                    storable_type
                )
            })?;
        }

        Ok(ret)
    }

    fn get_keyshare(&mut self) -> Result<KeyShare, anyhow::Error> {
        // Reconstruct keyshare from local storage
        let id = self.id.clone();
        let keyshare = KeyShare::from(
            KeygenPublic::from_slice(
                &self
                    .retrieve(StorableType::PublicKeyshare, &id, false)?
                    .bytes,
            )?,
            KeygenPrivate::from_slice(
                &self
                    .retrieve(StorableType::PrivateKeyshare, &id, false)?
                    .bytes,
            )?,
        );
        Ok(keyshare)
    }

    /// Aggregate the other parties' public keyshares from storage. But don't remove them
    /// from storage.
    ///
    /// This returns a HashMap with the key as the party id and the value as the KeygenPublic
    fn get_other_parties_public_keyshares(
        &mut self,
    ) -> Result<HashMap<PartyIdentifier, KeygenPublic>, anyhow::Error> {
        if !self.has_collected_all_of_others(StorableType::PublicKeyshare)? {
            return Err(anyhow::anyhow!(
                "Not ready to get other parties public keyshares just yet!"
            ));
        }

        let mut hm = HashMap::new();
        for other_party_id in self.other_party_ids.clone() {
            let val = self.retrieve(StorableType::PublicKeyshare, &other_party_id, false)?;
            hm.insert(other_party_id, KeygenPublic::from_slice(val.bytes)?);
        }
        Ok(hm)
    }

    /// Aggregate the other parties' round three public values from storage. But don't remove them
    /// from storage.
    ///
    /// This returns a Vec with the values
    fn get_other_parties_round_three_publics(
        &mut self,
    ) -> Result<Vec<crate::round_three::Public>, anyhow::Error> {
        if !self.has_collected_all_of_others(StorableType::RoundThreePublic)? {
            return Err(anyhow::anyhow!(
                "Not ready to get other parties round three publics just yet!"
            ));
        }

        let mut ret_vec = vec![];
        for other_party_id in self.other_party_ids.clone() {
            let val = self.retrieve(StorableType::RoundThreePublic, &other_party_id, false)?;
            ret_vec.push(crate::round_three::Public::from_slice(val.bytes)?);
        }
        Ok(ret_vec)
    }

    /// Aggregate the other parties' values needed for round three from storage. This includes:
    /// - public keyshares
    /// - round two private values
    /// - round two public values
    ///
    /// This returns a HashMap with the key as the party id and these values being mapped
    fn get_other_parties_round_three_values(
        &mut self,
    ) -> Result<HashMap<PartyIdentifier, RoundThreeValue>, anyhow::Error> {
        if !self.has_collected_all_of_others(StorableType::PublicKeyshare)?
            || !self.has_collected_all_of_others(StorableType::RoundTwoPrivate)?
            || !self.has_collected_all_of_others(StorableType::RoundTwoPublic)?
        {
            return Err(anyhow::anyhow!(
                "Not ready to get other parties round three values just yet!"
            ));
        }

        let mut hm = HashMap::new();
        for other_party_id in self.other_party_ids.clone() {
            let public_keyshare =
                self.retrieve(StorableType::PublicKeyshare, &other_party_id, false)?;
            let round_two_private =
                self.retrieve(StorableType::RoundTwoPrivate, &other_party_id, false)?;
            let round_two_public =
                self.retrieve(StorableType::RoundTwoPublic, &other_party_id, false)?;
            hm.insert(
                other_party_id.clone(),
                RoundThreeValue {
                    party_id: other_party_id.clone(),
                    keygen_public: KeygenPublic::from_slice(public_keyshare.bytes)?,
                    round_two_private: crate::round_two::Private::from_slice(
                        round_two_private.bytes,
                    )?,
                    round_two_public: crate::round_two::Public::from_slice(round_two_public.bytes)?,
                },
            );
        }
        Ok(hm)
    }

    /// Returns true if in storage, there is one storable_type for each other
    /// party in the quorum.
    fn has_collected_all_of_others(
        &mut self,
        storable_type: StorableType,
    ) -> Result<bool, anyhow::Error> {
        for other_party_id in self.other_party_ids.clone() {
            if self
                .retrieve(storable_type.clone(), &other_party_id, false)
                .is_err()
            {
                return Ok(false);
            }
        }
        Ok(true)
    }
}

struct RoundThreeValue {
    party_id: PartyIdentifier,
    keygen_public: KeygenPublic,
    round_two_private: crate::round_two::Private,
    round_two_public: crate::round_two::Public,
}

/// Simple wrapper around the signature share output
pub struct SignatureShare {
    r: Option<k256::Scalar>,
    s: k256::Scalar,
}

impl Default for SignatureShare {
    fn default() -> Self {
        Self::new()
    }
}

impl SignatureShare {
    fn new() -> Self {
        Self {
            r: None,
            s: k256::Scalar::zero(),
        }
    }

    pub fn chain(&self, share: Self) -> Result<Self, anyhow::Error> {
        let r = match (self.r, share.r) {
            (_, None) => Err(anyhow::anyhow!("Invalid format for share, r scalar = 0")),
            (Some(prev_r), Some(new_r)) => {
                if prev_r != new_r {
                    return Err(anyhow::anyhow!("Cannot chain as r values don't match"));
                }
                Ok(prev_r)
            }
            (None, Some(new_r)) => Ok(new_r),
        }?;

        // Keep the same r, add in the s value
        Ok(Self {
            r: Some(r),
            s: self.s + share.s,
        })
    }

    pub fn finish(&self) -> Result<ecdsa::Signature<Secp256k1>, anyhow::Error> {
        let mut s = self.s;
        if s.is_high().unwrap_u8() == 1 {
            s = s.negate();
        }

        let sig = match self.r {
            Some(r) => Ok(ecdsa::Signature::from_scalars(r, s)?),
            None => Err(anyhow::anyhow!(
                "Cannot produce a signature without including shares"
            )),
        }?;

        Ok(sig)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PartyIdentifier(String);

impl PartyIdentifier {
    pub fn random<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        // Sample random 32 bytes and convert to hex
        let random_bytes = rng.gen::<[u8; 32]>();
        Self(hex::encode(random_bytes))
    }
}

impl Display for PartyIdentifier {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl FromStr for PartyIdentifier {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self(s.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ecdsa::signature::DigestVerifier;
    use rand::rngs::OsRng;
    use sha2::{Digest, Sha256};

    /// Delivers a message into a party's inbox
    fn deliver_one(message: &Message, recipient: &mut Party) -> Result<(), anyhow::Error> {
        recipient.accept_message(message)
    }

    /// Delivers all messages into their respective party's inboxes
    fn deliver_all(messages: &[Message], quorum: &mut Vec<Party>) -> Result<(), anyhow::Error> {
        for message in messages {
            for party in &mut *quorum {
                if party.id == message.to {
                    deliver_one(message, &mut *party)?;
                    break;
                }
            }
        }
        Ok(())
    }

    fn is_presigning_done(quorum: &[Party]) -> Result<bool, anyhow::Error> {
        for party in quorum {
            if party.is_ready_to_sign()? == false {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// For N parties, a typical flow for a single party looks like:
    ///
    /// Step 0. 1 keygen
    /// Step 1. 1 round one, only after all keygens are done
    ///         Each round one produces N-1 public components
    /// Step 2. N-1 round twos, one for each sender. Each round
    ///         two only relies on that sender's round one
    ///         information, and produces a single public value
    ///         for round two as well.
    ///
    #[test]
    fn test_run_protocol() -> Result<(), anyhow::Error> {
        let mut rng = OsRng;
        let mut quorum = Party::new_quorum(3, &mut rng)?;

        // Initialize all parties and get their public keyshares to construct the
        // final signature verification key
        let mut vk_point = k256::ProjectivePoint::identity();
        for party in quorum.iter_mut() {
            party.do_init(&mut rng)?;
            let X = party.get_public_share()?;
            vk_point += X;
        }
        let verification_key =
            ecdsa::VerifyingKey::from_encoded_point(&vk_point.to_affine().into())?;

        while !is_presigning_done(&quorum)? {
            // Pick a random party to process
            let index = rng.gen_range(0..quorum.len());

            if !quorum[index].has_messages() {
                // No messages to process for this party, so pick another party
                continue;
            }

            let messages = quorum[index].process_one(&mut rng)?;
            deliver_all(&messages, &mut quorum)?;
        }

        // Now, produce a valid signature
        let mut hasher = Sha256::new();
        hasher.update(b"some test message");

        let mut aggregator = SignatureShare::default();
        for party in quorum.iter_mut() {
            let signature_share = party.sign(hasher.clone())?;
            aggregator = aggregator.chain(signature_share)?;
        }
        let signature = aggregator.finish()?;

        // Moment of truth, does the signature verify?
        assert!(verification_key.verify_digest(hasher, &signature).is_ok());

        Ok(())
    }
}
