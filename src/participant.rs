// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

use crate::errors::Result;
use crate::message_queue::MessageQueue;
use crate::messages::{Message, MessageType};
use crate::protocol::ParticipantIdentifier;
use crate::storage::StorableType;
use crate::storage::Storage;
use crate::{CurvePoint, Identifier};
use std::collections::HashMap;
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone)]
pub(crate) struct ArbParticipant {
    /// A unique identifier for this participant
    id: ParticipantIdentifier,
    /// A list of all other participant identifiers participating in the protocol
    other_participant_ids: Vec<ParticipantIdentifier>,
    /// Local storage for this participant to store secrets
    storage: Storage,
}

#[derive(Serialize, Deserialize)]
struct ProgressIndex {
    func_name: String,
    sid: Identifier,
}


pub(crate) trait ProtocolParticipant{

    fn storage(&self) -> &Storage;
    fn storage_mut(&mut self) -> &mut Storage;
    fn id(&self) -> ParticipantIdentifier;

    fn stash_message(&mut self, message: &Message) -> Result<()> {
        let mut message_storage =
            match self
                .storage()
                .retrieve(StorableType::MessageQueue, message.id(), self.id())
            {
                Err(_) => MessageQueue::new(),
                Ok(message_storage_bytes) => deserialize!(&message_storage_bytes)?,
            };
        message_storage.store(message.message_type(), message.id(), message.clone())?;
        let my_id = self.id();
        self.storage_mut().store(
            StorableType::MessageQueue,
            message.id(),
            my_id,
            &serialize!(&message_storage)?,
        )?;
        Ok(())
    }

    fn fetch_messages(
        &mut self,
        message_type: MessageType,
        sid: Identifier,
    ) -> Result<Vec<Message>> {
        let mut message_storage =
            match self
                .storage()
                .retrieve(StorableType::MessageQueue, sid, self.id())
            {
                Err(_) => MessageQueue::new(),
                Ok(message_storage_bytes) => deserialize!(&message_storage_bytes)?,
            };
        let messages = message_storage.retrieve_all(message_type, sid)?;
        let my_id = self.id();
        self.storage_mut().store(
            StorableType::MessageQueue,
            sid,
            my_id,
            &serialize!(&message_storage)?,
        )?;
        Ok(messages)
    }

    fn write_progress(&mut self, func_name: String, sid: Identifier) -> Result<()> {
        let mut progress_storage =
            match self
                .storage()
                .retrieve(StorableType::ProgressStore, sid, self.id())
            {
                Err(_) => HashMap::new(),
                Ok(progress_storage_bytes) => deserialize!(&progress_storage_bytes)?,
            };
        let key = serialize!(&ProgressIndex{func_name, sid})?;
        progress_storage.insert(key, true);
        let my_id = self.id();
        self.storage_mut().store(
            StorableType::ProgressStore,
            sid,
            my_id,
            &serialize!(&progress_storage)?,
        )?;
        Ok(())
    }

    fn read_progress(&self, func_name: String, sid: Identifier) -> Result<bool> {
        let progress_storage =
            match self
                .storage()
                .retrieve(StorableType::ProgressStore, sid, self.id())
            {
                Err(_) => HashMap::<Vec<u8>, bool>::new(),
                Ok(progress_storage_bytes) => deserialize!(&progress_storage_bytes)?,
            };
        let key = serialize!(&ProgressIndex{func_name, sid})?;
        let result = match progress_storage.get(&key){
            None => false,
            Some(value) => *value,
        };
        Ok(result)
    }
}

#[macro_export]
/// A macro to keep track of which functions have already been run in a given session
macro_rules! run_only_once {
    ($self:ident . $func_name:ident ($rng:ident, $message:ident)) => {{
        if $self.read_progress(stringify!($func_name).to_string(), $message.id()).unwrap(){
            println!("By george!");
            Ok(vec![])
        }
        else{
            $self.write_progress(stringify!($func_name).to_string(), $message.id())?;
            $self.$func_name($rng, $message)
        }
    }};
}
