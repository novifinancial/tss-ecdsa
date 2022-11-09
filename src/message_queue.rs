// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

use crate::{
    errors::Result,
    messages::{Message, MessageType},
    protocol::Identifier,
};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, fmt::Debug};

/// A message that can be posted to (and read from) the broadcast channel
#[derive(Debug, Serialize, Deserialize)]
struct MessageIndex {
    message_type: MessageType,
    /// The unique identifier associated with this stored value
    identifier: Identifier,
}

#[derive(Serialize, Deserialize, Clone)]
pub(crate) struct MessageQueue(HashMap<Vec<u8>, Vec<Message>>);

impl MessageQueue {
    pub(crate) fn new() -> Self {
        Self(HashMap::new())
    }

    pub(crate) fn store(
        &mut self,
        message_type: MessageType,
        identifier: Identifier,
        message: Message,
    ) -> Result<()> {
        let message_index = MessageIndex {
            message_type,
            identifier,
        };
        let key = serialize!(&message_index)?;
        let mut queue = match self.0.remove(&key) {
            Some(a) => a,
            None => vec![],
        };
        queue.push(message);
        let _ = self.0.insert(key, queue);
        Ok(())
    }

    pub(crate) fn retrieve_all(
        &mut self,
        message_type: MessageType,
        identifier: Identifier,
    ) -> Result<Vec<Message>> {
        let message_index = MessageIndex {
            message_type,
            identifier,
        };
        let key = serialize!(&message_index)?;
        // delete retrieved messages from storage so that they aren't accidentally
        // processed again
        let queue = match self.0.remove(&key) {
            Some(a) => a,
            None => vec![],
        };
        Ok(queue)
    }
}
