// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use crate::errors::Result;
use crate::protocol::ParticipantIdentifier;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt::Debug;
use std::hash::Hash;

/////////////////////////
// Private Storage API //
/////////////////////////

#[derive(Debug, PartialEq, Eq, Hash, Clone, Serialize, Deserialize)]
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

/// A message that can be posted to (and read from) the broadcast channel
#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct PresignStorableIndex {
    pub(crate) storable_type: StorableType,
    // The participant identifier that this storable is associated with
    pub(crate) associated_participant_id: ParticipantIdentifier,
}

impl StorableIndex for PresignStorableIndex {}

pub trait StorableIndex: Serialize + Debug {}

pub(crate) struct Storage(HashMap<Vec<u8>, Vec<u8>>);

impl Storage {
    pub(crate) fn new() -> Self {
        Self(HashMap::new())
    }

    pub(crate) fn store_presign(
        &mut self,
        storable_type: StorableType,
        associated_participant_id: &ParticipantIdentifier,
        val: &[u8],
    ) -> Result<()> {
        let storable_index = PresignStorableIndex {
            storable_type,
            associated_participant_id: associated_participant_id.clone(),
        };
        self.store(storable_index, val)
    }

    pub(crate) fn retrieve_presign(
        &mut self,
        storable_type: StorableType,
        id: &ParticipantIdentifier,
    ) -> Result<Vec<u8>> {
        self.retrieve(PresignStorableIndex {
            storable_type,
            associated_participant_id: id.clone(),
        })
    }

    // Inner functions

    fn store<I: StorableIndex>(&mut self, storable_index: I, val: &[u8]) -> Result<()> {
        let key = serialize!(&storable_index)?;
        self.0.insert(key, val.to_vec());
        Ok(())
    }

    fn retrieve<I: StorableIndex>(&mut self, storable_index: I) -> Result<Vec<u8>> {
        let key = serialize!(&storable_index)?;
        let ret = self
            .0
            .get(&key)
            .ok_or_else(|| {
                bail_context!(
                    "Could not find {:?} when getting from storage",
                    storable_index
                )
            })?
            .clone();

        Ok(ret)
    }
}
