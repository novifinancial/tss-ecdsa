// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use crate::errors::Result;
use crate::protocol::{Identifier, ParticipantIdentifier};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt::Debug;
use std::hash::Hash;

/////////////////////////
// Private Storage API //
/////////////////////////

#[derive(Debug, PartialEq, Eq, Hash, Clone, Serialize, Deserialize)]
pub(crate) enum StorableType {
    AuxInfoPrivate,
    AuxInfoPublic,
    PrivateKeyshare,
    PublicKeyshare,
    RoundOnePrivate,
    RoundOnePublic,
    RoundTwoPrivate,
    RoundTwoPublic,
    RoundThreePrivate,
    RoundThreePublic,
    PresignRecord,
}

/// A message that can be posted to (and read from) the broadcast channel
#[derive(Debug, Serialize, Deserialize)]
struct StorableIndex {
    storable_type: StorableType,
    /// The unique identifier associated with this stored value
    identifier: Identifier,
    // The participant identifier that this storable is associated with
    participant: ParticipantIdentifier,
}

impl Storable for StorableIndex {}

pub(crate) trait Storable: Serialize + Debug {}

#[derive(Serialize, Deserialize)]
pub(crate) struct Storage(HashMap<Vec<u8>, Vec<u8>>);

impl Storage {
    pub(crate) fn new() -> Self {
        Self(HashMap::new())
    }

    pub(crate) fn store(
        &mut self,
        storable_type: StorableType,
        identifier: &Identifier,
        associated_participant_id: &ParticipantIdentifier,
        val: &[u8],
    ) -> Result<()> {
        let storable_index = StorableIndex {
            storable_type,
            identifier: *identifier,
            participant: *associated_participant_id,
        };
        self.store_index(storable_index, val)
    }

    pub(crate) fn retrieve(
        &self,
        storable_type: StorableType,
        identifier: Identifier,
        participant: ParticipantIdentifier,
    ) -> Result<Vec<u8>> {
        self.retrieve_index(StorableIndex {
            storable_type,
            identifier,
            participant,
        })
    }

    pub(crate) fn contains_batch(
        &self,
        type_and_id: &[(StorableType, Identifier, ParticipantIdentifier)],
    ) -> Result<()> {
        let storable_indices: Vec<StorableIndex> = type_and_id
            .iter()
            .map(|(t, identifier, participant)| StorableIndex {
                storable_type: t.clone(),
                identifier: *identifier,
                participant: *participant,
            })
            .collect();
        self.contains_index_batch(&storable_indices)
    }

    // Inner functions

    fn store_index<I: Storable>(&mut self, storable_index: I, val: &[u8]) -> Result<()> {
        let key = serialize!(&storable_index)?;
        self.0.insert(key, val.to_vec());
        Ok(())
    }

    fn retrieve_index<I: Storable>(&self, storable_index: I) -> Result<Vec<u8>> {
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

    fn contains_index_batch<I: Storable>(&self, storable_indices: &[I]) -> Result<()> {
        for storable_index in storable_indices {
            let key = serialize!(&storable_index)?;
            let ret = self.0.contains_key(&key);
            if !ret {
                return bail!("Could not find key in hashmap");
            }
        }
        Ok(())
    }
}
