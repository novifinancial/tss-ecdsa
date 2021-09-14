// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

//! A list of error types which are produced during an execution of the protocol
use core::fmt::Debug;
use std::error::Error;

use displaydoc::Display;

/// Represents an error in the manipulation of internal cryptographic data
#[derive(Clone, Display, Eq, Hash, PartialEq)]
pub enum InternalError {
    /// Could not find square roots modulo n
    NoSquareRoots,
    /// Elements are not coprime
    NotCoprime,
    /// Could not find uniqueness for fourth roots combination in Paillier-Blum modulus proof
    NonUniqueFourthRootsCombination,
    /// Could not invert a BigNumber
    CouldNotInvertBigNumber,
}

impl Debug for InternalError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NoSquareRoots => f.debug_tuple("NoSquareRoots").finish(),
            Self::NotCoprime => f.debug_tuple("NotCoprime").finish(),
            Self::NonUniqueFourthRootsCombination => {
                f.debug_tuple("NonUniqueFourthRootsCombination").finish()
            }
            Self::CouldNotInvertBigNumber => f.debug_tuple("CouldNotInvertBigNumber").finish(),
        }
    }
}

impl Error for InternalError {}
