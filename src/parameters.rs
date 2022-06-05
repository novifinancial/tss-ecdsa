// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

///////////////
// Constants //
// ========= //
///////////////

/// See caption for Table 2 at bottom of page 69 in https://eprint.iacr.org/2021/060.pdf
/// ELL = 1 * SecParam
/// ELL_PRIME = 5 * SecParam
/// EPSILON = 2 * SecParam
pub(crate) const ELL: usize = 256;
pub(crate) const ELL_PRIME: usize = 5 * 256;
pub(crate) const EPSILON: usize = 2 * 256;
pub(crate) const PRIME_BITS: usize = 512; // 512-bit primes are needed
pub(crate) const SOUNDNESS_PARAMETER: usize = 8; // Needs to be a multiple of 8 for Pi_prm
