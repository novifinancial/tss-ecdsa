// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use libpaillier::unknown_order::BigNumber;
use rand::{CryptoRng, RngCore};

/// Computes a^e (mod n)
#[cfg_attr(feature = "flame_it", flame("utils"))]
pub(crate) fn modpow(a: &BigNumber, e: &BigNumber, n: &BigNumber) -> BigNumber {
    a.modpow(e, n)
}

/// Generate a random positive BigNumber in the range 0..2^{n+1}
pub(crate) fn random_bn_in_range<R: RngCore + CryptoRng>(_rng: &mut R, n: usize) -> BigNumber {
    BigNumber::random(&(BigNumber::one() << (n + 1)))
}

/// Generate a random BigNumber in the range 1..N-1 (Z_N^*) (non-zero)
pub(crate) fn random_bn_in_z_star<R: RngCore + CryptoRng>(
    _rng: &mut R,
    n: &BigNumber,
) -> BigNumber {
    loop {
        let bn = BigNumber::random(n);
        if bn != BigNumber::zero() {
            return bn;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    #[test]
    fn test_random_bn_in_range() {
        // Statistical tests -- should generate random numbers that are long enough

        let mut max_len = 0;
        let num_bytes = 100;

        let mut rng = OsRng;
        for _ in 0..1000 {
            let bn = random_bn_in_range(&mut rng, num_bytes * 8);
            let len = bn.to_bytes().len();
            if max_len < len {
                max_len = len;
            }
        }

        assert!(max_len > num_bytes - 2);
    }
}
