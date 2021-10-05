// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

//! Generates setup parameters (N, s, t) used for other ZKPs. See
//! the paragraph before Section 2.3.1 of https://eprint.iacr.org/2021/060.pdf
//! for a description.

use crate::errors::*;
use crate::serialization::*;
use crate::zkp::pimod::{PiModInput, PiModProof, PiModSecret};
use libpaillier::unknown_order::BigNumber;

use super::piprm::{PiPrmInput, PiPrmProof, PiPrmSecret};
use crate::zkp::Proof;
use rand::{CryptoRng, RngCore};

#[derive(Debug, Clone)]
pub struct ZkSetupParameters {
    pub(crate) N: BigNumber,
    pub(crate) s: BigNumber,
    pub(crate) t: BigNumber,
    pimod: PiModProof,
    piprm: PiPrmProof,
}

impl ZkSetupParameters {
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let result = [
            serialize(&self.N.to_bytes(), 2)?,
            serialize(&self.s.to_bytes(), 2)?,
            serialize(&self.t.to_bytes(), 2)?,
            serialize(&self.pimod.to_bytes()?, 2)?,
            serialize(&self.piprm.to_bytes()?, 2)?,
        ]
        .concat();
        Ok(result)
    }

    pub fn from_slice(input: &[u8]) -> Result<Self> {
        let (n_bytes, input) = tokenize(input, 2)?;
        let (s_bytes, input) = tokenize(&input, 2)?;
        let (t_bytes, input) = tokenize(&input, 2)?;
        let (pimod_bytes, input) = tokenize(&input, 2)?;
        let (piprm_bytes, input) = tokenize(&input, 2)?;
        if !input.is_empty() {
            // Should not be encountering any more bytes
            return Err(InternalError::Serialization);
        }

        let N = BigNumber::from_slice(n_bytes);
        let s = BigNumber::from_slice(s_bytes);
        let t = BigNumber::from_slice(t_bytes);
        let pimod = PiModProof::from_slice(pimod_bytes)?;
        let piprm = PiPrmProof::from_slice(&piprm_bytes)?;

        Ok(ZkSetupParameters {
            N,
            s,
            t,
            pimod,
            piprm,
        })
    }
}

impl ZkSetupParameters {
    #[allow(unused)]
    pub(crate) fn gen<R: RngCore + CryptoRng>(rng: &mut R) -> Result<Self> {
        let p = crate::get_random_safe_prime_512();
        let q = crate::get_random_safe_prime_512();
        let N = &p * &q;
        Self::gen_from_primes(rng, &N, &p, &q)
    }

    pub(crate) fn gen_from_primes<R: RngCore + CryptoRng>(
        rng: &mut R,
        N: &BigNumber,
        p: &BigNumber,
        q: &BigNumber,
    ) -> Result<Self> {
        let phi_n = (p - 1) * (q - 1);
        let tau = BigNumber::random(N);
        let lambda = BigNumber::random(&phi_n);
        let t = tau.modpow(&BigNumber::from(2), N);
        let s = t.modpow(&lambda, N);

        let pimod = PiModProof::prove(rng, &PiModInput::new(N), &PiModSecret::new(p, q))?;
        let piprm = PiPrmProof::prove(
            rng,
            &PiPrmInput::new(N, &s, &t),
            &PiPrmSecret::new(&lambda, &phi_n),
        )?;

        Ok(Self {
            N: N.clone(),
            s,
            t,
            pimod,
            piprm,
        })
    }

    pub(crate) fn verify(&self) -> bool {
        self.pimod.verify(&PiModInput::new(&self.N))
            && self
                .piprm
                .verify(&PiPrmInput::new(&self.N, &self.s, &self.t))
    }
}
