// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

//! Generates setup parameters (N, s, t) used for other ZKPs. See
//! the paragraph before Section 2.3.1 of https://eprint.iacr.org/2021/060.pdf
//! for a description.

use crate::errors::*;
use crate::serialization::*;
use crate::zkp::pimod::PaillierBlumModulusProof;
use libpaillier::unknown_order::BigNumber;

use super::piprm::RingPedersenProof;

#[derive(Debug)]
pub struct ZkSetupParameters {
    pub(crate) N: BigNumber,
    s: BigNumber,
    t: BigNumber,
    proof: ZkSetupParametersProof,
}

#[derive(Debug)]
struct ZkSetupParametersProof {
    pimod: PaillierBlumModulusProof,
    piprm: RingPedersenProof,
}

impl ZkSetupParametersProof {
    fn verify(&self) -> bool {
        self.pimod.verify() && self.piprm.verify()
    }
}

impl ZkSetupParameters {
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let result = [
            serialize(&self.N.to_bytes(), 2)?,
            serialize(&self.s.to_bytes(), 2)?,
            serialize(&self.t.to_bytes(), 2)?,
            serialize(&self.proof.to_bytes()?, 2)?,
        ]
        .concat();
        Ok(result)
    }

    pub fn from_slice(input: &[u8]) -> Result<Self> {
        let (n_bytes, input) = tokenize(input, 2)?;
        let (s_bytes, input) = tokenize(&input, 2)?;
        let (t_bytes, input) = tokenize(&input, 2)?;
        let (proof_bytes, input) = tokenize(&input, 2)?;
        if !input.is_empty() {
            // Should not be encountering any more bytes
            return Err(InternalError::Serialization);
        }

        let N = BigNumber::from_slice(n_bytes);
        let s = BigNumber::from_slice(s_bytes);
        let t = BigNumber::from_slice(t_bytes);
        let proof = ZkSetupParametersProof::from_slice(&proof_bytes)?;

        Ok(ZkSetupParameters { N, s, t, proof })
    }
}

impl ZkSetupParametersProof {
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let result = [
            serialize(&self.pimod.to_bytes(), 2)?,
            serialize(&self.piprm.to_bytes()?, 2)?,
        ]
        .concat();
        Ok(result)
    }

    pub fn from_slice(input: &[u8]) -> Result<Self> {
        let (pimod_bytes, input) = tokenize(input, 2)?;
        let (piprm_bytes, input) = tokenize(&input, 2)?;
        if !input.is_empty() {
            // Should not be encountering any more bytes
            return Err(InternalError::Serialization);
        }

        let pimod = PaillierBlumModulusProof::from_slice(pimod_bytes)?;
        let piprm = RingPedersenProof::from_slice(&piprm_bytes)?;

        Ok(Self { pimod, piprm })
    }
}

impl ZkSetupParameters {
    #[allow(unused)]
    pub(crate) fn gen() -> Result<Self> {
        let p = crate::get_random_safe_prime_512();
        let q = crate::get_random_safe_prime_512();
        let N = &p * &q;
        Self::gen_from_primes(&N, &p, &q)
    }

    pub(crate) fn gen_from_primes(N: &BigNumber, p: &BigNumber, q: &BigNumber) -> Result<Self> {
        let phi_n = (p - 1) * (q - 1);
        let tau = BigNumber::random(N);
        let lambda = BigNumber::random(&phi_n);
        let t = tau.modpow(&BigNumber::from(2), N);
        let s = t.modpow(&lambda, N);

        let pimod = PaillierBlumModulusProof::prove(N, p, q)?;
        let piprm = RingPedersenProof::gen(N, &phi_n, &s, &t, &lambda)?;

        let proof = ZkSetupParametersProof { pimod, piprm };

        Ok(Self {
            N: N.clone(),
            s,
            t,
            proof,
        })
    }

    pub(crate) fn verify(&self) -> bool {
        self.proof.verify()
            && self.N == self.proof.pimod.N
            && self.s == self.proof.piprm.s
            && self.t == self.proof.piprm.t
    }
}
