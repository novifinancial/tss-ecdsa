// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

//! Implements the ZKP from Figure 14 of <https://eprint.iacr.org/2021/060.pdf>
//!
//! Proves that the plaintext of the Paillier ciphertext K_i lies within the range
//! [1, 2^{ELL+EPSILON}]

use super::Proof;
use crate::utils::{
    k256_order, modpow, plusminus_bn_random_from_transcript, random_bn_in_range,
    random_bn_in_z_star,
};
use crate::zkp::setup::ZkSetupParameters;
use crate::{
    errors::*,
    paillier::PaillierCiphertext,
    parameters::{ELL, EPSILON},
};
use libpaillier::unknown_order::BigNumber;
use merlin::Transcript;
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct PiEncProof {
    alpha: BigNumber,
    S: BigNumber,
    A: BigNumber,
    C: BigNumber,
    e: BigNumber,
    z1: BigNumber,
    z2: BigNumber,
    z3: BigNumber,
}

#[derive(Serialize)]
pub(crate) struct PiEncInput {
    setup_params: ZkSetupParameters,
    N0: BigNumber,
    K: PaillierCiphertext,
}

impl PiEncInput {
    pub(crate) fn new(
        setup_params: &ZkSetupParameters,
        N0: &BigNumber,
        K: &PaillierCiphertext,
    ) -> Self {
        Self {
            setup_params: setup_params.clone(),
            N0: N0.clone(),
            K: K.clone(),
        }
    }
}

pub(crate) struct PiEncSecret {
    k: BigNumber,
    rho: BigNumber,
}

impl PiEncSecret {
    pub(crate) fn new(k: &BigNumber, rho: &BigNumber) -> Self {
        Self {
            k: k.clone(),
            rho: rho.clone(),
        }
    }
}

impl Proof for PiEncProof {
    type CommonInput = PiEncInput;
    type ProverSecret = PiEncSecret;

    // FIXME: could benefit from a batch API since this is done multiple times where
    // the only differing parameter is setup_params
    //
    // N0: modulus, K: Paillier ciphertext
    #[cfg_attr(feature = "flame_it", flame("PiEncProof"))]
    fn prove<R: RngCore + CryptoRng>(
        rng: &mut R,
        input: &Self::CommonInput,
        secret: &Self::ProverSecret,
    ) -> Result<Self> {
        // Sample alpha from +- 2^{ELL + EPSILON}
        let alpha = random_bn_in_range(rng, ELL + EPSILON);

        let mu = random_bn_in_range(rng, ELL) * &input.setup_params.N;
        let r = random_bn_in_z_star(rng, &input.N0);
        let gamma = random_bn_in_range(rng, ELL + EPSILON) * &input.setup_params.N;

        let N0_squared = &input.N0 * &input.N0;

        let S = {
            let a = modpow(&input.setup_params.s, &secret.k, &input.setup_params.N);
            let b = modpow(&input.setup_params.t, &mu, &input.setup_params.N);
            a.modmul(&b, &input.setup_params.N)
        };
        let A = {
            let a = modpow(&(&BigNumber::one() + &input.N0), &alpha, &N0_squared);
            let b = modpow(&r, &input.N0, &N0_squared);
            a.modmul(&b, &N0_squared)
        };
        let C = {
            let a = modpow(&input.setup_params.s, &alpha, &input.setup_params.N);
            let b = modpow(&input.setup_params.t, &gamma, &input.setup_params.N);
            a.modmul(&b, &input.setup_params.N)
        };

        let mut transcript = Transcript::new(b"PiEncProof");
        transcript.append_message(b"CommonInput", &serialize!(&input)?);
        transcript.append_message(b"alpha", &alpha.to_bytes());
        transcript.append_message(
            b"(S, A, C)",
            &[S.to_bytes(), A.to_bytes(), C.to_bytes()].concat(),
        );

        // Verifier is supposed to sample from e in +- q (where q is the group order), we sample from
        // [0, 2*q] instead
        let e = plusminus_bn_random_from_transcript(
            &mut transcript,
            &(BigNumber::from(2) * &k256_order()),
        );

        let z1 = &alpha + &e * &secret.k;
        let z2 = r.modmul(&modpow(&secret.rho, &e, &input.N0), &input.N0);
        let z3 = gamma + &e * mu;

        let proof = Self {
            alpha,
            S,
            A,
            C,
            e,
            z1,
            z2,
            z3,
        };

        Ok(proof)
    }

    #[cfg_attr(feature = "flame_it", flame("PiEncProof"))]
    fn verify(&self, input: &Self::CommonInput) -> Result<()> {
        // First check Fiat-Shamir challenge consistency

        let mut transcript = Transcript::new(b"PiEncProof");
        transcript.append_message(b"CommonInput", &serialize!(&input)?);
        transcript.append_message(b"alpha", &self.alpha.to_bytes());
        transcript.append_message(
            b"(S, A, C)",
            &[self.S.to_bytes(), self.A.to_bytes(), self.C.to_bytes()].concat(),
        );

        let e = plusminus_bn_random_from_transcript(
            &mut transcript,
            &(BigNumber::from(2u64) * &k256_order()),
        );
        if e != self.e {
            return verify_err!("Fiat-Shamir didn't verify");
        }

        let N0_squared = &input.N0 * &input.N0;

        // Do equality checks

        let eq_check_1 = {
            let a = modpow(&(&BigNumber::one() + &input.N0), &self.z1, &N0_squared);
            let b = modpow(&self.z2, &input.N0, &N0_squared);
            let lhs = a.modmul(&b, &N0_squared);
            let rhs = self
                .A
                .modmul(&modpow(&input.K.0, &e, &N0_squared), &N0_squared);
            lhs == rhs
        };
        if !eq_check_1 {
            return verify_err!("eq_check_1 failed");
        }

        let eq_check_2 = {
            let a = modpow(&input.setup_params.s, &self.z1, &input.setup_params.N);
            let b = modpow(&input.setup_params.t, &self.z3, &input.setup_params.N);
            let lhs = a.modmul(&b, &input.setup_params.N);
            let rhs = self.C.modmul(
                &modpow(&self.S, &e, &input.setup_params.N),
                &input.setup_params.N,
            );
            lhs == rhs
        };
        if !eq_check_2 {
            return verify_err!("eq_check_2 failed");
        }

        // Do range check
        let bound = BigNumber::one() << (ELL + EPSILON);
        if self.z1 < -bound.clone() || self.z1 > bound {
            return verify_err!("self.z1 > bound check failed");
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::paillier::PaillierEncryptionKey;
    use crate::utils::random_bn_in_range_min;
    use libpaillier::*;
    use rand::rngs::OsRng;

    fn random_paillier_encryption_in_range_proof(k: &BigNumber) -> Result<()> {
        let mut rng = OsRng;

        let p = crate::get_random_safe_prime_512();
        let q = crate::get_random_safe_prime_512();
        let N = &p * &q;

        let sk = DecryptionKey::with_safe_primes_unchecked(&p, &q).unwrap();
        let pk = PaillierEncryptionKey(EncryptionKey::from(&sk));

        let (K, rho) = pk.encrypt(k);
        let setup_params = ZkSetupParameters::gen(&mut rng)?;

        let input = PiEncInput {
            setup_params,
            N0: N,
            K: PaillierCiphertext(K),
        };

        let proof = PiEncProof::prove(&mut rng, &input, &PiEncSecret { k: k.clone(), rho })?;

        let proof_bytes = bincode::serialize(&proof).unwrap();
        let roundtrip_proof: PiEncProof = bincode::deserialize(&proof_bytes).unwrap();
        let roundtrip_proof_bytes = bincode::serialize(&roundtrip_proof).unwrap();
        assert_eq!(proof_bytes, roundtrip_proof_bytes);

        proof.verify(&input)
    }

    #[test]
    fn test_paillier_encryption_in_range_proof() -> Result<()> {
        let mut rng = OsRng;

        let k_small = random_bn_in_range(&mut rng, ELL);
        let k_large = random_bn_in_range_min(&mut rng, ELL + EPSILON + 1, ELL + EPSILON)?;

        // Sampling k in the range 2^ELL should always succeed
        random_paillier_encryption_in_range_proof(&k_small)?;

        // Sampling k in the range (2^{ELL + EPSILON, 2^{ELL + EPSILON + 1}] should fail
        assert!(random_paillier_encryption_in_range_proof(&k_large).is_err());

        Ok(())
    }
}
