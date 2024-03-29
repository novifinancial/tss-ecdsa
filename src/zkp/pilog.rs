// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

//! Implements the ZKP from Figure 25 of <https://eprint.iacr.org/2021/060.pdf>

use super::Proof;
use crate::utils::{
    self, modpow, plusminus_bn_random_from_transcript, random_bn_in_range, random_bn_in_z_star,
    random_bn_plusminus,
};
use crate::zkp::setup::ZkSetupParameters;
use crate::{
    errors::*,
    parameters::{ELL, EPSILON},
};
use libpaillier::unknown_order::BigNumber;
use merlin::Transcript;
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use utils::CurvePoint;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct PiLogProof {
    alpha: BigNumber,
    S: BigNumber,
    A: BigNumber,
    Y: CurvePoint,
    D: BigNumber,
    e: BigNumber,
    z1: BigNumber,
    z2: BigNumber,
    z3: BigNumber,
}

#[derive(Serialize)]
pub(crate) struct PiLogInput {
    setup_params: ZkSetupParameters,
    q: BigNumber,
    N0: BigNumber,
    C: BigNumber,
    X: CurvePoint,
    g: CurvePoint,
}

impl PiLogInput {
    pub(crate) fn new(
        setup_params: &ZkSetupParameters,
        q: &BigNumber,
        N0: &BigNumber,
        C: &BigNumber,
        X: &CurvePoint,
        g: &CurvePoint,
    ) -> Self {
        Self {
            setup_params: setup_params.clone(),
            q: q.clone(),
            N0: N0.clone(),
            C: C.clone(),
            X: *X,
            g: *g,
        }
    }
}

pub(crate) struct PiLogSecret {
    x: BigNumber,
    rho: BigNumber,
}

impl PiLogSecret {
    pub(crate) fn new(x: &BigNumber, rho: &BigNumber) -> Self {
        Self {
            x: x.clone(),
            rho: rho.clone(),
        }
    }
}

// Common input is: q, N0, C, X, g
// Prover secrets are: (x, rho)
impl Proof for PiLogProof {
    type CommonInput = PiLogInput;
    type ProverSecret = PiLogSecret;

    // N0: modulus, K: Paillier ciphertext
    #[cfg_attr(feature = "flame_it", flame("PiLogProof"))]
    fn prove<R: RngCore + CryptoRng>(
        rng: &mut R,
        input: &Self::CommonInput,
        secret: &Self::ProverSecret,
    ) -> Result<Self> {
        // Sample alpha from 2^{ELL + EPSILON}
        let alpha = random_bn_in_range(rng, ELL + EPSILON);

        let r = random_bn_in_z_star(rng, &input.N0);

        // range = 2^{ELL} * N_hat
        let range_ell = (BigNumber::one() << ELL) * &input.setup_params.N;
        let mu = random_bn_plusminus(rng, &range_ell);

        // range = 2^{ELL+EPSILON} * N_hat
        let range_ell_epsilon = (BigNumber::one() << (ELL + EPSILON)) * &input.setup_params.N;
        let gamma = random_bn_plusminus(rng, &range_ell_epsilon);

        let N0_squared = &input.N0 * &input.N0;

        let S = {
            let a = modpow(&input.setup_params.s, &secret.x, &input.setup_params.N);
            let b = modpow(&input.setup_params.t, &mu, &input.setup_params.N);
            a.modmul(&b, &input.setup_params.N)
        };
        let A = {
            let a = modpow(&(BigNumber::one() + &input.N0), &alpha, &N0_squared);
            let b = modpow(&r, &input.N0, &N0_squared);
            a.modmul(&b, &N0_squared)
        };
        let Y = CurvePoint(input.g.0 * utils::bn_to_scalar(&alpha).unwrap());
        let D = {
            let a = modpow(&input.setup_params.s, &alpha, &input.setup_params.N);
            let b = modpow(&input.setup_params.t, &gamma, &input.setup_params.N);
            a.modmul(&b, &input.setup_params.N)
        };

        let mut transcript = Transcript::new(b"PiLogProof");
        transcript.append_message(b"CommonInput", &serialize!(&input)?);
        transcript.append_message(
            b"(S, A, Y, D)",
            &[
                S.to_bytes(),
                A.to_bytes(),
                bincode::serialize(&Y).unwrap(),
                D.to_bytes(),
            ]
            .concat(),
        );

        // Verifier samples from e in +- q (where q is the group order)
        let e = plusminus_bn_random_from_transcript(&mut transcript, &input.q);

        let z1 = &alpha + &e * &secret.x;
        let z2 = r.modmul(&modpow(&secret.rho, &e, &input.N0), &input.N0);
        let z3 = gamma + &e * mu;

        let proof = Self {
            alpha,
            S,
            A,
            Y,
            D,
            e,
            z1,
            z2,
            z3,
        };

        Ok(proof)
    }

    #[cfg_attr(feature = "flame_it", flame("PiLogProof"))]
    fn verify(&self, input: &Self::CommonInput) -> Result<()> {
        // First, do Fiat-Shamir consistency check
        let mut transcript = Transcript::new(b"PiLogProof");
        transcript.append_message(b"CommonInput", &serialize!(&input)?);
        transcript.append_message(
            b"(S, A, Y, D)",
            &[
                self.S.to_bytes(),
                self.A.to_bytes(),
                bincode::serialize(&self.Y).unwrap(),
                self.D.to_bytes(),
            ]
            .concat(),
        );

        // Verifier samples from e in +- q (where q is the group order)
        let e = plusminus_bn_random_from_transcript(&mut transcript, &input.q);

        if e != self.e {
            return verify_err!("Fiat-Shamir consistency check failed");
        }

        let N0_squared = &input.N0 * &input.N0;

        // Do equality checks

        let eq_check_1 = {
            let a = modpow(&(BigNumber::one() + &input.N0), &self.z1, &N0_squared);
            let b = modpow(&self.z2, &input.N0, &N0_squared);
            let lhs = a.modmul(&b, &N0_squared);
            let rhs = self
                .A
                .modmul(&modpow(&input.C, &self.e, &N0_squared), &N0_squared);
            lhs == rhs
        };
        if !eq_check_1 {
            return verify_err!("eq_check_1 failed");
        }

        let eq_check_2 = {
            let lhs = CurvePoint(input.g.0 * utils::bn_to_scalar(&self.z1).unwrap());
            let rhs = CurvePoint(self.Y.0 + input.X.0 * utils::bn_to_scalar(&self.e).unwrap());
            lhs == rhs
        };
        if !eq_check_2 {
            return verify_err!("eq_check_2 failed");
        }

        let eq_check_3 = {
            let a = modpow(&input.setup_params.s, &self.z1, &input.setup_params.N);
            let b = modpow(&input.setup_params.t, &self.z3, &input.setup_params.N);
            let lhs = a.modmul(&b, &input.setup_params.N);
            let rhs = self.D.modmul(
                &modpow(&self.S, &self.e, &input.setup_params.N),
                &input.setup_params.N,
            );
            lhs == rhs
        };
        if !eq_check_3 {
            return verify_err!("eq_check_4 failed");
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
    use crate::paillier::*;
    use crate::utils::random_bn_in_range_min;
    use libpaillier::*;
    use rand::rngs::OsRng;

    fn random_paillier_log_proof(x: &BigNumber) -> Result<()> {
        let mut rng = OsRng;

        let p0 = crate::utils::get_random_safe_prime_512();
        let q0 = crate::utils::get_random_safe_prime_512();
        let N0 = &p0 * &q0;

        let sk = DecryptionKey::with_safe_primes_unchecked(&p0, &q0).unwrap();
        let pk = PaillierEncryptionKey(EncryptionKey::from(&sk));

        let g = CurvePoint(k256::ProjectivePoint::GENERATOR);

        let X = CurvePoint(g.0 * utils::bn_to_scalar(x).unwrap());
        let (C, rho) = pk.encrypt(x);

        let setup_params = ZkSetupParameters::gen(&mut rng)?;

        let input = PiLogInput::new(&setup_params, &crate::utils::k256_order(), &N0, &C, &X, &g);

        let proof = PiLogProof::prove(&mut rng, &input, &PiLogSecret::new(x, &rho))?;

        proof.verify(&input)
    }

    #[test]
    fn test_paillier_log_proof() -> Result<()> {
        let mut rng = OsRng;

        let x_small = random_bn_in_range(&mut rng, ELL);
        let x_large = random_bn_in_range_min(&mut rng, ELL + EPSILON + 1, ELL + EPSILON)?;

        // Sampling x in the range 2^ELL should always succeed
        random_paillier_log_proof(&x_small)?;

        // Sampling x in the range (2^{ELL + EPSILON}, 2^{ELL + EPSILON + 1}] should fail
        assert!(random_paillier_log_proof(&x_large).is_err());

        Ok(())
    }
}
