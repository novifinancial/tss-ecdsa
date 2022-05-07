// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

//! Implements the ZKP from Figure 15 of https://eprint.iacr.org/2021/060.pdf
//!
//! Proves that the prover knows an x and y where X = g^x and y is the
//! plaintext of a Paillier ciphertext
//!
//! FIXME: need to make a distinction here between L and L'

use super::Proof;
use crate::utils::{
    self, bn_random_from_transcript, k256_order, modpow, random_bn, random_bn_in_range,
    random_bn_in_z_star,
};
use crate::zkp::setup::ZkSetupParameters;
use crate::{
    errors::*,
    parameters::{ELL, ELL_PRIME, EPSILON},
};
use libpaillier::unknown_order::BigNumber;
use merlin::Transcript;
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use utils::CurvePoint;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PiAffgProof {
    alpha: BigNumber,
    beta: BigNumber,
    S: BigNumber,
    T: BigNumber,
    A: BigNumber,
    B_x: CurvePoint,
    B_y: BigNumber,
    E: BigNumber,
    F: BigNumber,
    e: BigNumber,
    z1: BigNumber,
    z2: BigNumber,
    z3: BigNumber,
    z4: BigNumber,
    w: BigNumber,
    w_y: BigNumber,
}

pub(crate) struct PiAffgInput {
    setup_params: ZkSetupParameters,
    g: CurvePoint,
    N0: BigNumber,
    N1: BigNumber,
    C: BigNumber,
    D: BigNumber,
    Y: BigNumber,
    X: CurvePoint,
}

impl PiAffgInput {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        setup_params: &ZkSetupParameters,
        g: &CurvePoint,
        N0: &BigNumber,
        N1: &BigNumber,
        C: &BigNumber,
        D: &BigNumber,
        Y: &BigNumber,
        X: &CurvePoint,
    ) -> Self {
        Self {
            setup_params: setup_params.clone(),
            g: *g,
            N0: N0.clone(),
            N1: N1.clone(),
            C: C.clone(),
            D: D.clone(),
            Y: Y.clone(),
            X: *X,
        }
    }
}

pub(crate) struct PiAffgSecret {
    x: BigNumber,
    y: BigNumber,
    rho: BigNumber,
    rho_y: BigNumber,
}

impl PiAffgSecret {
    pub(crate) fn new(x: &BigNumber, y: &BigNumber, rho: &BigNumber, rho_y: &BigNumber) -> Self {
        Self {
            x: x.clone(),
            y: y.clone(),
            rho: rho.clone(),
            rho_y: rho_y.clone(),
        }
    }
}

// Common input is: g, N0, N1, C, D, Y, X
// Prover secrets are: (x, y, rho, rho_y)
//
// (Note that we use ELL = ELL' from the paper)
impl Proof for PiAffgProof {
    type CommonInput = PiAffgInput;
    type ProverSecret = PiAffgSecret;

    // N0: modulus, K: Paillier ciphertext
    #[cfg_attr(feature = "flame_it", flame("PiAffgProof"))]
    #[allow(clippy::many_single_char_names)]
    fn prove<R: RngCore + CryptoRng>(
        rng: &mut R,
        input: &Self::CommonInput,
        secret: &Self::ProverSecret,
    ) -> Result<Self> {
        // Sample alpha from 2^{ELL + EPSILON}
        let alpha = random_bn_in_range(rng, ELL + EPSILON);
        // Sample beta from 2^{ELL_PRIME + EPSILON}.
        let beta = random_bn_in_range(rng, ELL_PRIME + EPSILON);

        let r = random_bn_in_z_star(rng, &input.N0);
        let r_y = random_bn_in_z_star(rng, &input.N1);

        let gamma = random_bn_in_range(rng, ELL + EPSILON);
        let delta = random_bn_in_range(rng, ELL + EPSILON);

        // range = 2^{ELL+1} * N_hat
        let range = (BigNumber::one() << (ELL + 1)) * &input.setup_params.N;
        let m = random_bn(rng, &range);
        let mu = random_bn(rng, &range);

        let N0_squared = &input.N0 * &input.N0;
        let N1_squared = &input.N1 * &input.N1;

        let A = {
            let a = modpow(&input.C, &alpha, &N0_squared);
            let b = {
                let c = modpow(&(BigNumber::one() + &input.N0), &beta, &N0_squared);
                let d = modpow(&r, &input.N0, &N0_squared);
                c.modmul(&d, &N0_squared)
            };
            a.modmul(&b, &N0_squared)
        };
        let B_x = CurvePoint(input.g.0 * utils::bn_to_scalar(&alpha).unwrap());
        let B_y = {
            let a = modpow(&(BigNumber::one() + &input.N1), &beta, &N1_squared);
            let b = modpow(&r_y, &input.N1, &N1_squared);
            a.modmul(&b, &N1_squared)
        };
        let E = {
            let a = modpow(&input.setup_params.s, &alpha, &input.setup_params.N);
            let b = modpow(&input.setup_params.t, &gamma, &input.setup_params.N);
            a.modmul(&b, &input.setup_params.N)
        };
        let S = {
            let a = modpow(&input.setup_params.s, &secret.x, &input.setup_params.N);
            let b = modpow(&input.setup_params.t, &m, &input.setup_params.N);
            a.modmul(&b, &input.setup_params.N)
        };
        let F = {
            let a = modpow(&input.setup_params.s, &beta, &input.setup_params.N);
            let b = modpow(&input.setup_params.t, &delta, &input.setup_params.N);
            a.modmul(&b, &input.setup_params.N)
        };
        let T = {
            let a = modpow(&input.setup_params.s, &secret.y, &input.setup_params.N);
            let b = modpow(&input.setup_params.t, &mu, &input.setup_params.N);
            a.modmul(&b, &input.setup_params.N)
        };

        let mut transcript = Transcript::new(b"PiAffgProof");
        transcript.append_message(
            b"(N, s, t)",
            &[
                input.setup_params.N.to_bytes(),
                input.setup_params.s.to_bytes(),
                input.setup_params.t.to_bytes(),
            ]
            .concat(),
        );
        transcript.append_message(
            b"(S, T, A, B_x, B_y, E, F)",
            &[
                S.to_bytes(),
                T.to_bytes(),
                A.to_bytes(),
                bincode::serialize(&B_x).unwrap(),
                B_y.to_bytes(),
                E.to_bytes(),
                F.to_bytes(),
            ]
            .concat(),
        );

        // Verifier is supposed to sample from e in +- q (where q is the group order), we sample from
        // [0, 2*q] instead
        let e =
            bn_random_from_transcript(&mut transcript, &(BigNumber::from(2u64) * &k256_order()));

        let z1 = &alpha + &e * &secret.x;
        let z2 = &beta + &e * &secret.y;
        let z3 = gamma + &e * m;
        let z4 = delta + &e * mu;
        let w = r.modmul(&modpow(&secret.rho, &e, &input.N0), &input.N0);
        let w_y = r_y.modmul(&modpow(&secret.rho_y, &e, &input.N1), &input.N1);

        let proof = Self {
            alpha,
            beta,
            S,
            T,
            A,
            B_x,
            B_y,
            E,
            F,
            e,
            z1,
            z2,
            z3,
            z4,
            w,
            w_y,
        };

        Ok(proof)
    }

    #[cfg_attr(feature = "flame_it", flame("PiAffgProof"))]
    fn verify(&self, input: &Self::CommonInput) -> Result<()> {
        // First, do Fiat-Shamir consistency check

        let mut transcript = Transcript::new(b"PiAffgProof");
        transcript.append_message(
            b"(N, s, t)",
            &[
                input.setup_params.N.to_bytes(),
                input.setup_params.s.to_bytes(),
                input.setup_params.t.to_bytes(),
            ]
            .concat(),
        );
        transcript.append_message(
            b"(S, T, A, B_x, B_y, E, F)",
            &[
                self.S.to_bytes(),
                self.T.to_bytes(),
                self.A.to_bytes(),
                bincode::serialize(&self.B_x).unwrap(),
                self.B_y.to_bytes(),
                self.E.to_bytes(),
                self.F.to_bytes(),
            ]
            .concat(),
        );

        // Verifier is supposed to sample from e in +- q (where q is the group order), we sample from
        // [0, 2*q] instead
        let e =
            bn_random_from_transcript(&mut transcript, &(BigNumber::from(2u64) * &k256_order()));

        if e != self.e {
            return verify_err!("Fiat-Shamir consistency check failed");
        }

        let N0_squared = &input.N0 * &input.N0;
        let N1_squared = &input.N1 * &input.N1;

        // Do equality checks

        let eq_check_1 = {
            let a = modpow(&input.C, &self.z1, &N0_squared);
            let b = modpow(&(BigNumber::one() + &input.N0), &self.z2, &N0_squared);
            let c = modpow(&self.w, &input.N0, &N0_squared);
            let lhs = a.modmul(&b, &N0_squared).modmul(&c, &N0_squared);
            let rhs = self
                .A
                .modmul(&modpow(&input.D, &self.e, &N0_squared), &N0_squared);
            lhs == rhs
        };
        if !eq_check_1 {
            return verify_err!("eq_check_1 failed");
        }

        let eq_check_2 = {
            let lhs = CurvePoint(input.g.0 * utils::bn_to_scalar(&self.z1).unwrap());
            let rhs = CurvePoint(self.B_x.0 + input.X.0 * utils::bn_to_scalar(&self.e).unwrap());
            lhs == rhs
        };
        if !eq_check_2 {
            return verify_err!("eq_check_2 failed");
        }

        let eq_check_3 = {
            let a = modpow(&(BigNumber::one() + &input.N1), &self.z2, &N1_squared);
            let b = modpow(&self.w_y, &input.N1, &N1_squared);
            let lhs = a.modmul(&b, &N1_squared);
            let rhs = self
                .B_y
                .modmul(&modpow(&input.Y, &self.e, &N1_squared), &N1_squared);
            lhs == rhs
        };
        if !eq_check_3 {
            return verify_err!("eq_check_3 failed");
        }

        let eq_check_4 = {
            let a = modpow(&input.setup_params.s, &self.z1, &input.setup_params.N);
            let b = modpow(&input.setup_params.t, &self.z3, &input.setup_params.N);
            let lhs = a.modmul(&b, &input.setup_params.N);
            let rhs = self.E.modmul(
                &modpow(&self.S, &self.e, &input.setup_params.N),
                &input.setup_params.N,
            );
            lhs == rhs
        };
        if !eq_check_4 {
            return verify_err!("eq_check_4 failed");
        }

        let eq_check_5 = {
            let a = modpow(&input.setup_params.s, &self.z2, &input.setup_params.N);
            let b = modpow(&input.setup_params.t, &self.z4, &input.setup_params.N);
            let lhs = a.modmul(&b, &input.setup_params.N);
            let rhs = self.F.modmul(
                &modpow(&self.T, &self.e, &input.setup_params.N),
                &input.setup_params.N,
            );
            lhs == rhs
        };
        if !eq_check_5 {
            return verify_err!("eq_check_5 failed");
        }

        // Do range check

        let ell_bound = BigNumber::one() << (ELL + EPSILON + 1);
        let ell_prime_bound = BigNumber::one() << (ELL_PRIME + EPSILON + 1);
        if self.z1 > ell_bound || self.z2 > ell_prime_bound {
            return verify_err!("self.z1 > ell_bound || self.z2 > ell_prime_bound check failed");
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use libpaillier::*;
    use rand::rngs::OsRng;

    fn random_paillier_affg_proof(k_range: usize) -> Result<()> {
        let mut rng = OsRng;

        let p0 = crate::get_random_safe_prime_512();
        let q0 = crate::get_random_safe_prime_512();
        let N0 = &p0 * &q0;

        let p1 = crate::get_random_safe_prime_512();
        let q1 = crate::get_random_safe_prime_512();
        let N1 = &p1 * &q1;

        let sk0 = DecryptionKey::with_safe_primes_unchecked(&p0, &q0).unwrap();
        let pk0 = EncryptionKey::from(&sk0);

        let sk1 = DecryptionKey::with_safe_primes_unchecked(&p1, &q1).unwrap();
        let pk1 = EncryptionKey::from(&sk1);

        let x = random_bn_in_range(&mut rng, k_range);
        let y = random_bn_in_range(&mut rng, k_range);

        let g = k256::ProjectivePoint::GENERATOR;

        let X = CurvePoint(g * utils::bn_to_scalar(&x).unwrap());
        let (Y, rho_y) = pk1.encrypt(&y.to_bytes(), None).unwrap();

        let N0_squared = &N0 * &N0;
        let C = random_bn(&mut rng, &N0_squared);

        // Compute D = C^x * (1 + N0)^y rho^N0 (mod N0^2)
        let (D, rho) = {
            let (D_intermediate, rho) = pk0.encrypt(&y.to_bytes(), None).unwrap();
            let D = modpow(&C, &x, &N0_squared).modmul(&D_intermediate, &N0_squared);
            (D, rho)
        };

        let setup_params = ZkSetupParameters::gen(&mut rng)?;

        let input = PiAffgInput::new(&setup_params, &CurvePoint(g), &N0, &N1, &C, &D, &Y, &X);
        let proof = PiAffgProof::prove(&mut rng, &input, &PiAffgSecret::new(&x, &y, &rho, &rho_y))?;

        proof.verify(&input)
    }

    #[test]
    fn test_paillier_affg_proof() -> Result<()> {
        // FIXME: extend to supporting ELL_PRIME different from ELL

        // Sampling x,y in the range 2^ELL should always succeed
        let result = random_paillier_affg_proof(ELL);
        assert!(result.is_ok());

        // Sampling x,y in the range 2^{ELL + EPSILON + 100} should (usually) fail
        assert!(random_paillier_affg_proof(ELL + EPSILON + 100).is_err());

        Ok(())
    }
}
