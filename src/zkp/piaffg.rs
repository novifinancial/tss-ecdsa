// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

//! Implements the ZKP from Figure 14 of https://eprint.iacr.org/2021/060.pdf
//!
//! Proves that the plaintext of the Paillier ciphertext K_i lies within the range
//! [1, 2^{ELL+EPSILON+1}]

use crate::utils::{self, modpow, random_bn, random_bn_in_range, random_bn_in_z_star, bn_random_from_transcript, k256_order};
use crate::zkp::setup::ZkSetupParameters;
use crate::{errors::*, Ciphertext, ELL, EPSILON};
use ecdsa::elliptic_curve::group::GroupEncoding;
use libpaillier::unknown_order::BigNumber;
use merlin::Transcript;
use rand::rngs::OsRng;

#[derive(Debug)]
pub struct PiAffgProof {
    pub(crate) setup_params: ZkSetupParameters,
    alpha: BigNumber,
    beta: BigNumber,
    S: BigNumber,
    T: BigNumber,
    A: BigNumber,
    B_x: k256::ProjectivePoint,
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

// Common input is: g, N0, N1, C, D, Y, X
// Prover secrets are: (x, y, rho, rho_y)
//
// (Note that we use ELL = ELL' from the paper)
impl PiAffgProof {

    // N0: modulus, K: Paillier ciphertext
    #[cfg_attr(feature = "flame_it", flame("PiAffgProof"))]
    pub(crate) fn prove(
        setup_params: &ZkSetupParameters,
        g: &k256::ProjectivePoint,
        N0: &BigNumber,
        N1: &BigNumber,
        C: &BigNumber,
        D: &BigNumber,
        Y: &BigNumber,
        X: &BigNumber,
        x: &BigNumber,
        y: &BigNumber,
        rho: &BigNumber,
        rho_y: &BigNumber,
    ) -> Result<Self> {
        let mut rng = OsRng;
        // Sample alpha from 2^{ELL + EPSILON}
        let alpha = random_bn_in_range(&mut rng, ELL + EPSILON);
        // Sample beta from 2^{ELL + EPSILON}.
        let beta = random_bn_in_range(&mut rng, ELL + EPSILON);

        let r = random_bn_in_z_star(&mut rng, N0);
        let r_y = random_bn_in_z_star(&mut rng, N1);

        let gamma = random_bn_in_range(&mut rng, ELL + EPSILON);
        let delta = random_bn_in_range(&mut rng, ELL + EPSILON);

        // range = 2^{ELL+1} * N_hat
        let range = (BigNumber::one() << (ELL+1)) * &setup_params.N;
        let m = random_bn(&mut rng, &range);
        let mu = random_bn(&mut rng, &range);

        let N0_squared = N0 * N0;
        let N1_squared = N0 * N0;


        let A = {
            let a = modpow(C, &alpha, &N0_squared);
            let b = {
                let c = modpow(&(BigNumber::one() + N0), &beta, &N0_squared);
                let d = modpow(&r, N0, &N0_squared);
                c.modmul(&d, &N0_squared)
            };
            a.modmul(&b, &N0_squared)
        };
        let B_x = g * &utils::bn_to_scalar(&alpha).unwrap();
        let B_y = {
            let a = modpow(&(BigNumber::one() + N1), &beta, &N1_squared);
            let b = modpow(&r_y, &N1, &N1_squared);
            a.modmul(&b, &N1_squared)
        };
        let E = {
            let a = modpow(&setup_params.s, &alpha, &setup_params.N);
            let b = modpow(&setup_params.t, &gamma, &setup_params.N);
            a.modmul(&b, &setup_params.N)
        };
        let S = {
            let a = modpow(&setup_params.s, &x, &setup_params.N);
            let b = modpow(&setup_params.t, &m, &setup_params.N);
            a.modmul(&b, &setup_params.N)
        };
        let F = {
            let a = modpow(&setup_params.s, &beta, &setup_params.N);
            let b = modpow(&setup_params.t, &delta, &setup_params.N);
            a.modmul(&b, &setup_params.N)
        };
        let T = {
            let a = modpow(&setup_params.s, &y, &setup_params.N);
            let b = modpow(&setup_params.t, &mu, &setup_params.N);
            a.modmul(&b, &setup_params.N)
        };

        let mut transcript = Transcript::new(b"PiAffgProof");
        transcript.append_message(
            b"(N, s, t)",
            &[
                setup_params.N.to_bytes(),
                setup_params.s.to_bytes(),
                setup_params.t.to_bytes(),
            ]
            .concat(),
        );
        transcript.append_message(
            b"(S, T, A, B_x, B_y, E, F)",
            &[S.to_bytes(), T.to_bytes(), A.to_bytes(), B_x.to_bytes().to_vec(), B_y.to_bytes(), E.to_bytes(), F.to_bytes()].concat(),
        );

        // Verifier is supposed to sample from e in +- q (where q is the group order), we sample from
        // [0, 2*q] instead
        let e = bn_random_from_transcript(&mut transcript, &(BigNumber::from(2) * &k256_order()));

        let z1 = &alpha + &e * x;
        let z2 = &beta + &e * y;
        let z3 = gamma + &e * m;
        let z4 = delta + &e * mu;
        let w = r.modmul(&modpow(rho, &e, N0), N0);
        let w_y = r_y.modmul(&modpow(rho_y, &e, N1), N1);

        Ok(Self {
            setup_params: setup_params.clone(),
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
            w_y
        })
    }

    fn verify(&self) -> bool {

    }
}
