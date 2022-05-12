// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

//! Implements the ZKP from Figure 22 of https://eprint.iacr.org/2021/060.pdf

use super::Proof;
use crate::errors::*;
use crate::utils::{self, bn_random_from_transcript};
use libpaillier::unknown_order::BigNumber;
use merlin::Transcript;
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use utils::CurvePoint;

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct PiSchProof {
    alpha: BigNumber,
    A: CurvePoint,
    e: BigNumber,
    z: BigNumber,
}

pub(crate) struct PiSchInput {
    g: CurvePoint,
    q: BigNumber,
    X: CurvePoint,
}

impl PiSchInput {
    #[cfg(test)]
    pub(crate) fn new(g: &CurvePoint, q: &BigNumber, X: &CurvePoint) -> Self {
        Self {
            g: *g,
            q: q.clone(),
            X: *X,
        }
    }
}

pub(crate) struct PiSchSecret {
    x: BigNumber,
}

impl PiSchSecret {
    #[cfg(test)]
    pub(crate) fn new(x: &BigNumber) -> Self {
        Self { x: x.clone() }
    }
}

impl Proof for PiSchProof {
    type CommonInput = PiSchInput;
    type ProverSecret = PiSchSecret;

    #[cfg_attr(feature = "flame_it", flame("PiSchProof"))]
    fn prove<R: RngCore + CryptoRng>(
        rng: &mut R,
        input: &Self::CommonInput,
        secret: &Self::ProverSecret,
    ) -> Result<Self> {
        // Sample alpha from F_q
        let alpha = crate::utils::random_bn(rng, &input.q);
        let A = CurvePoint(input.g.0 * utils::bn_to_scalar(&alpha).unwrap());

        let mut transcript = Transcript::new(b"PiSchProof");
        transcript.append_message(
            b"(g, q, X)",
            &[
                bincode::serialize(&input.g).unwrap(),
                input.q.to_bytes(),
                bincode::serialize(&input.X).unwrap(),
            ]
            .concat(),
        );
        transcript.append_message(b"alpha", &alpha.to_bytes());
        transcript.append_message(b"A", &bincode::serialize(&A).unwrap());

        // Verifier samples e in F_q
        let e = bn_random_from_transcript(&mut transcript, &input.q);

        let z = &alpha + &e * &secret.x;

        let proof = Self { alpha, A, e, z };
        Ok(proof)
    }

    #[cfg_attr(feature = "flame_it", flame("PiEncProof"))]
    fn verify(&self, input: &Self::CommonInput) -> Result<()> {
        // First check Fiat-Shamir challenge consistency

        let mut transcript = Transcript::new(b"PiSchProof");
        transcript.append_message(
            b"(g, q, X)",
            &[
                bincode::serialize(&input.g).unwrap(),
                input.q.to_bytes(),
                bincode::serialize(&input.X).unwrap(),
            ]
            .concat(),
        );
        transcript.append_message(b"alpha", &self.alpha.to_bytes());
        transcript.append_message(b"A", &bincode::serialize(&self.A).unwrap());

        // Verifier samples e in F_q
        let e = bn_random_from_transcript(&mut transcript, &input.q);
        if e != self.e {
            return verify_err!("Fiat-Shamir consistency check failed");
        }

        // Do equality checks

        let eq_check_1 = {
            let lhs = CurvePoint(input.g.0 * utils::bn_to_scalar(&self.z).unwrap());
            let rhs = CurvePoint(self.A.0 + input.X.0 * utils::bn_to_scalar(&self.e).unwrap());
            lhs == rhs
        };
        if !eq_check_1 {
            return verify_err!("eq_check_1 failed");
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    fn random_schnorr_proof(additive: bool) -> Result<(PiSchInput, PiSchProof)> {
        let mut rng = OsRng;

        let q = crate::utils::k256_order();
        let g = CurvePoint(k256::ProjectivePoint::GENERATOR);

        let mut x = crate::utils::random_bn(&mut rng, &q);
        let X = CurvePoint(g.0 * utils::bn_to_scalar(&x).unwrap());
        if additive {
            x += crate::utils::random_bn(&mut rng, &q);
        }

        let input = PiSchInput::new(&g, &q, &X);
        let proof = PiSchProof::prove(&mut rng, &input, &PiSchSecret::new(&x))?;

        Ok((input, proof))
    }

    #[test]
    fn test_schnorr_proof() -> Result<()> {
        let (input, proof) = random_schnorr_proof(false)?;
        assert!(proof.verify(&input).is_ok());

        let (input, proof) = random_schnorr_proof(true)?;
        assert!(!proof.verify(&input).is_ok());

        Ok(())
    }
}
