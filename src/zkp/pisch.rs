// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

//! Implements the ZKP from Figure 22 of https://eprint.iacr.org/2021/060.pdf

use super::Proof;
use crate::errors::*;
use crate::serialization::*;
use crate::utils::{self, bn_random_from_transcript};
use ecdsa::elliptic_curve::group::GroupEncoding;
use libpaillier::unknown_order::BigNumber;
use merlin::Transcript;
use rand::{CryptoRng, RngCore};

#[derive(Debug)]
pub struct PiSchProof {
    alpha: BigNumber,
    A: k256::ProjectivePoint,
    e: BigNumber,
    z: BigNumber,
}

pub(crate) struct PiSchInput {
    g: k256::ProjectivePoint,
    q: BigNumber,
    X: k256::ProjectivePoint,
}

impl PiSchInput {
    #[cfg(test)]
    pub(crate) fn new(g: &k256::ProjectivePoint, q: &BigNumber, X: &k256::ProjectivePoint) -> Self {
        Self {
            g: g.clone(),
            q: q.clone(),
            X: X.clone(),
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
        let A = input.g * utils::bn_to_scalar(&alpha).unwrap();

        let mut transcript = Transcript::new(b"PiSchProof");
        transcript.append_message(
            b"(g, q, X)",
            &[
                input.g.to_bytes().to_vec(),
                input.q.to_bytes(),
                input.X.to_bytes().to_vec(),
            ]
            .concat(),
        );
        transcript.append_message(b"alpha", &alpha.to_bytes());
        transcript.append_message(b"A", &A.to_bytes());

        // Verifier samples e in F_q
        let e = bn_random_from_transcript(&mut transcript, &input.q);

        let z = &alpha + &e * &secret.x;

        let proof = Self { alpha, A, e, z };
        Ok(proof)
    }

    #[cfg_attr(feature = "flame_it", flame("PiEncProof"))]
    fn verify(&self, input: &Self::CommonInput) -> bool {
        // First check Fiat-Shamir challenge consistency

        let mut transcript = Transcript::new(b"PiSchProof");
        transcript.append_message(
            b"(g, q, X)",
            &[
                input.g.to_bytes().to_vec(),
                input.q.to_bytes(),
                input.X.to_bytes().to_vec(),
            ]
            .concat(),
        );
        transcript.append_message(b"alpha", &self.alpha.to_bytes());
        transcript.append_message(b"A", &self.A.to_bytes());

        // Verifier samples e in F_q
        let e = bn_random_from_transcript(&mut transcript, &input.q);
        if e != self.e {
            // Fiat-Shamir didn't verify
            return false;
        }

        // Do equality checks

        let eq_check_1 = {
            let lhs = input.g * utils::bn_to_scalar(&self.z).unwrap();
            let rhs = self.A + input.X * utils::bn_to_scalar(&self.e).unwrap();
            lhs == rhs
        };
        if !eq_check_1 {
            // Failed equality check 1
            return false;
        }

        true
    }

    fn to_bytes(&self) -> Result<Vec<u8>> {
        let result = [
            serialize(&self.alpha.to_bytes(), 2)?,
            serialize(&self.A.to_bytes(), 2)?,
            serialize(&self.e.to_bytes(), 2)?,
            serialize(&self.z.to_bytes(), 2)?,
        ]
        .concat();
        Ok(result)
    }

    fn from_slice<B: Clone + AsRef<[u8]>>(buf: B) -> Result<Self> {
        let (alpha_bytes, input) = tokenize(buf.as_ref(), 2)?;
        let (A_bytes, input) = tokenize(&input, 2)?;
        let (e_bytes, input) = tokenize(&input, 2)?;
        let (z_bytes, input) = tokenize(&input, 2)?;

        if !input.is_empty() {
            // Should not be encountering any more bytes
            return Err(InternalError::Serialization);
        }

        let alpha = BigNumber::from_slice(alpha_bytes);
        let A = utils::point_from_bytes(&A_bytes)?;
        let e = BigNumber::from_slice(e_bytes);
        let z = BigNumber::from_slice(z_bytes);

        Ok(Self { alpha, A, e, z })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    fn random_schnorr_proof(additive: bool) -> Result<(PiSchInput, PiSchProof)> {
        let mut rng = OsRng;

        let q = crate::utils::k256_order();
        let g = k256::ProjectivePoint::generator();

        let mut x = crate::utils::random_bn(&mut rng, &q);
        let X = g * utils::bn_to_scalar(&x).unwrap();
        if additive {
            x = x + crate::utils::random_bn(&mut rng, &q);
        }

        let input = PiSchInput::new(&g, &q, &X);
        let proof = PiSchProof::prove(&mut rng, &input, &PiSchSecret::new(&x))?;

        Ok((input, proof))
    }

    #[test]
    fn test_schnorr_proof() -> Result<()> {
        let (input, proof) = random_schnorr_proof(false)?;
        assert!(proof.verify(&input));

        let (input, proof) = random_schnorr_proof(true)?;
        assert!(!proof.verify(&input));

        Ok(())
    }
}
