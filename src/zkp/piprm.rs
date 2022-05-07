// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

//! Implements the ZKP from Figure 17 of https://eprint.iacr.org/2021/060.pdf

use crate::errors::*;
use crate::utils::*;
use libpaillier::unknown_order::BigNumber;
use merlin::Transcript;
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use std::convert::TryInto;

use super::Proof;

// Soundness parameter lambda.
// Must be a multiple of 8
const LAMBDA: usize = crate::parameters::SOUNDNESS_PARAMETER;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PiPrmProof {
    a_values: [BigNumber; LAMBDA],
    e_values: [bool; LAMBDA],
    z_values: [BigNumber; LAMBDA],
}

pub(crate) struct PiPrmInput {
    N: BigNumber,
    s: BigNumber,
    t: BigNumber,
}

impl PiPrmInput {
    pub(crate) fn new(N: &BigNumber, s: &BigNumber, t: &BigNumber) -> Self {
        Self {
            N: N.clone(),
            s: s.clone(),
            t: t.clone(),
        }
    }
}

pub(crate) struct PiPrmSecret {
    lambda: BigNumber,
    phi_n: BigNumber,
}

impl PiPrmSecret {
    pub(crate) fn new(lambda: &BigNumber, phi_n: &BigNumber) -> Self {
        Self {
            lambda: lambda.clone(),
            phi_n: phi_n.clone(),
        }
    }
}

impl Proof for PiPrmProof {
    type CommonInput = PiPrmInput;
    type ProverSecret = PiPrmSecret;

    // Needs to be the case that s = t^lambda (mod N)
    #[cfg_attr(feature = "flame_it", flame("RingPedersenProof"))]
    fn prove<R: RngCore + CryptoRng>(
        rng: &mut R,
        input: &Self::CommonInput,
        secret: &Self::ProverSecret,
    ) -> Result<Self> {
        let mut secret_a_values = vec![];
        let mut public_a_values = vec![];

        for _ in 0..LAMBDA {
            let a = random_bn(rng, &secret.phi_n);
            let a_commit = modpow(&input.t, &a, &input.N);

            secret_a_values.push(a);
            public_a_values.push(a_commit);
        }

        let e_values = generate_e_from_a(&public_a_values);
        let mut z_values = vec![];
        for i in 0..LAMBDA {
            let z = match e_values[i] {
                true => secret_a_values[i].modadd(&secret.lambda, &secret.phi_n),
                false => secret_a_values[i].clone(),
            };
            z_values.push(z);
        }

        let proof = Self {
            a_values: public_a_values
                .try_into()
                .map_err(|_| InternalError::Serialization)?,
            e_values,
            z_values: z_values
                .try_into()
                .map_err(|_| InternalError::Serialization)?,
        };

        Ok(proof)
    }

    #[cfg_attr(feature = "flame_it", flame("RingPedersenProof"))]
    fn verify(&self, input: &Self::CommonInput) -> Result<()> {
        if self.a_values.len() != LAMBDA
            || self.e_values.len() != LAMBDA
            || self.z_values.len() != LAMBDA
        {
            // Ensure that everything should be the same length LAMBDA
            return verify_err!("Check that everything should be the same length LAMBDA failed");
        }

        // FIXME: Also need to check that s and t are mod N, as well as a and z values

        let e_values = generate_e_from_a(&self.a_values);

        // Check Fiat-Shamir consistency
        if e_values != self.e_values {
            return verify_err!("Fiat-Shamir consistency check failed");
        }

        for (i, e) in e_values.iter().enumerate() {
            // Verify that t^z = A * s^e (mod N)
            let lhs = modpow(&input.t, &self.z_values[i], &input.N);
            let rhs = match e {
                true => self.a_values[i].modmul(&input.s, &input.N),
                false => self.a_values[i].modadd(&BigNumber::zero(), &input.N),
            };
            if lhs != rhs {
                return verify_err!("Verify that t^z = A * s^e (mod N) check failed");
            }
        }

        Ok(())
    }
}

#[cfg_attr(feature = "flame_it", flame("RingPedersenProof"))]
fn generate_e_from_a(a_values: &[BigNumber]) -> [bool; LAMBDA] {
    let mut e_values = [false; LAMBDA];

    let mut transcript = Transcript::new(b"RingPedersenProof");
    for i in 0..LAMBDA {
        transcript.append_message(b"A_i", &a_values[i].to_bytes());
        let mut e = vec![0u8; 1];
        transcript.challenge_bytes(b"sampling randomness", e.as_mut_slice());
        e_values[i] = e[0] % 2 == 1; // Ensure that it's either a 0 or a 1
    }

    e_values
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    fn random_ring_pedersen_proof() -> Result<(PiPrmInput, PiPrmProof)> {
        let p = crate::get_random_safe_prime_512();
        let q = crate::get_random_safe_prime_512();
        let N = &p * &q;
        let phi_n = (p - 1) * (q - 1);
        let tau = BigNumber::random(&N);
        let lambda = BigNumber::random(&phi_n);
        let t = modpow(&tau, &BigNumber::from(2), &N);
        let s = modpow(&t, &lambda, &N);

        let mut rng = OsRng;
        let input = PiPrmInput::new(&N, &s, &t);
        let proof = PiPrmProof::prove(&mut rng, &input, &PiPrmSecret::new(&lambda, &phi_n))?;
        Ok((input, proof))
    }

    #[test]
    fn test_ring_pedersen_proof() -> Result<()> {
        let (input, proof) = random_ring_pedersen_proof()?;
        assert!(proof.verify(&input).is_ok());

        Ok(())
    }

    #[test]
    fn test_ring_pedersen_proof_roundtrip() -> Result<()> {
        let (_, proof) = random_ring_pedersen_proof()?;
        let buf = bincode::serialize(&proof).unwrap();
        let orig: PiPrmProof = bincode::deserialize(&buf).unwrap();
        assert_eq!(buf, bincode::serialize(&orig).unwrap());
        Ok(())
    }
}
