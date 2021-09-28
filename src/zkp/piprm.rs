// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

//! Implements the ZKP from Figure 17 of https://eprint.iacr.org/2021/060.pdf

use crate::errors::*;
use crate::serialization::*;
use crate::utils::*;
use libpaillier::unknown_order::BigNumber;
use merlin::Transcript;
use rand::{CryptoRng, RngCore};
use std::convert::TryInto;

use super::Proof;

// Soundness parameter lambda: FIXME: This needs to be 128
// Must be a multiple of 8
const LAMBDA: usize = 16;

#[derive(Debug, Clone)]
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

        match proof.verify(input) {
            true => Ok(proof),
            false => Err(InternalError::CouldNotGenerateProof),
        }
    }

    #[cfg_attr(feature = "flame_it", flame("RingPedersenProof"))]
    fn verify(&self, input: &Self::CommonInput) -> bool {
        if self.a_values.len() != LAMBDA
            || self.e_values.len() != LAMBDA
            || self.z_values.len() != LAMBDA
        {
            // Ensure that everything should be the same length LAMBDA
            return false;
        }

        // FIXME: Also need to check that s and t are mod N, as well as a and z values

        let e_values = generate_e_from_a(&self.a_values);

        // Check Fiat-Shamir consistency
        if e_values != self.e_values {
            return false;
        }

        for (i, e) in e_values.iter().enumerate() {
            // Verify that t^z = A * s^e (mod N)
            let lhs = modpow(&input.t, &self.z_values[i], &input.N);
            let rhs = match e {
                true => self.a_values[i].modmul(&input.s, &input.N),
                false => self.a_values[i].modadd(&BigNumber::zero(), &input.N),
            };
            if lhs != rhs {
                return false;
            }
        }

        true
    }

    fn to_bytes(&self) -> Result<Vec<u8>> {
        let result = [
            serialize_vec(&self.a_values)?,
            self.e_values.to_vec().iter().map(|&x| x as u8).collect(),
            serialize_vec(&self.z_values)?,
        ]
        .concat();
        Ok(result)
    }

    fn from_slice<B: Clone + AsRef<[u8]>>(buf: B) -> Result<Self> {
        let (a_values, input) = tokenize_vec(buf.as_ref())?;

        if input.len() < LAMBDA {
            // Not enough bytes remaining to deserialize properly
            return Err(InternalError::Serialization);
        }

        let e_values_vec: Vec<bool> = input[..LAMBDA].iter().map(|&x| x != 0).collect();
        let (z_values, input) = tokenize_vec(&input[LAMBDA..])?;

        if !input.is_empty() {
            // Should not be encountering any more bytes
            return Err(InternalError::Serialization);
        }
        let mut e_values = [false; LAMBDA];
        e_values[..].clone_from_slice(&e_values_vec[..]);

        Ok(Self {
            a_values,
            e_values,
            z_values,
        })
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

fn serialize_vec(input: &[BigNumber; LAMBDA]) -> Result<Vec<u8>> {
    let mut result = vec![];
    for x in input {
        result.extend_from_slice(&serialize(&x.to_bytes(), 2)?);
    }
    Ok(result)
}

fn tokenize_vec(input: &[u8]) -> Result<([BigNumber; LAMBDA], Vec<u8>)> {
    let mut bytes = input.to_vec();
    let mut result = vec![];
    for _ in 0..LAMBDA {
        let (value, bytes_copy) = tokenize(&bytes, 2)?;
        bytes = bytes_copy;
        result.push(BigNumber::from_slice(&value));
    }
    let result_arr = result
        .try_into()
        .map_err(|_| InternalError::Serialization)?;
    Ok((result_arr, bytes))
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
        assert!(proof.verify(&input));
        Ok(())
    }

    #[test]
    fn test_ring_pedersen_proof_roundtrip() -> Result<()> {
        let (_, proof) = random_ring_pedersen_proof()?;
        let buf = proof.to_bytes()?;
        let orig = PiPrmProof::from_slice(&buf).unwrap();
        assert_eq!(buf, orig.to_bytes()?);
        Ok(())
    }
}
