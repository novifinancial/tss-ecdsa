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
use std::convert::TryInto;

// Soundness parameter lambda: FIXME: This needs to be 128
// Must be a multiple of 8
const LAMBDA: usize = 16;

#[derive(Debug)]
pub struct RingPedersenProof {
    pub(crate) N: BigNumber,
    pub(crate) s: BigNumber,
    pub(crate) t: BigNumber,
    a_values: [BigNumber; LAMBDA],
    e_values: [bool; LAMBDA],
    z_values: [BigNumber; LAMBDA],
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

impl RingPedersenProof {
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let result = [
            serialize(&self.N.to_bytes(), 2)?,
            serialize(&self.s.to_bytes(), 2)?,
            serialize(&self.t.to_bytes(), 2)?,
            serialize_vec(&self.a_values)?,
            self.e_values.to_vec().iter().map(|&x| x as u8).collect(),
            serialize_vec(&self.z_values)?,
        ]
        .concat();
        Ok(result)
    }

    pub fn from_slice(input: &[u8]) -> Result<Self> {
        let (n_bytes, input) = tokenize(input, 2)?;
        let (s_bytes, input) = tokenize(&input, 2)?;
        let (t_bytes, input) = tokenize(&input, 2)?;
        let (a_values, input) = tokenize_vec(&input)?;

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

        let N = BigNumber::from_slice(n_bytes);
        let s = BigNumber::from_slice(s_bytes);
        let t = BigNumber::from_slice(t_bytes);

        let mut e_values = [false; LAMBDA];
        e_values[..].clone_from_slice(&e_values_vec[..]);

        Ok(Self {
            N,
            s,
            t,
            a_values,
            e_values,
            z_values,
        })
    }
}

impl RingPedersenProof {
    // Needs to be the case that s = t^lambda (mod N)
    #[cfg_attr(feature = "flame_it", flame("RingPedersenProof"))]
    pub(crate) fn gen(
        N: &BigNumber,
        phi_n: &BigNumber,
        s: &BigNumber,
        t: &BigNumber,
        lambda: &BigNumber,
    ) -> Result<Self> {
        let mut secret_a_values = vec![];
        let mut public_a_values = vec![];

        for _ in 0..LAMBDA {
            let a = BigNumber::random(phi_n);
            let a_commit = modpow(t, &a, N);

            secret_a_values.push(a);
            public_a_values.push(a_commit);
        }

        let e_values = generate_e_from_a(&public_a_values);
        let mut z_values = vec![];
        for i in 0..LAMBDA {
            let z = match e_values[i] {
                true => secret_a_values[i].modadd(lambda, phi_n),
                false => secret_a_values[i].clone(),
            };
            z_values.push(z);
        }

        let proof = Self {
            N: N.clone(),
            s: s.clone(),
            t: t.clone(),
            a_values: public_a_values
                .try_into()
                .map_err(|_| InternalError::Serialization)?,
            e_values,
            z_values: z_values
                .try_into()
                .map_err(|_| InternalError::Serialization)?,
        };

        match proof.verify() {
            true => Ok(proof),
            false => Err(InternalError::CouldNotGenerateProof),
        }
    }

    #[cfg_attr(feature = "flame_it", flame("RingPedersenProof"))]
    pub(crate) fn verify(&self) -> bool {
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
            let lhs = modpow(&self.t, &self.z_values[i], &self.N);
            let rhs = match e {
                true => self.a_values[i].modmul(&self.s, &self.N),
                false => self.a_values[i].modadd(&BigNumber::zero(), &self.N),
            };
            if lhs != rhs {
                return false;
            }
        }

        true
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

    fn random_ring_pedersen_proof() -> Result<RingPedersenProof> {
        let p = crate::get_random_safe_prime_512();
        let q = crate::get_random_safe_prime_512();
        let N = &p * &q;
        let phi_n = (p - 1) * (q - 1);
        let tau = BigNumber::random(&N);
        let lambda = BigNumber::random(&phi_n);
        let t = modpow(&tau, &BigNumber::from(2), &N);
        let s = modpow(&t, &lambda, &N);
        RingPedersenProof::gen(&N, &phi_n, &s, &t, &lambda)
    }

    #[test]
    fn test_ring_pedersen_proof() -> Result<()> {
        let proof = random_ring_pedersen_proof()?;
        assert!(proof.verify());
        Ok(())
    }

    #[test]
    fn test_ring_pedersen_proof_roundtrip() -> Result<()> {
        let proof = random_ring_pedersen_proof()?;
        let buf = proof.to_bytes()?;
        let orig = RingPedersenProof::from_slice(&buf).unwrap();
        assert_eq!(buf, orig.to_bytes()?);
        Ok(())
    }
}
