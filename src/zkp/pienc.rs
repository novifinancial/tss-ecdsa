// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

//! Implements the ZKP from Figure 14 of https://eprint.iacr.org/2021/060.pdf
//!
//! Proves that the plaintext of the Paillier ciphertext K_i lies within the range
//! [1, 2^{ELL+EPSILON+1}]

use super::Proof;
use crate::serialization::*;
use crate::utils::{
    bn_random_from_transcript, k256_order, modpow, random_bn_in_range, random_bn_in_z_star,
};
use crate::zkp::setup::ZkSetupParameters;
use crate::{
    errors::*,
    parameters::{ELL, EPSILON},
    Ciphertext,
};
use libpaillier::unknown_order::BigNumber;
use merlin::Transcript;
use rand::{CryptoRng, RngCore};

#[derive(Debug, Clone)]
pub struct PiEncProof {
    alpha: BigNumber,
    S: BigNumber,
    A: BigNumber,
    C: BigNumber,
    e: BigNumber,
    z1: BigNumber,
    z2: BigNumber,
    z3: BigNumber,
}

pub(crate) struct PiEncInput {
    setup_params: ZkSetupParameters,
    N0: BigNumber,
    K: Ciphertext,
}

impl PiEncInput {
    pub(crate) fn new(setup_params: &ZkSetupParameters, N0: &BigNumber, K: &Ciphertext) -> Self {
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
        // Sample alpha from 2^{ELL + EPSILON}
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
        transcript.append_message(
            b"(N, s, t)",
            &[
                input.setup_params.N.to_bytes(),
                input.setup_params.s.to_bytes(),
                input.setup_params.t.to_bytes(),
            ]
            .concat(),
        );
        transcript.append_message(b"alpha", &alpha.to_bytes());
        transcript.append_message(
            b"(S, A, C)",
            &[S.to_bytes(), A.to_bytes(), C.to_bytes()].concat(),
        );

        // Verifier is supposed to sample from e in +- q (where q is the group order), we sample from
        // [0, 2*q] instead
        let e = bn_random_from_transcript(&mut transcript, &(BigNumber::from(2) * &k256_order()));

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
    fn verify(&self, input: &Self::CommonInput) -> bool {
        // First check Fiat-Shamir challenge consistency

        let mut transcript = Transcript::new(b"PiEncProof");
        transcript.append_message(
            b"(N, s, t)",
            &[
                input.setup_params.N.to_bytes(),
                input.setup_params.s.to_bytes(),
                input.setup_params.t.to_bytes(),
            ]
            .concat(),
        );
        transcript.append_message(b"alpha", &self.alpha.to_bytes());
        transcript.append_message(
            b"(S, A, C)",
            &[self.S.to_bytes(), self.A.to_bytes(), self.C.to_bytes()].concat(),
        );

        let e = bn_random_from_transcript(&mut transcript, &(BigNumber::from(2) * &k256_order()));
        if e != self.e {
            // Fiat-Shamir didn't verify
            println!("Failing on Fiat-shamir verification!");
            return false;
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
            // Failed equality check 1
            println!("Failing on equality check 1");
            return false;
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
            // Failed equality check 2
            println!("Failing on equality check 2");
            return false;
        }

        // Do range check
        let bound = BigNumber::one() << (ELL + EPSILON + 1);
        if self.z1 > bound {
            return false;
        }

        true
    }

    fn to_bytes(&self) -> Result<Vec<u8>> {
        let result = [
            serialize(&self.alpha.to_bytes(), 2)?,
            serialize(&self.S.to_bytes(), 2)?,
            serialize(&self.A.to_bytes(), 2)?,
            serialize(&self.C.to_bytes(), 2)?,
            serialize(&self.e.to_bytes(), 2)?,
            serialize(&self.z1.to_bytes(), 2)?,
            serialize(&self.z2.to_bytes(), 2)?,
            serialize(&self.z3.to_bytes(), 2)?,
        ]
        .concat();
        Ok(result)
    }

    fn from_slice<B: Clone + AsRef<[u8]>>(buf: B) -> Result<Self> {
        let (alpha_bytes, input) = tokenize(buf.as_ref(), 2)?;
        let (S_bytes, input) = tokenize(&input, 2)?;
        let (A_bytes, input) = tokenize(&input, 2)?;
        let (C_bytes, input) = tokenize(&input, 2)?;
        let (e_bytes, input) = tokenize(&input, 2)?;
        let (z1_bytes, input) = tokenize(&input, 2)?;
        let (z2_bytes, input) = tokenize(&input, 2)?;
        let (z3_bytes, input) = tokenize(&input, 2)?;

        if !input.is_empty() {
            // Should not be encountering any more bytes
            return Err(InternalError::Serialization);
        }

        let alpha = BigNumber::from_slice(alpha_bytes);
        let S = BigNumber::from_slice(S_bytes);
        let A = BigNumber::from_slice(A_bytes);
        let C = BigNumber::from_slice(C_bytes);
        let e = BigNumber::from_slice(e_bytes);
        let z1 = BigNumber::from_slice(z1_bytes);
        let z2 = BigNumber::from_slice(z2_bytes);
        let z3 = BigNumber::from_slice(z3_bytes);

        Ok(Self {
            alpha,
            S,
            A,
            C,
            e,
            z1,
            z2,
            z3,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use libpaillier::*;
    use rand::rngs::OsRng;

    fn random_paillier_encryption_in_range_proof(k_range: usize) -> Result<()> {
        let mut rng = OsRng;

        let p = crate::get_random_safe_prime_512();
        let q = crate::get_random_safe_prime_512();
        let N = &p * &q;

        let sk = DecryptionKey::with_safe_primes_unchecked(&p, &q).unwrap();
        let pk = EncryptionKey::from(&sk);

        let k = random_bn_in_range(&mut rng, k_range);
        let (K, rho) = pk.encrypt(&k.to_bytes(), None).unwrap();
        let setup_params = ZkSetupParameters::gen(&mut rng)?;

        let input = PiEncInput {
            setup_params,
            N0: N,
            K: Ciphertext(K),
        };

        let proof = PiEncProof::prove(&mut rng, &input, &PiEncSecret { k, rho })?;

        let proof_bytes = proof.to_bytes()?;
        let roundtrip_proof = PiEncProof::from_slice(&proof_bytes)?;
        let roundtrip_proof_bytes = roundtrip_proof.to_bytes()?;
        assert_eq!(proof_bytes, roundtrip_proof_bytes);

        match proof.verify(&input) {
            true => Ok(()),
            false => Err(InternalError::CouldNotGenerateProof),
        }
    }

    #[test]
    fn test_paillier_encryption_in_range_proof() -> Result<()> {
        // Sampling k in the range 2^ELL should always succeed
        let result = random_paillier_encryption_in_range_proof(ELL);
        assert!(result.is_ok());

        // Sampling k in the range 2^{ELL + EPSILON + 100} should (usually) fail
        let result = random_paillier_encryption_in_range_proof(ELL + EPSILON + 100);
        assert!(match result {
            Err(InternalError::CouldNotGenerateProof) => true,
            _ => false,
        });

        Ok(())
    }
}
