// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

//! Implements the ZKP from Figure 14 of https://eprint.iacr.org/2021/060.pdf

use crate::utils::{modpow, random_bn_in_range, random_bn_in_z_star};
use crate::zkp::setup::ZkSetupParameters;
use crate::{errors::*, Ciphertext, ELL, EPSILON};
use libpaillier::unknown_order::BigNumber;
use merlin::Transcript;
use rand::rngs::OsRng;

#[derive(Debug)]
pub struct PaillierEncryptionInRangeProof {
    pub(crate) setup_params: ZkSetupParameters,
    pub(crate) N0: BigNumber,
    pub(crate) K: Ciphertext,
    alpha: BigNumber,
    S: BigNumber,
    A: BigNumber,
    C: BigNumber,
    e: BigNumber,
    z1: BigNumber,
    z2: BigNumber,
    z3: BigNumber,
}

impl PaillierEncryptionInRangeProof {
    // FIXME: could benefit from a batch API since this is done multiple times where
    // the only differing parameter is setup_params
    //
    // N0: modulus, K: Paillier ciphertext
    #[cfg_attr(feature = "flame_it", flame("PaillierEncryptionInRangeProof"))]
    pub(crate) fn prove(
        setup_params: &ZkSetupParameters,
        N0: &BigNumber,
        K: &Ciphertext,
        k: &BigNumber,
        rho: &BigNumber,
    ) -> Result<Self> {
        let mut rng = OsRng;
        // Sample alpha from 2^{ELL + EPSILON}
        let alpha = random_bn_in_range(&mut rng, ELL + EPSILON);

        let mu = random_bn_in_range(&mut rng, ELL) * &setup_params.N;
        let r = random_bn_in_z_star(&mut rng, N0);
        let gamma = random_bn_in_range(&mut rng, ELL + EPSILON) * &setup_params.N;

        let N0_squared = N0 * N0;

        let S = {
            let a = modpow(&setup_params.s, k, &setup_params.N);
            let b = modpow(&setup_params.t, &mu, &setup_params.N);
            a.modmul(&b, &setup_params.N)
        };
        let A = {
            let a = modpow(&(&BigNumber::one() + N0), &alpha, &N0_squared);
            let b = modpow(&r, N0, &N0_squared);
            a.modmul(&b, &N0_squared)
        };
        let C = {
            let a = modpow(&setup_params.s, &alpha, &setup_params.N);
            let b = modpow(&setup_params.t, &gamma, &setup_params.N);
            a.modmul(&b, &setup_params.N)
        };

        let mut transcript = Transcript::new(b"PaillierEncryptionInRangeProof");
        transcript.append_message(
            b"(N, s, t)",
            &[
                setup_params.N.to_bytes(),
                setup_params.s.to_bytes(),
                setup_params.t.to_bytes(),
            ]
            .concat(),
        );
        transcript.append_message(b"alpha", &alpha.to_bytes());
        transcript.append_message(
            b"(S, A, C)",
            &[S.to_bytes(), A.to_bytes(), C.to_bytes()].concat(),
        );

        // Verifier is supposed to sample from e in +- q (where q is the group order), but here we take a shortcut
        // and just sample from 2^256 since that is close enough
        let e = bn_random(&mut transcript, &BigNumber::from(256));

        let z1 = &alpha + &e * k;
        let z2 = r.modmul(&modpow(rho, &e, N0), N0);
        let z3 = gamma + &e * mu;

        let proof = Self {
            setup_params: setup_params.clone(),
            N0: N0.clone(),
            K: K.clone(),
            alpha,
            S,
            A,
            C,
            e,
            z1,
            z2,
            z3,
        };

        proof.verify();

        Ok(proof)
    }

    #[cfg_attr(feature = "flame_it", flame("PaillierEncryptionInRangeProof"))]
    pub(crate) fn verify(&self) -> bool {
        // First check Fiat-Shamir challenge consistency

        let mut transcript = Transcript::new(b"PaillierEncryptionInRangeProof");
        transcript.append_message(
            b"(N, s, t)",
            &[
                self.setup_params.N.to_bytes(),
                self.setup_params.s.to_bytes(),
                self.setup_params.t.to_bytes(),
            ]
            .concat(),
        );
        transcript.append_message(b"alpha", &self.alpha.to_bytes());
        transcript.append_message(
            b"(S, A, C)",
            &[self.S.to_bytes(), self.A.to_bytes(), self.C.to_bytes()].concat(),
        );

        let e = bn_random(&mut transcript, &BigNumber::from(256));
        if e != self.e {
            // Fiat-Shamir didn't verify
            return false;
        }

        let N0_squared = &self.N0 * &self.N0;

        // Do equality checks

        let eq_check_1 = {
            let a = modpow(&(&BigNumber::one() + &self.N0), &self.z1, &N0_squared);
            let b = modpow(&self.z2, &self.N0, &N0_squared);
            let lhs = a.modmul(&b, &N0_squared);
            let rhs = self
                .A
                .modmul(&modpow(&self.K.0, &e, &N0_squared), &N0_squared);
            lhs == rhs
        };
        if !eq_check_1 {
            // Failed equality check 1
            return false;
        }

        let eq_check_2 = {
            let a = modpow(&self.setup_params.s, &self.z1, &self.setup_params.N);
            let b = modpow(&self.setup_params.t, &self.z3, &self.setup_params.N);
            let lhs = a.modmul(&b, &self.setup_params.N);
            let rhs = self.C.modmul(
                &modpow(&self.S, &e, &self.setup_params.N),
                &self.setup_params.N,
            );
            lhs == rhs
        };
        if !eq_check_2 {
            // Failed equality check 2
            return false;
        }

        // Do range check
        let bound = BigNumber::one() << (ELL + EPSILON + 1);
        if self.z1 > bound {
            return false;
        }

        true
    }
}

/// Generate a random value less than `2^{n+1}`
/// Taken from unknown_order crate (since they don't currently support an API)
/// that passes an rng for this function
fn bn_random(transcript: &mut Transcript, n: &BigNumber) -> BigNumber {
    let len = n.to_bytes().len();
    let mut t = vec![0u8; len as usize];
    loop {
        transcript.challenge_bytes(b"sampling randomness", t.as_mut_slice());
        let b = BigNumber::from_slice(t.as_slice());
        if &b < n {
            return b;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use libpaillier::*;

    fn random_paillier_encryption_in_range_proof(
        k_range: usize,
    ) -> Result<PaillierEncryptionInRangeProof> {
        let mut rng = OsRng;

        let p = crate::get_random_safe_prime_512();
        let q = crate::get_random_safe_prime_512();
        let N = &p * &q;

        let sk = DecryptionKey::with_safe_primes_unchecked(&p, &q).unwrap();
        let pk = EncryptionKey::from(&sk);

        let k = random_bn_in_range(&mut rng, k_range);
        let (K, rho) = pk.encrypt(&k.to_bytes(), None).unwrap();
        let setup_params = ZkSetupParameters::gen()?;

        PaillierEncryptionInRangeProof::prove(&setup_params, &N, &Ciphertext(K), &k, &rho)
    }

    #[test]
    fn test_paillier_encryption_in_range_proof() -> Result<()> {
        // Sampling k in the range 2^ELL should always succeed
        let proof = random_paillier_encryption_in_range_proof(ELL)?;
        assert!(proof.verify());

        // Sampling k in the range 2^{ELL + EPSILON + 100} should (usually) fail
        let proof = random_paillier_encryption_in_range_proof(ELL + EPSILON + 100)?;
        assert!(!proof.verify());

        Ok(())
    }
}
