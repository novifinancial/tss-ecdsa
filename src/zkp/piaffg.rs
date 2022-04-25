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
use crate::serialization::*;
use crate::utils::{
    self, bn_random_from_transcript, k256_order, modpow, random_bn, random_bn_in_range,
    random_bn_in_z_star,
};
use crate::zkp::setup::ZkSetupParameters;
use crate::{errors::*, ELL, ELL_PRIME, EPSILON};
use ecdsa::elliptic_curve::group::GroupEncoding;
use libpaillier::unknown_order::BigNumber;
use merlin::Transcript;
use rand::{CryptoRng, RngCore};

#[derive(Debug, Clone)]
pub struct PiAffgProof {
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

pub(crate) struct PiAffgInput {
    setup_params: ZkSetupParameters,
    g: k256::ProjectivePoint,
    N0: BigNumber,
    N1: BigNumber,
    C: BigNumber,
    D: BigNumber,
    Y: BigNumber,
    X: k256::ProjectivePoint,
}

impl PiAffgInput {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        setup_params: &ZkSetupParameters,
        g: &k256::ProjectivePoint,
        N0: &BigNumber,
        N1: &BigNumber,
        C: &BigNumber,
        D: &BigNumber,
        Y: &BigNumber,
        X: &k256::ProjectivePoint,
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
        let B_x = input.g * utils::bn_to_scalar(&alpha).unwrap();
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
                B_x.to_bytes().to_vec(),
                B_y.to_bytes(),
                E.to_bytes(),
                F.to_bytes(),
            ]
            .concat(),
        );

        // Verifier is supposed to sample from e in +- q (where q is the group order), we sample from
        // [0, 2*q] instead
        let e = bn_random_from_transcript(&mut transcript, &(BigNumber::from(2) * &k256_order()));

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
    fn verify(&self, input: &Self::CommonInput) -> bool {
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
                self.B_x.to_bytes().to_vec(),
                self.B_y.to_bytes(),
                self.E.to_bytes(),
                self.F.to_bytes(),
            ]
            .concat(),
        );

        // Verifier is supposed to sample from e in +- q (where q is the group order), we sample from
        // [0, 2*q] instead
        let e = bn_random_from_transcript(&mut transcript, &(BigNumber::from(2) * &k256_order()));

        if e != self.e {
            // Fiat-Shamir consistency check failed
            return false;
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
            return false;
        }

        let eq_check_2 = {
            let lhs = input.g * utils::bn_to_scalar(&self.z1).unwrap();
            let rhs = self.B_x + input.X * utils::bn_to_scalar(&self.e).unwrap();
            lhs == rhs
        };
        if !eq_check_2 {
            return false;
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
            return false;
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
            return false;
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
            return false;
        }

        // Do range check

        let ell_bound = BigNumber::one() << (ELL + EPSILON + 1);
        let ell_prime_bound = BigNumber::one() << (ELL_PRIME + EPSILON + 1);
        if self.z1 > ell_bound || self.z2 > ell_prime_bound {
            return false;
        }

        true
    }

    fn to_bytes(&self) -> Result<Vec<u8>> {
        let result = [
            serialize(&self.alpha.to_bytes(), 2)?,
            serialize(&self.beta.to_bytes(), 2)?,
            serialize(&self.S.to_bytes(), 2)?,
            serialize(&self.T.to_bytes(), 2)?,
            serialize(&self.A.to_bytes(), 2)?,
            serialize(&self.B_x.to_bytes(), 2)?,
            serialize(&self.B_y.to_bytes(), 2)?,
            serialize(&self.E.to_bytes(), 2)?,
            serialize(&self.F.to_bytes(), 2)?,
            serialize(&self.e.to_bytes(), 2)?,
            serialize(&self.z1.to_bytes(), 2)?,
            serialize(&self.z2.to_bytes(), 2)?,
            serialize(&self.z3.to_bytes(), 2)?,
            serialize(&self.z4.to_bytes(), 2)?,
            serialize(&self.w.to_bytes(), 2)?,
            serialize(&self.w_y.to_bytes(), 2)?,
        ]
        .concat();
        Ok(result)
    }

    fn from_slice<B: Clone + AsRef<[u8]>>(buf: B) -> Result<Self> {
        let (alpha_bytes, input) = tokenize(buf.as_ref(), 2)?;
        let (beta_bytes, input) = tokenize(&input, 2)?;
        let (S_bytes, input) = tokenize(&input, 2)?;
        let (T_bytes, input) = tokenize(&input, 2)?;
        let (A_bytes, input) = tokenize(&input, 2)?;
        let (B_x_bytes, input) = tokenize(&input, 2)?;
        let (B_y_bytes, input) = tokenize(&input, 2)?;
        let (E_bytes, input) = tokenize(&input, 2)?;
        let (F_bytes, input) = tokenize(&input, 2)?;
        let (e_bytes, input) = tokenize(&input, 2)?;
        let (z1_bytes, input) = tokenize(&input, 2)?;
        let (z2_bytes, input) = tokenize(&input, 2)?;
        let (z3_bytes, input) = tokenize(&input, 2)?;
        let (z4_bytes, input) = tokenize(&input, 2)?;
        let (w_bytes, input) = tokenize(&input, 2)?;
        let (w_y_bytes, input) = tokenize(&input, 2)?;

        if !input.is_empty() {
            // Should not be encountering any more bytes
            return Err(InternalError::Serialization);
        }

        let alpha = BigNumber::from_slice(alpha_bytes);
        let beta = BigNumber::from_slice(beta_bytes);
        let S = BigNumber::from_slice(S_bytes);
        let T = BigNumber::from_slice(T_bytes);
        let A = BigNumber::from_slice(A_bytes);
        let B_x = utils::point_from_bytes(&B_x_bytes)?;
        let B_y = BigNumber::from_slice(B_y_bytes);
        let E = BigNumber::from_slice(E_bytes);
        let F = BigNumber::from_slice(F_bytes);
        let e = BigNumber::from_slice(e_bytes);
        let z1 = BigNumber::from_slice(z1_bytes);
        let z2 = BigNumber::from_slice(z2_bytes);
        let z3 = BigNumber::from_slice(z3_bytes);
        let z4 = BigNumber::from_slice(z4_bytes);
        let w = BigNumber::from_slice(w_bytes);
        let w_y = BigNumber::from_slice(w_y_bytes);

        Ok(Self {
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
        })
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

        let g = k256::ProjectivePoint::generator();

        let X = g * utils::bn_to_scalar(&x).unwrap();
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

        let input = PiAffgInput::new(&setup_params, &g, &N0, &N1, &C, &D, &Y, &X);
        let proof = PiAffgProof::prove(&mut rng, &input, &PiAffgSecret::new(&x, &y, &rho, &rho_y))?;

        match proof.verify(&input) {
            true => Ok(()),
            false => Err(InternalError::CouldNotGenerateProof),
        }
    }

    #[test]
    fn test_paillier_affg_proof() -> Result<()> {
        // FIXME: extend to supporting ELL_PRIME different from ELL

        // Sampling x,y in the range 2^ELL should always succeed
        let result = random_paillier_affg_proof(ELL);
        assert!(result.is_ok());

        // Sampling x,y in the range 2^{ELL + EPSILON + 100} should (usually) fail
        let result = random_paillier_affg_proof(ELL + EPSILON + 100);
        assert!(match result {
            Err(InternalError::CouldNotGenerateProof) => true,
            _ => false,
        });

        Ok(())
    }
}
