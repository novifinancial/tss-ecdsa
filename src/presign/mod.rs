// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

//! Converts a [KeyShare] into a [PresignRecord]

use generic_array::GenericArray;
use libpaillier::unknown_order::BigNumber;

use crate::errors::{InternalError, Result};
use crate::key::KeyShareAndInfo;
use crate::key::KeygenPublic;
use crate::parameters::COMPRESSED;
use crate::parameters::*;
use crate::protocol::ParticipantIdentifier;
use crate::serialization::*;
use crate::utils::*;
use crate::zkp::piaffg::*;
use crate::zkp::pienc::*;
use crate::zkp::pilog::*;
use crate::zkp::Proof;
use crate::Ciphertext;
use std::collections::HashMap;

// A note on sampling from +- 2^L, and mod N computations:
// In the paper (https://eprint.iacr.org/2021/060.pdf), ranges
// are sampled as from being positive/negative 2^L and (mod N)
// is taken to mean {-N/2, ..., N/2}. However, for the
// sake of convenience, we sample everything from
// + 2^{L+1} and use mod N to represent {0, ..., N-1}.

pub mod round_one {
    use super::*;
    use crate::zkp::{pienc::PiEncProof, setup::ZkSetupParameters};

    #[derive(Debug)]
    pub struct Private {
        pub(crate) k: BigNumber,
        pub(crate) rho: BigNumber,
        pub(crate) gamma: BigNumber,
        pub(crate) nu: BigNumber,
        pub(crate) G: Ciphertext, // Technically can be public but is only one per party
        pub(crate) K: Ciphertext, // Technically can be public but is only one per party
    }

    impl Private {
        pub fn to_bytes(&self) -> Result<Vec<u8>> {
            let result = [
                serialize(&self.k.to_bytes(), 2)?,
                serialize(&self.rho.to_bytes(), 2)?,
                serialize(&self.gamma.to_bytes(), 2)?,
                serialize(&self.nu.to_bytes(), 2)?,
                serialize(&self.G.0.to_bytes(), 2)?,
                serialize(&self.K.0.to_bytes(), 2)?,
            ]
            .concat();
            Ok(result)
        }

        pub fn from_slice<B: Clone + AsRef<[u8]>>(input: B) -> Result<Self> {
            let (k_bytes, input) = tokenize(input.as_ref(), 2)?;
            let (rho_bytes, input) = tokenize(input.as_ref(), 2)?;
            let (gamma_bytes, input) = tokenize(input.as_ref(), 2)?;
            let (nu_bytes, input) = tokenize(input.as_ref(), 2)?;
            let (G_bytes, input) = tokenize(input.as_ref(), 2)?;
            let (K_bytes, input) = tokenize(&input, 2)?;
            if !input.is_empty() {
                // Should not be encountering any more bytes
                return Err(InternalError::Serialization);
            }
            let k = BigNumber::from_slice(k_bytes);
            let rho = BigNumber::from_slice(rho_bytes);
            let gamma = BigNumber::from_slice(gamma_bytes);
            let nu = BigNumber::from_slice(nu_bytes);
            let G = Ciphertext(libpaillier::Ciphertext::from_slice(G_bytes));
            let K = Ciphertext(libpaillier::Ciphertext::from_slice(K_bytes));
            Ok(Self {
                k,
                rho,
                gamma,
                nu,
                G,
                K,
            })
        }
    }

    #[derive(Debug)]
    pub struct Public {
        pub(crate) K: Ciphertext,
        pub(crate) G: Ciphertext,
        pub(crate) proof: PiEncProof,
    }

    impl Public {
        pub fn to_bytes(&self) -> Result<Vec<u8>> {
            let result = [
                serialize(&self.K.0.to_bytes(), 2)?,
                serialize(&self.G.0.to_bytes(), 2)?,
                serialize(&self.proof.to_bytes()?, 2)?,
            ]
            .concat();
            Ok(result)
        }

        pub fn from_slice<B: Clone + AsRef<[u8]>>(input: B) -> Result<Self> {
            let (K_bytes, input) = tokenize(input.as_ref(), 2)?;
            let (G_bytes, input) = tokenize(&input, 2)?;
            let (proof_bytes, input) = tokenize(&input, 2)?;
            if !input.is_empty() {
                // Should not be encountering any more bytes
                return Err(InternalError::Serialization);
            }
            let K = Ciphertext(libpaillier::Ciphertext::from_slice(K_bytes));
            let G = Ciphertext(libpaillier::Ciphertext::from_slice(G_bytes));
            let proof = PiEncProof::from_slice(&proof_bytes)?;
            Ok(Self { K, G, proof })
        }

        /// Verify M(vrfy, Π^enc_i, (ssid, j), (I_ε, K_j), ψ_{i,j}) = 1
        /// setup_params should be the receiving party's setup parameters
        /// the modulus N should be the sending party's modulus N
        pub fn verify(
            &self,
            receiver_setup_params: &ZkSetupParameters,
            sender_modulus: &BigNumber,
        ) -> Result<()> {
            let input =
                crate::zkp::pienc::PiEncInput::new(receiver_setup_params, sender_modulus, &self.K);

            if !self.proof.verify(&input) {
                return Err(InternalError::FailedToVerifyProof);
            }

            Ok(())
        }
    }
}

pub mod round_two {
    use ecdsa::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
    use elliptic_curve::sec1::EncodedPoint;
    use k256::ProjectivePoint;

    use super::*;

    use crate::key::KeygenPublic;
    use crate::zkp::piaffg::{PiAffgInput, PiAffgProof};
    use crate::zkp::pilog::{PiLogInput, PiLogProof};

    #[derive(Clone)]
    pub struct Private {
        pub(crate) beta: BigNumber,
        pub(crate) beta_hat: BigNumber,
    }

    impl Private {
        pub fn to_bytes(&self) -> Result<Vec<u8>> {
            let result = [
                serialize(&self.beta.to_bytes(), 2)?,
                serialize(&self.beta_hat.to_bytes(), 2)?,
            ]
            .concat();
            Ok(result)
        }

        pub fn from_slice<B: Clone + AsRef<[u8]>>(input: B) -> Result<Self> {
            let (beta_bytes, input) = tokenize(input.as_ref(), 2)?;
            let (beta_hat_bytes, input) = tokenize(&input, 2)?;
            if !input.is_empty() {
                // Should not be encountering any more bytes
                return Err(InternalError::Serialization);
            }
            let beta = BigNumber::from_slice(beta_bytes);
            let beta_hat = BigNumber::from_slice(beta_hat_bytes);
            Ok(Self { beta, beta_hat })
        }
    }

    #[derive(Clone)]
    pub struct Public {
        pub(crate) D: Ciphertext,
        pub(crate) D_hat: Ciphertext,
        pub(crate) F: Ciphertext,
        pub(crate) F_hat: Ciphertext,
        pub(crate) Gamma: ProjectivePoint,
        pub(crate) psi: PiAffgProof,
        pub(crate) psi_hat: PiAffgProof,
        pub(crate) psi_prime: PiLogProof,
    }

    impl Public {
        pub fn to_bytes(&self) -> Result<Vec<u8>> {
            let result = [
                serialize(&self.D.0.to_bytes(), 2)?,
                serialize(&self.D_hat.0.to_bytes(), 2)?,
                serialize(&self.F.0.to_bytes(), 2)?,
                serialize(&self.F_hat.0.to_bytes(), 2)?,
                serialize(self.Gamma.to_encoded_point(COMPRESSED).as_bytes(), 2)?,
                serialize(&self.psi.to_bytes()?, 2)?,
                serialize(&self.psi_hat.to_bytes()?, 2)?,
                serialize(&self.psi_prime.to_bytes()?, 2)?,
            ]
            .concat();
            Ok(result)
        }

        pub fn from_slice<B: Clone + AsRef<[u8]>>(input: B) -> Result<Self> {
            let (D_bytes, input) = tokenize(input.as_ref(), 2)?;
            let (D_hat_bytes, input) = tokenize(&input, 2)?;
            let (F_bytes, input) = tokenize(&input, 2)?;
            let (F_hat_bytes, input) = tokenize(&input, 2)?;
            let (Gamma_bytes, input) = tokenize(&input, 2)?;
            let (psi_bytes, input) = tokenize(&input, 2)?;
            let (psi_hat_bytes, input) = tokenize(&input, 2)?;
            let (psi_prime_bytes, input) = tokenize(&input, 2)?;
            if !input.is_empty() {
                // Should not be encountering any more bytes
                return Err(InternalError::Serialization);
            }
            let D = Ciphertext(libpaillier::Ciphertext::from_slice(D_bytes));
            let D_hat = Ciphertext(libpaillier::Ciphertext::from_slice(D_hat_bytes));
            let F = Ciphertext(libpaillier::Ciphertext::from_slice(F_bytes));
            let F_hat = Ciphertext(libpaillier::Ciphertext::from_slice(F_hat_bytes));
            let Gamma = ProjectivePoint::from_encoded_point(
                &EncodedPoint::from_bytes(Gamma_bytes).map_err(|_| InternalError::Serialization)?,
            )
            .ok_or(InternalError::Serialization)?;
            let psi = PiAffgProof::from_slice(&psi_bytes)?;
            let psi_hat = PiAffgProof::from_slice(&psi_hat_bytes)?;
            let psi_prime = PiLogProof::from_slice(&psi_prime_bytes)?;
            Ok(Self {
                D,
                D_hat,
                F,
                F_hat,
                Gamma,
                psi,
                psi_hat,
                psi_prime,
            })
        }

        pub fn verify(
            &self,
            receiver_keygen_public: &KeygenPublic,
            sender_keygen_public: &KeygenPublic,
            receiver_r1_private: &round_one::Private,
            sender_r1_public: &round_one::Public,
        ) -> Result<()> {
            let g = k256::ProjectivePoint::generator();

            // Verify the psi proof
            let psi_input = PiAffgInput::new(
                &receiver_keygen_public.params,
                &g,
                receiver_keygen_public.pk.n(),
                sender_keygen_public.pk.n(),
                &receiver_r1_private.K.0,
                &self.D.0,
                &self.F.0,
                &self.Gamma,
            );
            if !self.psi.verify(&psi_input) {
                return Err(InternalError::FailedToVerifyProof);
            }

            // Verify the psi_hat proof
            let psi_hat_input = PiAffgInput::new(
                &receiver_keygen_public.params,
                &g,
                receiver_keygen_public.pk.n(),
                sender_keygen_public.pk.n(),
                &receiver_r1_private.K.0,
                &self.D_hat.0,
                &self.F_hat.0,
                &sender_keygen_public.X,
            );
            if !self.psi_hat.verify(&psi_hat_input) {
                return Err(InternalError::FailedToVerifyProof);
            }

            // Verify the psi_prime proof
            let psi_prime_input = PiLogInput::new(
                &receiver_keygen_public.params,
                &g,
                sender_keygen_public.pk.n(),
                &sender_r1_public.G.0,
                &self.Gamma,
            );
            if !self.psi_prime.verify(&psi_prime_input) {
                return Err(InternalError::FailedToVerifyProof);
            }

            Ok(())
        }
    }
}

pub mod round_three {
    use ecdsa::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
    use elliptic_curve::sec1::EncodedPoint;
    use k256::{ProjectivePoint, Scalar};

    use super::*;

    use crate::key::KeygenPublic;
    use crate::zkp::pilog::{PiLogInput, PiLogProof};

    pub struct Private {
        pub(crate) k: BigNumber,
        pub(crate) chi: Scalar,
        pub(crate) Gamma: ProjectivePoint,
        pub(crate) delta: Scalar,
        pub(crate) Delta: ProjectivePoint,
    }

    impl Private {
        pub fn to_bytes(&self) -> Result<Vec<u8>> {
            let result = [
                serialize(&self.k.to_bytes(), 2)?,
                serialize(&self.chi.to_bytes(), 2)?,
                serialize(self.Gamma.to_encoded_point(COMPRESSED).as_bytes(), 2)?,
                serialize(&self.delta.to_bytes(), 2)?,
                serialize(self.Delta.to_encoded_point(COMPRESSED).as_bytes(), 2)?,
            ]
            .concat();
            Ok(result)
        }

        pub fn from_slice<B: Clone + AsRef<[u8]>>(input: B) -> Result<Self> {
            let (k_bytes, input) = tokenize(input.as_ref(), 2)?;
            let (chi_bytes, input) = tokenize(&input, 2)?;
            let (Gamma_bytes, input) = tokenize(&input, 2)?;
            let (delta_bytes, input) = tokenize(&input, 2)?;
            let (Delta_bytes, input) = tokenize(&input, 2)?;
            if !input.is_empty() {
                // Should not be encountering any more bytes
                return Err(InternalError::Serialization);
            }
            let k = BigNumber::from_slice(&k_bytes);
            let chi = Scalar::from_bytes_reduced(&GenericArray::clone_from_slice(&chi_bytes));
            let Gamma = ProjectivePoint::from_encoded_point(
                &EncodedPoint::from_bytes(Gamma_bytes).map_err(|_| InternalError::Serialization)?,
            )
            .ok_or(InternalError::Serialization)?;
            let delta = Scalar::from_bytes_reduced(&GenericArray::clone_from_slice(&delta_bytes));
            let Delta = ProjectivePoint::from_encoded_point(
                &EncodedPoint::from_bytes(Delta_bytes).map_err(|_| InternalError::Serialization)?,
            )
            .ok_or(InternalError::Serialization)?;
            Ok(Self {
                k,
                chi,
                Gamma,
                delta,
                Delta,
            })
        }
    }

    #[derive(Clone)]
    pub struct Public {
        pub(crate) delta: Scalar,
        pub(crate) Delta: ProjectivePoint,
        pub(crate) psi_double_prime: PiLogProof,
        /// Gamma value included for convenience
        pub(crate) Gamma: ProjectivePoint,
    }

    impl Public {
        pub fn to_bytes(&self) -> Result<Vec<u8>> {
            let result = [
                serialize(&self.delta.to_bytes(), 2)?,
                serialize(self.Delta.to_encoded_point(COMPRESSED).as_bytes(), 2)?,
                serialize(&self.psi_double_prime.to_bytes()?, 2)?,
                serialize(self.Gamma.to_encoded_point(COMPRESSED).as_bytes(), 2)?,
            ]
            .concat();
            Ok(result)
        }

        pub fn from_slice<B: Clone + AsRef<[u8]>>(input: B) -> Result<Self> {
            let (delta_bytes, input) = tokenize(input.as_ref(), 2)?;
            let (Delta_bytes, input) = tokenize(&input, 2)?;
            let (psi_double_prime_bytes, input) = tokenize(&input, 2)?;
            let (Gamma_bytes, input) = tokenize(&input, 2)?;
            if !input.is_empty() {
                // Should not be encountering any more bytes
                return Err(InternalError::Serialization);
            }
            let delta = Scalar::from_bytes_reduced(&GenericArray::clone_from_slice(&delta_bytes));
            let Delta = ProjectivePoint::from_encoded_point(
                &EncodedPoint::from_bytes(Delta_bytes).map_err(|_| InternalError::Serialization)?,
            )
            .ok_or(InternalError::Serialization)?;
            let Gamma = ProjectivePoint::from_encoded_point(
                &EncodedPoint::from_bytes(Gamma_bytes).map_err(|_| InternalError::Serialization)?,
            )
            .ok_or(InternalError::Serialization)?;
            let psi_double_prime = PiLogProof::from_slice(&psi_double_prime_bytes)?;
            Ok(Self {
                delta,
                Delta,
                psi_double_prime,
                Gamma,
            })
        }

        pub(crate) fn verify(
            &self,
            receiver_keygen_public: &KeygenPublic,
            sender_keygen_public: &KeygenPublic,
            sender_r1_public: &round_one::Public,
        ) -> Result<()> {
            let psi_double_prime_input = PiLogInput::new(
                &receiver_keygen_public.params,
                &self.Gamma,
                sender_keygen_public.pk.n(),
                &sender_r1_public.K.0,
                &self.Delta,
            );
            if !self.psi_double_prime.verify(&psi_double_prime_input) {
                return Err(InternalError::FailedToVerifyProof);
            }

            Ok(())
        }
    }

    /// Used to bundle the inputs passed to round_three() together
    pub struct RoundThreeInput {
        pub(crate) keygen_public: crate::key::KeygenPublic,
        pub(crate) r2_private: round_two::Private,
        pub(crate) r2_public: round_two::Public,
    }
}

impl KeyShareAndInfo {
    /// Corresponds to pre-signing round 1 for party i
    ///
    /// Produces local shares k and gamma, along with their encrypted
    /// components K = enc(k) and G = enc(gamma).
    ///
    /// The public_keys parameter corresponds to a KeygenPublic for
    /// each of the other parties.
    #[cfg_attr(feature = "flame_it", flame)]
    pub fn round_one(
        &self,
        public_keys: &HashMap<ParticipantIdentifier, KeygenPublic>,
    ) -> Result<(
        round_one::Private,
        HashMap<ParticipantIdentifier, round_one::Public>,
    )> {
        let mut rng = rand::rngs::OsRng;
        let k = random_bn_in_range(&mut rng, ELL);
        let gamma = random_bn_in_range(&mut rng, ELL);

        let (K, rho) = self.public.pk.encrypt(&k.to_bytes(), None).unwrap();
        let (G, nu) = self.public.pk.encrypt(&gamma.to_bytes(), None).unwrap();

        let mut ret_publics = HashMap::new();
        for (id, keygen_public) in public_keys {
            let proof = PiEncProof::prove(
                &mut rng,
                &crate::zkp::pienc::PiEncInput::new(
                    &keygen_public.params,
                    self.public.pk.n(),
                    &Ciphertext(K.clone()),
                ),
                &crate::zkp::pienc::PiEncSecret::new(&k, &rho),
            )?;
            let r1_public = round_one::Public {
                K: Ciphertext(K.clone()),
                G: Ciphertext(G.clone()),
                proof: proof.clone(),
            };
            ret_publics.insert(id.clone(), r1_public);
        }

        let r1_private = round_one::Private {
            k,
            rho,
            gamma,
            nu,
            G: Ciphertext(G),
            K: Ciphertext(K),
        };

        Ok((r1_private, ret_publics))
    }

    /// Needs to be run once per party j != i
    ///
    /// Constructs a D = gamma * K and D_hat = x * K, and Gamma = g * gamma.
    ///
    #[cfg_attr(feature = "flame_it", flame)]
    pub fn round_two(
        &self,
        receiver_kg_pub: &KeygenPublic,
        sender_r1_priv: &round_one::Private,
        receiver_r1_pub: &round_one::Public,
    ) -> (round_two::Private, round_two::Public) {
        // Picking betas as elements of [+- 2^384] here is like sampling them from the distribution
        // [1, 2^256], which is akin to 2^{ell + epsilon} where ell = epsilon = 384. Note that
        // we need q/2^epsilon to be negligible.
        let mut rng = rand::rngs::OsRng;
        let beta = random_bn_in_range(&mut rng, ELL);
        let beta_hat = random_bn_in_range(&mut rng, ELL);

        let (beta_ciphertext, s) = receiver_kg_pub.pk.encrypt(beta.to_bytes(), None).unwrap();
        let (beta_hat_ciphertext, s_hat) = receiver_kg_pub
            .pk
            .encrypt(beta_hat.to_bytes(), None)
            .unwrap();

        let D = receiver_kg_pub
            .pk
            .add(
                &receiver_kg_pub
                    .pk
                    .mul(&receiver_r1_pub.K.0, &sender_r1_priv.gamma)
                    .unwrap(),
                &beta_ciphertext,
            )
            .unwrap();

        let D_hat = receiver_kg_pub
            .pk
            .add(
                &receiver_kg_pub
                    .pk
                    .mul(&receiver_r1_pub.K.0, &self.private.x)
                    .unwrap(),
                &beta_hat_ciphertext,
            )
            .unwrap();

        let (F, r) = self.public.pk.encrypt(beta.to_bytes(), None).unwrap();
        let (F_hat, r_hat) = self.public.pk.encrypt(beta_hat.to_bytes(), None).unwrap();

        let g = k256::ProjectivePoint::generator();
        let Gamma = g * bn_to_scalar(&sender_r1_priv.gamma).unwrap();

        // Generate three proofs

        let psi = PiAffgProof::prove(
            &mut rng,
            &PiAffgInput::new(
                &receiver_kg_pub.params,
                &g,
                receiver_kg_pub.pk.n(),
                self.public.pk.n(),
                &receiver_r1_pub.K.0,
                &D,
                &F,
                &Gamma,
            ),
            &PiAffgSecret::new(&sender_r1_priv.gamma, &beta, &s, &r),
        )
        .unwrap();

        let psi_hat = PiAffgProof::prove(
            &mut rng,
            &PiAffgInput::new(
                &receiver_kg_pub.params,
                &g,
                receiver_kg_pub.pk.n(),
                self.public.pk.n(),
                &receiver_r1_pub.K.0,
                &D_hat,
                &F_hat,
                &self.public.X,
            ),
            &PiAffgSecret::new(&self.private.x, &beta_hat, &s_hat, &r_hat),
        )
        .unwrap();

        let psi_prime = PiLogProof::prove(
            &mut rng,
            &PiLogInput::new(
                &receiver_kg_pub.params,
                &g,
                self.public.pk.n(),
                &sender_r1_priv.G.0,
                &Gamma,
            ),
            &PiLogSecret::new(&sender_r1_priv.gamma, &sender_r1_priv.nu),
        )
        .unwrap();

        (
            round_two::Private { beta, beta_hat },
            round_two::Public {
                D: Ciphertext(D),
                D_hat: Ciphertext(D_hat),
                F: Ciphertext(F),
                F_hat: Ciphertext(F_hat),
                Gamma,
                psi,
                psi_hat,
                psi_prime,
            },
        )
    }

    /// From the perspective of party i
    /// r2_privs and r2_pubs don't include party i
    ///
    /// First computes alpha = dec(D), alpha_hat = dec(D_hat).
    /// Computes a delta = gamma * k
    #[cfg_attr(feature = "flame_it", flame)]
    pub fn round_three(
        &self,
        sender_r1_priv: &round_one::Private,
        other_participant_inputs: &HashMap<ParticipantIdentifier, round_three::RoundThreeInput>,
    ) -> Result<(
        round_three::Private,
        HashMap<ParticipantIdentifier, round_three::Public>,
    )> {
        let order = k256_order();
        let mut delta: BigNumber = sender_r1_priv.gamma.modmul(&sender_r1_priv.k, &order);
        let mut chi: BigNumber = self.private.x.modmul(&sender_r1_priv.k, &order);

        let g = k256::ProjectivePoint::generator();
        let mut Gamma = g * bn_to_scalar(&sender_r1_priv.gamma).unwrap();

        for round_three_input in other_participant_inputs.values() {
            let r2_pub_j = round_three_input.r2_public.clone();
            let r2_priv_j = round_three_input.r2_private.clone();

            let alpha = BigNumber::from_slice(self.private.sk.decrypt(&r2_pub_j.D.0).unwrap());
            let alpha_hat =
                BigNumber::from_slice(self.private.sk.decrypt(&r2_pub_j.D_hat.0).unwrap());

            delta = delta.modadd(&alpha.modsub(&r2_priv_j.beta, &order), &order);
            chi = chi.modadd(&alpha_hat.modsub(&r2_priv_j.beta_hat, &order), &order);

            Gamma += r2_pub_j.Gamma;
        }

        let Delta = Gamma * bn_to_scalar(&sender_r1_priv.k).unwrap();

        let delta_scalar = bn_to_scalar(&delta).unwrap();
        let chi_scalar = bn_to_scalar(&chi).unwrap();

        let mut rng = rand::rngs::OsRng;

        let mut ret_publics = HashMap::new();
        for (other_id, round_three_input) in other_participant_inputs {
            let receiver_keygen_public = round_three_input.keygen_public.clone();
            let psi_double_prime = PiLogProof::prove(
                &mut rng,
                &PiLogInput::new(
                    &receiver_keygen_public.params,
                    &Gamma,
                    self.public.pk.n(),
                    &sender_r1_priv.K.0,
                    &Delta,
                ),
                &PiLogSecret::new(&sender_r1_priv.k, &sender_r1_priv.rho),
            )
            .unwrap();
            let val = round_three::Public {
                delta: delta_scalar,
                Delta,
                psi_double_prime,
                Gamma,
            };
            ret_publics.insert(other_id.clone(), val);
        }

        let private = round_three::Private {
            k: sender_r1_priv.k.clone(),
            chi: chi_scalar,
            Gamma,
            // These last two fields can be public, but for convenience
            // are stored in this party's private component
            delta: delta_scalar,
            Delta,
        };

        Ok((private, ret_publics))
    }
}

pub(crate) struct RecordPair {
    pub(crate) private: round_three::Private,
    pub(crate) publics: Vec<round_three::Public>,
}

pub struct PresignRecord {
    R: k256::ProjectivePoint,
    k: BigNumber,
    chi: k256::Scalar,
}

impl From<RecordPair> for PresignRecord {
    fn from(RecordPair { private, publics }: RecordPair) -> Self {
        let mut delta = private.delta;
        let mut Delta = private.Delta;
        for p in publics {
            delta += &p.delta;
            Delta += p.Delta;
        }

        let g = k256::ProjectivePoint::generator();
        if g * delta != Delta {
            // Error, failed to validate
            panic!("Error, failed to validate");
        }

        let R = private.Gamma * delta.invert().unwrap();

        PresignRecord {
            R,
            k: private.k,
            chi: private.chi,
        }
    }
}

use ecdsa::hazmat::FromDigest;
use elliptic_curve::group::GroupEncoding;

impl PresignRecord {
    fn x_from_point(p: &k256::ProjectivePoint) -> k256::Scalar {
        let r = &p.to_affine().to_bytes()[1..32 + 1];
        k256::Scalar::from_bytes_reduced(&GenericArray::clone_from_slice(r))
    }

    pub(crate) fn sign(&self, d: sha2::Sha256) -> (k256::Scalar, k256::Scalar) {
        let r = Self::x_from_point(&self.R);
        let m = k256::Scalar::from_digest(d);
        let s = bn_to_scalar(&self.k).unwrap() * m + r * self.chi;

        (r, s)
    }
}
