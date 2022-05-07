// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

//! Converts a [KeyShare] into a [PresignRecord]

use libpaillier::unknown_order::BigNumber;
use serde::{Deserialize, Serialize};
use sha2::Digest;

use crate::errors::Result;
use crate::key::KeyShareAndInfo;
use crate::key::KeygenPublic;
use crate::parameters::*;
use crate::protocol::ParticipantIdentifier;
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

    #[derive(Debug, Serialize, Deserialize)]
    pub struct Private {
        pub(crate) k: BigNumber,
        pub(crate) rho: BigNumber,
        pub(crate) gamma: BigNumber,
        pub(crate) nu: BigNumber,
        pub(crate) G: Ciphertext, // Technically can be public but is only one per party
        pub(crate) K: Ciphertext, // Technically can be public but is only one per party
    }
    #[derive(Debug, Serialize, Deserialize)]
    pub struct Public {
        pub(crate) K: Ciphertext,
        pub(crate) G: Ciphertext,
        pub(crate) proof: PiEncProof,
    }

    impl Public {
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

            self.proof.verify(&input)
        }
    }
}

pub mod round_two {

    use super::*;

    use crate::key::KeygenPublic;
    use crate::zkp::piaffg::{PiAffgInput, PiAffgProof};
    use crate::zkp::pilog::{PiLogInput, PiLogProof};

    #[derive(Clone, Serialize, Deserialize)]
    pub struct Private {
        pub(crate) beta: BigNumber,
        pub(crate) beta_hat: BigNumber,
    }

    #[derive(Clone, Serialize, Deserialize)]
    pub struct Public {
        pub(crate) D: Ciphertext,
        pub(crate) D_hat: Ciphertext,
        pub(crate) F: Ciphertext,
        pub(crate) F_hat: Ciphertext,
        pub(crate) Gamma: CurvePoint,
        pub(crate) psi: PiAffgProof,
        pub(crate) psi_hat: PiAffgProof,
        pub(crate) psi_prime: PiLogProof,
    }

    impl Public {
        pub fn verify(
            &self,
            receiver_keygen_public: &KeygenPublic,
            sender_keygen_public: &KeygenPublic,
            receiver_r1_private: &round_one::Private,
            sender_r1_public: &round_one::Public,
        ) -> Result<()> {
            let g = CurvePoint::GENERATOR;

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
            self.psi.verify(&psi_input)?;

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
            self.psi_hat.verify(&psi_hat_input)?;

            // Verify the psi_prime proof
            let psi_prime_input = PiLogInput::new(
                &receiver_keygen_public.params,
                &g,
                sender_keygen_public.pk.n(),
                &sender_r1_public.G.0,
                &self.Gamma,
            );
            self.psi_prime.verify(&psi_prime_input)?;

            Ok(())
        }
    }
}

pub mod round_three {
    use k256::Scalar;

    use super::*;

    use crate::key::KeygenPublic;
    use crate::zkp::pilog::{PiLogInput, PiLogProof};

    #[derive(Clone, Serialize, Deserialize)]
    pub struct Private {
        pub(crate) k: BigNumber,
        pub(crate) chi: Scalar,
        pub(crate) Gamma: CurvePoint,
        pub(crate) delta: Scalar,
        pub(crate) Delta: CurvePoint,
    }

    #[derive(Clone, Serialize, Deserialize)]
    pub struct Public {
        pub(crate) delta: Scalar,
        pub(crate) Delta: CurvePoint,
        pub(crate) psi_double_prime: PiLogProof,
        /// Gamma value included for convenience
        pub(crate) Gamma: CurvePoint,
    }

    impl Public {
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
            self.psi_double_prime.verify(&psi_double_prime_input)?;

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

        let g = CurvePoint::GENERATOR;
        let Gamma = CurvePoint(g.0 * bn_to_scalar(&sender_r1_priv.gamma).unwrap());

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

        let g = CurvePoint::GENERATOR;
        let mut Gamma = CurvePoint(g.0 * bn_to_scalar(&sender_r1_priv.gamma).unwrap());

        for round_three_input in other_participant_inputs.values() {
            let r2_pub_j = round_three_input.r2_public.clone();
            let r2_priv_j = round_three_input.r2_private.clone();

            let alpha = BigNumber::from_slice(self.private.sk.decrypt(&r2_pub_j.D.0).unwrap());
            let alpha_hat =
                BigNumber::from_slice(self.private.sk.decrypt(&r2_pub_j.D_hat.0).unwrap());

            delta = delta.modadd(&alpha.modsub(&r2_priv_j.beta, &order), &order);
            chi = chi.modadd(&alpha_hat.modsub(&r2_priv_j.beta_hat, &order), &order);

            Gamma = CurvePoint(Gamma.0 + r2_pub_j.Gamma.0);
        }

        let Delta = CurvePoint(Gamma.0 * bn_to_scalar(&sender_r1_priv.k).unwrap());

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
    R: CurvePoint,
    k: BigNumber,
    chi: k256::Scalar,
}

impl From<RecordPair> for PresignRecord {
    fn from(RecordPair { private, publics }: RecordPair) -> Self {
        let mut delta = private.delta;
        let mut Delta = private.Delta;
        for p in publics {
            delta += &p.delta;
            Delta = CurvePoint(Delta.0 + p.Delta.0);
        }

        let g = CurvePoint::GENERATOR;
        if CurvePoint(g.0 * delta) != Delta {
            // Error, failed to validate
            panic!("Error, failed to validate");
        }

        let R = CurvePoint(private.Gamma.0 * delta.invert().unwrap());

        PresignRecord {
            R,
            k: private.k,
            chi: private.chi,
        }
    }
}

//use ecdsa::hazmat::FromDigest;
use k256::elliptic_curve::AffineXCoordinate;
use k256::elliptic_curve::PrimeField;

impl PresignRecord {
    fn x_from_point(p: &CurvePoint) -> k256::Scalar {
        let r = &p.0.to_affine().x();
        k256::Scalar::from_repr(*r).unwrap()
    }

    pub(crate) fn sign(&self, d: sha2::Sha256) -> (k256::Scalar, k256::Scalar) {
        let r = Self::x_from_point(&self.R);
        let m = k256::Scalar::from_repr(d.finalize()).unwrap();
        let s = bn_to_scalar(&self.k).unwrap() * m + r * self.chi;

        (r, s)
    }
}
