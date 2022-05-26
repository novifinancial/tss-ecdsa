// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

//! Runs the presignature generation protocol, producing a [PresignRecord]

use libpaillier::unknown_order::BigNumber;
use serde::{Deserialize, Serialize};
use sha2::Digest;

use crate::auxinfo::AuxInfoPrivate;
use crate::auxinfo::AuxInfoPublic;
use crate::errors::Result;
use crate::keygen::KeySharePrivate;
use crate::keygen::KeySharePublic;
use crate::paillier::PaillierCiphertext;
use crate::parameters::*;
use crate::protocol::ParticipantIdentifier;
use crate::utils::*;
use crate::zkp::piaffg::*;
use crate::zkp::pienc::*;
use crate::zkp::pilog::*;
use crate::zkp::Proof;
use std::collections::HashMap;

pub(crate) mod round_one {
    use super::*;
    use crate::zkp::{pienc::PiEncProof, setup::ZkSetupParameters};

    #[derive(Debug, Serialize, Deserialize)]
    pub(crate) struct Private {
        pub(crate) k: BigNumber,
        pub(crate) rho: BigNumber,
        pub(crate) gamma: BigNumber,
        pub(crate) nu: BigNumber,
        pub(crate) G: PaillierCiphertext, // Technically can be public but is only one per party
        pub(crate) K: PaillierCiphertext, // Technically can be public but is only one per party
    }
    #[derive(Debug, Serialize, Deserialize)]
    pub(crate) struct Public {
        pub(crate) K: PaillierCiphertext,
        pub(crate) G: PaillierCiphertext,
        pub(crate) proof: PiEncProof,
    }

    impl Public {
        /// Verify M(vrfy, Π^enc_i, (ssid, j), (I_ε, K_j), ψ_{i,j}) = 1
        /// setup_params should be the receiving party's setup parameters
        /// the modulus N should be the sending party's modulus N
        pub(crate) fn verify(
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

pub(crate) mod round_two {

    use super::*;

    use crate::zkp::piaffg::{PiAffgInput, PiAffgProof};
    use crate::zkp::pilog::{PiLogInput, PiLogProof};

    #[derive(Clone, Serialize, Deserialize)]
    pub(crate) struct Private {
        pub(crate) beta: BigNumber,
        pub(crate) beta_hat: BigNumber,
    }

    #[derive(Clone, Serialize, Deserialize)]
    pub(crate) struct Public {
        pub(crate) D: PaillierCiphertext,
        pub(crate) D_hat: PaillierCiphertext,
        pub(crate) F: PaillierCiphertext,
        pub(crate) F_hat: PaillierCiphertext,
        pub(crate) Gamma: CurvePoint,
        pub(crate) psi: PiAffgProof,
        pub(crate) psi_hat: PiAffgProof,
        pub(crate) psi_prime: PiLogProof,
    }

    impl Public {
        pub(crate) fn verify(
            &self,
            receiver_auxinfo_public: &AuxInfoPublic,
            sender_auxinfo_public: &AuxInfoPublic,
            sender_keyshare_public: &KeySharePublic,
            receiver_r1_private: &round_one::Private,
            sender_r1_public: &round_one::Public,
        ) -> Result<()> {
            let g = CurvePoint::GENERATOR;

            // Verify the psi proof
            let psi_input = PiAffgInput::new(
                &receiver_auxinfo_public.params,
                &g,
                receiver_auxinfo_public.pk.n(),
                sender_auxinfo_public.pk.n(),
                &receiver_r1_private.K.0,
                &self.D.0,
                &self.F.0,
                &self.Gamma,
            );
            self.psi.verify(&psi_input)?;

            // Verify the psi_hat proof
            let psi_hat_input = PiAffgInput::new(
                &receiver_auxinfo_public.params,
                &g,
                receiver_auxinfo_public.pk.n(),
                sender_auxinfo_public.pk.n(),
                &receiver_r1_private.K.0,
                &self.D_hat.0,
                &self.F_hat.0,
                &sender_keyshare_public.X,
            );
            self.psi_hat.verify(&psi_hat_input)?;

            // Verify the psi_prime proof
            let psi_prime_input = PiLogInput::new(
                &receiver_auxinfo_public.params,
                &k256_order(),
                sender_auxinfo_public.pk.n(),
                &sender_r1_public.G.0,
                &self.Gamma,
                &g,
            );
            self.psi_prime.verify(&psi_prime_input)?;

            Ok(())
        }
    }
}

pub(crate) mod round_three {
    use k256::Scalar;

    use super::*;

    use crate::zkp::pilog::{PiLogInput, PiLogProof};

    #[derive(Clone, Serialize, Deserialize)]
    pub(crate) struct Private {
        pub(crate) k: BigNumber,
        pub(crate) chi: Scalar,
        pub(crate) Gamma: CurvePoint,
        pub(crate) delta: Scalar,
        pub(crate) Delta: CurvePoint,
    }

    #[derive(Clone, Serialize, Deserialize)]
    pub(crate) struct Public {
        pub(crate) delta: Scalar,
        pub(crate) Delta: CurvePoint,
        pub(crate) psi_double_prime: PiLogProof,
        /// Gamma value included for convenience
        pub(crate) Gamma: CurvePoint,
    }

    impl Public {
        pub(crate) fn verify(
            &self,
            receiver_keygen_public: &AuxInfoPublic,
            sender_keygen_public: &AuxInfoPublic,
            sender_r1_public: &round_one::Public,
        ) -> Result<()> {
            let psi_double_prime_input = PiLogInput::new(
                &receiver_keygen_public.params,
                &k256_order(),
                sender_keygen_public.pk.n(),
                &sender_r1_public.K.0,
                &self.Delta,
                &self.Gamma,
            );
            self.psi_double_prime.verify(&psi_double_prime_input)?;

            Ok(())
        }
    }

    /// Used to bundle the inputs passed to round_three() together
    pub(crate) struct RoundThreeInput {
        pub(crate) auxinfo_public: AuxInfoPublic,
        pub(crate) r2_private: round_two::Private,
        pub(crate) r2_public: round_two::Public,
    }
}

/////////////////
// Round Logic //
/////////////////

/// Convenience struct used to bundle together the parameters for
/// the current participant
pub(crate) struct PresignKeyShareAndInfo {
    pub(crate) keyshare_private: KeySharePrivate,
    pub(crate) keyshare_public: KeySharePublic,
    pub(crate) aux_info_private: AuxInfoPrivate,
    pub(crate) aux_info_public: AuxInfoPublic,
}

impl PresignKeyShareAndInfo {
    /// Corresponds to pre-signing round 1 for party i
    ///
    /// Produces local shares k and gamma, along with their encrypted
    /// components K = enc(k) and G = enc(gamma).
    ///
    /// The public_keys parameter corresponds to a KeygenPublic for
    /// each of the other parties.
    #[cfg_attr(feature = "flame_it", flame)]
    pub(crate) fn round_one(
        &self,
        public_keys: &HashMap<ParticipantIdentifier, AuxInfoPublic>,
    ) -> Result<(
        round_one::Private,
        HashMap<ParticipantIdentifier, round_one::Public>,
    )> {
        let mut rng = rand::rngs::OsRng;
        let order = k256_order();

        // Sample k <- F_q
        let k = random_positive_bn(&mut rng, &order);
        // Sample gamma <- F_q
        let gamma = random_positive_bn(&mut rng, &order);

        // Sample rho <- Z_N^* and set K = enc(k; rho)
        let (K, rho) = loop {
            let (K, rho) = self.aux_info_public.pk.encrypt(&k);
            if !BigNumber::is_zero(&rho) {
                break (K, rho);
            }
        };

        // Sample nu <- Z_N^* and set G = enc(gamma; nu)
        let (G, nu) = loop {
            let (G, nu) = self.aux_info_public.pk.encrypt(&gamma);

            if !BigNumber::is_zero(&nu) {
                break (G, nu);
            }
        };

        let mut ret_publics = HashMap::new();
        for (id, aux_info_public) in public_keys {
            // Compute psi_{j,i} for every participant j != i
            let proof = PiEncProof::prove(
                &mut rng,
                &crate::zkp::pienc::PiEncInput::new(
                    &aux_info_public.params,
                    self.aux_info_public.pk.n(),
                    &PaillierCiphertext(K.clone()),
                ),
                &crate::zkp::pienc::PiEncSecret::new(&k, &rho),
            )?;
            let r1_public = round_one::Public {
                K: PaillierCiphertext(K.clone()),
                G: PaillierCiphertext(G.clone()),
                proof: proof.clone(),
            };
            ret_publics.insert(*id, r1_public);
        }

        let r1_private = round_one::Private {
            k,
            rho,
            gamma,
            nu,
            G: PaillierCiphertext(G),
            K: PaillierCiphertext(K),
        };

        Ok((r1_private, ret_publics))
    }

    /// Needs to be run once per party j != i
    ///
    /// Constructs a D = gamma * K and D_hat = x * K, and Gamma = g * gamma.
    ///
    #[cfg_attr(feature = "flame_it", flame)]
    pub(crate) fn round_two(
        &self,
        receiver_aux_info: &AuxInfoPublic,
        sender_r1_priv: &round_one::Private,
        receiver_r1_pub: &round_one::Public,
    ) -> (round_two::Private, round_two::Public) {
        // Picking betas as elements of [+- 2^384] here is like sampling them from the distribution
        // [1, 2^256], which is akin to 2^{ell + epsilon} where ell = epsilon = 384. Note that
        // we need q/2^epsilon to be negligible.
        let mut rng = rand::rngs::OsRng;
        let beta = random_bn_in_range(&mut rng, ELL);
        let beta_hat = random_bn_in_range(&mut rng, ELL);

        let (beta_ciphertext, s) = receiver_aux_info.pk.encrypt(&beta);
        let (beta_hat_ciphertext, s_hat) = receiver_aux_info.pk.encrypt(&beta_hat);

        let D = receiver_aux_info
            .pk
            .0
            .add(
                &receiver_aux_info
                    .pk
                    .0
                    .mul(&receiver_r1_pub.K.0, &sender_r1_priv.gamma)
                    .unwrap(),
                &beta_ciphertext,
            )
            .unwrap();

        let D_hat = receiver_aux_info
            .pk
            .0
            .add(
                &receiver_aux_info
                    .pk
                    .0
                    .mul(&receiver_r1_pub.K.0, &self.keyshare_private.x)
                    .unwrap(),
                &beta_hat_ciphertext,
            )
            .unwrap();

        let (F, r) = self.aux_info_public.pk.encrypt(&beta);
        let (F_hat, r_hat) = self.aux_info_public.pk.encrypt(&beta_hat);

        let g = CurvePoint::GENERATOR;
        let Gamma = CurvePoint(g.0 * bn_to_scalar(&sender_r1_priv.gamma).unwrap());

        // Generate three proofs

        let psi = PiAffgProof::prove(
            &mut rng,
            &PiAffgInput::new(
                &receiver_aux_info.params,
                &g,
                receiver_aux_info.pk.n(),
                self.aux_info_public.pk.n(),
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
                &receiver_aux_info.params,
                &g,
                receiver_aux_info.pk.n(),
                self.aux_info_public.pk.n(),
                &receiver_r1_pub.K.0,
                &D_hat,
                &F_hat,
                &self.keyshare_public.X,
            ),
            &PiAffgSecret::new(&self.keyshare_private.x, &beta_hat, &s_hat, &r_hat),
        )
        .unwrap();

        let psi_prime = PiLogProof::prove(
            &mut rng,
            &PiLogInput::new(
                &receiver_aux_info.params,
                &k256_order(),
                self.aux_info_public.pk.n(),
                &sender_r1_priv.G.0,
                &Gamma,
                &g,
            ),
            &PiLogSecret::new(&sender_r1_priv.gamma, &sender_r1_priv.nu),
        )
        .unwrap();

        (
            round_two::Private { beta, beta_hat },
            round_two::Public {
                D: PaillierCiphertext(D),
                D_hat: PaillierCiphertext(D_hat),
                F: PaillierCiphertext(F),
                F_hat: PaillierCiphertext(F_hat),
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
    pub(crate) fn round_three(
        &self,
        sender_r1_priv: &round_one::Private,
        other_participant_inputs: &HashMap<ParticipantIdentifier, round_three::RoundThreeInput>,
    ) -> Result<(
        round_three::Private,
        HashMap<ParticipantIdentifier, round_three::Public>,
    )> {
        let order = k256_order();
        let mut delta: BigNumber = sender_r1_priv.gamma.modmul(&sender_r1_priv.k, &order);
        let mut chi: BigNumber = self.keyshare_private.x.modmul(&sender_r1_priv.k, &order);

        let g = CurvePoint::GENERATOR;
        let mut Gamma = CurvePoint(g.0 * bn_to_scalar(&sender_r1_priv.gamma).unwrap());

        for round_three_input in other_participant_inputs.values() {
            let r2_pub_j = round_three_input.r2_public.clone();
            let r2_priv_j = round_three_input.r2_private.clone();

            let alpha =
                BigNumber::from_slice(self.aux_info_private.sk.decrypt(&r2_pub_j.D.0).unwrap());
            let alpha_hat =
                BigNumber::from_slice(self.aux_info_private.sk.decrypt(&r2_pub_j.D_hat.0).unwrap());

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
            let psi_double_prime = PiLogProof::prove(
                &mut rng,
                &PiLogInput::new(
                    &round_three_input.auxinfo_public.params,
                    &order,
                    self.aux_info_public.pk.n(),
                    &sender_r1_priv.K.0,
                    &Delta,
                    &Gamma,
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
            ret_publics.insert(*other_id, val);
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

#[derive(Serialize, Deserialize)]
pub(crate) struct PresignRecord {
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
