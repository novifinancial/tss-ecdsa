#![allow(non_snake_case)] // FIXME: To be removed in the future

use ecdsa::hazmat::FromDigest;
use generic_array::GenericArray;
use k256::elliptic_curve::bigint::Encoding;
use k256::elliptic_curve::group::ff::PrimeField;
use k256::elliptic_curve::group::GroupEncoding;
use k256::elliptic_curve::Curve;
use k256::elliptic_curve::Field;
use libpaillier::{unknown_order::BigNumber, *};
use rand::{rngs::OsRng, CryptoRng, RngCore};

#[derive(Clone, Debug)]
struct Ciphertext(libpaillier::Ciphertext);

#[derive(Debug)]
pub struct KeygenPrivate {
    sk: DecryptionKey,
    x: k256::Scalar,
}
#[derive(Debug)]
pub struct KeygenPublic {
    pk: EncryptionKey,
    X: k256::ProjectivePoint,
}
pub struct KeyShare {
    public: KeygenPublic,
    private: KeygenPrivate,
}

impl KeyShare {
    pub fn new<R: RngCore + CryptoRng>(rng: &mut R, prime_bits: usize) -> Self {
        // FIXME: prime generation doesn't do safe primes... should we?
        let p = BigNumber::prime(prime_bits);
        let q = BigNumber::prime(prime_bits);

        let sk = DecryptionKey::with_safe_primes_unchecked(&p, &q).unwrap();
        let pk = EncryptionKey::from(&sk);

        let x = k256::Scalar::random(rng);
        let g = k256::ProjectivePoint::generator();
        let X = g * x; // public component

        Self {
            private: KeygenPrivate { sk, x },
            public: KeygenPublic { pk, X },
        }
    }
}

#[derive(Debug)]
pub struct RoundOnePrivate {
    k: k256::Scalar,
    gamma: k256::Scalar,
}

#[derive(Debug)]
pub struct RoundOnePublic {
    K: Ciphertext,
    G: Ciphertext,
}

/// Corresponds to pre-signing round 1 for party i
///
/// Produces local shares k and gamma, along with their encrypted
/// components K = enc(k) and G = enc(gamma).
///
pub fn round_one(keyshare: &KeyShare) -> (RoundOnePrivate, RoundOnePublic) {
    let k = k256::Scalar::random(&mut OsRng);
    let gamma = k256::Scalar::random(&mut OsRng);

    let (K, _) = keyshare.public.pk.encrypt(&k.to_bytes(), None).unwrap();
    let (G, _) = keyshare.public.pk.encrypt(&gamma.to_bytes(), None).unwrap();

    (
        RoundOnePrivate { k, gamma },
        RoundOnePublic {
            K: Ciphertext(K),
            G: Ciphertext(G),
        },
    )
}

/// Needs to be run once per party j != i
///
/// Constructs a D = gamma * K and D_hat = x * K, and Gamma = g * gamma.
///
pub fn round_two(
    keyshare: &KeyShare,
    kg_pub_j: &KeygenPublic,
    r1_priv_i: &RoundOnePrivate,
    r1_pub_j: &RoundOnePublic,
) -> (RoundTwoPrivate, RoundTwoPublic) {
    // Picking betas as k256 random scalars here is like sampling them from the distribution
    // [1, 2^256], which is akin to 2^{ell + epsilon} where ell = 128 and epsilon = 128
    let mut rng = rand::rngs::OsRng;
    let beta = k256::Scalar::random(&mut rng);
    let beta_hat = k256::Scalar::random(&mut rng);

    let (beta_ciphertext, _) = kg_pub_j.pk.encrypt(beta.to_bytes(), None).unwrap();
    let (beta_hat_ciphertext, _) = kg_pub_j.pk.encrypt(beta_hat.to_bytes(), None).unwrap();

    let D = kg_pub_j
        .pk
        .add(
            &kg_pub_j
                .pk
                .mul(
                    &r1_pub_j.K.0,
                    &BigNumber::from_slice(r1_priv_i.gamma.to_repr()),
                )
                .unwrap(),
            &beta_ciphertext,
        )
        .unwrap();

    let D_hat = kg_pub_j
        .pk
        .add(
            &kg_pub_j
                .pk
                .mul(
                    &r1_pub_j.K.0,
                    &BigNumber::from_slice(keyshare.private.x.to_repr()),
                )
                .unwrap(),
            &beta_hat_ciphertext,
        )
        .unwrap();

    let (F, _) = keyshare.public.pk.encrypt(beta.to_bytes(), None).unwrap();
    let (F_hat, _) = keyshare
        .public
        .pk
        .encrypt(beta_hat.to_bytes(), None)
        .unwrap();

    let g = k256::ProjectivePoint::generator();
    let Gamma = g * r1_priv_i.gamma;

    (
        RoundTwoPrivate { beta, beta_hat },
        RoundTwoPublic {
            D: Ciphertext(D),
            D_hat: Ciphertext(D_hat),
            F: Ciphertext(F),
            F_hat: Ciphertext(F_hat),
            Gamma,
        },
    )
}

#[derive(Clone)]
pub struct RoundTwoPrivate {
    beta: k256::Scalar,
    beta_hat: k256::Scalar,
}

#[derive(Clone)]
pub struct RoundTwoPublic {
    D: Ciphertext,
    D_hat: Ciphertext,
    F: Ciphertext,
    F_hat: Ciphertext,
    Gamma: k256::ProjectivePoint,
}

pub struct RoundThreePrivate {
    k: k256::Scalar,
    chi: k256::Scalar,
    Gamma: k256::ProjectivePoint,
}

pub struct RoundThreePublic {
    delta: k256::Scalar,
    Delta: k256::ProjectivePoint,
}

/// From the perspective of party i
/// r2_privs and r2_pubs don't include party i
///
/// First computes alpha = dec(D), alpha_hat = dec(D_hat).
/// Computes a delta = gamma * k
pub fn round_three(
    keyshare: &KeyShare,
    r1_priv_i: &RoundOnePrivate,
    r2_privs: &[Option<RoundTwoPrivate>],
    r2_pubs: &[Option<RoundTwoPublic>],
) -> (RoundThreePrivate, RoundThreePublic) {
    let mut delta: k256::Scalar = r1_priv_i.gamma * r1_priv_i.k;
    let mut chi: k256::Scalar = keyshare.private.x * r1_priv_i.k;

    assert!(r2_privs.len() == r2_pubs.len(), "Should be same length");

    let g = k256::ProjectivePoint::generator();
    let mut Gamma = g * r1_priv_i.gamma;

    for i in 0..r2_privs.len() {
        if r2_pubs[i].is_none() {
            assert!(
                r2_privs[i].is_none(),
                "Should both be None or neither are None"
            );
            continue;
        }
        let r2_pub_j = r2_pubs[i].clone().unwrap();
        let r2_priv_j = r2_privs[i].clone().unwrap();

        let alpha = bn_to_scalar(&BigNumber::from_slice(
            keyshare.private.sk.decrypt(&r2_pub_j.D.0).unwrap(),
        ))
        .unwrap();
        let alpha_hat = bn_to_scalar(&BigNumber::from_slice(
            keyshare.private.sk.decrypt(&r2_pub_j.D_hat.0).unwrap(),
        ))
        .unwrap();

        delta += alpha - r2_priv_j.beta;
        chi += alpha_hat - r2_priv_j.beta_hat;

        Gamma += r2_pub_j.Gamma;
    }

    let Delta = Gamma * r1_priv_i.k;

    (
        RoundThreePrivate {
            k: r1_priv_i.k,
            chi,
            Gamma,
        },
        RoundThreePublic { delta, Delta },
    )
}

pub struct PresignRecord {
    R: k256::ProjectivePoint,
    k: k256::Scalar,
    chi: k256::Scalar,
}

pub fn finish(r3_priv: &RoundThreePrivate, r3_pubs: &[RoundThreePublic]) -> PresignRecord {
    let mut delta = k256::Scalar::zero();
    let mut Delta = k256::ProjectivePoint::identity();
    for r3_pub in r3_pubs {
        delta += &r3_pub.delta;
        Delta += r3_pub.Delta;
    }

    let g = k256::ProjectivePoint::generator();
    if g * delta != Delta {
        // Error, failed to validate
        panic!("Error, failed to validate");
    }

    let R = r3_priv.Gamma * delta.invert().unwrap();

    PresignRecord {
        R,
        k: r3_priv.k,
        chi: r3_priv.chi,
    }
}

pub fn sign(record: &PresignRecord, d: sha2::Sha256) -> (k256::Scalar, k256::Scalar) {
    let r = x_from_point(&record.R);
    let m = k256::Scalar::from_digest(d);
    let s = record.k * m + r * record.chi;

    (r, s)
}

fn x_from_point(p: &k256::ProjectivePoint) -> k256::Scalar {
    let r = &p.to_affine().to_bytes()[1..32 + 1];
    k256::Scalar::from_bytes_reduced(&GenericArray::clone_from_slice(r))
}

fn bn_to_scalar(x: &BigNumber) -> Option<k256::Scalar> {
    // Take (mod q)
    let order_bytes: [u8; 32] = k256::Secp256k1::ORDER.to_be_bytes();
    let order = BigNumber::from_slice(&order_bytes);

    let x_modded = x % order;

    let bytes = x_modded.to_bytes();

    let mut slice = vec![0u8; 32 - bytes.len()];
    slice.extend_from_slice(&bytes);
    k256::Scalar::from_repr(GenericArray::clone_from_slice(&slice))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ecdsa::signature::DigestVerifier;
    use rand::rngs::OsRng;
    use sha2::{Digest, Sha256};

    /// Generate safe primes from a file. Usually, generating safe primes takes
    /// awhile (5-10 minutes per 1024-bit safe prime on my laptop)
    #[allow(dead_code)]
    fn get_safe_primes() -> Vec<BigNumber> {
        let file_contents = std::fs::read_to_string("src/safe_primes.txt").unwrap();
        let mut safe_primes_str: Vec<&str> = file_contents.split("\n").collect();
        safe_primes_str = safe_primes_str[0..safe_primes_str.len() - 1].to_vec(); // Remove the last element which is empty
        let safe_primes: Vec<BigNumber> = safe_primes_str
            .into_iter()
            .map(|s| bincode::deserialize(&hex::decode(&s).unwrap()).unwrap())
            .collect();
        safe_primes
    }

    /// Executes a test between two parties i and j
    #[test]
    fn run_test() {
        let mut rng = OsRng;
        let NUM_PARTIES = 3;

        // Keygen
        println!("Beginning Keygen");
        let mut keyshares = vec![];
        for _ in 0..NUM_PARTIES {
            let keyshare = KeyShare::new(&mut rng, 512);
            keyshares.push(keyshare);
        }

        // Round 1
        println!("Beginning Round 1");
        let mut r1_privs = vec![];
        let mut r1_pubs = vec![];
        for i in 0..NUM_PARTIES {
            let (r1_priv, r1_pub) = round_one(&keyshares[i]);
            r1_privs.push(r1_priv);
            r1_pubs.push(r1_pub);
        }

        // Round 2, each step needs to be done for each j != i
        println!("Beginning Round 2");
        let mut r2_privs = vec![];
        let mut r2_pubs = vec![];
        for i in 0..NUM_PARTIES {
            let mut r2_priv_i = vec![];
            let mut r2_pub_i = vec![];
            for j in 0..NUM_PARTIES {
                if j == i {
                    r2_priv_i.push(None);
                    r2_pub_i.push(None);
                    continue;
                }
                let (r2_priv_ij, r2_pub_ij) = round_two(
                    &keyshares[i],
                    &keyshares[j].public,
                    &r1_privs[i],
                    &r1_pubs[j],
                );
                r2_priv_i.push(Some(r2_priv_ij));
                r2_pub_i.push(Some(r2_pub_ij));
            }
            r2_privs.push(r2_priv_i);
            r2_pubs.push(r2_pub_i);
        }

        // Round 3, each step needs to be done for each j != i
        println!("Beginning Round 3");
        let mut r3_privs = vec![];
        let mut r3_pubs = vec![];
        for i in 0..NUM_PARTIES {
            let r2_pubs_cross = {
                let mut result = vec![];
                for j in 0..NUM_PARTIES {
                    result.push(r2_pubs[j][i].clone());
                }
                result
            };

            let (r3_priv, r3_pub) = round_three(
                &keyshares[i],
                &r1_privs[i],
                &r2_privs[i][..],
                &r2_pubs_cross[..],
            );
            r3_privs.push(r3_priv);
            r3_pubs.push(r3_pub);
        }

        // Presign Finish
        println!("Beginning Presign Finish");

        let mut presign_records = vec![];
        for i in 0..NUM_PARTIES {
            let record_i = finish(&r3_privs[i], &r3_pubs);
            presign_records.push(record_i);
        }

        // Produce sign share
        println!("Produce sign share");

        let mut hasher = Sha256::new();
        hasher.update(b"hello world");

        let mut signing_key = k256::Scalar::zero();
        let mut verifying_key = k256::ProjectivePoint::identity();
        for i in 0..NUM_PARTIES {
            signing_key += keyshares[i].private.x;
            verifying_key += keyshares[i].public.X;
        }

        let vk =
            ecdsa::VerifyingKey::from_encoded_point(&verifying_key.to_affine().into()).unwrap();

        let mut s_acc = k256::Scalar::zero();
        let mut r_scalars = vec![];
        for i in 0..NUM_PARTIES {
            let (r, s) = sign(&presign_records[i], hasher.clone());
            s_acc += s;
            r_scalars.push(r);
        }

        // All r's should be the same
        for i in 0..NUM_PARTIES - 1 {
            assert_eq!(r_scalars[i], r_scalars[i + 1]);
        }

        if s_acc.is_high().unwrap_u8() == 1 {
            s_acc = s_acc.negate();
        }

        let sig = ecdsa::Signature::from_scalars(r_scalars[0], s_acc).unwrap();

        assert!(vk.verify_digest(hasher, &sig).is_ok());
    }
}
