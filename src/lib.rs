#![allow(dead_code)] // FIXME: To be removed in the future
#![allow(non_snake_case)] // FIXME: To be removed in the future
#![allow(unused_variables)] // FIXME: To be removed in the future

use k256::elliptic_curve::group::ff::PrimeField;
use k256::elliptic_curve::Field;
use libpaillier::{unknown_order::BigNumber, *};

struct KeygenPrivate {
    sk: DecryptionKey,
    x: k256::Scalar,
}

struct KeygenPublic {
    pk: EncryptionKey,
    X: k256::ProjectivePoint,
}

/// Takes two safe primes p and q
fn keygen(p: &BigNumber, q: &BigNumber) -> (KeygenPrivate, KeygenPublic) {
    let mut rng = rand::rngs::OsRng;

    let sk = DecryptionKey::with_safe_primes_unchecked(p, q).unwrap();
    let pk = EncryptionKey::from(&sk);

    let x = k256::Scalar::random(&mut rng);
    let g = k256::ProjectivePoint::generator();
    let X = g * x; // public component

    (KeygenPrivate { sk, x }, KeygenPublic { pk, X })
}

struct RoundOnePrivate {
    k: k256::Scalar,
    gamma: k256::Scalar,
}

struct RoundOnePublic {
    K: BigNumber,
    G: BigNumber,
}

/// Corresponds to pre-signing round 1 for party i
///
fn round_1(kg_pub_i: &KeygenPublic) -> (RoundOnePrivate, RoundOnePublic) {
    let mut rng = rand::rngs::OsRng;

    let k = k256::Scalar::random(&mut rng);
    let gamma = k256::Scalar::random(&mut rng);

    let (K, _) = kg_pub_i.pk.encrypt(&k.to_bytes(), None).unwrap();
    let (G, _) = kg_pub_i.pk.encrypt(&gamma.to_bytes(), None).unwrap();

    (RoundOnePrivate { k, gamma }, RoundOnePublic { K, G })
}

struct RoundTwoPrivate {
    beta: BigNumber,
    beta_hat: BigNumber,
}

struct RoundTwoPublic {
    D: BigNumber,
    D_hat: BigNumber,
    F: BigNumber,
    F_hat: BigNumber,
}

/// Needs to be run once per party j != i
fn round_2(
    kg_priv_i: &KeygenPrivate,
    kg_pub_i: &KeygenPublic,
    kg_pub_j: &KeygenPublic,
    r1_priv_i: &RoundOnePrivate,
    r1_pub_j: &RoundOnePublic,
) -> (RoundTwoPrivate, RoundTwoPublic) {
    // FIXME: betas should be sampled from an interval
    let beta = BigNumber::from(256);
    let beta_hat = BigNumber::from(256);

    let D = kg_pub_j
        .pk
        .add(
            &kg_pub_j
                .pk
                .mul(
                    &r1_pub_j.K,
                    &BigNumber::from_slice(r1_priv_i.gamma.to_repr()),
                )
                .unwrap(),
            &beta,
        )
        .unwrap();

    let D_hat = kg_pub_j
        .pk
        .add(
            &kg_pub_j
                .pk
                .mul(&r1_pub_j.K, &BigNumber::from_slice(kg_priv_i.x.to_repr()))
                .unwrap(),
            &beta_hat,
        )
        .unwrap();

    let (F, _) = kg_pub_i.pk.encrypt(beta.to_bytes(), None).unwrap();
    let (F_hat, _) = kg_pub_i.pk.encrypt(beta_hat.to_bytes(), None).unwrap();

    (
        RoundTwoPrivate { beta, beta_hat },
        RoundTwoPublic { D, D_hat, F, F_hat },
    )
}
struct RoundThreePrivate {}

struct RoundThreePublic {}

/// From the perspective of party i
/// Note quite done yet
fn round_3(
    kg_priv_i: &KeygenPrivate,
    r1_priv_i: RoundOnePrivate,
    r2_privs: &[RoundTwoPrivate],
    r2_pubs: &[RoundTwoPublic],
) -> (RoundThreePrivate, RoundThreePublic) {
    let mut delta = BigNumber::from_slice((r1_priv_i.gamma * r1_priv_i.k).to_repr());
    let mut chi = BigNumber::from_slice((kg_priv_i.x * r1_priv_i.k).to_repr());

    assert!(r2_privs.len() == r2_pubs.len(), "Should be same length");

    for i in 0..r2_privs.len() {
        let alpha = kg_priv_i.sk.decrypt(&r2_pubs[i].D).unwrap();
        let alpha_hat = kg_priv_i.sk.decrypt(&r2_pubs[i].D_hat).unwrap();

        delta += BigNumber::from_slice(alpha) + &r2_privs[i].beta;
        chi += BigNumber::from_slice(alpha_hat) + &r2_privs[i].beta_hat;
    }

    (
        RoundThreePrivate {
            // FIXME: needs to be filled in
        },
        RoundThreePublic {
            // FIXME: needs to be filled in
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Generate safe primes from a file. Usually, generating safe primes takes
    /// awhile (5-10 minutes per 1024-bit safe prime on my laptop)
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
        // Keygen

        let safe_primes = get_safe_primes();
        let (kg_priv_i, kg_pub_i) = keygen(&safe_primes[0], &safe_primes[1]);
        let (kg_priv_j, kg_pub_j) = keygen(&safe_primes[2], &safe_primes[3]);

        // Round 1

        let (r1_priv_i, r1_pub_i) = round_1(&kg_pub_i);
        let (r1_priv_j, r1_pub_j) = round_1(&kg_pub_j);

        // Round 2, each step needs to be done for each j != i

        let (r2_priv_ij, r2_pub_ij) =
            round_2(&kg_priv_i, &kg_pub_i, &kg_pub_j, &r1_priv_i, &r1_pub_j);
        let (r2_priv_ji, r2_pub_ji) =
            round_2(&kg_priv_j, &kg_pub_j, &kg_pub_i, &r1_priv_j, &r1_pub_i);

        assert_eq!(1, 1);
    }
}
