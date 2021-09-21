use super::*;

use crate::errors::*;
use crate::key::KeygenPublic;
use ecdsa::signature::DigestVerifier;
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};

/// Executes a test between two parties i and j
#[cfg_attr(feature = "flame_it", flame)]
#[test]
fn run_test() -> Result<()> {
    let mut rng = OsRng;
    let NUM_PARTIES = 3;
    let safe_primes = get_safe_primes();

    // Keygen
    println!("Beginning Keygen");
    let mut keyshares = vec![];
    for i in 0..NUM_PARTIES {
        let keyshare =
            key::KeyShare::from_safe_primes(&mut rng, &safe_primes[2 * i], &safe_primes[2 * i + 1]);
        keyshares.push(keyshare);
    }

    let public_keys: Vec<Option<KeygenPublic>> =
        keyshares.iter().map(|x| Some(x.public.clone())).collect();

    // Round 1
    println!("Beginning Round 1");
    let mut r1_privs = vec![];
    let mut r1_pubs = vec![];
    for (i, k) in keyshares.iter().enumerate() {
        // Produce the vector of public keys, where the i'th entry is None
        let mut public_keys_without_self = public_keys.clone();
        public_keys_without_self[i] = None;

        let Pair { private, public } = k.round_one(&public_keys_without_self)?;
        r1_privs.push(private);
        r1_pubs.push(public);
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
            let Pair {
                private: r2_priv_ij,
                public: r2_pub_ij,
            } = keyshares[i].round_two(&keyshares[j].public, &r1_privs[i], &r1_pubs[j]);
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

        let Pair {
            private: r3_priv,
            public: r3_pub,
        } = keyshares[i].round_three(&r1_privs[i], &r2_privs[i][..], &r2_pubs_cross[..]);
        r3_privs.push(r3_priv);
        r3_pubs.push(r3_pub);
    }

    // Presign Finish
    println!("Beginning Presign Finish");

    let mut presign_records = vec![];
    for private in r3_privs.into_iter() {
        let record_i: PresignRecord = RecordPair {
            private,
            public: r3_pubs.clone(),
        }
        .into();
        presign_records.push(record_i);
    }

    // Produce sign share
    println!("Produce sign share");

    let mut hasher = Sha256::new();
    hasher.update(b"hello world");

    let mut signing_key = k256::Scalar::zero();
    let mut verifying_key = k256::ProjectivePoint::identity();
    for i in 0..NUM_PARTIES {
        signing_key += crate::key::bn_to_scalar(&keyshares[i].private.x).unwrap();
        verifying_key += keyshares[i].public.X;
    }

    let vk = ecdsa::VerifyingKey::from_encoded_point(&verifying_key.to_affine().into()).unwrap();

    let mut s_acc = k256::Scalar::zero();
    let mut r_scalars = vec![];
    for record in presign_records.into_iter() {
        let (r, s) = record.sign(hasher.clone());
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

    #[cfg(feature = "flame_it")]
    flame::dump_html(&mut std::fs::File::create("stats/flame-graph.html").unwrap()).unwrap();

    Ok(())
}
