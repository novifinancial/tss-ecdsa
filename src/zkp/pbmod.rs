// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

//! Implements the ZKP from Figure 16 of https://eprint.iacr.org/2021/060.pdf

use crate::errors::*;
use libpaillier::unknown_order::BigNumber;
use merlin::Transcript;

// Soundness parameter lambda: This needs to be 128, but
// right now it is too slow if it large
static LAMBDA: usize = 2;

#[derive(Debug)]
pub struct PaillierBlumModulusProof {
    pub(crate) N: BigNumber,
    w: BigNumber,
    // (x, a, b, z),
    elements: Vec<PaillierBlumModulusProofElements>,
}

#[derive(Debug)]
pub struct PaillierBlumModulusProofElements {
    x: BigNumber,
    a: usize,
    b: usize,
    z: BigNumber,
    y: BigNumber,
}

// Compute regular mod
fn bn_mod(n: &BigNumber, p: &BigNumber) -> BigNumber {
    n.modadd(&BigNumber::zero(), p)
}

// Denominator needs to be positive and odd
fn jacobi(numerator: &BigNumber, denominator: &BigNumber) -> isize {
    let mut n = bn_mod(numerator, denominator);
    let mut k = denominator.clone();
    let mut t = 1;

    while n != BigNumber::zero() {
        while bn_mod(&n, &BigNumber::from(2)) == BigNumber::zero() {
            n /= 2;
            let r = bn_mod(&k, &BigNumber::from(8));
            if r == BigNumber::from(3) || r == BigNumber::from(5) {
                t *= -1;
            }
        }

        // (n, k) = (k, n), swap them
        std::mem::swap(&mut n, &mut k);

        if bn_mod(&n, &BigNumber::from(4)) == BigNumber::from(3)
            && bn_mod(&k, &BigNumber::from(4)) == BigNumber::from(3)
        {
            t *= -1;
        }
        n = bn_mod(&n, &k);
    }

    if k == BigNumber::one() {
        return t;
    }

    0
}

/// Finds the two x's such that x^2 = n (mod p), where p is a prime that is 3 (mod 4)
fn square_roots_mod_prime(
    n: &BigNumber,
    p: &BigNumber,
) -> Result<(BigNumber, BigNumber), InternalError> {
    // Compute r = +- n^{p+1/4} (mod p)
    let r = n.modpow(&(&(p + 1) / 4), p);
    let neg_r = r.modneg(p);

    // Check that r and neg_r are such that r^2 = n (mod p) -- if not, then
    // there are no solutions

    if r.modpow(&BigNumber::from(2), p) == bn_mod(n, p) {
        return Ok((r, neg_r));
    }
    Err(InternalError::NoSquareRoots)
}

// Finds an (x,y) such that ax + by = 1, or returns error if gcd(a,b) != 1
fn extended_euclidean(
    a: &BigNumber,
    b: &BigNumber,
) -> Result<(BigNumber, BigNumber), InternalError> {
    let result = a.extended_gcd(b);

    if result.gcd != BigNumber::one() {
        return Err(InternalError::NotCoprime);
    }

    Ok((result.x, result.y))
}

/// Finds an x such that x = a1 (mod p) and x = a2 (mod q)
#[allow(clippy::many_single_char_names)]
fn chinese_remainder_theorem(
    a1: &BigNumber,
    a2: &BigNumber,
    p: &BigNumber,
    q: &BigNumber,
) -> Result<BigNumber, InternalError> {
    let (z, w) = extended_euclidean(p, q)?;
    let x = a1 * w * q + a2 * z * p;
    Ok(bn_mod(&x, &(p * q)))
}

/// Finds the four x's such that x^2 = n (mod pq), where p,q are primes that are 3 (mod 4)
fn square_roots_mod_composite(
    n: &BigNumber,
    p: &BigNumber,
    q: &BigNumber,
) -> Result<[BigNumber; 4], InternalError> {
    let (y1, y2) = square_roots_mod_prime(n, p)?;
    let (z1, z2) = square_roots_mod_prime(n, q)?;

    let x1 = chinese_remainder_theorem(&y1, &z1, p, q)?;
    let x2 = chinese_remainder_theorem(&y1, &z2, p, q)?;
    let x3 = chinese_remainder_theorem(&y2, &z1, p, q)?;
    let x4 = chinese_remainder_theorem(&y2, &z2, p, q)?;

    Ok([x1, x2, x3, x4])
}

fn fourth_roots_mod_composite(
    n: &BigNumber,
    p: &BigNumber,
    q: &BigNumber,
) -> Result<Vec<BigNumber>, InternalError> {
    let mut fourth_roots = vec![];

    let xs = square_roots_mod_composite(n, p, q)?;
    for x in xs {
        match square_roots_mod_composite(&x, p, q) {
            Ok(res) => {
                for y in res {
                    fourth_roots.push(y);
                }
            }
            Err(_) => {
                continue;
            }
        }
    }
    Ok(fourth_roots)
}

/// Compute y' = (-1)^a * w^b * y (mod N)
fn y_prime_from_y(y: &BigNumber, w: &BigNumber, a: usize, b: usize, N: &BigNumber) -> BigNumber {
    let mut y_prime = y.clone();

    if b == 1 {
        y_prime = y_prime.modmul(w, N);
    }

    if a == 1 {
        y_prime = y_prime.modneg(N);
    }

    y_prime
}

/// Finds unique a,b in {0,1} such that, for y' = (-1)^a * w^b * y, there is an x such that
/// x^4 = y (mod pq)
fn y_prime_combinations(
    w: &BigNumber,
    y: &BigNumber,
    p: &BigNumber,
    q: &BigNumber,
) -> Result<(usize, usize, Vec<BigNumber>), InternalError> {
    let N = p * q;

    let mut ret = vec![];

    let mut has_fourth_roots = 0;
    let mut success_a = 0;
    let mut success_b = 0;

    for a in 0..2 {
        for b in 0..2 {
            let y_prime = y_prime_from_y(y, w, a, b, &N);
            match fourth_roots_mod_composite(&y_prime, p, q) {
                Ok(values) => {
                    has_fourth_roots += 1;
                    success_a = a;
                    success_b = b;
                    ret.extend_from_slice(&values);
                }
                Err(_) => {
                    continue;
                }
            }
        }
    }

    if has_fourth_roots != 1 {
        return Err(InternalError::NonUniqueFourthRootsCombination);
    }

    Ok((success_a, success_b, ret))
}

/// Generate a random value less than `n`
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

impl PaillierBlumModulusProof {
    /// Generated by the prover, requires public input N and secrets (p,q)
    /// Prover generates a random w in Z_N of Jacobi symbol -1
    #[allow(clippy::many_single_char_names)]
    pub(crate) fn prove(
        N: &BigNumber,
        p: &BigNumber,
        q: &BigNumber,
    ) -> Result<Self, InternalError> {
        // Step 1: Pick a random w in [1, N) that has a Jacobi symbol of -1
        let mut w = BigNumber::random(N);
        while jacobi(&w, N) != -1 {
            w = BigNumber::random(N);
        }

        let mut transcript = Transcript::new(b"PaillierBlumModulusProof");

        transcript.append_message(b"w", &w.to_bytes());

        let mut elements = vec![];
        for _ in 0..LAMBDA {
            let y = bn_random(&mut transcript, N);

            let (a, b, x) = y_prime_combinations(&w, &y, p, q)?;

            // Compute phi(N) = (p-1) * (q-1)
            let phi_n = (p - 1) * (q - 1);
            let exp = N
                .invert(&phi_n)
                .ok_or(InternalError::CouldNotInvertBigNumber)?;
            let z = y.modpow(&exp, N);

            elements.push(PaillierBlumModulusProofElements {
                x: x[0].clone(),
                a,
                b,
                z,
                y,
            });
        }

        Ok(Self {
            N: N.clone(),
            w,
            elements,
        })
    }

    pub(crate) fn verify(&self) -> bool {
        // Verify that N is an odd composite number

        if &self.N % BigNumber::from(2) == BigNumber::zero() {
            // N is even
            println!("N is even");
            return false;
        }

        if self.N.is_prime() {
            // N is not composite
            println!("N is not composite");
            return false;
        }

        let mut transcript = Transcript::new(b"PaillierBlumModulusProof");
        transcript.append_message(b"w", &self.w.to_bytes());

        for elements in &self.elements {
            // First, check that y came from Fiat-Shamir transcript
            let y = bn_random(&mut transcript, &self.N);
            if y != elements.y {
                // y does not match Fiat-Shamir challenge
                return false;
            }

            let y_candidate = elements.z.modpow(&self.N, &self.N);
            if elements.y != y_candidate {
                // z^N != y (mod N)
                println!("z^N != y (mod N)");
                return false;
            }

            if elements.a != 0 && elements.a != 1 {
                // a not in {0,1}
                println!("a not in 0,1");
                return false;
            }

            if elements.b != 0 && elements.b != 1 {
                // b not in {0,1}
                println!("b not in 0,1");
                return false;
            }

            let y_prime = y_prime_from_y(&elements.y, &self.w, elements.a, elements.b, &self.N);
            if elements.x.modpow(&BigNumber::from(4), &self.N) != y_prime {
                // x^4 != y' (mod N)
                println!("x^4 != y' (mod N)");
                return false;
            }
        }

        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_jacobi() {
        let p = BigNumber::safe_prime(128);
        let q = BigNumber::safe_prime(128);

        let N = &p * &q;

        for _ in 0..100 {
            let a = BigNumber::random(&N);

            let a_p = jacobi(&a, &p);
            let a_q = jacobi(&a, &q);

            // Verify that a^{p-1/2} == a_p (mod p)
            assert_eq!(
                bn_mod(&BigNumber::from(a_p), &p),
                a.modpow(&(&(&p - 1) / 2), &p)
            );

            // Verify that a^{q-1/2} == a_q (mod q)
            assert_eq!(
                bn_mod(&BigNumber::from(a_q), &q),
                a.modpow(&(&(&q - 1) / 2), &q)
            );

            // Verify that (a/n) = (a/p) * (a/q)
            let a_n = jacobi(&a, &N);
            assert_eq!(a_n, a_p * a_q);
        }
    }

    #[test]
    fn test_square_roots_mod_prime() {
        let p = BigNumber::safe_prime(128);

        for _ in 0..100 {
            let a = BigNumber::random(&p);
            let a_p = jacobi(&a, &p);

            let roots = square_roots_mod_prime(&a, &p);
            match roots {
                Ok((r1, r2)) => {
                    assert_eq!(a_p, 1);
                    assert_eq!(r1.modpow(&BigNumber::from(2), &p), a);
                    assert_eq!(r2.modpow(&BigNumber::from(2), &p), a);
                }
                Err(InternalError::NoSquareRoots) => {
                    assert_ne!(a_p, 1);
                }
                Err(_) => {
                    panic!("Should not reach here");
                }
            }
        }
    }

    #[test]
    fn test_square_roots_mod_composite() {
        let p = BigNumber::safe_prime(128);
        let q = BigNumber::safe_prime(128);
        let N = &p * &q;

        // Loop until we've confirmed enough successes
        let mut success = 0;
        loop {
            if success == 10 {
                return;
            }
            let a = BigNumber::random(&N);
            let a_n = jacobi(&a, &N);

            let roots = square_roots_mod_composite(&a, &p, &q);
            match roots {
                Ok(xs) => {
                    assert_eq!(a_n, 1);
                    for x in xs {
                        assert_eq!(x.modpow(&BigNumber::from(2), &N), a);
                    }
                    success += 1;
                }
                Err(_) => {
                    continue;
                }
            }
        }
    }

    #[test]
    fn test_fourth_roots_mod_composite() {
        let p = BigNumber::safe_prime(128);
        let q = BigNumber::safe_prime(128);
        let N = &p * &q;

        // Loop until we've confirmed enough successes
        let mut success = 0;
        loop {
            if success == 10 {
                return;
            }
            let a = BigNumber::random(&N);
            let a_n = jacobi(&a, &N);

            let roots = fourth_roots_mod_composite(&a, &p, &q);
            match roots {
                Ok(xs) => {
                    assert_eq!(a_n, 1);
                    for x in xs {
                        assert_eq!(x.modpow(&BigNumber::from(4), &N), a);
                    }
                    success += 1;
                }
                Err(_) => {
                    continue;
                }
            }
        }
    }

    #[test]
    fn test_chinese_remainder_theorem() {
        let p = BigNumber::safe_prime(128);
        let q = BigNumber::safe_prime(128);

        for _ in 0..100 {
            let a1 = BigNumber::random(&p);
            let a2 = BigNumber::random(&q);

            let x = chinese_remainder_theorem(&a1, &a2, &p, &q).unwrap();

            assert_eq!(bn_mod(&x, &p), a1);
            assert_eq!(bn_mod(&x, &q), a2);
            assert!(x < &p * &q);
        }
    }
}
