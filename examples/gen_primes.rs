use libpaillier::unknown_order::BigNumber;

use std::fs::OpenOptions;
use std::io::prelude::*;
use std::time::{Duration, Instant};

fn main() {
    let mut file = OpenOptions::new()
        .write(true)
        .append(true)
        .open("src/safe_primes_512.txt")
        .unwrap();

    let mut prev = Instant::now();

    let iterations = 1000;

    let mut total_seconds = Duration::new(0, 0);

    println!("Generating {} 512-bit safe primes...", iterations);
    for i in 0..iterations {
        let prime = BigNumber::safe_prime(512);
        let next = Instant::now();
        let duration = next - prev;
        prev = next;
        total_seconds += duration;
        println!("Generating that prime took: {} seconds", duration.as_secs());
        println!(
            "Total average prime generation time: {} seconds",
            total_seconds.as_secs() as f64 / (i as f64 + 1.0)
        );
        writeln!(file, "{}", hex::encode(prime.to_bytes())).unwrap();
        file.flush().unwrap();
    }
    println!("Hello World!");
}
