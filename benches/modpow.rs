// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

#[macro_use]
extern crate criterion;

use criterion::Criterion;

use libpaillier::unknown_order::BigNumber;
use rand::rngs::OsRng;

fn base(c: &mut Criterion) {
    let num_bits_in_bn: usize = 2048;

    let mut a = BigNumber::random(&(BigNumber::one() << (num_bits_in_bn + 1)));
    let e = BigNumber::random(&(BigNumber::one() << (num_bits_in_bn + 1)));
    let n = BigNumber::random(&(BigNumber::one() << (num_bits_in_bn + 1)));

    c.bench_function(&format!("base ({} bits)", num_bits_in_bn), move |b| {
        b.iter(|| {
            a = a.modpow(&e, &n);
        })
    });
}

criterion_group!(
    modpow_benches,
    base,
    //montgomery_ladder,
);
criterion_main!(modpow_benches);
