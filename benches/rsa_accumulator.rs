use std::str::FromStr;

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use ecc_acc_bls_test::rsa_accumulator::Accumulator;
use num_bigint_dig::{
    prime::{self, probably_prime},
    BigUint, RandBigInt, RandPrime,
};
use proptest::prelude::Rng;
use rand_chacha::{rand_core::SeedableRng, ChaCha12Rng, ChaCha20Rng};

pub fn criterion_benchmark(c: &mut Criterion) {
    let rsa_2048 = BigUint::from_str(
        "25195908475657893494027183240048398571429282126204032027777137836043662020707595556264018525880784406918290641249515082189298559149176184502808489120072844992687392807287776735971418347270261896375014971824691165077613379859095700097330459748808428401797429100642458691817195118746121515172654632282216869987549182422433637259085141865462043576798423387184774447920739934236584823824281198163815010674810451660377306056201619676256133844143603833904414952634432190114657544454178424020924616515723350778707749817125772467962926386356373289912154831438167899885040445364023527381951378636564391212010397122822120720357",
    )
    .unwrap();

    c.bench_function("256-bit add to accumulator", |b| {
        b.iter_batched(
            || {
                let rng = &mut ChaCha12Rng::from_entropy();
                let acc = Accumulator::from(rsa_2048.clone(), rng);
                (acc, rng.gen_prime(256))
            },
            |(mut acc, prime)| black_box(acc.add(black_box(&prime))),
            criterion::BatchSize::SmallInput,
        )
    });
    c.bench_function("accumulator PoKE* with 1 element", |b| {
        b.iter_batched(
            || {
                let rng = &mut ChaCha12Rng::from_entropy();
                let acc = Accumulator::from(rsa_2048.clone(), rng);
                (acc, rng.gen_prime(256))
            },
            |(mut acc, prime)| black_box(acc.add_batch(black_box(&[prime]))),
            criterion::BatchSize::SmallInput,
        )
    });
    c.bench_function("accumulator PoKE* with 10 elements", |b| {
        b.iter_batched(
            || {
                let rng = &mut ChaCha12Rng::from_entropy();
                let acc = Accumulator::from(rsa_2048.clone(), rng);
                let mut vec = Vec::new();
                for _ in 0..10 {
                    vec.push(rng.gen_prime(256));
                }
                (acc, vec)
            },
            |(mut acc, primes)| black_box(acc.add_batch(black_box(&primes))),
            criterion::BatchSize::SmallInput,
        )
    });
}
