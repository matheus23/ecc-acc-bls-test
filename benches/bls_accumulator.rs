use bls12_381::Scalar;
use criterion::{black_box, Criterion};
use ecc_acc_bls_test::bls::{Accumulator, TrustlessSetup};
use ff::Field;
use rand_chacha::{rand_core::SeedableRng, ChaCha12Rng};

pub fn criterion_benchmark(c: &mut Criterion) {
    c.bench_function("100-element trustless ECC accumulator setup", |b| {
        b.iter_batched(
            || ChaCha12Rng::from_entropy(),
            |rng| black_box(TrustlessSetup::create(black_box(100), rng)),
            criterion::BatchSize::SmallInput,
        )
    });
    n_element_add(1, c);
    n_element_add(5, c);
    n_element_add(10, c);
    n_element_add(15, c);
    n_element_add(20, c);
}

fn n_element_add(n: usize, c: &mut Criterion) {
    c.bench_function(&format!("{n}-element trustless ECC accumulator add"), |b| {
        b.iter_batched(
            || {
                let (setup, _) = TrustlessSetup::create(n + 2, ChaCha12Rng::from_entropy());
                let mut acc = Accumulator::empty();
                for element in (0..n).map(|_| Scalar::random(ChaCha12Rng::from_entropy())) {
                    acc.add(&setup, element);
                }
                let element = Scalar::random(ChaCha12Rng::from_entropy());
                (setup, acc, element)
            },
            |(setup, mut acc, num)| black_box(acc.add(&setup, num)),
            criterion::BatchSize::SmallInput,
        )
    });
}
