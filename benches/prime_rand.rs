use criterion::{black_box, criterion_group, criterion_main, Criterion};
use num_bigint_dig::{prime, BigUint, RandPrime};
use proptest::prelude::{Rng, RngCore};
use rand_chacha::{rand_core::SeedableRng, ChaCha12Rng, ChaCha20Rng};

pub fn criterion_benchmark(c: &mut Criterion) {
    // let mut seed = [0u8; 32];
    // hex::decode_to_slice(
    //     "2f24d77ef60d86e3c30e54655ea06e1c8aa9b663aabd2ae0284d44bc73f34148",
    //     &mut seed,
    // )
    // .unwrap();
    // let seed = b"test                            ";

    c.bench_function("256-bit prime via chacha 12", |b| {
        b.iter_batched(
            || ChaCha12Rng::from_entropy(),
            |mut rng| rng.gen_prime(black_box(256)),
            criterion::BatchSize::SmallInput,
        )
    });
    c.bench_function("256-bit prime via chacha 20", |b| {
        b.iter_batched(
            || ChaCha20Rng::from_entropy(),
            |mut rng| rng.gen_prime(black_box(256)),
            criterion::BatchSize::SmallInput,
        )
    });
    c.bench_function("256-bit prime via next_prime", |b| {
        b.iter_batched(
            || BigUint::from_bytes_le(&ChaCha12Rng::from_entropy().gen::<[u8; 32]>()),
            |num| prime::next_prime(black_box(&num)),
            criterion::BatchSize::SmallInput,
        )
    });
    c.bench_function("256-bit exponentiation of 2048-bit primes", |b| {
        b.iter_batched(
            || {
                let mut rng = ChaCha12Rng::from_entropy();
                let p = rng.gen_prime(2048);
                let q = rng.gen_prime(2048);
                let n = p * q;
                let bytes = &mut [0u8; 300];
                rng.fill_bytes(bytes);
                let g = BigUint::from_bytes_le(bytes).modpow(&BigUint::from(1u8), &n);
                let exponent = rng.gen_prime(256);
                (n, g, exponent)
            },
            |(n, g, exponent)| g.modpow(&exponent, &n),
            criterion::BatchSize::SmallInput,
        )
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
