use criterion::{black_box, criterion_group, criterion_main, Criterion};
use num_bigint_dig::RandPrime;
use rand_chacha::{rand_core::SeedableRng, ChaCha12Rng, ChaCha20Rng, ChaCha8Rng};

pub fn criterion_benchmark(c: &mut Criterion) {
    // let mut seed = [0u8; 32];
    // hex::decode_to_slice(
    //     "2f24d77ef60d86e3c30e54655ea06e1c8aa9b663aabd2ae0284d44bc73f34148",
    //     &mut seed,
    // )
    // .unwrap();
    // let seed = b"test                            ";

    c.bench_function("2048-bit prime via chacha 8", |b| {
        b.iter_batched(
            || ChaCha8Rng::from_entropy(),
            |mut rng| rng.gen_prime(black_box(2048)),
            criterion::BatchSize::SmallInput,
        )
    });
    c.bench_function("1024-bit prime via chacha 8", |b| {
        b.iter_batched(
            || ChaCha8Rng::from_entropy(),
            |mut rng| rng.gen_prime(black_box(1024)),
            criterion::BatchSize::SmallInput,
        )
    });
    c.bench_function("2048-bit prime via chacha 12", |b| {
        b.iter_batched(
            || ChaCha12Rng::from_entropy(),
            |mut rng| rng.gen_prime(black_box(2048)),
            criterion::BatchSize::SmallInput,
        )
    });
    c.bench_function("1024-bit prime via chacha 12", |b| {
        b.iter_batched(
            || ChaCha12Rng::from_entropy(),
            |mut rng| rng.gen_prime(black_box(1024)),
            criterion::BatchSize::SmallInput,
        )
    });
    c.bench_function("2048-bit prime via chacha 20", |b| {
        b.iter_batched(
            || ChaCha20Rng::from_entropy(),
            |mut rng| rng.gen_prime(black_box(2048)),
            criterion::BatchSize::SmallInput,
        )
    });
    c.bench_function("1024-bit prime via chacha 20", |b| {
        b.iter_batched(
            || ChaCha20Rng::from_entropy(),
            |mut rng| rng.gen_prime(black_box(1024)),
            criterion::BatchSize::SmallInput,
        )
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
