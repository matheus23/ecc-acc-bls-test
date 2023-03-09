use criterion::{criterion_group, criterion_main};

mod bls_accumulator;
mod prime_rand;
mod rsa_accumulator;

criterion_group!(
    benches,
    // bls_accumulator::criterion_benchmark,
    // prime_rand::criterion_benchmark
    rsa_accumulator::criterion_benchmark,
);
criterion_main!(benches);
