pub mod bls;

use num_bigint_dig::RandPrime;
use rand_chacha::{rand_core::SeedableRng, ChaCha12Rng, ChaCha20Rng, ChaCha8Rng};

fn main() {
    let seed = b"test                            ";
    let mut det_rng = ChaCha20Rng::from_seed(*seed);
    let large_prime = det_rng.gen_prime(2048);

    println!("{large_prime}");
}
