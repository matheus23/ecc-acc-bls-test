use std::{ops::ShlAssign, str::FromStr};

use num_bigint_dig::{prime::probably_prime, BigUint, RandBigInt, RandPrime};
use rand::RngCore;
use rand_chacha::{rand_core::SeedableRng, ChaCha12Rng};

fn gen_safe_prime<R: RngCore>(rng: &mut R, bits: usize) -> BigUint {
    if bits < 3 {
        panic!("Cannot generate safe prime number under 3 bits");
    }
    let one = BigUint::from(1u8);
    loop {
        // generate a prime number p
        let mut prime = rng.gen_prime(bits - 1);
        // then check if 2p + 1 is prime
        prime <<= 1;
        prime |= &one;
        if probably_prime(&prime, 20) {
            return prime;
        }
    }
}

#[test]
fn test_random_safe_prime() {
    let bits = 1024;
    let prime = gen_safe_prime(&mut ChaCha12Rng::from_entropy(), bits);
    assert_eq!(bits, prime.bits());
}

pub fn setup<R: RngCore>(rng: &mut R, bits: usize) -> (BigUint, BigUint, BigUint) {
    let p = gen_safe_prime(rng, bits / 2);
    let q = gen_safe_prime(rng, bits / 2);
    let n = &p * &q;
    (n, p, q)
}

#[test]
fn is_rsa_240_safe_prime_product() {
    let p = BigUint::from_str("509435952285839914555051023580843714132648382024111473186660296521821206469746700620316443478873837606252372049619334517").unwrap();
    let q = BigUint::from_str("244624208838318150567813139024002896653802092578931401452041221336558477095178155258218897735030590669041302045908071447").unwrap();

    let rsa_240 = BigUint::from_str("124620366781718784065835044608106590434820374651678805754818788883289666801188210855036039570272508747509864768438458621054865537970253930571891217684318286362846948405301614416430468066875699415246993185704183030512549594371372159029236099").unwrap();
    let n = &p * &q;

    assert_eq!(n, rsa_240);

    println!("p prime? {}", probably_prime(&p, 25));
    println!("q prime? {}", probably_prime(&q, 25));

    let p_prime = (&p - BigUint::from(1u8)) / BigUint::from(2u8);
    let q_prime = (&q - BigUint::from(1u8)) / BigUint::from(2u8);

    let is_p_safe = probably_prime(&p_prime, 25);
    let is_q_safe = probably_prime(&q_prime, 25);

    println!("p safe prime? {is_p_safe}");
    println!("q safe prime? {is_q_safe}");
}
