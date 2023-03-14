use num_bigint_dig::{prime::probably_prime, BigUint, RandBigInt, RandPrime};
use num_traits::{One, ToPrimitive};
use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha12Rng;
use std::{collections::HashSet, io::Write};

fn main() {
    let rng = &mut ChaCha12Rng::from_seed([0u8; 32]);

    // loop {
    //     println!("{}", rng.gen_prime(1024) % BigUint::from(4u8));
    // }

    let trials = 100;
    let bits = 12;
    let mut group_sizes = 0;
    let mut groups = 0;
    let mut min_size = usize::MAX;
    let mut max_size = 0;
    for i in 0..trials {
        // let p = gen_safe_prime(rng, bits).to_u64().unwrap();
        // let q = gen_safe_prime(rng, bits).to_u64().unwrap();
        // let p = gen_mod_prime(rng, bits, 5, 6).to_u64().unwrap();
        // let q = gen_mod_prime(rng, bits, 5, 6).to_u64().unwrap();
        let p = rng.gen_prime(bits).to_u64().unwrap();
        let q = rng.gen_prime(bits).to_u64().unwrap();
        let modulus = p * q;
        // println!("modulus: {modulus}");
        // println!("non relatively prime: {}", &p + &q - 1);
        // println!("numbers relatively prime: {}", &modulus - (&p + &q - 1));

        for j in 0..trials {
            let x = rng
                .gen_biguint_range(&BigUint::one(), &BigUint::from(modulus))
                .to_u64()
                .unwrap();

            if &x == &p || &x == &q {
                println!("The usually unlikely thing happened");
                continue;
            }
            // let qr = normalize((x * x) % modulus, modulus);
            let qr = (x * x) % modulus;
            let mut group = HashSet::from([qr]);
            let mut qr_power = qr;
            loop {
                qr_power *= qr;
                qr_power %= modulus;
                // qr_power = normalize(qr_power, modulus);

                if group.contains(&qr_power) {
                    break;
                }

                group.insert(qr_power);
            }

            use std::cmp;
            min_size = cmp::min(group.len(), min_size);
            max_size = cmp::max(group.len(), max_size);
            group_sizes += group.len();
            // println!("group size: {}", group.len());
            groups += 1;

            print!(
                "\rProgress: {}/{} (size: {})     \t",
                i * trials + j,
                trials * trials,
                group.len()
            );
            std::io::stdout().flush().unwrap();
        }
    }
    let avg_size = group_sizes as f64 / groups as f64;
    println!(
        "\n{}-bit modulus avg QR groups size: {avg_size} (min: {min_size}, max: {max_size})",
        bits * 2
    );
}

fn normalize(n: u64, modulus: u64) -> u64 {
    if n >= modulus / 2 {
        (n + modulus) % modulus
    } else {
        n
    }
}

fn gen_safe_prime(rng: &mut impl RngCore, bits: usize) -> BigUint {
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

fn gen_mod_prime(rng: &mut impl RngCore, bits: usize, congruent: u64, modulo: u64) -> BigUint {
    let congruent = BigUint::from(congruent);
    let modulo = BigUint::from(modulo);
    loop {
        let prime = rng.gen_prime(bits);
        // then check if p mod 4 = 3
        if &prime % &modulo == congruent {
            return prime;
        }
    }
}
