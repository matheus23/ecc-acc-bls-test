use num_bigint_dig::{prime::probably_prime, BigUint};

pub fn next_prime(bigint: &BigUint) -> BigUint {
    let two = BigUint::from(2usize);

    let mut working = bigint | BigUint::from(1usize);
    loop {
        if probably_prime(&working, 20) {
            return working;
        }

        working += &two;
    }
}
