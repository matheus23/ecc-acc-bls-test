use std::{
    ops::{Mul, MulAssign},
    rc::Rc,
};

use digest::Digest;
use num_bigint_dig::{prime::probably_prime, BigUint, RandBigInt, RandPrime};
use num_integer::Integer;
use num_traits::{One, Zero};
use proptest::collection::vec;
use proptest::{prelude::any, prop_assert_eq, strategy::Strategy};
use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha12Rng;
use test_strategy::proptest;

#[derive(Debug, Clone)]
pub struct Accumulator {
    modulus: BigUint,
    state: BigUint,
}

impl Accumulator {
    pub fn from_state(modulus: BigUint, state: BigUint) -> Self {
        Self { modulus, state }
    }

    pub fn from(modulus: BigUint, rng: &mut impl RngCore) -> Self {
        let state = Self::setup_quadratic_residue(&modulus, rng);
        Self { modulus, state }
    }

    pub fn new(bits: usize, rng: &mut impl RngCore) -> Self {
        // immediately throw away P and Q
        let modulus = rng.gen_prime(bits / 2) * rng.gen_prime(bits / 2);
        let state = Self::setup_quadratic_residue(&modulus, rng);
        Self { modulus, state }
    }

    fn setup_quadratic_residue(modulus: &BigUint, rng: &mut impl RngCore) -> BigUint {
        let r = rng.gen_biguint_below(modulus);
        r.modpow(&BigUint::from(2u8), modulus)
    }

    pub fn add(&mut self, prime_elem: &BigUint) {
        self.state = self.state.modpow(prime_elem, &self.modulus);
    }

    pub fn simple_verify(&self, witness: &Self, exponent: &BigUint) -> bool {
        let mut w = witness.clone();
        w.add(exponent);
        w.state == self.state
    }

    pub fn add_batch(&mut self, primes: &[BigUint]) -> (BigUint, PokeStar) {
        let mut product = BigUint::one();
        for prime in primes.iter() {
            product *= prime;
        }

        let witness = self.state.clone();
        self.add(&product);

        let mut hasher = sha3::Sha3_256::new();
        hasher.update(&self.modulus.to_bytes_le());
        hasher.update(&witness.to_bytes_le());
        hasher.update(&self.state.to_bytes_le());
        let (l, l_nonce) = prime_digest(hasher);

        let (q, r) = product.div_mod_floor(&l);

        let big_q = witness.modpow(&q, &self.modulus);

        (witness, PokeStar { l_nonce, big_q, r })
    }

    pub fn verify(&self, witness: &BigUint, proof: &PokeStar) -> bool {
        let mut hasher = sha3::Sha3_256::new();
        hasher.update(&self.modulus.to_bytes_le());
        hasher.update(&witness.to_bytes_le());
        hasher.update(&self.state.to_bytes_le());
        let Some(l) = verify_prime_digest(hasher, proof.l_nonce) else {
            return false;
        };

        if proof.r >= l {
            return false;
        }

        let expected_state = proof.big_q.modpow(&l, &self.modulus)
            * witness.modpow(&proof.r, &self.modulus)
            % &self.modulus;

        expected_state == self.state
    }
}

/// PoKE* (Proof of Knowledge of Exponent),
/// assuming that the base is trusted
/// (e.g. part of a common reference string, CRS).
#[derive(Debug, Clone)]
pub struct PokeStar {
    l_nonce: u32,
    big_q: BigUint,
    r: BigUint,
}

impl PokeStar {}

#[test]
fn test_add() {
    let rng = &mut ChaCha12Rng::from_entropy();
    let bits = 2048;
    let mut acc = Accumulator::new(bits, rng);
    acc.add(&rng.gen_prime(256));
    let witness = acc.clone();
    let elem = rng.gen_prime(256);
    acc.add(&elem);
    assert!(acc.simple_verify(&witness, &elem));
    let non_elem = rng.gen_prime(256);
    assert!(!acc.simple_verify(&witness, &non_elem));
}

#[test]
fn test_add_poke() {
    let rng = &mut ChaCha12Rng::from_entropy();
    let bits = 2048;
    let mut acc = Accumulator::new(bits, rng);
    let elems = [
        rng.gen_prime(256),
        rng.gen_prime(256),
        rng.gen_prime(256),
        rng.gen_prime(256),
    ];
    let (witness, proof) = acc.add_batch(&elems);
    assert!(acc.verify(&witness, &proof));
    assert!(!acc.verify(&acc.state, &proof));
}

#[test]
fn test_golden_poke() {
    let rng = &mut ChaCha12Rng::from_seed(*b"Hello? Yes this is dog. Or seed?");
    let bits = 2048;
    let mut acc = Accumulator::new(bits, rng);
    let elems = [
        rng.gen_prime(256),
        rng.gen_prime(256),
        rng.gen_prime(256),
        rng.gen_prime(256),
    ];
    let (witness, proof) = acc.add_batch(&elems);
    assert!(acc.verify(&witness, &proof));
    assert!(!acc.verify(&acc.state, &proof));
    println!("l_nonce: {}", proof.l_nonce);
    println!("big_q: {}", proof.big_q);
    println!("r: {}", proof.r);
    assert_eq!(proof.l_nonce.to_string(), "1282");
    assert_eq!(proof.big_q.to_string(), "12117271039263737819615146232217918602560888065784689992116757202851990361309932042932100867413234044316909888405349944336001137043271091115456367161556148793576819234837124506888775982486516238849956150889610482533485615619012138164998537585561668303564967285889086839307783103652491442079340022590334512056757180948335498358783927473330318867846674177749827422204944261549138740242880034294033298941062569994542411491450238695409104544658592695382785683228261336964412330586335774532088432512328518434699788636500507978659400729616038659350039107693570974084627918823399015104723803362621969117129946301649236032054");
    assert_eq!(
        proof.r.to_string(),
        "49979675822201868791018284424654332550088070864253120193918675049884441160229"
    );
}

fn biguint(s: impl Strategy<Value = u64>) -> impl Strategy<Value = BigUint> {
    s.prop_map(|u| BigUint::from(u))
}

#[proptest(cases = 1000)]
fn test_div_mod_of_product_2(
    #[strategy(biguint((0..100000000u64)))] x1: BigUint,
    #[strategy(biguint((0..100000000u64)))] x2: BigUint,
    #[strategy(biguint((1..100000000u64)))] l: BigUint,
) {
    let (q1, r1) = x1.div_mod_floor(&l);
    let (q2, r2) = x2.div_mod_floor(&l);
    let (exp_q, exp_r) = (&x1 * &x2).div_mod_floor(&l);
    let (q, r) = div_mod_product_2(&(q1, r1), &(q2, r2), &l);

    prop_assert_eq!(q, exp_q);
    prop_assert_eq!(r, exp_r);
}

#[proptest(cases = 1000)]
fn test_div_mod_of_product(
    #[strategy(vec(biguint(any::<u64>()), 0..100))] factors: Vec<BigUint>,
    #[strategy(biguint(1..100000000000u64))] l: BigUint,
) {
    let mut product = BigUint::one();
    for factor in factors.iter() {
        product *= factor;
    }

    let expectation = product.div_mod_floor(&l);
    let actual = div_mod_product(&factors, &l);
    prop_assert_eq!(actual, expectation);
}

/// Not actually faster than just calling .div_mod_floor on the huge product,
/// if the product is computed recursively in O(n log n), and even slower than
/// the direct div_mod_floor on a product computed O(n), if the product is <256kbit.
pub fn div_mod_product(factors: &[BigUint], l: &BigUint) -> (BigUint, BigUint) {
    match factors {
        &[] => (BigUint::zero(), BigUint::one()),
        [f] => f.div_mod_floor(l),
        other => {
            let mid = other.len() / 2;
            let (left, right) = other.split_at(mid);
            div_mod_product_2(&div_mod_product(left, l), &div_mod_product(right, l), l)
        }
    }
}

fn div_mod_product_2(
    (q1, r1): &(BigUint, BigUint),
    (q2, r2): &(BigUint, BigUint),
    l: &BigUint,
) -> (BigUint, BigUint) {
    let q_prime = q1 * (q2 * l + r2) + q2 * r1;
    let r_prime = r1 * r2;

    let (q_plus, r) = r_prime.div_mod_floor(l);

    let q = q_prime + q_plus;

    (q, r)
}

fn prime_digest(hasher: impl Digest) -> (BigUint, u32) {
    let hash = hasher.finalize();
    let mut candidate = BigUint::from_bytes_le(&hash);
    let mut inc: u32 = if &candidate % 2usize == BigUint::one() {
        0
    } else {
        1
    };
    candidate |= BigUint::one();
    loop {
        if probably_prime(&candidate, 20) {
            return (candidate, inc);
        }

        inc += 2;
        // The chance that this overflows right at the 256-bit border is *extremely* small
        candidate += 2usize;
    }
}

fn verify_prime_digest(hasher: impl Digest, inc: u32) -> Option<BigUint> {
    let hash = hasher.finalize();
    let mut to_verify = BigUint::from_bytes_le(&hash);
    to_verify += inc;
    if !probably_prime(&to_verify, 20) {
        None
    } else {
        Some(to_verify)
    }
}
