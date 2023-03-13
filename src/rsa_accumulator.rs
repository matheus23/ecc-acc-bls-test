use digest::Digest;
use num_bigint_dig::ModInverse;
use num_bigint_dig::{prime::probably_prime, BigUint, RandBigInt, RandPrime};
use num_integer::Integer;
use num_traits::{One, Signed, Zero};
use proptest::{collection::vec, prop_assert};
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

#[derive(Debug)]
pub struct PokeStars {
    big_q_product: BigUint,
    parts: Vec<PokeStarsPart>,
}

#[derive(Debug, Clone)]
pub struct PokeStarsPart {
    l_nonce: u32,
    r: BigUint,
}

impl PokeStars {
    fn new(pokes: &[PokeStar], modulus: &BigUint) -> PokeStars {
        let big_q_product = nlogn_mod_poduct(&pokes, |poke| &poke.big_q, modulus);
        let parts = pokes
            .iter()
            .map(|poke| PokeStarsPart {
                l_nonce: poke.l_nonce,
                r: poke.r.clone(),
            })
            .collect();
        PokeStars {
            big_q_product,
            parts,
        }
    }

    fn verify(&self, base: &BigUint, commitments: &[BigUint], modulus: &BigUint) -> bool {
        if commitments.len() != self.parts.len() {
            return false;
        }

        let mut hasher_base = sha3::Sha3_256::new();
        hasher_base.update(&modulus.to_bytes_le());
        hasher_base.update(&base.to_bytes_le());

        let mut bases_and_exponents = Vec::with_capacity(commitments.len());

        for (commitment, part) in commitments.iter().zip(self.parts.iter()) {
            // computing l_i
            let mut hasher = hasher_base.clone();
            hasher.update(&commitment.to_bytes_le());
            let Some(prime_hash) = verify_prime_digest(hasher, part.l_nonce) else {
                return false;
            };

            if part.r >= prime_hash {
                return false;
            }

            // computing alpha_i
            let base = (commitment
                * base
                    .mod_inverse(modulus)
                    .unwrap()
                    .to_biguint()
                    .unwrap()
                    .modpow(&part.r, modulus))
                % modulus;

            bases_and_exponents.push((base, prime_hash));
        }

        let l_star = nlogn_product(&bases_and_exponents, |(_, l_i)| l_i);

        self.big_q_product.modpow(&l_star, modulus) == multi_exp(&bases_and_exponents, modulus)
    }
}

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

#[test]
fn test_poke_aggregation() {
    let rng = &mut ChaCha12Rng::from_seed(*b"Hello? Yes this is dog. Or seed?");
    let bits = 2048;
    let acc = Accumulator::new(bits, rng);
    let elems = [
        rng.gen_prime(256),
        rng.gen_prime(256),
        rng.gen_prime(256),
        rng.gen_prime(256),
    ];
    let mut commitments = Vec::new();
    let mut pokes = Vec::new();
    for elem in elems {
        let mut acc2 = acc.clone();
        let (_, poke) = acc2.add_batch(&[elem.clone()]);
        commitments.push(acc2.state);
        pokes.push(poke);
    }
    let poke_agg = PokeStars::new(&pokes, &acc.modulus);
    assert!(poke_agg.verify(&acc.state, &commitments, &acc.modulus));
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

/// With (alpha_i, x_i) = bases_and_exponents[i], this
/// computes the product of all alpha_i ^ (product of all x_j with j != i).
pub fn multi_exp(bases_and_exponents: &[(BigUint, BigUint)], modulus: &BigUint) -> BigUint {
    match bases_and_exponents {
        &[] => BigUint::one(),
        [(base, _)] => base.clone() % modulus,
        other => {
            let mid = other.len() / 2;
            let (left, right) = other.split_at(mid);
            let x_star_left = nlogn_product(left, |(_, x_i)| x_i);
            let x_star_right = nlogn_product(right, |(_, x_i)| x_i);
            (multi_exp(left, modulus).modpow(&x_star_right, modulus)
                * multi_exp(right, modulus).modpow(&x_star_left, modulus))
                % modulus
        }
    }
}

pub fn nlogn_product<A>(factors: &[A], f: fn(&A) -> &BigUint) -> BigUint {
    match factors {
        [] => BigUint::one(),
        [factor] => f(factor).clone(),
        other => {
            let mid = other.len() / 2;
            let (left, right) = factors.split_at(mid);
            nlogn_product(left, f) * nlogn_product(right, f)
        }
    }
}

pub fn nlogn_mod_poduct<A>(factors: &[A], f: fn(&A) -> &BigUint, modulus: &BigUint) -> BigUint {
    match factors {
        [] => BigUint::one(),
        [factor] => f(factor) % modulus,
        other => {
            let mid = other.len() / 2;
            let (left, right) = factors.split_at(mid);
            (nlogn_product(left, f) * nlogn_product(right, f)) % modulus
        }
    }
}

pub fn prime_digest(hasher: impl Digest) -> (BigUint, u32) {
    let hash = hasher.finalize();
    let mut candidate = BigUint::from_bytes_le(&hash[..16]);
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

pub fn verify_prime_digest(hasher: impl Digest, inc: u32) -> Option<BigUint> {
    let hash = hasher.finalize();
    let mut to_verify = BigUint::from_bytes_le(&hash[..16]);
    to_verify += inc;
    if !probably_prime(&to_verify, 20) {
        None
    } else {
        Some(to_verify)
    }
}

#[proptest(cases = 1000)]
fn test_prime_digest(#[strategy(vec(any::<u8>(), 0..100))] bytes: Vec<u8>) {
    let mut hasher = sha3::Sha3_256::new();
    hasher.update(&bytes);

    let (prime_hash, inc) = prime_digest(hasher.clone());
    prop_assert!(probably_prime(&prime_hash, 20));
    prop_assert_eq!(verify_prime_digest(hasher.clone(), inc), Some(prime_hash));
}

fn rand_modulus(bits: impl Strategy<Value = usize>) -> impl Strategy<Value = BigUint> {
    (bits, any::<[u8; 32]>().no_shrink()).prop_map(move |(bits, seed)| {
        let bits = std::cmp::max(bits, 4);
        let rng = &mut ChaCha12Rng::from_seed(seed);
        rng.gen_prime(bits / 2) * rng.gen_prime(bits / 2)
    })
}

#[proptest(cases = 100)]
fn test_multi_exp(
    #[strategy(vec((1u64.., 1u64..), 0..100))] bases_and_exponents: Vec<(u64, u64)>,
    #[strategy(rand_modulus(4usize..64))] modulus: BigUint,
) {
    let bases_and_exponents: Vec<(BigUint, BigUint)> = bases_and_exponents
        .iter()
        .map(|(b, e)| (BigUint::from(*b), BigUint::from(*e)))
        .collect();

    let actual = multi_exp(&bases_and_exponents, &modulus);
    let expected = multi_exp_naive(&bases_and_exponents, &modulus);
    prop_assert_eq!(actual, expected);
}

fn multi_exp_naive(bases_and_exponents: &[(BigUint, BigUint)], modulus: &BigUint) -> BigUint {
    let x_star = nlogn_product(&bases_and_exponents, |(_, x_i)| x_i);

    let mut product = BigUint::one();
    for (alpha_i, x_i) in bases_and_exponents {
        let exponent = x_star.div_floor(&x_i);
        product *= alpha_i.modpow(&exponent, modulus);
        product %= modulus;
    }
    product
}
