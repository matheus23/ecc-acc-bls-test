use std::{
    ops::{Mul, MulAssign},
    rc::Rc,
};

use digest::Digest;
use num_bigint_dig::{prime::probably_prime, BigUint, RandBigInt, RandPrime};
use num_integer::Integer;
use num_traits::One;
use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha12Rng;

#[derive(Debug, PartialEq, Eq)]
struct RSASetup {
    modulus: BigUint,
    modulus_half: BigUint, // invariant: modulus_half = floor(modulus / 2)
}

impl RSASetup {
    fn from(modulus: BigUint) -> Self {
        let modulus_half = &modulus / BigUint::from(2u8);
        Self {
            modulus,
            modulus_half,
        }
    }

    fn new(bits: usize, rng: &mut impl RngCore) -> Self {
        let modulus = &rng.gen_prime(bits / 2) * &rng.gen_prime(bits / 2);
        Self::from(modulus)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct QRPlus {
    params: Rc<RSASetup>,
    num: BigUint, // invariant: num \in [0, params.modulus / 2)
}

impl Mul for QRPlus {
    type Output = QRPlus;

    fn mul(mut self, rhs: Self) -> Self::Output {
        self.mul_assign(rhs);
        self
    }
}

impl Mul for &QRPlus {
    type Output = QRPlus;

    fn mul(self, rhs: Self) -> Self::Output {
        let mut num = self.clone();
        num.mul_assign(rhs.clone());
        num
    }
}

impl MulAssign for QRPlus {
    fn mul_assign(&mut self, rhs: Self) {
        if self.params != rhs.params {
            panic!("Multiplying quadratic residues must use same modulus")
        }
        self.num *= rhs.num;
        self.num %= &self.params.modulus;
        positive_normalize(&mut self.num, &self.params);
    }
}

impl QRPlus {
    fn new(params: Rc<RSASetup>, rng: &mut impl RngCore) -> Self {
        // TODO(matheus23): This may not need to be a quadratic residue, but I'm not sure.
        let r = rng.gen_biguint_below(&params.modulus);
        let mut num = &r * &r;
        positive_normalize(&mut num, &params);
        Self { params, num }
    }

    fn pow(&mut self, exponent: &BigUint) {
        self.num = self.num.modpow(exponent, &self.params.modulus);
        positive_normalize(&mut self.num, &self.params);
    }
}

fn positive_normalize(num: &mut BigUint, params: &RSASetup) {
    if *num >= params.modulus_half {
        *num += &params.modulus;
        *num %= &params.modulus;
    }
}

#[derive(Debug, Clone)]
pub struct Accumulator {
    params: Rc<RSASetup>,
    state: QRPlus,
}

impl Accumulator {
    pub fn from(modulus: BigUint, rng: &mut impl RngCore) -> Self {
        let params = Rc::new(RSASetup::from(modulus));
        let state = QRPlus::new(Rc::clone(&params), rng);
        Self { params, state }
    }

    pub fn new(bits: usize, rng: &mut impl RngCore) -> Self {
        let params = Rc::new(RSASetup::new(bits, rng));
        let state = QRPlus::new(Rc::clone(&params), rng);
        Self { params, state }
    }

    pub fn add(&mut self, prime_elem: &BigUint) {
        if !probably_prime(prime_elem, 20) {
            panic!("Parameter needs to be prime!");
        }

        self.state.pow(prime_elem);
    }

    pub fn simple_verify(&self, witness: &Self, prime_elem: &BigUint) -> bool {
        let mut w = witness.clone();
        w.add(prime_elem);
        w.state == self.state
    }

    pub fn add_batch(&mut self, primes: &[BigUint]) -> PokeStar {
        let witness = self.state.clone();

        for prime in primes.iter() {
            self.add(prime);
        }

        let mut hasher = sha3::Sha3_256::new();
        hasher.update(&self.params.modulus.to_bytes_le());
        hasher.update(&witness.num.to_bytes_le());
        hasher.update(&self.state.num.to_bytes_le());
        let (l, l_nonce) = prime_digest(hasher);

        let mut product = BigUint::one();
        for prime in primes.iter() {
            product *= prime;
        }

        let (q, r) = product.div_mod_floor(&l);

        let big_q = witness.num.modpow(&q, &self.params.modulus);

        PokeStar { l_nonce, big_q, r }
    }

    pub fn verify(&self, witness: &Self, proof: &PokeStar) -> bool {
        let mut hasher = sha3::Sha3_256::new();
        hasher.update(&self.params.modulus.to_bytes_le());
        hasher.update(&witness.state.num.to_bytes_le());
        hasher.update(&self.state.num.to_bytes_le());
        let Some(l) = verify_prime_digest(hasher, proof.l_nonce) else {
            return false;
        };

        if proof.r >= l {
            return false;
        }

        let mut expected_state = proof.big_q.modpow(&l, &self.params.modulus)
            * witness.state.num.modpow(&proof.r, &self.params.modulus);

        positive_normalize(&mut expected_state, &self.params);

        expected_state == self.state.num
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
    let witness = acc.clone();
    let proof = acc.add_batch(&elems);
    assert!(acc.verify(&witness, &proof));
    assert!(!acc.verify(&acc, &proof));
}

#[test]
fn test_golden_poke() {
    let rng = &mut ChaCha12Rng::from_seed(*b"Hello yes this is dog. Or seed.?");
    let bits = 2048;
    let mut acc = Accumulator::new(bits, rng);
    let elems = [
        rng.gen_prime(256),
        rng.gen_prime(256),
        rng.gen_prime(256),
        rng.gen_prime(256),
    ];
    let witness = acc.clone();
    let proof = acc.add_batch(&elems);
    assert!(acc.verify(&witness, &proof));
    assert!(!acc.verify(&acc, &proof));
    // println!("l_nonce: {}", proof.l_nonce);
    // println!("big_q: {}", proof.big_q);
    // println!("r: {}", proof.r);
    assert_eq!(proof.l_nonce.to_string(), "8");
    assert_eq!(proof.big_q.to_string(), "8409876224065280613797694548964236694502270756376562071381105811817285063835834270766028060927599775054808890058975111835048261352946293480288259808548006750032703295192015588193327429982320216042858602771871685378214073242491387027672710350772276401776856424112720398319262246092753143317972339262235949369921342802895407883818547136524657379615581152287007457703214243248689462523048779063144325264697105566222711681755279548300048803718105225423218377201581130548415325430788307992260686433957444033358827014496583453713620082391848594260119516879051639022509815961111057103716320899807113080527495003819943089985");
    assert_eq!(
        proof.r.to_string(),
        "5853184725620449521594003835260194072898583518750701750781116516759621283462"
    );
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
