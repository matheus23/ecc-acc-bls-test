use std::ops::Mul;

use bls12_381::{G1Projective, G2Affine, G2Projective, Scalar};
use ff::{Field, PrimeField};
use group::{Curve, Group, GroupEncoding};
use proptest::test_runner::{RngAlgorithm, TestRng};
use rand::{RngCore, SeedableRng};
use rand_chacha::{ChaCha12Core, ChaCha12Rng};
use subtle::Choice;

pub struct Accumulator {
    /// Invariant: commitment = sum(0..n, i => factor * sk^i*G1)
    /// Invariant: p.len() > 0
    /// represents the polynomial's factors
    polynomial: Vec<Scalar>,
}

pub struct TrustlessSetup {
    /// setup[n] = sk^n * G1
    sk_powers: Vec<G1Projective>,
    /// pk = sk * G2
    pk: G2Projective,
}

pub struct AccumulatorCommitment(G1Projective);

pub struct AccumulatorWitness {
    without_element: AccumulatorCommitment,
    with_element: AccumulatorCommitment,
    element: Scalar,
}

impl TrustlessSetup {
    pub fn create<R: RngCore>(capacity: usize, rng: R) -> (Self, Scalar) {
        let sk = Scalar::random(rng);
        let pk = G2Projective::generator() * sk;

        let mut sk_powers = Vec::with_capacity(capacity);
        let mut sk_power = Scalar::one();
        for _ in 0..capacity {
            sk_powers.push(G1Projective::generator() * sk_power);
            sk_power *= sk;
        }

        (TrustlessSetup { sk_powers, pk }, sk)
    }
}

impl Accumulator {
    pub fn empty() -> Self {
        Accumulator {
            polynomial: vec![Scalar::one()],
        }
    }

    pub fn commitment(&self, setup: &TrustlessSetup) -> AccumulatorCommitment {
        if setup.sk_powers.len() < self.polynomial.len() {
            panic!("Cannot compute commitment of accumulator. Trusless setup exhausted");
        }

        AccumulatorCommitment(
            self.polynomial
                .iter()
                .zip(setup.sk_powers.iter())
                .map(|(coefficient, indeterminate)| indeterminate * coefficient)
                .sum(),
        )
    }

    pub fn add(&mut self, setup: &TrustlessSetup, element: Scalar) -> AccumulatorWitness {
        if setup.sk_powers.len() <= self.polynomial.len() {
            panic!("Cannot add to accumulator. Trusless setup exhausted");
        }

        let without_element = self.commitment(setup);

        let mut new_poly = Vec::new();

        for i in 0..self.polynomial.len() {
            let at_i_before = if i == 0 {
                Scalar::zero()
            } else {
                self.polynomial[i - 1]
            };
            let at_i = self.polynomial[i];

            new_poly.push(at_i * element + at_i_before);
        }

        new_poly.push(Scalar::one());

        self.polynomial = new_poly;

        let with_element = self.commitment(setup);

        AccumulatorWitness {
            without_element,
            with_element,
            element,
        }
    }
}

impl AccumulatorWitness {
    pub fn verify(&self, pk: G2Projective) -> Choice {
        accum_verify(
            self.with_element.0,
            self.without_element.0,
            self.element,
            pk,
        )
    }
}

fn accum_add(accumulator: G1Projective, value: Scalar, sk: Scalar) -> G1Projective {
    accumulator * (value + sk)
}

fn accum_remove(accumulator: G1Projective, value: Scalar, sk: Scalar) -> G1Projective {
    // crashes if value = -sk
    // should be extremely unlikely if sk is sampled randomly and unknown to the agent generating values.
    accumulator * (value + sk).invert().unwrap()
}

fn accum_witness(accumulator: G1Projective, value: Scalar, sk: Scalar) -> G1Projective {
    accum_remove(accumulator, value, sk)
}

fn accum_verify(
    accumulator: G1Projective,
    witness: G1Projective,
    value: Scalar,
    pk: G2Projective,
) -> Choice {
    // can be more efficient. Need to figure out multi-pairing
    let p1 = bls12_381::pairing(
        &witness.into(),
        &(G2Projective::generator() * value + pk).into(),
    );
    let p2 = bls12_381::pairing(&(-accumulator).into(), &G2Affine::generator());
    (p1 + p2).is_identity()
}

#[test]
fn test_bls_acc_example() {
    let seed = b"test                            ";
    let sk = Scalar::random(TestRng::from_seed(RngAlgorithm::ChaCha, seed));
    let pk = G2Projective::generator() * sk;

    let v1 = Scalar::from_raw([0, 0, 0, 10]);
    let v2 = Scalar::from_raw([0, 0, 0, 111]);
    let v3 = Scalar::from_raw([0, 0, 0, 9]);

    let mut accumulator = G1Projective::generator();
    accumulator = accum_add(accumulator, v1, sk);
    accumulator = accum_add(accumulator, v2, sk);
    let witness = accum_witness(accumulator, v3, sk);

    let is_valid = accum_verify(accumulator, witness, v3, pk);
    let is_valid: bool = is_valid.into();

    println!("sk: {}", hex::encode(sk.to_bytes()));
    println!("pk: {}", hex::encode(pk.to_bytes()));
    println!("acc: {}", hex::encode(accumulator.to_bytes()));
    println!("witness: {}", hex::encode(witness.to_bytes()));
    println!("valid: {}", is_valid);
}

#[test]
fn test_add_and_remove_is_identity() {
    let seed = b"test                            ";
    let sk = Scalar::random(TestRng::from_seed(RngAlgorithm::ChaCha, seed));
    // let pk = G2Projective::generator() * sk;

    let v1 = Scalar::from_raw([0, 0, 0, 10]);
    let v2 = Scalar::from_raw([0, 0, 0, 100]);

    let accumulator0 = G1Projective::generator();
    let accumulator1 = accum_add(accumulator0, v2, sk);
    let accumulator2 = accum_add(accumulator1, v1, sk);
    let accumulator3 = accum_remove(accumulator2, v1, sk);

    assert_eq!(accumulator1, accumulator3);
}

#[test]
fn test_basic_example() {
    let s0 = Scalar::from_str_vartime("12329").unwrap();
    let s1 = Scalar::from_str_vartime("44").unwrap();
    let s2 = Scalar::from_str_vartime("12003").unwrap();

    let (setup, sk) = TrustlessSetup::create(1000, ChaCha12Rng::from_entropy());
    let mut accumulator = G1Projective::generator();

    let mut acc = Accumulator::empty();

    assert_eq!(
        accumulator.to_affine(),
        acc.commitment(&setup).0.to_affine()
    );

    acc.add(&setup, s0);
    accumulator = accum_add(accumulator, s0, sk);

    assert_eq!(
        accumulator.to_affine(),
        acc.commitment(&setup).0.to_affine()
    );

    acc.add(&setup, s1);
    accumulator = accum_add(accumulator, s1, sk);

    assert_eq!(
        accumulator.to_affine(),
        acc.commitment(&setup).0.to_affine()
    );

    let witness = acc.add(&setup, s2);
    accumulator = accum_add(accumulator, s2, sk);

    assert_eq!(
        accumulator.to_affine(),
        acc.commitment(&setup).0.to_affine()
    );

    let verified: bool = witness.verify(setup.pk).into();

    assert!(verified);
}
