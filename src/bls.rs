use bls12_381::{G1Projective, G2Affine, G2Projective, Scalar};
use ff::Field;
use group::{Group, GroupEncoding};
use proptest::test_runner::{RngAlgorithm, TestRng};
use subtle::Choice;

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
