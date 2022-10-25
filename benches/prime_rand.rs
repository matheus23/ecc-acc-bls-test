use std::str::FromStr;

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use num_bigint_dig::{prime, BigUint, RandBigInt, RandPrime};
use proptest::prelude::Rng;
use rand_chacha::{rand_core::SeedableRng, ChaCha12Rng, ChaCha20Rng};

pub fn criterion_benchmark(c: &mut Criterion) {
    let rsa_2048 = BigUint::from_str(
        "25195908475657893494027183240048398571429282126204032027777137836043662020707595556264018525880784406918290641249515082189298559149176184502808489120072844992687392807287776735971418347270261896375014971824691165077613379859095700097330459748808428401797429100642458691817195118746121515172654632282216869987549182422433637259085141865462043576798423387184774447920739934236584823824281198163815010674810451660377306056201619676256133844143603833904414952634432190114657544454178424020924616515723350778707749817125772467962926386356373289912154831438167899885040445364023527381951378636564391212010397122822120720357",
    )
    .unwrap();
    let custom_gen = BigUint::from_str(
        "23109091759037056298536353972403698854338124506453871515652035372462996777809160021525301809750452355978867367042113020792685250385080887960286789615042058315050046522687407290374280202464065016830694887413058328399078598304443861417023225081724372918538335541513811262095426618987362845963049871179201423827055859049168535326740447965618645522341058831848205397611772007049420280950704911231779902871249013563837456694535222272272062660232932164974265167538445200526965638984993129056075300525508562879429819420581593282271165482549583164469880225215953362983006860922169833345938792055324703273825457812939635657391"
    ).unwrap();

    // let mut seed = [0u8; 32];
    // hex::decode_to_slice(
    //     "2f24d77ef60d86e3c30e54655ea06e1c8aa9b663aabd2ae0284d44bc73f34148",
    //     &mut seed,
    // )
    // .unwrap();
    // let seed = b"test                            ";

    c.bench_function("256-bit prime via chacha 12", |b| {
        b.iter_batched(
            || ChaCha12Rng::from_entropy(),
            |mut rng| black_box(rng.gen_prime(black_box(256))),
            criterion::BatchSize::SmallInput,
        )
    });
    c.bench_function("256-bit prime via chacha 20", |b| {
        b.iter_batched(
            || ChaCha20Rng::from_entropy(),
            |mut rng| black_box(rng.gen_prime(black_box(256))),
            criterion::BatchSize::SmallInput,
        )
    });
    c.bench_function("256-bit prime via next_prime", |b| {
        b.iter_batched(
            || BigUint::from_bytes_le(&ChaCha12Rng::from_entropy().gen::<[u8; 32]>()),
            |num| black_box(prime::next_prime(black_box(&num))),
            criterion::BatchSize::SmallInput,
        )
    });
    c.bench_function(
        "256-bit exponentiation of 2048-bit numbers modulo RSA-2048",
        |b| {
            b.iter_batched(
                || {
                    let mut rng = ChaCha12Rng::from_entropy();
                    let g = rng.gen_biguint_below(&rsa_2048);
                    let exponent = rng.gen_prime(256);
                    (g, exponent)
                },
                |(g, exponent)| black_box(g.modpow(black_box(&exponent), &rsa_2048)),
                criterion::BatchSize::SmallInput,
            )
        },
    );
    c.bench_function("256-bit exponentiation of 2048-bit numbers", |b| {
        b.iter_batched(
            || {
                let mut rng = ChaCha12Rng::from_entropy();
                let p = rng.gen_prime(1020);
                let q = rng.gen_prime(1028);
                let n = p * q;
                let g = rng.gen_biguint_below(&n);
                let exponent = rng.gen_prime(256);
                (n, g, exponent)
            },
            |(n, g, exponent)| black_box(g.modpow(black_box(&exponent), &n)),
            criterion::BatchSize::SmallInput,
        )
    });
}
