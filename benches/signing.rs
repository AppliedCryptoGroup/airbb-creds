use airbnb_creds::signature::sign;
use airbnb_creds::{keygen, PublicParams};
use ark_bls12_381::Fr;
use ark_std::UniformRand;
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use rand::Rng;

fn bench_signing(c: &mut Criterion) {
    let mut group = c.benchmark_group("signing");
    let mut rng = ark_std::test_rng();
    let num_attr: Vec<usize> = vec![1, 10, 50, 100, 500, 1000];

    for l in num_attr {
        group.throughput(Throughput::Elements(l as u64));
        group.bench_with_input(BenchmarkId::from_parameter(l), &l, |b, &l| {
            let setup = bench_setup(l, &mut rng);

            b.iter(|| {
                sign(black_box(&setup.params), black_box(&setup.sk), black_box(&setup.messages), &mut rng).expect("signing failed");
            })
        } );
    }

    group.finish();

}

struct BenchSetup {
    params: PublicParams,
    messages: Vec<Fr>,
    sk: airbnb_creds::keys::SecretKey,
}

fn bench_setup(l: usize, rng: &mut impl Rng) -> BenchSetup {
    let params = PublicParams::setup(l, rng);
    let (sk, _vk) = keygen(&params, rng);
    let messages: Vec<Fr> = (0..l).map(|_| Fr::rand(rng)).collect();

    BenchSetup{params, messages, sk}
}

criterion_group!(benches, bench_signing);

criterion_main!(benches);