use airbnb_creds::commitment::{open, CommitGroup};
use airbnb_creds::signature::{blind_sign, sign};
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

fn bench_blind_signing(c: &mut Criterion) {
    let mut group = c.benchmark_group("blind_signing");
    let mut rng = ark_std::test_rng();
    let num_attr: Vec<usize> = vec![2, 10, 50, 100, 500];

    for l in num_attr {
        group.throughput(Throughput::Elements(l as u64));
        group.bench_with_input(BenchmarkId::from_parameter(l), &l, |b, &l| {
            let setup = bench_setup(l, &mut rng);
            // Always reveal half of the attributes for blind signing.
            let rev_indices: Vec<usize> = (0..l / 2).collect();
            let a = Fr::rand(&mut rng);
            let (com, com_hid) = open(&setup.params, &setup.messages, &a, &rev_indices, None, CommitGroup::G1)
                .expect("open failed");
            let rev_messages: Vec<Fr> = rev_indices.iter().map(|&i| setup.messages[i]).collect();

            b.iter(|| {
                blind_sign(
                    black_box(&setup.params),
                    black_box(&setup.sk),
                    black_box(&com),
                    black_box(&com_hid),
                    black_box(&rev_messages),
                    &mut rng,
                )
                    .expect("blind_sign failed");
            });
        });
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


criterion_group!(benches, bench_signing, bench_blind_signing);

criterion_main!(benches);