use airbnb_creds::keys::keygen;
use airbnb_creds::presentation::{present, verify_present, Credential};
use airbnb_creds::signature::sign;
use airbnb_creds::PublicParams;
use ark_bls12_381::Fr;
use ark_std::UniformRand;
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use rand::Rng;

// Bench 1: present — varying total attribute count, revealing half
fn bench_present(c: &mut Criterion) {
    let mut group = c.benchmark_group("present/varying_l");
    let mut rng = ark_std::test_rng();
    let sizes: Vec<usize> = vec![1, 10, 50, 100, 500];

    for l in sizes {
        group.throughput(Throughput::Elements(l as u64));
        group.bench_with_input(BenchmarkId::from_parameter(l), &l, |b, &l| {
            let setup = bench_setup(l, &mut rng);
            let rev_indices: Vec<usize> = (0..l / 2).collect();
            let aux = Fr::rand(&mut rng);

            b.iter(|| {
                present(
                    black_box(&setup.params),
                    black_box(&setup.cred),
                    black_box(&rev_indices),
                    black_box(&aux),
                    &mut rng,
                )
                .expect("present failed");
            });
        });
    }

    group.finish();
}

// Bench 2: verify_present — varying total attribute count, revealing half
fn bench_verify_present(c: &mut Criterion) {
    let mut group = c.benchmark_group("verify_present/varying_l");
    let mut rng = ark_std::test_rng();
    let sizes: Vec<usize> = vec![1, 10, 50, 100, 500];

    for l in sizes {
        group.throughput(Throughput::Elements(l as u64));
        group.bench_with_input(BenchmarkId::from_parameter(l), &l, |b, &l| {
            let setup = bench_setup(l, &mut rng);
            let rev_indices: Vec<usize> = (0..l / 2).collect();
            let aux = Fr::rand(&mut rng);
            let presentation =
                present(&setup.params, &setup.cred, &rev_indices, &aux, &mut rng)
                    .expect("present failed");

            b.iter(|| {
                verify_present(
                    black_box(&setup.params),
                    black_box(&setup.vk),
                    black_box(&presentation),
                )
                .expect("verify_present failed");
            });
        });
    }

    group.finish();
}

// Bench 3: verify_present — fixed l=100, varying revealed set size
fn bench_verify_present_varying_rev(c: &mut Criterion) {
    let mut group = c.benchmark_group("verify_present/varying_rev");
    let mut rng = ark_std::test_rng();
    let l = 100;
    let setup = bench_setup(l, &mut rng);
    let rev_sizes: Vec<usize> = vec![0, 10, 25, 50, 75, 100];

    for rev in rev_sizes {
        group.throughput(Throughput::Elements(rev as u64));
        group.bench_with_input(BenchmarkId::from_parameter(rev), &rev, |b, &rev| {
            let rev_indices: Vec<usize> = (0..rev).collect();
            let aux = Fr::rand(&mut rng);
            let presentation =
                present(&setup.params, &setup.cred, &rev_indices, &aux, &mut rng)
                    .expect("present failed");

            b.iter(|| {
                verify_present(
                    black_box(&setup.params),
                    black_box(&setup.vk),
                    black_box(&presentation),
                )
                .expect("verify_present failed");
            });
        });
    }

    group.finish();
}

struct BenchSetup {
    params: PublicParams,
    cred: Credential,
    vk: airbnb_creds::keys::VerificationKey,
}

fn bench_setup(l: usize, rng: &mut impl Rng) -> BenchSetup {
    let params = PublicParams::setup(l, rng);
    let (sk, vk) = keygen(&params, rng);
    let attributes: Vec<Fr> = (0..l).map(|_| Fr::rand(rng)).collect();
    let sig = sign(&params, &sk, &attributes, rng).expect("sign failed");
    let cred = Credential::new(sig, attributes);
    BenchSetup { params, cred, vk }
}

criterion_group!(benches, bench_present, bench_verify_present, bench_verify_present_varying_rev);
criterion_main!(benches);
