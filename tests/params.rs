use ark_bls12_381::Bls12_381;
use ark_ec::pairing::Pairing;
use airbnb_creds::PublicParams;

fn rng() -> impl rand::Rng {
    ark_std::test_rng()
}

// e(h1, g2) = e(g1, h2)  since h1 = hx·g1 and h2 = hx·g2
#[test]
fn h1_h2_consistent() {
    let mut rng = rng();
    let params = PublicParams::setup(4, &mut rng);
    let lhs = Bls12_381::pairing(params.h1, params.g2);
    let rhs = Bls12_381::pairing(params.g1, params.h2);
    assert_eq!(lhs, rhs, "e(h1, g2) = e(g1, h2) mismatch");
}

// e(g1_tau[i], h2) = e(h1_tau[i], g2) since h1_tau[i] = hx·g1_tau[i]
#[test]
fn g1_tau_and_h1_tau_consistent() {
    let mut rng = rng();
    let params = PublicParams::setup(4, &mut rng);
    for i in 0..params.l {
        let lhs = Bls12_381::pairing(params.g1_tau[i], params.h2);
        let rhs = Bls12_381::pairing(params.h1_tau[i], params.g2);
        assert_eq!(lhs, rhs, "e(g1_tau[{i}], h2) = e(h1_tau[{i}], g2) mismatch");
    }
}

// e(g1_tau[i], h2_tau[0]) = e(g1_tau[i+1], h2)
#[test]
fn g1_tau_consecutive_powers() {
    let mut rng = rng();
    let params = PublicParams::setup(4, &mut rng);
    for i in 0..params.l {
        let lhs = Bls12_381::pairing(params.g1_tau[i], params.h2_tau[0]);
        let rhs = Bls12_381::pairing(params.g1_tau[i + 1], params.h2);
        assert_eq!(lhs, rhs, "e(g1_tau[{i}], h2_tau[0]) = e(g1_tau[{}], h2) mismatch", i + 1);
    }
}

// e(h1_tau[i], h2_tau[j]) = e(h1_tau[i+j+1], h2)
#[test]
fn h1_tau_h2_tau_exponents_add() {
    let mut rng = rng();
    let l = 5;
    let params = PublicParams::setup(l, &mut rng);
    for i in 0..l {
        for j in 0..l {
            let sum = i + j + 1;
            if sum >= l { continue; }
            let lhs = Bls12_381::pairing(params.h1_tau[i], params.h2_tau[j]);
            let rhs = Bls12_381::pairing(params.h1_tau[sum], params.h2);
            assert_eq!(lhs, rhs, "exponent addition mismatch at i={i}, j={j}");
        }
    }
}
