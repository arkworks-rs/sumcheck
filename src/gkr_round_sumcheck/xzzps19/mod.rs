//! Implementation of GKR function by Xie et al.
//!
//! [Source](https://eprint.iacr.org/2019/317.pdf)

pub use fs::*;
pub use fs::*;
pub(crate) use prover::*;
pub(crate) use verifier::*;

/// type of messages
mod msg;

/// Fiat-Shamir
mod fs;

/// interactive prover
mod prover;
/// interactive verifier
mod verifier;

#[cfg(test)]
pub mod tests {
    #[cfg(feature = "std")]
    use std::time::Instant;

    use algebra::{test_rng, UniformRand};

    use crate::data_structures::ml_extension::{GKRFunction, MLExtension};
    use crate::data_structures::protocol::tests::{test_communication, test_protocol_completeness};
    use crate::data_structures::random::FeedableRNG;
    use crate::data_structures::test_field::TestField;
    use crate::data_structures::{
        AsDummyFeedable, Blake2s512Rng, MLExtensionRefArray, SparseMLExtensionMap,
    };
    use crate::gkr_round_sumcheck::xzzps19::prover::XZZPS19Prover;
    use crate::gkr_round_sumcheck::xzzps19::verifier::XZZPS19Verifier;
    use crate::gkr_round_sumcheck::{GKRFuncVerifierSubclaim, Prover, Verifier as _};
    #[cfg(not(feature = "std"))]
    use alloc::vec::Vec;
    type F = TestField;
    type S = SparseMLExtensionMap<F>;
    type D<'a> = MLExtensionRefArray<'a, F>;

    #[test]
    fn communication_sanity_test() {
        const NV: usize = 7;
        let mut rng = test_rng();
        random_gkr!(&mut rng, NV, gkr);

        let g = fill_vec!(NV, F::rand(&mut rng));
        let rnfg = AsDummyFeedable::new(&mut rng);
        let prover = XZZPS19Prover::setup(&gkr, &g).unwrap();
        let asserted_sum = prover.get_sum();
        let verifier = XZZPS19Verifier::setup(&g, rnfg, asserted_sum).unwrap();

        test_communication(prover, verifier, (NV * 2) as u32, true);
    }

    #[test]
    fn completeness_test() {
        const NV: usize = 9;
        let mut rng = test_rng();
        let f1: S;
        let f2_arr;
        let f2;
        let f3_arr;
        let f3;
        let gkr;
        {
            use crate::data_structures::tests::random_sparse_poly_fast;
            use crate::data_structures::GKRAsLink;
            use algebra::UniformRand;
            f1 = random_sparse_poly_fast(NV * 3, &mut rng);
            f2_arr = (0..(1 << NV))
                .map(|_| (F::rand(&mut rng)))
                .collect::<Vec<_>>();
            f2 = D::from_slice(&f2_arr).unwrap();
            f3_arr = (0..(1 << NV))
                .map(|_| (F::rand(&mut rng)))
                .collect::<Vec<_>>();
            f3 = D::from_slice(&f3_arr).unwrap();
            gkr = GKRAsLink::new(&f1, &f2, &f3).unwrap();
        }
        let g = fill_vec!(NV, F::rand(&mut rng));
        let mut prover = XZZPS19Prover::setup(&gkr, &g).unwrap();
        let asserted_sum = prover.get_sum();
        let mut verifier: XZZPS19Verifier<_, AsDummyFeedable<_>> =
            XZZPS19Verifier::setup(&g, (&mut rng).into(), asserted_sum).unwrap();

        test_protocol_completeness(&mut prover, &mut verifier, (NV * 2) as u32, true);

        // tests subclaim
        let subclaim = verifier.get_sub_claim().unwrap();

        // subclaim point
        let g = subclaim.g();
        let x = &subclaim.point()[0..NV];
        let y = &subclaim.point()[NV..];
        let mut gxy = g.to_vec();
        gxy.extend(x);
        gxy.extend(y);

        let actual = gkr.get_f1().eval_at(&gxy).unwrap()
            * gkr.get_f2().eval_at(x).unwrap()
            * gkr.get_f3().eval_at(y).unwrap();

        assert_eq!(actual, subclaim.should_evaluate_to());

        assert!(subclaim.is_correct(actual));
    }

    #[test]
    #[cfg(feature = "std")]
    fn benchmark() {
        println!("Runtime analysis for XZZPS19 GKRFunc sumcheck protocol");
        timeit!(benchmark_for(7));
        timeit!(benchmark_for(8));
        timeit!(benchmark_for(9));
        timeit!(benchmark_for(10));
        timeit!(benchmark_for(11));
        timeit!(benchmark_for(12));
        timeit!(benchmark_for(13));
        timeit!(benchmark_for(14));
        timeit!(benchmark_for(15));
        timeit!(benchmark_for(16));
        timeit!(benchmark_for(17));
    }

    #[cfg(feature = "std")]
    fn benchmark_for(dim: usize) {
        use crate::data_structures::protocol::tests::test_protocol_benchmark;
        let mut rng = test_rng();
        random_gkr!(&mut rng, dim, gkr);
        let g = fill_vec!(dim, F::rand(&mut rng));
        let rnfg = AsDummyFeedable::new(&mut rng);
        let t0 = Instant::now();
        let prover = XZZPS19Prover::setup(&gkr, &g).unwrap();
        let t_prover_setup = Instant::now() - t0;

        let asserted_sum = prover.get_sum();

        let t0 = Instant::now();
        let verifier = XZZPS19Verifier::setup(&g, rnfg, asserted_sum).unwrap();
        let t_verifier_setup = Instant::now() - t0;

        let ((t_prover_get, t_prover_push), (t_verifier_get, t_verifier_push)) =
            test_protocol_benchmark(prover, verifier, (dim * 2) as u32);

        println!("XZZPS19 GKR Function Prover Benchmark Result (dim={})", dim);
        println!(
            "Prover Time = Setup({}ms) + Get({}ms) + Push({}ms) = {}ms",
            t_prover_setup.as_millis(),
            t_prover_get.as_millis(),
            t_prover_push.as_millis(),
            (t_prover_setup + t_prover_get + t_prover_push).as_millis()
        );
        println!(
            "Verifier Time = Setup({}ms) + Get({}ms) + Push({}ms) = {}ms",
            t_verifier_setup.as_millis(),
            t_verifier_get.as_millis(),
            t_verifier_push.as_millis(),
            (t_verifier_setup + t_verifier_get + t_verifier_push).as_millis()
        );
    }

    #[test]
    fn fs_deterministic_test() {
        const NV: usize = 7;
        let mut rng = test_rng();
        random_gkr!(&mut rng, NV, gkr);
        let g = fill_vec!(NV, F::rand(&mut rng));

        let prng = Blake2s512Rng::setup();
        let prover = XZZPS19Prover::setup(&gkr, &g).unwrap();
        let asserted_sum = prover.get_sum();
        let verifier = XZZPS19Verifier::setup(&g, prng, asserted_sum).unwrap();
        let (_, v_msg) = test_communication(prover, verifier, (2 * NV) as u32, true);

        // another time
        let prng = Blake2s512Rng::setup();
        let prover = XZZPS19Prover::setup(&gkr, &g).unwrap();
        let asserted_sum = prover.get_sum();
        let verifier = XZZPS19Verifier::setup(&g, prng, asserted_sum).unwrap();
        let (_, v_msg_2) = test_communication(prover, verifier, (2 * NV) as u32, true);
        assert_eq!(v_msg, v_msg_2);

        // different randomness
        random_gkr!(&mut rng, NV, gkr);
        let g = fill_vec!(NV, F::rand(&mut rng));
        let prng = Blake2s512Rng::setup();
        let prover = XZZPS19Prover::setup(&gkr, &g).unwrap();
        let asserted_sum = prover.get_sum();
        let verifier = XZZPS19Verifier::setup(&g, prng, asserted_sum).unwrap();
        let (_, v_msg_3) = test_communication(prover, verifier, (2 * NV) as u32, true);

        assert_ne!(v_msg, v_msg_3)
    }
}
