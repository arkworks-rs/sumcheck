//! Implementation of GKR Round Sumcheck algorithm as described in [XZZPS19](https://eprint.iacr.org/2019/317.pdf#subsection.3.3) (Section 3.3)
//!
//! GKR Round Sumcheck will use `ml_sumcheck` as a subroutine.

pub mod data_structures;
#[cfg(test)]
mod test;

use crate::gkr_round_sumcheck::data_structures::{GKRProof, GKRRoundSumcheckSubClaim};
use crate::ml_sumcheck::protocol::prover::ProverState;
use crate::ml_sumcheck::protocol::{IPForMLSumcheck, ListOfProductsOfPolynomials, PolynomialInfo};
use crate::rng::FeedableRNG;
use ark_ff::{Field, Zero};
use ark_poly::{DenseMultilinearExtension, MultilinearExtension, SparseMultilinearExtension};
use ark_std::marker::PhantomData;
use ark_std::rc::Rc;
use ark_std::vec::Vec;

/// Takes multilinear f1, f3, and input g = g1,...,gl. Returns h_g, and f1 fixed at g.
pub fn initialize_phase_one<F: Field>(
    f1: &SparseMultilinearExtension<F>,
    f3: &DenseMultilinearExtension<F>,
    g: &[F],
) -> (DenseMultilinearExtension<F>, SparseMultilinearExtension<F>) {
    let dim = f3.num_vars; // 'l` in paper
    assert_eq!(f1.num_vars, dim * 3);
    assert_eq!(g.len(), dim);
    let mut a_hg: Vec<_> = (0..(1 << dim)).map(|_| F::zero()).collect();
    let f1_at_g = f1.fix_variables(g);
    for (xy, v) in f1_at_g.evaluations.iter() {
        if v != &F::zero() {
            let x = xy & ((1 << dim) - 1);
            let y = xy >> dim;
            a_hg[x] += *v * f3[y];
        }
    }

    let hg = DenseMultilinearExtension::from_evaluations_vec(dim, a_hg);
    (hg, f1_at_g)
}

/// Takes h_g and returns a sumcheck state
pub fn start_phase1_sumcheck<F: Field>(
    h_g: &DenseMultilinearExtension<F>,
    f2: &DenseMultilinearExtension<F>,
) -> ProverState<F> {
    let dim = h_g.num_vars;
    assert_eq!(f2.num_vars, dim);
    let mut poly = ListOfProductsOfPolynomials::new(dim);
    poly.add_product(vec![Rc::new(h_g.clone()), Rc::new(f2.clone())], F::one());
    IPForMLSumcheck::prover_init(&poly)
}

/// Takes multilinear f1 fixed at g, phase one randomness u. Returns f1 fixed at g||u
pub fn initialize_phase_two<F: Field>(
    f1_g: &SparseMultilinearExtension<F>,
    u: &[F],
) -> DenseMultilinearExtension<F> {
    assert_eq!(u.len() * 2, f1_g.num_vars);
    f1_g.fix_variables(u).to_dense_multilinear_extension()
}

/// Takes f1 fixed at g||u, f3, and f2 evaluated at u.
pub fn start_phase2_sumcheck<F: Field>(
    f1_gu: &DenseMultilinearExtension<F>,
    f3: &DenseMultilinearExtension<F>,
    f2_u: F,
) -> ProverState<F> {
    let f3_f2u = {
        let mut zero = DenseMultilinearExtension::zero();
        zero += (f2_u, f3);
        zero
    };

    let dim = f1_gu.num_vars;
    assert_eq!(f3.num_vars, dim);
    let mut poly = ListOfProductsOfPolynomials::new(dim);
    poly.add_product(vec![Rc::new(f1_gu.clone()), Rc::new(f3_f2u)], F::one());
    IPForMLSumcheck::prover_init(&poly)
}

/// Sumcheck Argument for GKR Round Function
pub struct GKRRoundSumcheck<F: Field> {
    _marker: PhantomData<F>,
}

impl<F: Field> GKRRoundSumcheck<F> {
    /// Takes a GKR Round Function and input, prove the sum.
    /// * `f1`,`f2`,`f3`: represents the GKR round function
    /// * `g`: represents the fixed input.
    pub fn prove<R: FeedableRNG>(
        rng: &mut R,
        f1: &SparseMultilinearExtension<F>,
        f2: &DenseMultilinearExtension<F>,
        f3: &DenseMultilinearExtension<F>,
        g: &[F],
    ) -> GKRProof<F> {
        assert_eq!(f1.num_vars, 3 * f2.num_vars);
        assert_eq!(f1.num_vars, 3 * f3.num_vars);

        let dim = f2.num_vars;
        let g = g.to_vec();

        let (h_g, f1_g) = initialize_phase_one(f1, f3, &g);
        let mut phase1_ps = start_phase1_sumcheck(&h_g, f2);
        let mut phase1_vm = None;
        let mut phase1_prover_msgs = Vec::with_capacity(dim);
        let mut u = Vec::with_capacity(dim);
        for _ in 0..dim {
            let pm = IPForMLSumcheck::prove_round(&mut phase1_ps, &phase1_vm);

            rng.feed(&pm).unwrap();
            phase1_prover_msgs.push(pm);
            let vm = IPForMLSumcheck::sample_round(rng);
            phase1_vm = Some(vm.clone());
            u.push(vm.randomness);
        }

        let f1_gu = initialize_phase_two(&f1_g, &u);
        let mut phase2_ps = start_phase2_sumcheck(&f1_gu, f3, f2.evaluate(&u).unwrap());
        let mut phase2_vm = None;
        let mut phase2_prover_msgs = Vec::with_capacity(dim);
        let mut v = Vec::with_capacity(dim);
        for _ in 0..dim {
            let pm = IPForMLSumcheck::prove_round(&mut phase2_ps, &phase2_vm);
            rng.feed(&pm).unwrap();
            phase2_prover_msgs.push(pm);
            let vm = IPForMLSumcheck::sample_round(rng);
            phase2_vm = Some(vm.clone());
            v.push(vm.randomness);
        }

        GKRProof {
            phase1_sumcheck_msgs: phase1_prover_msgs,
            phase2_sumcheck_msgs: phase2_prover_msgs,
        }
    }

    /// Takes a GKR Round Function, input, and proof, and returns a subclaim.
    ///
    /// If the `claimed_sum` is correct, then it is `subclaim.verify_subclaim` will return true.
    /// Otherwise, it is very likely that `subclaim.verify_subclaim` will return false.
    /// Larger field size guarantees smaller soundness error.
    /// * `f2_num_vars`: represents number of variables of f2
    pub fn verify<R: FeedableRNG>(
        rng: &mut R,
        f2_num_vars: usize,
        proof: &GKRProof<F>,
        claimed_sum: F,
    ) -> Result<GKRRoundSumcheckSubClaim<F>, crate::Error> {
        // verify first sumcheck
        let dim = f2_num_vars;

        let mut phase1_vs = IPForMLSumcheck::verifier_init(&PolynomialInfo {
            max_multiplicands: 2,
            num_variables: dim,
        });

        for i in 0..dim {
            let pm = &proof.phase1_sumcheck_msgs[i];
            rng.feed(pm).unwrap();
            let _result = IPForMLSumcheck::verify_round((*pm).clone(), &mut phase1_vs, rng);
        }
        let phase1_subclaim = IPForMLSumcheck::check_and_generate_subclaim(phase1_vs, claimed_sum)?;
        let u = phase1_subclaim.point;

        let mut phase2_vs = IPForMLSumcheck::verifier_init(&PolynomialInfo {
            max_multiplicands: 2,
            num_variables: dim,
        });
        for i in 0..dim {
            let pm = &proof.phase2_sumcheck_msgs[i];
            rng.feed(pm).unwrap();
            let _result = IPForMLSumcheck::verify_round((*pm).clone(), &mut phase2_vs, rng);
        }
        let phase2_subclaim = IPForMLSumcheck::check_and_generate_subclaim(
            phase2_vs,
            phase1_subclaim.expected_evaluation,
        )?;

        let v = phase2_subclaim.point;

        let expected_evaluation = phase2_subclaim.expected_evaluation;

        Ok(GKRRoundSumcheckSubClaim {
            u,
            v,
            expected_evaluation,
        })
    }
}
