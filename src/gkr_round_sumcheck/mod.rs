//! GKR Round Sumcheck as described in [XZZPS19](https://eprint.iacr.org/2019/317.pdf#subsection.3.3) (Section 3.3)
//!
//! GKR Round Sumcheck will use `ml_sumcheck` as a subroutine.

pub mod data_structures;
#[cfg(test)]
mod test;

use crate::gkr_round_sumcheck::data_structures::{GKRProof, GKRRoundSumcheckSubClaim};
use crate::ml_sumcheck::ahp::prover::ProverState;
use crate::ml_sumcheck::ahp::{AHPForMLSumcheck, ProductsOfMLExtensions};
use crate::ml_sumcheck::IndexVerifierKey;
use crate::rng::{Blake2s512Rng, FeedableRNG};
use ark_ff::{Field, Zero};
use ark_poly::{DenseMultilinearExtension, MultilinearExtension, SparseMultilinearExtension};
use ark_std::marker::PhantomData;
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
        let x = xy & ((1 << dim) - 1);
        let y = xy >> dim;
        a_hg[x] += *v * f3[y];
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
    let mut poly = ProductsOfMLExtensions::new(dim);
    poly.add_product(vec![h_g.clone(), f2.clone()]);
    let index = AHPForMLSumcheck::index_move(poly);
    AHPForMLSumcheck::prover_init(&index)
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
    let mut poly = ProductsOfMLExtensions::new(dim);
    poly.add_product(vec![f1_gu.clone(), f3_f2u]);
    let index = AHPForMLSumcheck::index(&poly);
    AHPForMLSumcheck::prover_init(&index)
}

/// Sumcheck Argument for GKR Round Function
pub struct GKRRoundSumcheck<F: Field> {
    _marker: PhantomData<F>,
}

impl<F: Field> GKRRoundSumcheck<F> {
    /// Takes a GKR Round Function and input, prove the sum.
    /// * `f1`,`f2`,`f3`: represents the GKR round function
    /// * `g`: represents the fixed input.
    pub fn prove(
        f1: &SparseMultilinearExtension<F>,
        f2: &DenseMultilinearExtension<F>,
        f3: &DenseMultilinearExtension<F>,
        g: &[F],
    ) -> GKRProof<F> {
        assert_eq!(f1.num_vars, 3 * f2.num_vars);
        assert_eq!(f1.num_vars, 3 * f3.num_vars);

        let dim = f2.num_vars;
        let g = g.to_vec();

        let mut rng = Blake2s512Rng::setup();

        let (h_g, f1_g) = initialize_phase_one(f1, f3, &g);
        let mut phase1_ps = start_phase1_sumcheck(&h_g, f2);
        let mut phase1_vm = None;
        let mut phase1_prover_msgs = Vec::with_capacity(dim);
        let mut u = Vec::with_capacity(dim);
        for _ in 0..dim {
            let (pm, ps) = AHPForMLSumcheck::prove_round(phase1_ps, &phase1_vm);
            phase1_ps = ps;
            rng.feed(&pm).unwrap();
            phase1_prover_msgs.push(pm);
            let vm = AHPForMLSumcheck::sample_round(&mut rng);
            phase1_vm = Some(vm.clone());
            u.push(vm.randomness);
        }

        let f1_gu = initialize_phase_two(&f1_g, &u);
        let mut phase2_ps = start_phase2_sumcheck(&f1_gu, f3, f2.evaluate(&u).unwrap());
        let mut phase2_vm = None;
        let mut phase2_prover_msgs = Vec::with_capacity(dim);
        let mut v = Vec::with_capacity(dim);
        for _ in 0..dim {
            let (pm, ps) = AHPForMLSumcheck::prove_round(phase2_ps, &phase2_vm);
            phase2_ps = ps;
            rng.feed(&pm).unwrap();
            phase2_prover_msgs.push(pm);
            let vm = AHPForMLSumcheck::sample_round(&mut rng);
            phase2_vm = Some(vm.clone());
            v.push(vm.randomness);
        }

        GKRProof {
            phase1_sumcheck_msgs: phase1_prover_msgs,
            phase2_sumcheck_msgs: phase2_prover_msgs,
        }
    }

    /// Takes a GKR Round Function, input, and proof, verify the sum.
    /// * `f2_num_vars`: represents number of variables of f2
    pub fn verify(
        f2_num_vars: usize,
        proof: &GKRProof<F>,
        claimed_sum: F,
    ) -> Result<GKRRoundSumcheckSubClaim<F>, crate::Error> {
        // verify first sumcheck
        let dim = f2_num_vars;

        let mut rng = Blake2s512Rng::setup();

        let mut phase1_vs = AHPForMLSumcheck::verifier_init(&IndexVerifierKey {
            max_multiplicands: 2,
            num_variables: dim,
        });

        for i in 0..dim {
            let pm = &proof.phase1_sumcheck_msgs[i];
            rng.feed(pm).unwrap();
            let result = AHPForMLSumcheck::verify_round((*pm).clone(), phase1_vs, &mut rng);
            phase1_vs = result.1;
        }
        let phase1_subclaim =
            AHPForMLSumcheck::check_and_generate_subclaim(phase1_vs, claimed_sum)?;
        let u = phase1_subclaim.point;

        let mut phase2_vs = AHPForMLSumcheck::verifier_init(&IndexVerifierKey {
            max_multiplicands: 2,
            num_variables: dim,
        });
        for i in 0..dim {
            let pm = &proof.phase2_sumcheck_msgs[i];
            rng.feed(pm).unwrap();
            let result = AHPForMLSumcheck::verify_round((*pm).clone(), phase2_vs, &mut rng);
            phase2_vs = result.1;
        }
        let phase2_subclaim = AHPForMLSumcheck::check_and_generate_subclaim(
            phase2_vs,
            phase1_subclaim.expected_evaluation,
        )?;

        let v = phase2_subclaim.point;

        let expected_evaluation = phase2_subclaim.expected_evaluation;
        // let guv: Vec<_> = g
        //     .iter()
        //     .chain(u.iter())
        //     .chain(v.iter())
        //     .map(|x| *x)
        //     .collect();
        // let actual_evaluation =
        //     f1.evaluate(&guv).unwrap() * &f2.evaluate(&u).unwrap() * &f3.evaluate(&v).unwrap();

        Ok(GKRRoundSumcheckSubClaim {
            u,
            v,
            expected_evaluation,
        })
    }
}
