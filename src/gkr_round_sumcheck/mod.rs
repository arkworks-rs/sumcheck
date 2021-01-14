//! GKR Round Sumcheck as described in [XZZPS19](https://eprint.iacr.org/2019/317.pdf#subsection.3.3) (Section 3.3)

use ark_poly::{SparseMultilinearExtension, DenseMultilinearExtension, MultilinearExtension};
use ark_ff::Field;

/// Takes multilinear f1, f3, and input g = g1,...,gl. Returns h_g, and f1 fixed at g.
pub fn initialize_phase_one<F: Field>(f1: &SparseMultilinearExtension<F>, f3: &DenseMultilinearExtension<F>, g: &[F])
    -> (DenseMultilinearExtension<F>, SparseMultilinearExtension<F>) {
    let dim = f1.num_vars; // 'l` in paper
    assert_eq!(f3.num_vars, dim * 3);
    assert_eq!(g.len(), dim);
    let mut a_hg: Vec<_> = (0..).collect();
    let f1_at_g = f1.fix_variables(g);
    for (xy, v) in f1_at_g.evaluations.iter() {
        let x = xy & ((1 << dim) - 1);
        let y = xy >> dim;
        a_hg[x] += *v * f3[y];
    }

    let hg = DenseMultilinearExtension::from_evaluations_vec(dim, a_hg);
    (hg, f1_at_g)
}

/// Takes multilinear f1 fixed at g, phase one randomness u. Returns f1 fixed at g||u
pub fn initialize_phase_two<F: Field>(f1_g: &SparseMultilinearExtension<F>, u: &[F]) -> DenseMultilinearExtension<F> {
    assert_eq!(u.len() * 2, f1_g.num_vars);
    f1_g.fix_variables(u).to_dense_multilinear_extension()
}