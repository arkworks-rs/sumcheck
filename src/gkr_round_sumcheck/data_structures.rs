//! Data structures used by GKR Round Sumcheck

use crate::ml_sumcheck::protocol::prover::ProverMsg;
use ark_ff::Field;
use ark_poly::{DenseMultilinearExtension, MultilinearExtension, SparseMultilinearExtension};
use ark_std::vec::Vec;

/// Proof for GKR Round Function
pub struct GKRProof<F: Field> {
    pub(crate) phase1_sumcheck_msgs: Vec<ProverMsg<F>>,
    pub(crate) phase2_sumcheck_msgs: Vec<ProverMsg<F>>,
}

impl<F: Field> GKRProof<F> {
    /// Extract the witness (i.e. the sum of GKR)
    pub fn extract_sum(&self) -> F {
        self.phase1_sumcheck_msgs[0].evaluations[0] + self.phase1_sumcheck_msgs[0].evaluations[1]
    }
}

/// Subclaim for GKR Round Function
pub struct GKRRoundSumcheckSubClaim<F: Field> {
    /// u
    pub u: Vec<F>,
    /// v
    pub v: Vec<F>,
    /// expected evaluation at f(g,u,v)
    pub expected_evaluation: F,
}

impl<F: Field> GKRRoundSumcheckSubClaim<F> {
    /// Verify that the subclaim is true by evaluating the GKR Round function.
    pub fn verify_subclaim(
        &self,
        f1: &SparseMultilinearExtension<F>,
        f2: &DenseMultilinearExtension<F>,
        f3: &DenseMultilinearExtension<F>,
        g: &[F],
    ) -> bool {
        let dim = self.u.len();
        assert_eq!(self.v.len(), dim);
        assert_eq!(f1.num_vars, 3 * dim);
        assert_eq!(f2.num_vars, dim);
        assert_eq!(f3.num_vars, dim);
        assert_eq!(g.len(), dim);

        let guv: Vec<_> = g
            .iter()
            .chain(self.u.iter())
            .chain(self.v.iter()).copied()
            .collect();
        let actual_evaluation = f1.evaluate(&guv).unwrap()
            * f2.evaluate(&self.u).unwrap()
            * f3.evaluate(&self.v).unwrap();

        actual_evaluation == self.expected_evaluation
    }
}
