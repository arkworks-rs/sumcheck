use algebra::Field;
use rand_core::RngCore;

use crate::data_structures::ml_extension::{GKRFunction, MLExtension, SparseMLExtension};
use crate::data_structures::protocol::Protocol;

/// interactive prover of GKR Function Sum-check

pub(crate) trait Prover<'a, F: Field>: Protocol {
    /// Sparse representation of multilinear extension
    type SparseMLE: SparseMLExtension<F>;
    /// general representation of multilinear extension
    type DenseMLE: MLExtension<F>;
    /// GKR function container holding sparse f1, dense f2, and dense f3
    type GKRFunc: GKRFunction<F, Self::SparseMLE, Self::DenseMLE>;

    /// Setup the prover
    fn setup(gkr: &'a Self::GKRFunc, g: &[F]) -> Result<Self, Self::Error>;
}

pub(crate) trait ProverWithRand<'a, F: Field, R: RngCore>: Prover<'a, F> {
    /// Setup the prover with rng
    fn setup_with_rand(gkr: &'a Self::GKRFunc, g: &[F], rng: R) -> Result<Self, Self::Error>;
}
