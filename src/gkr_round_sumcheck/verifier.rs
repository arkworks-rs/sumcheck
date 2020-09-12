/// interactive protocol for GKR function
use algebra::{CanonicalDeserialize, CanonicalSerialize, Field};

use crate::data_structures::protocol::VerifierProtocol;
use crate::data_structures::random::RnFg;

/// The sub-claim as output of the verifier.
/// The sub-claim contains a point, and an expected value that `P(point)` should evaluate t0, where
/// P is the GKR. The sub-claim assumes the verifier of this claim has access to `P`.
pub(crate) trait GKRFuncVerifierSubclaim<F: Field>:
    CanonicalSerialize + CanonicalDeserialize
{
    /// Return the reference to the point.
    fn point(&self) -> &[F];
    /// Return the value that P(point) should evaluate to
    fn should_evaluate_to(&self) -> F;

    /// Given P'(point), return if P(point) = P'(point)
    fn is_correct(&self, value: F) -> bool {
        self.should_evaluate_to().eq(&value)
    }

    /// get g for the gkr
    fn g(&self) -> &[F];
}

/// interactive GKR function Verifier
/// ### Implementation Spec
/// **In general, implementors should follow the scheme shown below.**
/// - At round `i`, the prover sends to the verifier
/// `H_i(x) = sum of H(m1, m2, ..., m_(i-1), x, v_(i+1), ... v_2n) over v_(i+1) to v_2n`
/// where `m1, m2, ..., m_(i-1)` is fixed and was previously set by verifier.
/// - Verifier checks that `H_i(0) + H_i(1)` is indeed `H_{i-1}(m_{i-1})`. (If it is round 1,
/// the expected value is the asserted sum)
/// - Verifier interpolates `H_i(x)`, generates random `m_i` in field, calculate `H_i(m_i)` and save for next round.
/// If this is the last round, then `H_i(m_i) = H_2n(m1, ..., m_2n)` is part of the sub-claim.
/// Sub-claim will be `H_2n(m1, ..., m_2n) = H(m1, ..., m_2n)` where `H` is the GKR function.
/// ### Example Message sent to prover
/// A possible representation of `H_i(x)` is `H_i(0)`,`H_i(1)`,`H_i(2)`.
/// `H_i(x)` is a degree-2 polynomial, so the prover sends the verifier `H_i(0)`,`H_i(1)`,`H_i(2)`
pub(crate) trait Verifier<F: Field, R: RnFg<F>>: VerifierProtocol {
    /// type of Output Subclaim
    type SubClaim: GKRFuncVerifierSubclaim<F>;

    /// # Setup
    /// Initialize the interactive GKR verifier.
    /// GKR function is in form `H = f1(g, x, y)*f2(x)*f3(y)`
    ///
    /// parameter `g` is used for:
    /// - generate sub-claim when the verifier is convinced.
    /// - determining the dimension of `g`, `x`, and `y`.
    fn setup(g: &[F], rng: R, asserted_sum: F) -> Result<Self, Self::Error>;

    /// Get the result sub-claim when the verifier is convinced.
    /// Return Error if the verifier is not convinced.
    fn get_sub_claim(&self) -> Result<Self::SubClaim, Self::Error>;
}
