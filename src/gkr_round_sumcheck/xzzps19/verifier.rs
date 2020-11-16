use ark_ff::Field;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, SerializationError};
use ark_std::io::{Read, Write};

use crate::data_structures::protocol::{Protocol, VerifierProtocol, VerifierState};
use crate::data_structures::random::{FeedableRNG, RnFg};
use crate::gkr_round_sumcheck::xzzps19::msg::{XZZPS19PMsg, XZZPS19VMsg};
use crate::gkr_round_sumcheck::{GKRFuncVerifierSubclaim, Verifier as GKRRoundVerifier};

use ark_std::vec::Vec;
/// Verifier for GKR Protocol.
pub(crate) struct XZZPS19Verifier<F: Field, R: RnFg<F> + FeedableRNG> {
    /// Random generator
    rng: R,
    /// if the verifier is active
    can_push: bool,
    /// if the verifier is convinced
    convinced: bool,
    /// When next time prover send a message, what the verifier expect H(0) + H(1) be.
    expected: F,
    /// Record the current round
    round: u32,
    /// number of variables in g, x, and y
    dim: u32,
    /// fixed g in GKR
    g: Vec<F>,
    /// randomness generated
    fixed_args: Vec<F>,
}

impl<F: Field, R: RnFg<F> + FeedableRNG> GKRRoundVerifier<F, R> for XZZPS19Verifier<F, R> {
    type SubClaim = XZZPS19Subclaim<F>;

    fn setup(g: &[F], mut rng: R, asserted_sum: F) -> Result<Self, Self::Error> {
        let dim = g.len();
        let g = g.to_vec();
        let expected = asserted_sum;
        unwrap_safe!(rng.feed(&g));
        // feed randomness
        unwrap_safe!(rng.feed(&expected));
        let round = 1;
        Ok(Self {
            rng,
            can_push: true,
            convinced: false,
            expected,
            round,
            dim: dim as u32,
            g,
            fixed_args: Vec::with_capacity(dim),
        })
    }

    fn get_sub_claim(&self) -> Result<Self::SubClaim, Self::Error> {
        if let VerifierState::Convinced = self.get_state() {
            Ok(XZZPS19Subclaim::new(
                self.fixed_args.to_vec(),
                self.expected,
                self.g.to_vec(),
            ))
        } else {
            Err(Self::Error::InvalidOperationError(None))
        }
    }
}

impl<F: Field, R: RnFg<F> + FeedableRNG> VerifierProtocol for XZZPS19Verifier<F, R> {
    fn get_state(&self) -> VerifierState {
        if self.can_push {
            VerifierState::Round(self.round)
        } else if self.convinced {
            VerifierState::Convinced
        } else {
            VerifierState::Rejected
        }
    }
}

impl<F: Field, R: RnFg<F> + FeedableRNG> Protocol for XZZPS19Verifier<F, R> {
    type InboundMessage = XZZPS19PMsg<F>;
    type OutBoundMessage = XZZPS19VMsg<F>;
    type Error = crate::Error;

    fn current_round(&self) -> Result<u32, Self::Error> {
        if let VerifierState::Round(r) = self.get_state() {
            Ok(r)
        } else {
            Err(Self::Error::InvalidOperationError(None))
        }
    }
    #[inline]
    fn is_active(&self) -> bool {
        self.can_push
    }

    fn get_message(&self, round: u32) -> Result<Self::OutBoundMessage, Self::Error> {
        // current round's message has not come out at this point, because `push_message` has not been called.
        if round >= self.round {
            Err(Self::Error::InvalidOperationError(Some(format!(
                "Only Message earlier than round {} is sent. Requested message at round {}. ",
                self.round, round
            ))))
        } else if let Some(v) = self.fixed_args.get((round - 1) as usize) {
            Ok(Self::OutBoundMessage { x: *v })
        } else {
            Err(Self::Error::InternalDataStructureCorruption(None))
        }
    }

    fn push_message(&mut self, msg: &Self::InboundMessage) -> Result<(), Self::Error> {
        if !self.can_push {
            return Err(Self::Error::InvalidOperationError(None));
        };

        // feed randomness

        unwrap_safe!(self.rng.feed(&msg));

        let p0 = msg.0;
        let p1 = msg.1;

        if p0 + p1 != self.expected {
            self.reject_and_close();
            return Err(Self::Error::Reject(None));
        }

        let r = self.rng.random_field();
        self.expected = interpolate_deg2_poly(msg.0, msg.1, msg.2, r);
        self.fixed_args.push(r);
        // end
        if self.round == self.dim * 2 {
            self.accept_and_close();
        };
        self.round += 1;
        Ok(())
    }
}

impl<F: Field, R: RnFg<F> + FeedableRNG> XZZPS19Verifier<F, R> {
    /// immediately reject the prover and become inactive.
    #[inline]
    fn reject_and_close(&mut self) {
        self.can_push = false;
        self.convinced = false;
    }

    #[inline]
    fn accept_and_close(&mut self) {
        self.can_push = false;
        self.convinced = true;
    }
}

/// lagrange interpolation of a deg-2 poly
fn interpolate_deg2_poly<F: Field>(p0: F, p1: F, p2: F, eval_at: F) -> F {
    let mut result = F::zero();
    let args = [p0, p1, p2];
    let mut i = F::zero();
    for term in args.iter() {
        let mut term = *term;
        let mut j = F::zero();
        for _ in 0..3 {
            if j != i {
                term = term * (eval_at - j) / (i - j)
            }
            j += F::one();
        }
        i += F::one();
        result += term;
    }

    result
}

/// Subclaim of the XZZPS19 verifier.
pub(crate) struct XZZPS19Subclaim<F: Field> {
    point: Vec<F>,
    should_evaluate_to: F,
    g: Vec<F>,
}

impl<F: Field> GKRFuncVerifierSubclaim<F> for XZZPS19Subclaim<F> {
    fn point(&self) -> &[F] {
        &self.point
    }

    fn should_evaluate_to(&self) -> F {
        self.should_evaluate_to
    }

    fn g(&self) -> &[F] {
        &self.g
    }
}

impl<F: Field> XZZPS19Subclaim<F> {
    /// Generate a subclaim.
    pub(crate) fn new(point: Vec<F>, should_evaluate_to: F, g: Vec<F>) -> Self {
        XZZPS19Subclaim {
            point,
            should_evaluate_to,
            g,
        }
    }
}

impl<F: Field> CanonicalSerialize for XZZPS19Subclaim<F> {
    fn serialize<W: Write>(&self, _writer: W) -> Result<(), SerializationError> {
        unimplemented!()
    }

    fn serialized_size(&self) -> usize {
        unimplemented!()
    }
}

impl<F: Field> CanonicalDeserialize for XZZPS19Subclaim<F> {
    fn deserialize<R: Read>(_reader: R) -> Result<Self, SerializationError> {
        unimplemented!()
    }
}

#[cfg(test)]
mod tests {
    use ark_ff::{test_rng, One, Zero};
    use ark_poly::polynomial::UVPolynomial;
    use ark_poly::univariate::DensePolynomial;
    use rand::Rng;

    use crate::data_structures::test_field::TestField;

    use super::interpolate_deg2_poly;
    use ark_poly::Polynomial;

    //noinspection RsBorrowChecker
    #[test]
    fn test_interpolate() {
        const NUM_ITER: usize = 1000;
        type F = TestField;
        let mut rng = test_rng();

        for _ in 0..NUM_ITER {
            let poly = DensePolynomial::<F>::rand(2, &mut rng);
            let eval_at: TestField = rng.gen();

            let p0 = poly.evaluate(&F::zero());
            let p1 = poly.evaluate(&F::one());
            let p2 = poly.evaluate(&(F::one() + F::one()));

            let expected = poly.evaluate(&eval_at);
            let actual = interpolate_deg2_poly(p0, p1, p2, eval_at);
            assert_eq!(actual, expected);
        }
    }
}
