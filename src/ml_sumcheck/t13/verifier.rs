use ark_ff::Field;

use crate::data_structures::protocol::{Protocol, VerifierProtocol, VerifierState};
use crate::data_structures::random::{FeedableRNG, RnFg};
use crate::ml_sumcheck::t13::msg::{MLLibraPMsg, MLLibraVMsg};

use ark_std::vec::Vec;
pub(crate) struct MLLibraVerifier<F: Field, R: RnFg<F> + FeedableRNG> {
    rng: R,
    can_push: bool,
    convinced: bool,
    expected: F,
    round: u32,
    nv: u32,
    fixed_args: Vec<F>,
}

impl<F: Field, R: RnFg<F> + FeedableRNG> MLLibraVerifier<F, R> {
    pub(crate) fn setup(num_variables: u32, asserted_sum: F, rng: R) -> Result<Self, crate::Error> {
        if num_variables < 1 {
            unwrap_safe!(Err(crate::Error::InvalidArgumentError(Some(
                "num_variables < 1".into()
            ))));
        }
        Ok(Self {
            rng,
            can_push: true,
            convinced: false,
            expected: asserted_sum,
            round: 1,
            nv: num_variables,
            fixed_args: Vec::new(),
        })
    }

    pub(crate) fn subclaim_fixed_args(&self) -> Result<Vec<F>, crate::Error> {
        if self.get_state() != VerifierState::Convinced {
            return Err(crate::Error::InvalidOperationError(Some(
                "Verifier has not convinced. ".into(),
            )));
        }
        Ok(self.fixed_args.to_vec())
    }

    pub(crate) fn subclaim_evaluation_at_fixed_point(&self) -> Result<F, crate::Error> {
        if self.get_state() != VerifierState::Convinced {
            return Err(crate::Error::InvalidOperationError(Some(
                "Verifier has not convinced. ".into(),
            )));
        }
        Ok(self.expected)
    }
}

impl<F: Field, R: RnFg<F> + FeedableRNG> MLLibraVerifier<F, R> {
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

impl<F: Field, R: RnFg<F> + FeedableRNG> VerifierProtocol for MLLibraVerifier<F, R> {
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

impl<F: Field, R: RnFg<F> + FeedableRNG> Protocol for MLLibraVerifier<F, R> {
    type InboundMessage = MLLibraPMsg<F>;
    type OutBoundMessage = MLLibraVMsg<F>;
    type Error = crate::Error;

    fn current_round(&self) -> Result<u32, Self::Error> {
        if let VerifierState::Round(r) = self.get_state() {
            Ok(r)
        } else {
            Err(Self::Error::InvalidOperationError(None))
        }
    }

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
        unwrap_safe!(self.rng.feed(&msg));
        let p0: &F =
            unwrap_safe!(msg
                .evaluations
                .get(0)
                .ok_or_else(|| Self::Error::InvalidArgumentError(Some(
                    "invalid message length".into()
                ))));
        let p1: &F =
            unwrap_safe!(msg
                .evaluations
                .get(1)
                .ok_or_else(|| Self::Error::InvalidArgumentError(Some(
                    "invalid message length".into()
                ))));
        if *p0 + *p1 != self.expected {
            self.reject_and_close();
            unwrap_safe!(Err(Self::Error::Reject(None)))
        }

        let r = self.rng.random_field();

        self.expected = interpolate_deg_n_poly(&msg.evaluations, r);
        self.fixed_args.push(r);

        if self.round == self.nv {
            self.accept_and_close();
        }
        self.round += 1;
        Ok(())
    }
}

pub(crate) fn interpolate_deg_n_poly<F: Field>(p_i: &[F], eval_at: F) -> F {
    let mut result = F::zero();
    let mut i = F::zero();
    for term in p_i.iter() {
        let mut term = *term;
        let mut j = F::zero();
        for _ in 0..p_i.len() {
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

#[cfg(test)]
mod tests {
    use ark_ff::{test_rng, One, Zero};
    use ark_poly::DensePolynomial;
    use rand::Rng;

    use crate::data_structures::test_field::TestField;
    use crate::ml_sumcheck::t13::verifier::interpolate_deg_n_poly;

    use ark_std::vec::Vec;
    //noinspection RsBorrowChecker
    #[test]
    fn test_interpolate() {
        const NUM_ITER: usize = 10;
        type F = TestField;
        let mut rng = test_rng();

        for _ in 0..NUM_ITER {
            let poly = DensePolynomial::<F>::rand(7, &mut rng);
            let eval_at: F = rng.gen();

            let mut at = F::zero();
            let ev: Vec<_> = (0..8)
                .map(|_| {
                    let ans = poly.evaluate(at);
                    at += F::one();
                    ans
                })
                .collect();

            let expected = poly.evaluate(eval_at);
            let actual = interpolate_deg_n_poly(&ev, eval_at);
            assert_eq!(actual, expected);
        }
    }
}
