use algebra_core::Field;

use crate::data_structures::ml_extension::MLExtension;
use crate::data_structures::protocol::Protocol;
use crate::ml_sumcheck::t13::msg::{MLLibraPMsg, MLLibraVMsg};

use ark_std::vec::Vec;
use ark_std::cmp::max;

pub(crate) struct MLLibraProver<F: Field> {
    generated_messages: Vec<MLLibraPMsg<F>>,
    randomness: Vec<F>,
    tables: Vec<Vec<Vec<F>>>, // sum of product of MLE
    nv: usize,
    num_multiplicands: usize,
    round: usize,
    cached_sum: F,
}

impl<F: Field> MLLibraProver<F> {
    pub(crate) fn setup<P: MLExtension<F>>(poly: &[&[P]]) -> Result<Self, crate::Error> {
        let nv: usize = unwrap_safe!(extract_safe!(extract_safe!(poly.get(0)).get(0)).num_variables());
        let num_terms = poly.len();
        if num_terms < 1 {
            return Err(crate::Error::InvalidArgumentError(Some(
                "num_multiplicands < 1".into(),
            )));
        }
        let mut add_table = Vec::with_capacity(num_terms);

        let mut max_multiplicands = 0;
        for product_poly in poly {
            let num_multiplicands = product_poly.len();
            max_multiplicands = max(max_multiplicands, num_multiplicands);
            let mut mul_table = Vec::with_capacity(num_multiplicands);
            for single_poly in product_poly.iter() {
                if unwrap_safe!(single_poly.num_variables()) != nv {
                    return Err(crate::Error::InvalidArgumentError(Some(
                        "polynomials should be same number of variables".into(),
                    )));
                }

                mul_table.push(unwrap_safe!(single_poly.table()));
            }
            add_table.push(mul_table);
        }

        let mut ans = Self {
            generated_messages: Vec::with_capacity(nv),
            randomness: Vec::with_capacity(nv),
            tables: add_table,
            nv,
            num_multiplicands: max_multiplicands,
            round: 1,
            cached_sum: F::zero(), // filled afterwards
        };

        ans.gen_sum_and_push_message(1);
        let (p0, p1) = {
            let evaluations = &ans.generated_messages[0].evaluations;
            (evaluations[0], evaluations[1])
        };
        ans.cached_sum = p0 + p1;
        Ok(ans)
    }

    /// fix an argument (by getting from the last randomness element) and mutate the table
    /// `i`: current round (round i: get -> <u>push</u> )
    fn fix_arg(&mut self, i: usize) {
        let r = self.randomness[i - 1];
        for pmf in &mut self.tables{
            let num_multiplicands = pmf.len();
            for j in 0..num_multiplicands {
                for b in 0..1 << (self.nv - i) {
                    pmf[j][b] =
                        pmf[j][b << 1] * (F::one() - r) + pmf[j][(b << 1) + 1] * r;
                }
            }
        }

    }

    /// generate the latest sum and push the latest message
    /// * `i`: current round (round i: <u>get</u> -> push )
    fn gen_sum_and_push_message(&mut self, i: usize) {
        let mut products_sum = Vec::with_capacity(self.num_multiplicands + 1);
        products_sum.resize(self.num_multiplicands + 1, F::zero());

        for b in 0..1 << (self.nv - i) {
            let mut t_as_field = F::zero();
            for t in 0..self.num_multiplicands + 1 {
                for pmf in &self.tables {
                    let num_multiplicands = pmf.len();
                    let mut product = F::one();
                    for j in 0..num_multiplicands {
                        let table = &pmf[j]; // j's range is checked in init
                        product *=
                            table[b << 1] * (F::one() - t_as_field) + table[(b << 1) + 1] * t_as_field;
                    }
                    products_sum[t] += product;
                }
                t_as_field += F::one();

            }
        }

        self.generated_messages.push(MLLibraPMsg {
            evaluations: products_sum,
        });
    }
}

impl<F: Field> Protocol for MLLibraProver<F> {
    type InboundMessage = MLLibraVMsg<F>;
    type OutBoundMessage = MLLibraPMsg<F>;
    type Error = crate::Error;

    fn current_round(&self) -> Result<u32, Self::Error> {
        Ok(self.round as u32)
    }

    fn is_active(&self) -> bool {
        self.round <= self.nv
    }

    fn get_message(&self, round: u32) -> Result<Self::OutBoundMessage, Self::Error> {
        let round = round as usize;
        if round > self.round {
            return Err(Self::Error::InvalidOperationError(Some(
                "round > current_round".into(),
            )));
        }
        Ok(self.generated_messages[round - 1].clone())
    }

    fn push_message(&mut self, msg: &Self::InboundMessage) -> Result<(), Self::Error> {
        if !self.is_active() {
            return Err(Self::Error::InvalidOperationError(Some(
                "not active".into(),
            )));
        }

        self.randomness.push(msg.x);
        self.fix_arg(self.round);
        self.round += 1;
        if self.round <= self.nv {
            self.gen_sum_and_push_message(self.round);
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::data_structures::protocol::tests::{test_communication, test_protocol_completeness};
    use crate::data_structures::test_field::TestField;
    use crate::data_structures::{AsDummyFeedable, MLExtensionArray};
    use crate::ml_sumcheck::t13::prover::MLLibraProver;
    use crate::ml_sumcheck::t13::MLLibraVerifier;
    use algebra::{test_rng, UniformRand};

    use ark_std::vec::Vec;

    type F = TestField;

    //noinspection RsBorrowChecker
    #[test]
    fn test_com() {
        const NV: usize = 7;
        const NM: usize = 5;

        let mut rng = test_rng();
        let poly: Vec<_> = (0..NM)
            .map(|_| MLExtensionArray::from_slice(&fill_vec!(1 << NV, F::rand(&mut rng))).unwrap())
            .collect();
        let prover = MLLibraProver::setup(&[&poly]).unwrap();
        let verifier = MLLibraVerifier::setup(
            NV as u32,
            prover.cached_sum,
            AsDummyFeedable::new(test_rng()),
        )
        .unwrap();
        test_communication(prover, verifier, NV as u32, true);
    }

    #[test]
    fn test_completeness() {
        const NV: usize = 7;
        const NM: usize = 5;
        let mut rng = test_rng();
        let poly: Vec<_> = (0..NM)
            .map(|_| MLExtensionArray::from_slice(&fill_vec!(1 << NV, F::rand(&mut rng))).unwrap())
            .collect();
        let mut prover = MLLibraProver::setup(&[&poly]).unwrap();
        let mut verifier = MLLibraVerifier::setup(
            NV as u32,
            prover.cached_sum,
            AsDummyFeedable::new(test_rng()),
        )
        .unwrap();
        test_protocol_completeness(&mut prover, &mut verifier, NV as u32, true);
    }
}
