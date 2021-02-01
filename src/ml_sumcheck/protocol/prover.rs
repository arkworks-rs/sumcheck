//! Prover
use crate::ml_sumcheck::protocol::verifier::VerifierMsg;
use crate::ml_sumcheck::protocol::{IPForMLSumcheck, ListOfProductsOfPolynomials};
use ark_ff::Field;
use ark_poly::{DenseMultilinearExtension, MultilinearExtension};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Read, SerializationError, Write};
use ark_std::vec::Vec;

/// Prover Message
#[derive(Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct ProverMsg<F: Field> {
    /// evaluations on P(0), P(1), P(2), ...
    pub(crate) evaluations: Vec<F>,
}
/// Prover State
pub struct ProverState<F: Field> {
    /// sampled randomness given by the verifier
    pub randomness: Vec<F>,
    list_of_products: Vec<Vec<DenseMultilinearExtension<F>>>,
    num_vars: usize,
    num_multiplicands: usize,
    round: usize,
}

impl<F: Field> IPForMLSumcheck<F> {
    /// initialize the prover to argue for the sum of polynomial over {0,1}^`num_vars`
    ///
    /// The polynomial is represented by a list of products of polynomials that is meant to be added together.
    ///
    /// This data structure of the polynomial is a list of list of `DenseMultilinearExtension`, and the resulting polynomial is
    /// $$\sum_{i=0}^{`polynomial.products.len()`}\prod_{j=0}^{`polynomial.products[i].len()`}P_{ij}$$
    ///
    pub fn prover_init(polynomial: &ListOfProductsOfPolynomials<F>) -> ProverState<F> {
        if polynomial.num_variables == 0 {
            panic!("Attempt to prove a constant.")
        }
        ProverState {
            randomness: Vec::with_capacity(polynomial.num_variables),
            list_of_products: polynomial.products.clone(),
            num_vars: polynomial.num_variables,
            num_multiplicands: polynomial.max_multiplicands,
            round: 0,
        }
    }

    /// receive message from verifier, generate prover message, and proceed to next round
    ///
    /// Main algorithm used is from section 3.2 of [XZZPS19](https://eprint.iacr.org/2019/317.pdf#subsection.3.2).
    pub fn prove_round(
        mut prover_state: ProverState<F>,
        v_msg: &Option<VerifierMsg<F>>,
    ) -> (ProverMsg<F>, ProverState<F>) {
        if let Some(msg) = v_msg {
            if prover_state.round == 0 {
                panic!("first round should be prover first.");
            }
            prover_state.randomness.push(msg.randomness);

            // fix argument
            let i = prover_state.round;
            let r = prover_state.randomness[i - 1];
            for pmf in &mut prover_state.list_of_products {
                let num_multiplicands = pmf.len();
                for j in 0..num_multiplicands {
                    pmf[j] = pmf[j].fix_variables(&[r]);
                }
            }
        } else {
            if prover_state.round > 0 {
                panic!("verifier message is empty");
            }
        }

        prover_state.round += 1;

        if prover_state.round > prover_state.num_vars {
            panic!("Prover is not active");
        }

        let i = prover_state.round;
        let nv = prover_state.num_vars;
        let num_multiplicands = prover_state.num_multiplicands;

        let mut products_sum = Vec::with_capacity(num_multiplicands + 1);
        products_sum.resize(num_multiplicands + 1, F::zero());

        // generate sum
        for b in 0..1 << (nv - i) {
            let mut t_as_field = F::zero();
            for t in 0..num_multiplicands + 1 {
                for pmf in &prover_state.list_of_products {
                    let num_multiplicands = pmf.len();
                    let mut product = F::one();
                    for j in 0..num_multiplicands {
                        let table = &pmf[j]; // j's range is checked in init
                        product *= table[b << 1] * (F::one() - t_as_field)
                            + table[(b << 1) + 1] * t_as_field;
                    }
                    products_sum[t] += product;
                }
                t_as_field += F::one();
            }
        }

        (
            ProverMsg {
                evaluations: products_sum,
            },
            prover_state,
        )
    }
}
