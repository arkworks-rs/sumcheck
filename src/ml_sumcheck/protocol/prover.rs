//! Prover
use crate::ml_sumcheck::data_structures::ListOfProductsOfPolynomials;
use crate::ml_sumcheck::protocol::verifier::VerifierMsg;
use crate::ml_sumcheck::protocol::IPForMLSumcheck;
use ark_ff::Field;
use ark_poly::{DenseMultilinearExtension, MultilinearExtension};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::vec::Vec;
#[cfg(feature = "parallel")]
use rayon::prelude::*;

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
    /// Stores the list of products that is meant to be added together. Each multiplicand is represented by
    /// the index in flattened_ml_extensions
    pub list_of_products: Vec<(F, Vec<usize>)>,
    /// Stores a list of multilinear extensions in which `self.list_of_products` points to
    pub flattened_ml_extensions: Vec<DenseMultilinearExtension<F>>,
    num_vars: usize,
    max_multiplicands: usize,
    round: usize,
}

impl<F: Field> IPForMLSumcheck<F> {
    /// initialize the prover to argue for the sum of polynomial over {0,1}^`num_vars`
    ///
    /// The polynomial is represented by a list of products of polynomials along with its coefficient that is meant to be added together.
    ///
    /// This data structure of the polynomial is a list of list of `(coefficient, DenseMultilinearExtension)`.
    /// * Number of products n = `polynomial.products.len()`,
    /// * Number of multiplicands of ith product m_i = `polynomial.products[i].1.len()`,
    /// * Coefficient of ith product c_i = `polynomial.products[i].0`
    ///
    /// The resulting polynomial is
    ///
    /// $$\sum_{i=0}^{n}C_i\cdot\prod_{j=0}^{m_i}P_{ij}$$
    ///
    pub fn prover_init(polynomial: &ListOfProductsOfPolynomials<F>) -> ProverState<F> {
        if polynomial.num_variables == 0 {
            panic!("Attempt to prove a constant.")
        }

        // create a deep copy of all unique MLExtensions
        let flattened_ml_extensions = polynomial
            .flattened_ml_extensions
            .iter()
            .map(|x| x.as_ref().clone())
            .collect();

        ProverState {
            randomness: Vec::with_capacity(polynomial.num_variables),
            list_of_products: polynomial.products.clone(),
            flattened_ml_extensions,
            num_vars: polynomial.num_variables,
            max_multiplicands: polynomial.max_multiplicands,
            round: 0,
        }
    }

    /// receive message from verifier, generate prover message, and proceed to next round
    ///
    /// Main algorithm used is from section 3.2 of [XZZPS19](https://eprint.iacr.org/2019/317.pdf#subsection.3.2).
    pub fn prove_round(
        prover_state: &mut ProverState<F>,
        v_msg: &Option<VerifierMsg<F>>,
    ) -> ProverMsg<F> {
        if let Some(msg) = v_msg {
            if prover_state.round == 0 {
                panic!("first round should be prover first.");
            }
            prover_state.randomness.push(msg.randomness);

            // fix argument
            let i = prover_state.round;
            let r = prover_state.randomness[i - 1];
            for multiplicand in prover_state.flattened_ml_extensions.iter_mut() {
                *multiplicand = multiplicand.fix_variables(&[r]);
            }
        } else if prover_state.round > 0 {
            panic!("verifier message is empty");
        }

        prover_state.round += 1;

        if prover_state.round > prover_state.num_vars {
            panic!("Prover is not active");
        }

        let products_sum = compute_sum(prover_state);

        ProverMsg {
            evaluations: products_sum,
        }
    }
}

#[cfg(not(feature = "parallel"))]
fn compute_sum<F: Field>(prover_state: &mut ProverState<F>) -> Vec<F> {
    let i = prover_state.round;
    let nv = prover_state.num_vars;
    let degree = prover_state.max_multiplicands; // the degree of univariate polynomial sent by prover at this round

    let mut products_sum = vec![F::zero(); degree + 1];
    let mut product_scratch = vec![F::zero(); degree + 1];

    // generate sum
    for b in 0..1 << (nv - i) {
        sum_over_list_of_products(
            prover_state,
            degree,
            b,
            &mut products_sum,
            &mut product_scratch,
        );
    }
    products_sum
}

fn sum_over_list_of_products<F: Field>(
    prover_state: &ProverState<F>,
    degree: usize,
    b: usize,
    products_sum: &mut [F],
    product_scratch: &mut [F],
) {
    for (coefficient, products) in &prover_state.list_of_products {
        product_scratch.fill(*coefficient);
        for &jth_product in products {
            let table = &prover_state.flattened_ml_extensions[jth_product];
            let mut start = table[b << 1];
            let step = table[(b << 1) + 1] - start;
            for p in product_scratch.iter_mut() {
                *p *= start;
                start += step;
            }
        }
        for t in 0..degree + 1 {
            products_sum[t] += product_scratch[t];
        }
    }
}

#[cfg(feature = "parallel")]
fn compute_sum<F: Field>(prover_state: &ProverState<F>) -> Vec<F> {
    let i = prover_state.round;
    let nv = prover_state.num_vars;
    let degree = prover_state.max_multiplicands; // the degree of univariate polynomial sent by prover at this round

    let min_par_len = 1 << 10; // the minimum length for which we should actually parallelize

    // generate sum
    (0..1 << (nv - i))
        .into_par_iter()
        .with_min_len(min_par_len)
        .fold(
            || (vec![F::zero(); degree + 1], vec![F::zero(); degree + 1]),
            |mut scratch, b| {
                // The first vec in this `scratch` tuple is the running sum in this fold sublist.
                // The second vec is the `product_scratch` parameter for `sum_over_list_of_products`.
                sum_over_list_of_products(prover_state, degree, b, &mut scratch.0, &mut scratch.1);
                scratch
            },
        )
        .map(|scratch| scratch.0) // We really only care able the first element: the sum of the fold sublist.
        .reduce(
            || vec![F::zero(); degree + 1],
            |mut full_products_sum: Vec<F>, sublist_sum| {
                full_products_sum
                    .iter_mut()
                    .zip(sublist_sum.iter())
                    .for_each(|(f, s)| *f += s);
                full_products_sum
            },
        )
}
