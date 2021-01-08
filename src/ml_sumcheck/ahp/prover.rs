//! Prover
use crate::ml_sumcheck::ahp::indexer::Index;
use crate::ml_sumcheck::ahp::verifier::VerifierMsg;
use crate::ml_sumcheck::ahp::AHPForMLSumcheck;
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
    tables: Vec<Vec<DenseMultilinearExtension<F>>>,
    nv: usize,
    num_multiplicands: usize,
    round: usize,
}

impl<F: Field> AHPForMLSumcheck<F> {
    /// initialize the prover
    pub fn prover_init(index: &Index<F>) -> ProverState<F> {
        if index.num_variables == 0 {
            panic!("Attempt to prove a constant.")
        }
        ProverState {
            randomness: Vec::with_capacity(index.num_variables),
            tables: index.add_table.clone(),
            nv: index.num_variables,
            num_multiplicands: index.max_multiplicands,
            round: 0,
        }
    }

    /// receive message from verifier, generate prover message, and proceed to next round
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
            for pmf in &mut prover_state.tables {
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

        if prover_state.round > prover_state.nv {
            panic!("Prover is not active");
        }

        let i = prover_state.round;
        let nv = prover_state.nv;
        let num_multiplicands = prover_state.num_multiplicands;

        let mut products_sum = Vec::with_capacity(num_multiplicands + 1);
        products_sum.resize(num_multiplicands + 1, F::zero());

        // generate sum
        for b in 0..1 << (nv - i) {
            let mut t_as_field = F::zero();
            for t in 0..num_multiplicands + 1 {
                for pmf in &prover_state.tables {
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
