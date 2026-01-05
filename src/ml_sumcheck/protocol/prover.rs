//! Prover
use crate::ml_sumcheck::data_structures::BinaryConstraintPolynomial;
use crate::ml_sumcheck::protocol::verifier::VerifierMsg;
use crate::ml_sumcheck::protocol::IPForMLSumcheck;
use ark_ff::Field;
use ark_poly::{DenseMultilinearExtension, MultilinearExtension};
use ark_serialize::CanonicalSerialize;
use ark_std::{cfg_iter_mut, vec::Vec};
#[cfg(feature = "parallel")]
use rayon::prelude::*;

/// Prover Message
#[derive(Clone, CanonicalSerialize)]
pub struct ProverMsg<F: Field> {
    /// evaluations on P(0), P(1), P(2), ... 
    pub(crate) evaluations: Vec<F>,
}

/// Prover State for binary constraints with eq_t masking and g polynomial
pub struct ProverState<F: Field> {
    /// sampled randomness given by the verifier
    pub randomness: Vec<F>,
    /// List of (coefficient, polynomial) pairs
    pub constraints: Vec<(F, DenseMultilinearExtension<F>)>,
    /// The eq_t point (original, never modified)
    pub eq_point_original: Vec<F>,
    /// Coefficient α for g term
    pub alpha: F,
    /// Random univariate polynomials g₁, ..., gₙ (coefficients)
    pub g_polys: Vec<Vec<F>>,
    /// Cached sum of fixed g values: Σⱼ₌₀^{i-2} gⱼ(rⱼ)
    pub fixed_g_sum: F,
    /// Cached product of fixed randomness for eq_{1,...,1}: ∏ⱼ₌₀^{i-2} rⱼ
    pub fixed_eq_ones_product: F,
    /// Cached product for eq_t from fixed variables: ∏ⱼ₌₀^{i-2} [(1-tⱼ) + rⱼ(2tⱼ-1)]
    pub fixed_eq_t_product: F,
    /// Number of variables
    pub num_vars: usize,
    /// The current round number
    pub round: usize,
}

impl<F: Field> IPForMLSumcheck<F> {
    /// Initialize the prover for binary constraint polynomial with eq masking and g
    pub fn prover_init(polynomial: &BinaryConstraintPolynomial<F>) -> ProverState<F> {
        if polynomial.num_variables == 0 {
            panic!("Attempt to prove a constant.");
        }

        // Clone all polynomials
        let constraints = polynomial
            .constraints
            .iter()
            .map(|(c, p)| (*c, p.clone()))
            .collect();

        ProverState {
            randomness: Vec::with_capacity(polynomial.num_variables),
            constraints,
            eq_point_original: polynomial.eq_point.clone(),
            alpha: polynomial.alpha,
            g_polys: polynomial.g_polys.clone(),
            fixed_g_sum: F::zero(),
            fixed_eq_ones_product: F::one(),
            fixed_eq_t_product: F::one(),
            num_vars: polynomial.num_variables,
            round: 0,
        }
    }

    /// Receive message from verifier, generate prover message, and proceed to next round
    pub fn prove_round(
        prover_state: &mut ProverState<F>,
        v_msg: &Option<VerifierMsg<F>>,
    ) -> ProverMsg<F> {
        if let Some(msg) = v_msg {
            if prover_state.round == 0 {
                panic!("first round should be prover first.");
            }
            
            let r = msg.randomness;
            prover_state.randomness.push(r);

            // Fix variables in all polynomials
            cfg_iter_mut!(prover_state.constraints).for_each(|(_, poly)| {
                *poly = poly.fix_variables(&[r]);
            });
            
            let j = prover_state.round - 1;  // Variable that was just fixed
            
            // Update fixed_g_sum by evaluating the newly fixed variable
            let coeffs = &prover_state.g_polys[j];
            let mut g_j_val = coeffs[0];
            let mut r_pow = r;
            for k in 1..5 {
                g_j_val += coeffs[k] * r_pow;
                r_pow *= r;
            }
            prover_state.fixed_g_sum += g_j_val;
            
            // Update fixed_eq_ones_product
            prover_state.fixed_eq_ones_product *= r;
            
            // Update fixed_eq_t_product
            let tj = prover_state.eq_point_original[j];
            let two = F::from(2u64);
            let eq_t_factor = (F::one() - tj) + r * (two * tj - F::one());
            prover_state.fixed_eq_t_product *= eq_t_factor;
        } else if prover_state.round > 0 {
            panic!("verifier message is empty");
        }

        prover_state.round += 1;

        if prover_state.round > prover_state.num_vars {
            panic!("Prover is not active");
        }

        let i = prover_state.round;
        let nv = prover_state.num_vars;
        
        // Degree is 4
        let degree = 4;

        #[cfg(not(feature = "parallel"))]
        let zeros = vec![F::zero(); degree + 1];
        #[cfg(feature = "parallel")]
        let zeros = || vec![F::zero(); degree + 1];

        let fold_result = ark_std::cfg_into_iter!(0..1 << (nv - i), 1 << 10).fold(
            zeros,
            |mut sum, b| {
                let one = F::one();
                let two = F::from(2u64);
                
                // Precompute eq_t contribution from remaining variables (constant across all x)
                let mut eq_remaining = one;
                for j in 0..(nv - i) {
                    let tj = prover_state.eq_point_original[i + j];
                    let xj = if (b >> j) & 1 == 1 { one } else { F::zero() };
                    eq_remaining *= (one - tj) + xj * (two * tj - one);
                }
                
                // Precompute eq_{1,...,1} contribution from remaining variables (constant across all x)
                let mut eq_ones_remaining = one;
                for j in 0..(nv - i) {
                    let xj = if (b >> j) & 1 == 1 { one } else { F::zero() };
                    eq_ones_remaining *= xj;
                }
                
                // eq_t contribution from current variable (depends on x)
                let ti = prover_state.eq_point_original[i - 1];
                let eq_current_const = one - ti;
                let eq_current_linear = two * ti - one;
                
                // For each constraint cᵢ·Pᵢ(1-Pᵢ)
                for (coefficient, poly) in &prover_state.constraints {
                    let p0 = poly[b << 1];
                    let p1 = poly[(b << 1) + 1];

                    // P(X) = p0 + X(p1 - p0)
                    let delta = p1 - p0;

                    // P(X)(1-P(X)) coefficients: a0 + a1·X + a2·X²
                    let a0 = p0 * (one - p0);
                    let a1 = delta * (one - two * p0);
                    let a2 = -(delta * delta);

                    // Evaluate at X = 0, 1, 2, 3, 4
                    for x in 0..=degree {
                        let x_field = F::from(x as u64);
                        
                        // Binary constraint at X
                        let binary_val = a0 + a1 * x_field + a2 * x_field * x_field;
                        
                        // eq_t contribution
                        // eq_t = fixed_product * [(1-ti) + X(2ti-1)] * eq_remaining
                        let eq_val = prover_state.fixed_eq_t_product 
                                   * (eq_current_const + x_field * eq_current_linear)
                                   * eq_remaining;
                        
                        // eq_{1,...,1} contribution
                        // eq_{1,...,1} = fixed_product * X * eq_ones_remaining
                        let eq_ones_val = prover_state.fixed_eq_ones_product 
                                        * x_field 
                                        * eq_ones_remaining;
                        
                        // Binary constraint term: binary_val * eq_val * (1 - eq_ones_val)
                        let binary_term = binary_val * eq_val * (one - eq_ones_val);
                        
                        sum[x] += *coefficient * binary_term;
                    }
                }
                sum
            },
        );

        #[cfg(not(feature = "parallel"))]
        let mut products_sum = fold_result;

        #[cfg(feature = "parallel")]
        let mut products_sum = fold_result.reduce(
            || vec![F::zero(); degree + 1],
            |mut overall, sublist| {
                overall
                    .iter_mut()
                    .zip(sublist.iter())
                    .for_each(|(f, s)| *f += s);
                overall
            },
        );

        // Add α·g terms
        
        // Contribution from fixed variables (cached, constant term)
        let fixed_contribution = if i > 1 {
            let num_all_remaining = F::from(1u64 << (nv - i));
            prover_state.alpha * prover_state.fixed_g_sum * num_all_remaining
        } else {
            F::zero()
        };

        // Contribution from remaining unfixed variables (constant term)
        let remaining_contribution = if i < nv {
            #[cfg(not(feature = "parallel"))]
            let remaining_g_sum = {
                let mut sum = F::zero();
                for j in i..nv {
                    let coeffs = &prover_state.g_polys[j];
                    let g_j_at_0 = coeffs[0];
                    let g_j_at_1 = coeffs[0] + coeffs[1] + coeffs[2] + coeffs[3] + coeffs[4];
                    sum += g_j_at_0 + g_j_at_1;
                }
                sum
            };
            
            #[cfg(feature = "parallel")]
            let remaining_g_sum = {
                // Only parallelize if there are enough remaining variables
                if nv - i > 16 {
                    (i..nv)
                        .into_par_iter()
                        .map(|j| {
                            let coeffs = &prover_state.g_polys[j];
                            let g_j_at_0 = coeffs[0];
                            let g_j_at_1 = coeffs[0] + coeffs[1] + coeffs[2] + coeffs[3] + coeffs[4];
                            g_j_at_0 + g_j_at_1
                        })
                        .sum()
                } else {
                    let mut sum = F::zero();
                    for j in i..nv {
                        let coeffs = &prover_state.g_polys[j];
                        let g_j_at_0 = coeffs[0];
                        let g_j_at_1 = coeffs[0] + coeffs[1] + coeffs[2] + coeffs[3] + coeffs[4];
                        sum += g_j_at_0 + g_j_at_1;
                    }
                    sum
                }
            };
            
            let num_half_remaining = F::from(1u64 << (nv - i - 1));
            prover_state.alpha * remaining_g_sum * num_half_remaining
        } else {
            F::zero()
        };

        // Add constant contributions
        for x in 0..=degree {
            products_sum[x] += fixed_contribution + remaining_contribution;
        }

        // Contribution from current variable g_{i-1}(X)
        let g_coeffs = &prover_state.g_polys[i - 1];
        let num_current_remaining = F::from(1u64 << (nv - i));
        
        for x in 0..=degree {
            let x_field = F::from(x as u64);
            let mut g_i_val = g_coeffs[0];
            let mut x_pow = x_field;
            for j in 1..5 {
                g_i_val += g_coeffs[j] * x_pow;
                x_pow *= x_field;
            }
            products_sum[x] += prover_state.alpha * num_current_remaining * g_i_val;
        }

        ProverMsg {
            evaluations: products_sum,
        }
    }
}