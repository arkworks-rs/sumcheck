//! testing utility

use ark_ff::{Field, UniformRand};
use ark_relations::r1cs::{
    ConstraintSynthesizer, ConstraintSystem, ConstraintSystemRef, Matrix, Variable,
};
use hashbrown::HashSet;
use rand::RngCore;

use crate::data_structures::constraints::TestSynthesizer;
use ark_bls12_381::Bls12_381;
use ark_ec::PairingEngine;

/// scalar field used for tests
pub type TestCurve = Bls12_381;
pub type TestCurveFr = <TestCurve as PairingEngine>::Fr;

pub fn random_matrix<R: RngCore>(
    log_size: usize,
    num_non_zero: usize,
    rng: &mut R,
) -> Matrix<TestCurveFr> {
    let bound = 1 << log_size;
    let mut mat: Vec<_> = (0..bound).map(|_| Vec::new()).collect();
    let mut added = HashSet::new();
    for _ in 0..num_non_zero {
        let mut x = (rng.next_u64() & (bound - 1)) as usize;
        let mut y = (rng.next_u64() & (bound - 1)) as usize;
        while added.contains(&(x, y)) {
            x = (rng.next_u64() & (bound - 1)) as usize;
            y = (rng.next_u64() & (bound - 1)) as usize;
        }
        added.insert((x, y));
        mat[x].push((TestCurveFr::rand(rng), y));
    }
    mat
}

pub fn bits_to_field_elements<F: Field>(mut bits: usize, mut num_bits: usize) -> Vec<F> {
    let mut result = Vec::new();
    while num_bits > 0 {
        let bi = bits & 1;
        result.push(if bi == 1 { F::one() } else { F::zero() });
        bits >>= 1;
        num_bits -= 1;
    }

    result
}

pub fn generate_circuit_with_random_input<F: Field, R: RngCore>(
    num_public_variables: usize,
    num_private_variables: usize,
    pad_to_square: bool,
    density: u8,
    rng: &mut R,
) -> (ConstraintSystemRef<F>, Vec<F>, Vec<F>) {
    let synthesizer =
        TestSynthesizer::new(num_private_variables, num_public_variables, density, rng);

    let cs = ConstraintSystem::new_ref();
    cs.set_mode(ark_relations::r1cs::SynthesisMode::Prove {
        construct_matrices: true,
    });

    synthesizer.generate_constraints(cs.clone()).unwrap();
    if pad_to_square {
        make_matrices_square(cs.clone(), num_public_variables + num_private_variables);
    }
    cs.inline_all_lcs();
    let v: Vec<_> = (0..cs.num_instance_variables())
        .map(|x| cs.assigned_value(Variable::Instance(x)).unwrap())
        .collect();
    let w: Vec<_> = (0..cs.num_witness_variables())
        .map(|x| cs.assigned_value(Variable::Witness(x)).unwrap())
        .collect();

    return (cs, v, w);
}

pub(crate) fn make_matrices_square<F: Field>(
    cs: ConstraintSystemRef<F>,
    num_formatted_variables: usize,
) {
    let num_constraints = cs.num_constraints();
    let matrix_padding = ((num_formatted_variables as isize) - (num_constraints as isize)).abs();

    if num_formatted_variables > num_constraints {
        // Add dummy constraints of the form 0 * 0 == 0
        for _ in 0..matrix_padding {
            cs.enforce_constraint(lc!(), lc!(), lc!())
                .expect("enforce 0 * 0 == 0 failed");
        }
    } else {
        // Add dummy unconstrained variables
        for _ in 0..matrix_padding {
            let _ = cs
                .new_witness_variable(|| Ok(F::one()))
                .expect("alloc failed");
        }
    }
}
