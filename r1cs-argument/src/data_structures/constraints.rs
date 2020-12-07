use ark_ff::Field;
use ark_relations::r1cs::{
    ConstraintSynthesizer, ConstraintSystemRef, LinearCombination, SynthesisError, Variable,
};
use ark_std::marker::PhantomData;
use rand::{Rng, RngCore};

pub struct TestSynthesizer<'a, R: RngCore, F: Field> {
    num_private_variables: usize,
    num_public_variables: usize,
    rng: &'a mut R,
    density: u8,
    _marker: PhantomData<F>,
}

impl<'a, R: RngCore, F: Field> TestSynthesizer<'a, R, F> {
    pub fn new(
        num_private_variables: usize,
        num_public_variables: usize,
        density: u8,
        rng: &'a mut R,
    ) -> Self {
        if num_public_variables <= 3 {
            panic!("number of public variables should be greater to 3");
        }
        Self {
            num_private_variables,
            num_public_variables,
            rng,
            density,
            _marker: PhantomData,
        }
    }
}

impl<'a, R: RngCore, F: Field> ConstraintSynthesizer<F> for TestSynthesizer<'a, R, F> {
    /// code copied from
    /// [groth16 repo](https://github.com/scipr-lab/zexe/blob/master/groth16/examples/snark-scalability/constraints.rs)
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        let mut assignments = Vec::new();
        let mut a_val = F::rand(self.rng);
        let mut a_var = cs.new_input_variable(|| Ok(a_val))?;
        assignments.push((a_val, a_var));

        let mut b_val = F::rand(self.rng);
        let mut b_var = cs.new_input_variable(|| Ok(b_val))?;
        assignments.push((a_val, a_var));

        // add addition public variables
        for _ in 0..self.num_public_variables - 3 {
            let val = F::rand(self.rng);
            let var = cs.new_input_variable(|| Ok(val))?;
            assignments.push((val, var));
        }

        let num_sparse_constraints =
            (self.num_private_variables - 1) * (510 - self.density as usize) / 510;

        for i in 0..num_sparse_constraints {
            let offset_var_index = self.rng.gen_range(2, self.num_public_variables - 1);
            let (offset_val, offset_var) = assignments[offset_var_index];

            if i % 2 != 0 {
                let c_val = a_val * (b_val + offset_val);
                let c_var = cs.new_witness_variable(|| Ok(c_val))?;

                cs.enforce_constraint(lc!() + a_var, lc!() + b_var + offset_var, lc!() + c_var)?;

                assignments.push((c_val, c_var));
                a_val = b_val;
                a_var = b_var;
                b_val = c_val;
                b_var = c_var;
            } else {
                let c_val = a_val + &b_val + offset_val;
                let c_var = cs.new_witness_variable(|| Ok(c_val))?;

                cs.enforce_constraint(
                    lc!() + a_var + b_var + offset_var,
                    lc!() + Variable::One,
                    lc!() + c_var,
                )?;

                assignments.push((c_val, c_var));
                a_val = b_val;
                a_var = b_var;
                b_val = c_val;
                b_var = c_var;
            }
        }

        for _ in num_sparse_constraints..self.num_private_variables {
            let mut a_lc = LinearCombination::zero();
            let mut b_lc = LinearCombination::zero();
            let mut c_val = F::zero();

            for &(val, var) in &assignments {
                a_lc = a_lc + var;
                b_lc = b_lc + var;
                c_val = c_val + &val;
            }
            c_val = c_val.square();

            let c_var = cs.new_witness_variable(|| Ok(c_val))?;

            cs.enforce_constraint(lc!() + a_lc, lc!() + b_lc, lc!() + c_var)?;
        }

        Ok(())
    }
}
