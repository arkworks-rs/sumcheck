//! functions used for opening the polynomial
use crate::data_structures::PublicParameter;
use crate::error::SResult;
use crate::MLPolyCommit;
use ark_ec::msm::VariableBaseMSM;
use ark_ec::{PairingEngine, ProjectiveCurve};
use ark_ff::{One, PrimeField, Zero};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Read, SerializationError, Write};
use ark_std::vec::Vec;
use linear_sumcheck::data_structures::ml_extension::MLExtension;
use linear_sumcheck::data_structures::MLExtensionArray;
#[derive(CanonicalSerialize, CanonicalDeserialize, Clone)]
/// Proof of evaluation of a multilinear polynomial
pub struct Proof<E: PairingEngine> {
    /// generator for G2
    pub h: E::G2Affine,
    /// Evaluation of quotients
    pub proofs: Vec<E::G2Affine>,
}

impl<E: PairingEngine> MLPolyCommit<E> {
    /// evaluate the polynomial and calculate the proof
    /// Return a tuple:
    /// - evaluation result
    /// - proof
    /// - raw quotient (verification does not need this)
    pub fn open(
        pp: &PublicParameter<E>,
        polynomial: MLExtensionArray<E::Fr>,
        point: &[E::Fr],
    ) -> SResult<(E::Fr, Proof<E>, Vec<Vec<E::Fr>>)> {
        // let timer = start_timer!(|| "Polynomial evaluation");
        let eval_result = polynomial.eval_at(point)?;
        // end_timer!(timer);
        let nv = polynomial.num_variables()?;
        let mut r: Vec<Vec<E::Fr>> = (0..nv + 1).map(|_| Vec::new()).collect();
        let mut q: Vec<Vec<E::Fr>> = (0..nv + 1).map(|_| Vec::new()).collect();

        r[nv] = polynomial.into_table()?;

        let mut proofs = Vec::new();
        // let timer = start_timer!(|| "quotient calculation");
        for i in 0..nv {
            let k = nv - i;
            let point_at_k = point[i];
            q[k] = (0..(1 << (k - 1))).map(|_| E::Fr::zero()).collect();
            r[k - 1] = (0..(1 << (k - 1))).map(|_| E::Fr::zero()).collect();
            for b in 0..(1 << (k - 1)) {
                q[k][b] = r[k][(b << 1) + 1] - &r[k][b << 1];
                r[k - 1][b] = r[k][b << 1] * &(E::Fr::one() - &point_at_k)
                    + &(r[k][(b << 1) + 1] * &point_at_k);
            }
            let scalars: Vec<_> = (0..(1 << k))
                .map(|x| q[k][x >> 1].into_repr()) // fine
                .collect();

            let pi_h =
                VariableBaseMSM::multi_scalar_mul(&pp.powers_of_h[i], &scalars).into_affine(); // no need to move outside and partition
            proofs.push(pi_h);
        }
        // end_timer!(timer);

        Ok((eval_result, Proof { h: pp.h, proofs }, q))
    }
}
