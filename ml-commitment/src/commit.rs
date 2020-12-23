//! Commit function for the commitment scheme
use crate::data_structures::PublicParameter;
use crate::error::SResult;
use crate::MLPolyCommit;
use ark_ec::msm::VariableBaseMSM;
use ark_ec::{PairingEngine, ProjectiveCurve};
use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Read, SerializationError, Write};
use ark_std::vec::Vec;
use linear_sumcheck::data_structures::ml_extension::MLExtension;
use linear_sumcheck::data_structures::MLExtensionArray;
#[derive(CanonicalSerialize, CanonicalDeserialize, Clone)]
/// commitment
pub struct Commitment<E: PairingEngine> {
    /// number of variables
    pub nv: usize,
    /// product of g as described by the vRAM paper
    pub g_product: E::G1Affine,
}

impl<E: PairingEngine> MLPolyCommit<E> {
    /// commit a multilinear polynomial
    pub fn commit(
        pp: &PublicParameter<E>,
        polynomial: impl Into<MLExtensionArray<E::Fr>>,
    ) -> SResult<Commitment<E>> {
        let polynomial = polynomial.into();
        let nv = polynomial.num_variables()?;
        // let timer = start_timer!(|| "mapping variables into representation");
        let scalars: Vec<_> = polynomial
            .into_table()?
            .into_iter()
            .map(|x| x.into_repr())
            .collect();
        // end_timer!(timer);
        // let g_bases: Vec<_> = E::G1Projective::batch_normalization_into_affine(&pp.powers_of_g[0]);  // do it in setup
        // let timer = start_timer!(|| "MSM");
        let g_product: E::G1Projective =
            VariableBaseMSM::multi_scalar_mul(&pp.powers_of_g[0], scalars.as_slice());
        // end_timer!(timer);

        Ok(Commitment {
            nv,
            g_product: g_product.into_affine(),
        })
    }
}

#[cfg(test)]
mod test {
    use crate::commit::Commitment;
    use crate::data_structures::PublicParameter;
    use crate::error::SResult;
    use crate::test_utils::TestCurve;
    use crate::MLPolyCommit;
    use ark_ec::{AffineCurve, PairingEngine, ProjectiveCurve};
    use ark_std::{test_rng, UniformRand};
    use linear_sumcheck::data_structures::ml_extension::MLExtension;
    use linear_sumcheck::data_structures::MLExtensionArray;

    type E = TestCurve;
    type Fr = <E as PairingEngine>::Fr;

    fn naive_commit(
        pp: &PublicParameter<E>,
        polynomial: MLExtensionArray<Fr>,
        rand_t: &[Fr],
    ) -> SResult<Commitment<E>> {
        let nv = polynomial.num_variables()?;
        let g_product = pp.g.mul(polynomial.eval_at(rand_t)?);
        Ok(Commitment {
            nv,
            g_product: g_product.into_affine(),
        })
    }
    #[test]
    fn commit_test() {
        let mut rng = test_rng();
        let (pp, _, t) = MLPolyCommit::<E>::keygen(4, &mut rng).unwrap();
        let mut rng = test_rng();
        let poly = MLExtensionArray::from_vec((0..(1 << 4)).map(|_| Fr::rand(&mut rng)).collect())
            .unwrap();
        let commit_expected = naive_commit(&pp, poly.clone(), &t).unwrap();
        let commit_actual = MLPolyCommit::commit(&pp, poly.clone()).unwrap();

        assert_eq!(commit_actual.g_product, commit_expected.g_product);
    }
}
