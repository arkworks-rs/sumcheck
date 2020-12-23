//! Setup for the commitment scheme
use crate::data_structures::{PublicParameter, VerifierParameter};
use crate::error::{invalid_arg, SResult};
use crate::MLPolyCommit;
use ark_ec::msm::FixedBaseMSM;
use ark_ec::{AffineCurve, PairingEngine, ProjectiveCurve};
use ark_ff::{Field, PrimeField, UniformRand};
use ark_std::collections::LinkedList;
use ark_std::iter::FromIterator;
use ark_std::vec::Vec;
use linear_sumcheck::data_structures::ml_extension::MLExtension;
use linear_sumcheck::data_structures::MLExtensionArray;
use rand::RngCore;
// convert f(0, x1, x2, ...) to f(x1, x2, ...)
fn remove_dummy_variable<F: Field>(poly: &[F], pad: usize) -> SResult<Vec<F>> {
    if pad == 0 {
        return Ok(poly.to_vec());
    }
    if !poly.len().is_power_of_two() {
        return Err(invalid_arg("invalid polynomial"));
    }
    let nv = ark_std::log2(poly.len()) as usize - pad;
    let table: Vec<_> = (0..(1 << nv)).map(|x| poly[x << pad]).collect();
    Ok(table)
}
pub(crate) fn eq_extension<F: Field>(t: &[F]) -> Result<Vec<MLExtensionArray<F>>, crate::Error> {
    let dim = t.len();
    let mut result = Vec::new();
    for i in 0..dim {
        let mut poly = Vec::with_capacity(1 << dim);
        for x in 0..(1 << dim) {
            let xi = if x >> i & 1 == 1 { F::one() } else { F::zero() };
            let ti = t[i];
            let ti_xi = ti * xi;
            poly.push(ti_xi + ti_xi - xi - ti + F::one());
        }
        result.push(MLExtensionArray::from_vec(poly)?);
    }

    Ok(result)
}
impl<E: PairingEngine> MLPolyCommit<E> {
    /// Generate random parameters
    /// * `nv`: number of variables
    ///
    /// Returns a tuple:
    /// - public parameter
    /// - verifier parameter
    /// - randomness used when generating those parameters: this randomness should be destroyed and should not be revealed
    pub fn keygen<R: RngCore>(
        nv: usize,
        rng: &mut R,
    ) -> SResult<(PublicParameter<E>, VerifierParameter<E>, Vec<E::Fr>)> {
        let g: E::G1Projective = E::G1Projective::rand(rng);
        let h: E::G2Projective = E::G2Projective::rand(rng);
        let g = g.into_affine();
        let h = h.into_affine();
        let mut powers_of_g = Vec::new();
        let mut powers_of_h = Vec::new();
        let t: Vec<_> = (0..nv).map(|_| E::Fr::rand(rng)).collect();
        let scalar_bits = E::Fr::size_in_bits();

        let mut eq = LinkedList::from_iter(eq_extension(&t)?.into_iter());
        let mut eq_arr = LinkedList::new();
        let mut base = eq.pop_back().unwrap().into_table()?;
        // let eq_ext_timer = start_timer!(|| "eq_extension");
        for i in (0..nv).rev() {
            eq_arr.push_front(remove_dummy_variable(&base, i)?);
            if i != 0 {
                let mul = eq.pop_back().unwrap().into_table()?;
                base = base
                    .into_iter()
                    .zip(mul.into_iter())
                    .map(|(a, b)| a * &b)
                    .collect();
            }
        }
        // end_timer!(eq_ext_timer);
        // let variable_mul_timer = start_timer!(|| "variable multiplication");

        let mut pp_powers = Vec::new();
        let mut total_scalars = 0;
        for i in 0..nv {
            let eq = eq_arr.pop_front().unwrap();
            let pp_k_powers = (0..(1 << (nv - i))).map(|x| eq[x]);
            pp_powers.extend(pp_k_powers);
            total_scalars += 1 << (nv - i);
        }
        let window_size = FixedBaseMSM::get_mul_window_size(total_scalars);
        let g_table = FixedBaseMSM::get_window_table(scalar_bits, window_size, g.into_projective());
        let h_table = FixedBaseMSM::get_window_table(scalar_bits, window_size, h.into_projective());

        let pp_g = E::G1Projective::batch_normalization_into_affine(
            &FixedBaseMSM::multi_scalar_mul(scalar_bits, window_size, &g_table, &pp_powers),
        );
        let pp_h = E::G2Projective::batch_normalization_into_affine(
            &FixedBaseMSM::multi_scalar_mul(scalar_bits, window_size, &h_table, &pp_powers),
        );
        let mut start = 0;
        for i in 0..nv {
            let size = 1 << (nv - i);
            let pp_k_g = (&pp_g[start..(start + size)]).to_vec();
            let pp_k_h = (&pp_h[start..(start + size)]).to_vec();
            powers_of_g.push(pp_k_g);
            powers_of_h.push(pp_k_h);
            start += size;
        }

        // end_timer!(variable_mul_timer);
        let pp = PublicParameter {
            nv,
            g,
            h,
            powers_of_g,
            powers_of_h,
        };
        // calculate vp
        // let vp_generation_timer = start_timer!(|| "VP generation");
        let vp = {
            let window_size = FixedBaseMSM::get_mul_window_size(nv);
            let g_table =
                FixedBaseMSM::get_window_table(scalar_bits, window_size, g.into_projective());
            let g_mask = E::G1Projective::batch_normalization_into_affine(
                &FixedBaseMSM::multi_scalar_mul(scalar_bits, window_size, &g_table, &t),
            );
            VerifierParameter {
                nv,
                g,
                h,
                g_mask_random: g_mask,
            }
        };
        // end_timer!(vp_generation_timer);

        Ok((pp, vp, t))
    }
}

#[cfg(test)]
mod tests {
    use crate::data_structures::{
        EvaluationHyperCubeOnG1, EvaluationHyperCubeOnG2, PublicParameter,
    };
    use crate::error::SResult;
    use crate::setup::eq_extension;
    use crate::test_utils::TestCurve;
    use crate::MLPolyCommit;
    use ark_ec::{AffineCurve, PairingEngine, ProjectiveCurve};
    use ark_ff::fields::PrimeField;
    use ark_std::{test_rng, UniformRand};
    use linear_sumcheck::data_structures::ml_extension::ArithmeticCombination;
    use rand::RngCore;
    fn dummy_keygen<R: RngCore, E: PairingEngine>(
        nv: usize,
        rng: &mut R,
    ) -> SResult<PublicParameter<E>> {
        let g: E::G1Projective = E::G1Projective::rand(rng);
        let h: E::G2Projective = E::G2Projective::rand(rng);
        let mut powers_of_g = Vec::new();
        let mut powers_of_h = Vec::new();
        let t: Vec<_> = (0..nv).map(|_| E::Fr::rand(rng)).collect();
        for i in 0..nv {
            let ext = eq_extension(&t[i..nv])?;
            let mut comb = ArithmeticCombination::new(nv - i);
            comb.add_product(ext.into_iter())?;
            let pp_k_g: Vec<_> = (0..(1 << (nv - i)))
                .map(|x| g.mul(comb.eval_binary_at(x).unwrap().into_repr()))
                .collect();
            let pp_k_g: EvaluationHyperCubeOnG1<E> =
                E::G1Projective::batch_normalization_into_affine(&pp_k_g);
            let pp_k_h: Vec<_> = (0..(1 << (nv - i)))
                .map(|x| h.mul(comb.eval_binary_at(x).unwrap().into_repr()))
                .collect();
            let pp_k_h: EvaluationHyperCubeOnG2<E> =
                E::G2Projective::batch_normalization_into_affine(&pp_k_h);
            powers_of_g.push(pp_k_g);
            powers_of_h.push(pp_k_h);
        }
        Ok(PublicParameter {
            nv,
            g: g.into_affine(),
            h: h.into_affine(),
            powers_of_g,
            powers_of_h,
        })
    }

    #[test]
    fn setup_test() {
        let mut rng1 = test_rng();
        let mut rng2 = test_rng();
        type E = TestCurve;
        let (pp_actual, _, _) = MLPolyCommit::<E>::keygen(5, &mut rng1).unwrap();
        let pp_expected = dummy_keygen::<_, E>(5, &mut rng2).unwrap();

        assert!(pp_actual.h == pp_expected.h.into_projective());
        assert!(pp_actual.powers_of_h.eq(&pp_expected.powers_of_h));
    }
}
