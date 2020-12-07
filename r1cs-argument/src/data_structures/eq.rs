use ark_ff::Field;
use linear_sumcheck::data_structures::MLExtensionArray;

/// Generate polynomial P(x) = eq(t,x) represented by products of multilinear polynomials
pub fn eq_extension<F: Field>(t: &[F]) -> Result<Vec<MLExtensionArray<F>>, crate::Error> {
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

#[cfg(test)]
mod test {
    use crate::data_structures::eq::eq_extension;
    use crate::test_utils::bits_to_field_elements;
    use ark_ff::{One, Zero};
    use linear_sumcheck::data_structures::ml_extension::MLExtension;

    #[test]
    fn functionality_test() {
        type F = crate::test_utils::TestCurveFr;
        let t = 0b101101001;
        let t_vec: Vec<F> = bits_to_field_elements(t, 9);
        let eq_ext = eq_extension(&t_vec).unwrap();
        for x in 0..(1 << 9) {
            let mut eval_result = F::one();
            for mle in eq_ext.iter() {
                eval_result *= mle.eval_binary(x).unwrap();
            }
            if x == t {
                assert_eq!(eval_result, F::one());
            } else {
                assert_eq!(eval_result, F::zero());
            }
        }
    }
}
