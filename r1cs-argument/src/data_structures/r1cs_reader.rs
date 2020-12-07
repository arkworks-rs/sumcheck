//! reader interpreting r1cs matrix as dense MLExtension

use ark_ff::Field;
use ark_relations::r1cs::Matrix;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Read, SerializationError, Write};
use linear_sumcheck::data_structures::ml_extension::{MLExtension, SparseMLExtension};
use linear_sumcheck::data_structures::{MLExtensionArray, SparseMLExtensionMap};
#[derive(Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct MatrixExtension<F: Field> {
    constraint: Matrix<F>,
    /// number of constraints
    pub num_constraints: usize,
}

/// given a 2D location (x,y) in the matrix,
/// return the 1d location in the multilinear extension array
/// Thus Matrix[x,y] is mapped to extended polynomial P(xy_combine(x,y))
/// * x: location x
/// * y: location y
/// * s: number of bits used to represent x and y (should be log(num_constraints))
#[inline]
fn xy_combine(x: usize, y: usize, s: usize) -> usize {
    (y << s) + x
}

#[inline]
#[allow(dead_code)]
fn xy_decompose(xy: usize, s: usize) -> (usize, usize) {
    let x = xy & ((1 << s) - 1);
    let y = xy >> s;
    (x, y)
}

impl<F: Field> MatrixExtension<F> {
    /// setup the MLExtension. The provided matrix should be square.
    pub fn new(matrix: Matrix<F>, num_constraints: usize) -> Result<Self, crate::Error> {
        // sanity check
        if !num_constraints.is_power_of_two() {
            // for now, we assume number constraints are power of two.
            // we can release the constraint by adding padding later.
            return Err(crate::Error::InvalidArgument(Some(
                "num of constraints should be power of two".into(),
            )));
        }

        // the length of matrix should be num_constraints
        if matrix.len() != num_constraints {
            return Err(crate::Error::InvalidArgument(Some(
                "matrix size is inconsistent with number of constraints".into(),
            )));
        }

        let idx_bound = num_constraints;
        // each term should within num_constraints
        for line in matrix.iter() {
            for &(_, idx) in line {
                if idx >= idx_bound {
                    return Err(crate::Error::InvalidArgument(Some(
                        "sparse index out of bound".into(),
                    )));
                }
            }
        }

        let s = Self {
            constraint: matrix,
            num_constraints,
        };
        Ok(s)
    }

    /// Convert the matrix A(x,y) to sum over y A(x,y)Z(y), given z
    ///
    /// return: multilinear extension sum over y A(x,y)Z(y) with `num_constraints` variables
    pub fn sum_over_y(&self, z: &MLExtensionArray<F>) -> Result<MLExtensionArray<F>, crate::Error> {
        if z.num_variables()? != ark_std::log2(self.num_constraints) as usize {
            return Err(crate::Error::InvalidArgument(Some("invalid z".into())));
        }
        let temp: Vec<F> = self
            .constraint
            .iter()
            .map(|v| v.iter().map(|(a, y)| *a * z.eval_binary(*y).unwrap()).sum())
            .collect();
        Ok(MLExtensionArray::from_slice(&temp)?)
    }

    //noinspection RsBorrowChecker
    /// Given A(x,y) and randomness r_x
    ///
    /// return: multilinear extension A(r_x,y) with `num_constraints` variables
    pub fn eval_on_x(&self, r_x: &[F]) -> Result<MLExtensionArray<F>, crate::Error> {
        if (1 << r_x.len()) != self.num_constraints {
            return Err(crate::Error::InvalidArgument(Some(
                "2^(r_x) should have size: num_constraints".into(),
            )));
        }

        // create a sparse map
        let s = ark_std::log2(self.num_constraints) as usize;
        let mut map = Vec::new();
        for (x, arr) in self.constraint.iter().enumerate() {
            for (value, y) in arr.iter() {
                map.push((xy_combine(x, *y, s), *value));
            }
        }

        let sparse_mle = SparseMLExtensionMap::from_slice(&map, s * 2)?;
        let partially_evaluated_sparse = sparse_mle.eval_partial_at(r_x)?;

        // convert this to array
        let mut ans = Vec::with_capacity(1 << s);
        ans.resize(1 << s, F::zero());
        for (y, val) in partially_evaluated_sparse.sparse_table()? {
            ans[y] = val;
        }
        Ok(MLExtensionArray::from_vec(ans)?)
    }
}

#[cfg(test)]
mod test {
    use crate::data_structures::r1cs_reader::MatrixExtension;
    use crate::test_utils::{random_matrix, TestCurveFr};
    use ark_ff::{test_rng, One, Zero};
    use linear_sumcheck::data_structures::ml_extension::MLExtension;

    #[test]
    fn test_eval_on_x_sanity() {
        let mut rng = test_rng();
        let matrix = random_matrix(6, 1 << 9, &mut rng);
        let expected_evaluations = &matrix[0b110010];
        let mat_ext = MatrixExtension::new(matrix.clone(), 1 << 6).unwrap();
        let eval_point = vec![
            TestCurveFr::zero(),
            TestCurveFr::one(),
            TestCurveFr::zero(),
            TestCurveFr::zero(),
            TestCurveFr::one(),
            TestCurveFr::one(),
        ];
        let actual_evaluations = mat_ext.eval_on_x(&eval_point).unwrap();
        for (val, idx) in expected_evaluations {
            assert_eq!(actual_evaluations.eval_binary(*idx).unwrap(), *val);
        }
    }
}
