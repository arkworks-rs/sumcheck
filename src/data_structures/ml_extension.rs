#![macro_use]

use algebra_core::alloc::fmt::Display;
/// multilinear extensions
use algebra_core::Field;
use algebra_core::vec::Vec;
use crate::error::Error;

/// Multilinear Extension
///
/// A data-structure representing a polynomial that is a multi-linear extension of an array.
pub trait MLExtension<F>: Sized
where
    F: Field,
{
    /// <b>Point in Binary Form</b>
    ///
    /// This type represents a number viewed as a little endian
    /// binary string viewed as a point in {0,1}^L.
    ///
    /// ### Example
    /// `0b1011` represents `P(1,1,0,1)`
    type BinaryArg: From<usize> + Into<usize> + Copy;

    /// Error Type
    type Error: algebra_core::Error + From<Error> + Display;

    /// Number of variables (L)
    ///
    /// This function returns the total number of variables in this polynomial. The number of
    /// variables is log2(size of array).
    fn num_variables(&self) -> Result<usize, Self::Error>;

    /// Evaluate the polynomial given point in length-L binary string
    ///
    /// This function takes a binary point and evaluate the polynomial at that point.
    /// This is equivalent to accessing an element in the array by index.
    /// Learn more about how the binary argument work in the doc of [MLExtensionArray](../struct.MLExtensionArray.html#method.from_slice)
    fn eval_binary(&self, point: Self::BinaryArg) -> Result<F, Self::Error>;

    /// Evaluate the polynomial at a point in Field
    fn eval_at(&self, point: &[F]) -> Result<F, Self::Error>;

    /// Get the copy of the values of all evaluations. Index: binary argument, value: F
    fn table(&self) -> Result<Vec<F>, Self::Error>;
}

/// Sparse Multilinear Extension
pub trait SparseMLExtension<F>: MLExtension<F>
where
    F: Field,
{
    /// get the copy of the values of all evaluations that are not zero along with the index.
    /// * return: index as binary arg, value
    fn sparse_table(&self) -> Result<Vec<(Self::BinaryArg, F)>, Self::Error>;
}

/// Represents the GKR Function as described in [[XZZPS19]](https://eprint.iacr.org/2019/317.pdf#page=15).
///
/// `GKR(g, x, y) = f1(g, x, y)*f2(x)*f3(y)`
pub trait GKRFunction<F, S, D>: Sized
where
    F: Field,
    S: SparseMLExtension<F>,
    D: MLExtension<F>,
{
    /// Error Type
    type Error: algebra_core::Error + From<Error> + Display;

    /// Get f1
    fn get_f1(&self) -> &S;

    /// Get f2
    fn get_f2(&self) -> &D;

    /// Get f3
    fn get_f3(&self) -> &D;

    /// # L for the GKR function (dimension of g, x, y)
    /// GKR Function has total of 3L variables.
    fn get_l(&self) -> Result<usize, Self::Error>;
}

#[cfg(test)]
pub mod tests {
    use algebra::{test_rng, Field};
    use algebra_core::vec::Vec;
    use crate::data_structures::ml_extension::{MLExtension, SparseMLExtension};

    /// utility: evaluate multilinear extension (in form of data array) at a random point in Field
    fn evaluate_data_array<F: Field>(data: &[F], point: &[F]) -> F {
        if data.len() != (1 << point.len()) {
            panic!("Data size mismatch with number of variables. ")
        }

        let nv = point.len();
        let mut a = data.to_vec();

        for i in 1..nv + 1 {
            let r = point[i - 1];
            for b in 0..(1 << (nv - i)) {
                a[b] = a[b << 1] * (F::one() - r) + a[(b << 1) + 1] * r;
            }
        }
        a[0]
    }

    /// Test if the multilinear extension works as desired.
    /// * `poly`: The polynomial to be tested.
    /// * `bookkeeping_table`: Values evaluated on {0,1}^n. Expect to be the same as `poly.table()`.
    pub fn test_basic_extension_methods<F, P>(poly: &P, bookkeeping_table: &[F])
    where
        F: Field,
        P: MLExtension<F>,
    {
        let data = bookkeeping_table;
        assert_eq!(
            (1 << poly.num_variables().unwrap()),
            bookkeeping_table.len()
        );

        // eval_binary correctness
        let _: Vec<_> = poly
            .table()
            .unwrap()
            .iter()
            .enumerate()
            .map(|(i, v)| {
                assert_eq!(poly.eval_binary(P::BinaryArg::from(i)).unwrap(), *v);
                assert_eq!(data[i], *v)
            })
            .collect();

        // eval_at correctness
        let mut rng = test_rng();
        for _ in 0..100 {
            let point = fill_vec!(poly.num_variables().unwrap(), F::rand(&mut rng));
            assert_eq!(
                poly.eval_at(&point).unwrap(),
                evaluate_data_array(data, &point)
            );
        }
    }

    /// Test if the sparse multilinear extension works as desired.
    /// * `poly`: the sparse MLExtension to be tested (should be random).
    /// * `bookkeeping_table`: sparse bookkeeping table.
    pub fn test_sparse_extension_methods<F, P>(poly: &P, bookkeeping_table: &[F])
    where
        F: Field,
        P: SparseMLExtension<F>,
    {
        let data = bookkeeping_table;
        let mut count = 0;
        for v in bookkeeping_table {
            if *v != F::zero() {
                count += 1;
            }
        }

        for (arg, v) in poly.sparse_table().unwrap() {
            count -= 1;
            assert_eq!(poly.eval_binary(arg).unwrap(), v);
            let arg: usize = arg.into();
            assert_eq!(data[arg], v);
        }

        assert_eq!(count, 0, "Sparse Table may not include all items. ")
    }
}
