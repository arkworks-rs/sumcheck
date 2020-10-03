use core::marker::PhantomData;

use algebra_core::log2;
use algebra_core::Field;
use ark_std::string::String;
use ark_std::vec::Vec;
use hashbrown::HashMap;

use crate::data_structures::ml_extension::{GKRFunction, MLExtension, SparseMLExtension};

type SparseMap<F> = HashMap<usize, F>; // now: unified map

/// This GKR is simply a reference to address of underlying MLExtensions.
pub struct GKRAsLink<'a, F, S, D>
where
    F: Field,
    S: SparseMLExtension<F>,
    D: MLExtension<F>,
{
    f1: &'a S,
    f2: &'a D,
    f3: &'a D,
    phantom: PhantomData<F>,
}

impl<'a, F, S, D> GKRAsLink<'a, F, S, D>
where
    F: Field,
    S: SparseMLExtension<F>,
    D: MLExtension<F>,
{
    /// create a new GKR that references f1, f2, f3
    pub fn new(f1: &'a S, f2: &'a D, f3: &'a D) -> Result<Self, crate::Error> {
        let nv1 = unwrap_safe!(f1.num_variables());
        let nv2 = unwrap_safe!(f2.num_variables());
        let nv3 = unwrap_safe!(f3.num_variables());
        if nv2 != nv3 || nv1 != 3 * nv2 || nv1 != 3 * nv3 {
            return Err(crate::Error::InvalidArgumentError(Some(
                algebra_core::format!("Numbers of variables mismatch. {}, {}, {}", nv1, nv2, nv3),
            )));
        }
        Ok(GKRAsLink {
            f1,
            f2,
            f3,
            phantom: PhantomData,
        })
    }
}

impl<'a, F, S, D> GKRFunction<F, S, D> for GKRAsLink<'a, F, S, D>
where
    F: Field,
    S: SparseMLExtension<F>,
    D: MLExtension<F>,
{
    type Error = crate::Error;

    fn get_f1(&self) -> &S {
        self.f1
    }

    fn get_f2(&self) -> &D {
        self.f2
    }

    fn get_f3(&self) -> &D {
        self.f3
    }

    fn get_l(&self) -> Result<usize, Self::Error> {
        Ok(unwrap_safe!(self.f2.num_variables()))
    }
}

/// An implementation of multilinear extension, storing the data of underlying array.
pub struct MLExtensionArray<F: Field> {
    store: Vec<F>,
    num_variables: usize,
}

/// Evaluate a multilinear extension.
/// * `poly`: array form of multilinear extension. The index of the array is the little endian
/// binary form of the point on domain hypercube, and the entry is the evaluation at that point.
/// * `nv`: number of variables
/// * `at`: the point we want to evaluate
fn eval_dense<F: Field>(poly: &[F], nv: usize, at: &[F]) -> Result<F, crate::Error> {
    Ok(partial_eval_dense(poly, nv, at)?[0])
}

fn partial_eval_dense<F: Field>(poly: &[F], nv: usize, at: &[F]) -> Result<Vec<F>, crate::Error> {
    if at.len() > nv {
        return Err(crate::Error::InvalidArgumentError(Some(
            "dimension of point is greater than nv".into(),
        )));
    }
    let mut a = poly.to_vec();
    let dim = at.len();
    for i in 1..dim + 1 {
        let r = at[i - 1];
        for b in 0usize..(1 << (nv - i)) {
            a[b] = a[b << 1] * (F::one() - r) + a[(b << 1) + 1] * r
        }
    }

    Ok((&a[0..(1 << (nv - dim))]).to_vec())
}

impl<F: Field> MLExtensionArray<F> {
    /// Generate the MLExtension from slice in array form. Copy all the data into the MLExtension.
    /// This constructor takes O(n) time.
    ///
    /// For example, suppose we have a polynomial P of 4 variables. If P(1,1,0,1)=7, then in
    /// array form P[`0b1011`]=7 (i.e. P[11]=7)
    ///
    /// ```
    /// # use algebra::{UniformRand, Field, One, Zero, test_rng};
    /// # use linear_sumcheck::data_structures::MLExtensionArray;
    /// # use linear_sumcheck::data_structures::ml_extension::MLExtension;
    /// # type F = algebra::bls12_377::Fr;
    /// // create a degree-4 polynomial.
    /// # let mut rng = test_rng();
    /// let poly: Vec<_> = (0..(1<<4)).map(|_|F::rand(&mut rng)).collect();
    /// let mle = MLExtensionArray::from_slice(&poly).unwrap();
    /// assert_eq!(*(poly.get(0b1011).unwrap()), mle.eval_at(&vec![F::one(),F::one(),F::zero(),F::one()]).unwrap())
    /// ```
    pub fn from_slice(data: &[F]) -> Result<Self, crate::Error> {
        Self::from_vec(data.to_vec())
    }

    /// Generate the MLExtension from vector in array form. Obtain the ownership of the vector without
    /// copying the data. This constructor takes O(1) time.
    ///
    /// ```
    /// # use algebra::{UniformRand, Field, One, Zero, test_rng};
    /// # use linear_sumcheck::data_structures::MLExtensionArray;
    /// # use linear_sumcheck::data_structures::ml_extension::MLExtension;
    /// # type F = algebra::bls12_377::Fr;
    /// // create a degree-4 polynomial.
    /// # let mut rng = test_rng();
    /// let poly: Vec<_> = (0..(1<<4)).map(|_|F::rand(&mut rng)).collect();
    /// let poly_copy = poly.to_vec();
    /// let mle = MLExtensionArray::from_vec(poly).unwrap();  // this step require ownership of poly
    /// assert_eq!(*(poly_copy.get(0b1011).unwrap()), mle.eval_at(&vec![F::one(),F::one(),F::zero(),F::one()]).unwrap())
    /// ```
    pub fn from_vec(data: Vec<F>) -> Result<Self, crate::Error> {
        let len = data.len();
        if !len.is_power_of_two() {
            return Err(crate::Error::InvalidArgumentError(Some(String::from(
                "Data should have size of power of 2. ",
            ))));
        }
        let num_variables = log2(len) as usize;
        Ok(Self {
            num_variables,
            store: data,
        })
    }
}

impl<F: Field> MLExtension<F> for MLExtensionArray<F> {
    type BinaryArg = usize;
    type Error = crate::Error;

    fn num_variables(&self) -> Result<usize, Self::Error> {
        Ok(self.num_variables)
    }

    fn eval_binary(&self, point: Self::BinaryArg) -> Result<F, Self::Error> {
        self.store
            .get(point)
            .ok_or(Self::Error::InternalDataStructureCorruption(Some(
                "Unable to get element from array".into(),
            )))
            .map(|v| *v)
    }

    /// Evaluate a point of the polynomial in field. This method will take linear time and linear space to the size of
    /// underlying array.
    fn eval_at(&self, point: &[F]) -> Result<F, Self::Error> {
        eval_dense(&self.store, self.num_variables, point)
    }

    fn eval_partial_at(&self, point: &[F]) -> Result<Self, Self::Error> {
        Ok(Self::from_vec(partial_eval_dense(
            &self.store,
            self.num_variables,
            point,
        )?)?)
    }

    fn table(&self) -> Result<Vec<F>, Self::Error> {
        Ok(self.store.to_vec())
    }
}

/// MLExtension with data referenced from outer source
pub struct MLExtensionRefArray<'a, F: Field> {
    store: &'a [F],
    num_variables: usize,
}

impl<'a, F: Field> MLExtensionRefArray<'a, F> {
    /// Generate the MLExtension from slice. Copy all the data into the MLExtension.
    ///
    /// Go to [MLExtensionArray](struct.MLExtensionArray.html#method.from_slice) to learn more about
    /// how the polynomial is represented.
    pub fn from_slice(data: &'a [F]) -> Result<Self, crate::Error> {
        let len = data.len();
        if !len.is_power_of_two() {
            return Err(crate::Error::InvalidArgumentError(Some(String::from(
                "Data should have size of power of 2. ",
            ))));
        }
        let num_variables = log2(len) as usize;
        Ok(Self {
            num_variables,
            store: data,
        })
    }
}

impl<'a, F: Field> MLExtension<F> for MLExtensionRefArray<'a, F> {
    type BinaryArg = usize;
    type Error = crate::Error;

    fn num_variables(&self) -> Result<usize, Self::Error> {
        Ok(self.num_variables)
    }

    fn eval_binary(&self, point: Self::BinaryArg) -> Result<F, Self::Error> {
        self.store
            .get(point)
            .ok_or(Self::Error::InternalDataStructureCorruption(Some(
                "Unable to get element from array".into(),
            )))
            .map(|v| *v)
    }

    fn eval_at(&self, point: &[F]) -> Result<F, Self::Error> {
        eval_dense(self.store, self.num_variables, point)
    }

    fn eval_partial_at(&self, _point: &[F]) -> Result<Self, Self::Error> {
        unimplemented!("Use MLExtensionArray instead")
    }

    fn table(&self) -> Result<Vec<F>, Self::Error> {
        Ok(self.store.to_vec())
    }
}

/// Sparse multilinear extension implementation
pub struct SparseMLExtensionMap<F: Field> {
    store: SparseMap<F>,
    num_variables: usize,
}

impl<F: Field> SparseMLExtensionMap<F> {
    /// construct a sparse multilinear extension from slice
    /// * `data`: Slice of tuple (binary arg, value)
    /// * `num_variables`: Number of variables
    /// Any duplicate arg will cause an error.
    pub fn from_slice(data: &[(usize, F)], num_variables: usize) -> Result<Self, crate::Error> {
        let mut store = SparseMap::new();
        for (arg, v) in data {
            if *arg >= (1 << num_variables) {
                return Err(crate::Error::InvalidArgumentError(Some(
                    algebra_core::format!("Binary Argument {} is too large.", arg),
                )));
            }
            if let Some(pv) = store.insert(*arg, *v) {
                return Err(crate::Error::InvalidArgumentError(Some(
                    algebra_core::format!(
                        "Duplicate argument ({}, {}) and ({}, {})",
                        arg,
                        pv,
                        arg,
                        v
                    ),
                )));
            }
        }
        Ok(Self {
            store,
            num_variables,
        })
    }

    fn _partial_eval(&self, point: &[F]) -> Result<HashMap<usize, F>, crate::Error> {
        let nv = self.num_variables;
        if nv < point.len() {
            return Err(crate::Error::InvalidArgumentError(Some(
                "dimension of point is greater than nv".into(),
            )));
        }
        let dim = point.len();
        let mut dp0 = self.store.clone();
        let mut dp1 = SparseMap::new();
        for i in 0..dim {
            let r = point[i];
            for (k, v) in dp0.iter() {
                let entry = dp1.entry(*k >> 1).or_insert(F::zero());
                if k & 1 == 0 {
                    *entry += *v * (F::one() - r);
                } else {
                    *entry += *v * r;
                }
            }
            dp0 = dp1;
            dp1 = SparseMap::new();
        }

        Ok(dp0)
    }
}

impl<F: Field> SparseMLExtension<F> for SparseMLExtensionMap<F> {
    fn sparse_table(&self) -> Result<Vec<(Self::BinaryArg, F)>, Self::Error> {
        Ok(self.store.iter().map(|(arg, val)| (*arg, *val)).collect())
    }
}

impl<F: Field> MLExtension<F> for SparseMLExtensionMap<F> {
    type BinaryArg = usize;
    type Error = crate::Error;

    fn num_variables(&self) -> Result<usize, Self::Error> {
        Ok(self.num_variables)
    }

    fn eval_binary(&self, point: Self::BinaryArg) -> Result<F, Self::Error> {
        if let Some(v) = self.store.get(&point) {
            Ok(*v)
        } else {
            Ok(F::zero())
        }
    }

    /// runtime: O(n*log(n))
    fn eval_at(&self, point: &[F]) -> Result<F, Self::Error> {
        let mut dp = self._partial_eval(point)?;

        Ok(*(dp.entry(0usize).or_insert(F::zero())))
    }

    fn eval_partial_at(&self, point: &[F]) -> Result<Self, Self::Error> {
        let partial_map = self._partial_eval(point)?;
        Ok(Self {
            store: partial_map,
            num_variables: self.num_variables - point.len(),
        })
    }

    fn table(&self) -> Result<Vec<F>, Self::Error> {
        let mut table = Vec::with_capacity(1 << self.num_variables);
        for _ in 0..(1 << self.num_variables) {
            table.push(F::zero());
        }
        for (arg, v) in self.store.iter() {
            let result = table
                .get_mut(*arg)
                .ok_or(Self::Error::InternalDataStructureCorruption(None));
            *(unwrap_safe!(result)) = *v;
        }

        Ok(table)
    }
}

#[cfg(test)]
pub mod tests {
    use algebra::{test_rng, Field, UniformRand};
    use ark_std::collections::BTreeMap;
    use ark_std::vec::Vec;
    use rand::Rng;
    use rand_core::RngCore;

    use crate::data_structures::impl_ml_extension::{
        MLExtensionArray, MLExtensionRefArray, SparseMLExtensionMap,
    };
    use crate::data_structures::ml_extension::tests::{
        test_basic_extension_methods, test_sparse_extension_methods,
    };
    use crate::data_structures::test_field::TestField;

    pub type SparseMap<F> = BTreeMap<usize, F>;

    #[test]
    /// Test multilinear extension works.
    fn test_dense_ml_functionality() {
        const NUM_ITER: i32 = 10;
        const NUM_VARS: usize = 8;
        let mut rng = test_rng();
        type F = TestField;
        for _ in 0..NUM_ITER {
            // generate random array
            let data = fill_vec!(1 << NUM_VARS, F::rand(&mut rng));
            let poly = MLExtensionArray::from_slice(&data).unwrap();
            test_basic_extension_methods(&poly, &data, true);
        }
    }

    #[test]
    /// Test Multilinear extension reference works.
    fn test_dense_mlr_functionality() {
        const NUM_ITER: i32 = 10;
        const NUM_VARS: usize = 8;
        let mut rng = test_rng();
        type F = TestField;
        for _ in 0..NUM_ITER {
            // generate random array
            let data = fill_vec!(1 << NUM_VARS, F::rand(&mut rng));
            let poly = MLExtensionRefArray::from_slice(&data).unwrap();
            test_basic_extension_methods(&poly, &data, false);
        }
    }

    //noinspection RsBorrowChecker
    #[test]
    /// Test Sparse multilinear extension works
    fn test_sparse_ml_functionality() {
        const DENSE_ITER: i32 = 3;
        const SPARSE_ITER: i32 = 7;
        const NUM_VARS: usize = 8;
        let mut rng = test_rng();
        type F = TestField;

        // test basic extension method
        for _ in 0..DENSE_ITER {
            let (poly, table): (SparseMLExtensionMap<F>, Vec<F>) =
                random_sparse_poly(NUM_VARS, &mut rng);
            test_basic_extension_methods(&poly, &table, true);
        }

        // test sparse extension method
        for _ in 0..SPARSE_ITER {
            let (poly, table): (SparseMLExtensionMap<F>, Vec<F>) =
                random_sparse_poly(NUM_VARS, &mut rng);
            test_sparse_extension_methods(&poly, &table);
        }
    }

    pub fn random_sparse_poly<F: Field, R: RngCore>(
        nv: usize,
        rng: &mut R,
    ) -> (SparseMLExtensionMap<F>, Vec<F>) {
        let mut arr = fill_vec!(1 << nv, F::zero());
        for _ in 0..1 << (nv / 3) {
            // store 2^dim values
            let index: usize = rng.gen::<usize>() % (1 << nv);
            arr[index] = F::rand(rng);
        }
        let mut buf = Vec::new();
        for (arg, v) in arr.iter().enumerate() {
            if *v != F::zero() {
                buf.push((arg, *v));
            }
        }
        let poly = SparseMLExtensionMap::from_slice(&buf, nv).unwrap();
        (poly, arr)
    }

    /// generate a random sparse poly without generating the bookkeeping table
    pub fn random_sparse_poly_fast<F: Field, R: RngCore>(
        nv: usize,
        rng: &mut R,
    ) -> SparseMLExtensionMap<F> {
        let mut map = SparseMap::new();
        for _ in 0..1 << (nv / 3) {
            // store 2^dim values
            let mut index = rng.gen::<usize>() % (1 << nv);
            while let Some(_) = map.get(&index) {
                index = rng.gen::<usize>() % (1 << nv);
            }
            map.entry(index).or_insert(F::rand(rng));
        }
        let mut buf = Vec::new();
        for (arg, v) in map.iter() {
            if *v != F::zero() {
                buf.push((*arg, *v));
            }
        }
        SparseMLExtensionMap::from_slice(&buf, nv).unwrap()
    }
}
