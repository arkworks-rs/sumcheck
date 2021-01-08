//! AHP protocol for multilinear sumcheck

use ark_ff::Field;
use ark_poly::{DenseMultilinearExtension, MultilinearExtension};
use ark_std::cmp::max;
use ark_std::marker::PhantomData;
use ark_std::vec::Vec;
pub mod indexer;
pub mod prover;
pub mod verifier;

/// Algebraic Holographic Proof defined in [T13](https://eprint.iacr.org/2013/351).
pub struct AHPForMLSumcheck<F: Field> {
    #[doc(hidden)]
    _marker: PhantomData<F>,
}

/// Represents a polynomial which is the sum of products of multilinear extensions.
pub struct ProductsOfMLExtensions<F: Field> {
    /// max number of multiplicands in each product
    pub max_multiplicands: usize,
    /// number of variables
    pub num_variables: usize,
    /// list of products of multilinear extension
    pub products: Vec<Vec<DenseMultilinearExtension<F>>>,
}

impl<F: Field> ProductsOfMLExtensions<F> {
    /// Returns an empty polynomial
    pub fn new(num_variables: usize) -> Self {
        ProductsOfMLExtensions {
            max_multiplicands: 0,
            num_variables,
            products: Vec::new(),
        }
    }

    /// Add one product of multilinear extensions to the polynomial
    pub fn add_product(&mut self, product: impl IntoIterator<Item = DenseMultilinearExtension<F>>) {
        let product: Vec<DenseMultilinearExtension<F>> = product.into_iter().collect();
        assert!(product.len() > 0);
        product
            .iter()
            .map(|p| assert_eq!(p.num_vars, self.num_variables))
            .last();
        self.max_multiplicands = max(self.max_multiplicands, product.len());
        self.products.push(product);
    }

    /// Evaluate the polynomial at point `point`
    pub fn evaluate(&self, point: &[F]) -> F {
        self.products
            .iter()
            .map(|p| p.iter().map(|f| f.evaluate(point).unwrap()).product::<F>())
            .sum()
    }
}
