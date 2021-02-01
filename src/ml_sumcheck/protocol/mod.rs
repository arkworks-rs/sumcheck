//! Interactive Protocol used for Multilinear Sumcheck

use ark_ff::Field;
use ark_poly::{DenseMultilinearExtension, MultilinearExtension};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Read, SerializationError, Write};
use ark_std::cmp::max;
use ark_std::marker::PhantomData;
use ark_std::vec::Vec;
pub mod prover;
pub mod verifier;

/// Interactive Protocol for Multilinear Sumcheck
pub struct IPForMLSumcheck<F: Field> {
    #[doc(hidden)]
    _marker: PhantomData<F>,
}

/// Stores a list of products of `DenseMultilinearExtension` that is meant to be added together.
///
/// This data structure is a list of list of `DenseMultilinearExtension`, and the resulting polynomial is
/// $$\sum_{i=0}^{`self.products.len()`}\prod_{j=0}^{`self.products[i].len()`}P_{ij}$$
///
/// The result polynomial is used as the prover key.
#[derive(CanonicalSerialize, CanonicalDeserialize)]
pub struct ListOfProductsOfPolynomials<F: Field> {
    /// max number of multiplicands in each product
    pub max_multiplicands: usize,
    /// number of variables of the polynomial
    pub num_variables: usize,
    /// list of products of multilinear extension
    pub products: Vec<Vec<DenseMultilinearExtension<F>>>,
}

impl<F: Field> ListOfProductsOfPolynomials<F> {
    /// Extract the max number of multiplicands and number of variables of the list of products.
    pub fn info(&self) -> PolynomialInfo {
        PolynomialInfo {
            max_multiplicands: self.max_multiplicands,
            num_variables: self.num_variables,
        }
    }
}

#[derive(CanonicalSerialize, CanonicalDeserialize, Clone)]
/// Stores the number of variables and max number of multiplicands of the added polynomial used by the prover.
/// This data structures will is used as the verifier key.
pub struct PolynomialInfo {
    /// max number of multiplicands in each product
    pub max_multiplicands: usize,
    /// number of variables of the polynomial
    pub num_variables: usize,
}

impl<F: Field> ListOfProductsOfPolynomials<F> {
    /// Returns an empty polynomial
    pub fn new(num_variables: usize) -> Self {
        ListOfProductsOfPolynomials {
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
