//! Indexer

use crate::ml_sumcheck::ahp::{AHPForMLSumcheck, ProductsOfMLExtensions};
use ark_ff::Field;
use ark_poly::DenseMultilinearExtension;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Read, SerializationError, Write};
use ark_std::marker::PhantomData;
use ark_std::vec::Vec;

use ark_std::iter::FromIterator;

/// Index used for MLSumcheck
#[derive(CanonicalSerialize, CanonicalDeserialize)]
pub struct Index<F: Field> {
    /// max number of multiplicands in each product
    pub max_multiplicands: usize,
    /// number of variables of the polynomial
    pub num_variables: usize,
    /// sum of product of multilinear extensions
    pub add_table: Vec<Vec<DenseMultilinearExtension<F>>>,
    #[doc(hidden)]
    _marker: PhantomData<F>,
}

#[derive(CanonicalSerialize, CanonicalDeserialize, Clone)]
/// Index information used by verifier
pub struct IndexInfo {
    /// max number of multiplicands in each product
    pub max_multiplicands: usize,
    /// number of variables of the polynomial
    pub num_variables: usize,
}

impl<F: Field> Index<F> {
    /// get the info of number of multiplicands and number of variables (used as verifier key)
    pub fn info(&self) -> IndexInfo {
        IndexInfo {
            max_multiplicands: self.max_multiplicands,
            num_variables: self.num_variables,
        }
    }
}

impl<F: Field> AHPForMLSumcheck<F> {
    /// index to sum of products of multilinear polynomials from data array
    pub fn index(polynomial: &ProductsOfMLExtensions<F>) -> Index<F> {
        let mut add_table = Vec::new();
        assert!(polynomial.products.len() > 0);

        for product in polynomial.products.iter() {
            let mul_table = Vec::from_iter(product.iter().map(|x| x.clone()));
            add_table.push(mul_table);
        }
        Index {
            num_variables: polynomial.num_variables,
            max_multiplicands: polynomial.max_multiplicands,
            add_table,
            _marker: PhantomData,
        }
    }

    /// consume the polynomial and index to sum of products of multilinear polynomials from data array
    pub fn index_move(polynomial: ProductsOfMLExtensions<F>) -> Index<F> {
        assert!(polynomial.products.len() > 0);

        Index {
            num_variables: polynomial.num_variables,
            max_multiplicands: polynomial.max_multiplicands,
            add_table: polynomial.products,
            _marker: PhantomData,
        }
    }
}
