//! Defines the data structures used by the `MLSumcheck` protocol.

use ark_ff::PrimeField;
use ark_poly::{DenseMultilinearExtension, MultilinearExtension};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Read, SerializationError, Write};
use ark_sponge::Absorb;
use ark_std::{cmp::max, rc::Rc, vec::Vec};
use hashbrown::HashMap;
/// Stores a list of products of `DenseMultilinearExtension` that is meant to be
/// added together.
///
/// The polynomial is represented by a list of products of polynomials along
/// with its coefficient that is meant to be added together.
///
/// This data structure of the polynomial is a list of list of `(coefficient,
/// DenseMultilinearExtension)`.
/// * Number of products n = `self.products.len()`,
/// * Number of multiplicands of ith product m_i = `self.products[i].1.len()`,
/// * Coefficient of ith product c_i = `self.products[i].0`
///
/// The resulting polynomial is
///
/// $$\sum_{i=0}^{n}C_i\cdot\prod_{j=0}^{m_i}P_{ij}$$
///
/// The result polynomial is used as the prover key.
#[derive(Clone)]
pub struct ListOfProductsOfPolynomials<F: PrimeField> {
    /// max number of multiplicands in each product
    pub max_multiplicands: usize,
    /// number of variables of the polynomial
    pub num_variables: usize,
    /// list of reference to products (as usize) of multilinear extension
    pub products: Vec<(F, Vec<usize>)>,
    // TODO: unnecessary to use pointer. Fix it.
    /// Stores multilinear extensions in which product multiplicand can refer
    /// to.
    pub flattened_ml_extensions: Vec<Rc<DenseMultilinearExtension<F>>>,
    /// Store the index of each `ml_extension` in `flattened_ml_extensions`.
    raw_pointers_lookup_table: HashMap<*const DenseMultilinearExtension<F>, usize>,
}

impl<F: PrimeField> ListOfProductsOfPolynomials<F> {
    /// Extract the max number of multiplicands and number of variables of the
    /// list of products.
    pub fn info(&self) -> PolynomialInfo {
        PolynomialInfo {
            max_multiplicands: self.max_multiplicands,
            num_variables: self.num_variables,
        }
    }
}

#[derive(CanonicalSerialize, CanonicalDeserialize, Clone)]
/// Stores the number of variables and max number of multiplicands of the added
/// polynomial used by the prover. This data structures will is used as the
/// verifier key.
pub struct PolynomialInfo {
    /// max number of multiplicands in each product
    pub max_multiplicands: usize,
    /// number of variables of the polynomial
    pub num_variables: usize,
}

impl Absorb for PolynomialInfo {
    fn to_sponge_bytes(&self, dest: &mut Vec<u8>) {
        self.serialize(dest).expect("serialization failed");
    }

    fn to_sponge_field_elements<F: PrimeField>(&self, dest: &mut Vec<F>) {
        dest.push(F::from(self.max_multiplicands as u128));
        dest.push(F::from(self.num_variables as u128));
    }
}

impl<F: PrimeField> ListOfProductsOfPolynomials<F> {
    /// Returns an empty polynomial
    pub fn new(num_variables: usize) -> Self {
        ListOfProductsOfPolynomials {
            max_multiplicands: 0,
            num_variables,
            products: Vec::new(),
            flattened_ml_extensions: Vec::new(),
            raw_pointers_lookup_table: HashMap::new(),
        }
    }

    /// Add a list of multilinear extensions that is meant to be multiplied
    /// together. The resulting polynomial will be multiplied by the scalar
    /// `coefficient`.
    pub fn add_product(
        &mut self,
        product: impl IntoIterator<Item = Rc<DenseMultilinearExtension<F>>>,
        coefficient: F,
    ) {
        let product: Vec<Rc<DenseMultilinearExtension<F>>> = product.into_iter().collect();
        let mut indexed_product = Vec::with_capacity(product.len());
        assert!(!product.is_empty(), "product is empty");
        self.max_multiplicands = max(self.max_multiplicands, product.len());
        for m in product {
            assert_eq!(
                m.num_vars, self.num_variables,
                "product has a multiplicand with wrong number of variables"
            );
            let m_ptr: *const DenseMultilinearExtension<F> = Rc::as_ptr(&m);
            if let Some(index) = self.raw_pointers_lookup_table.get(&m_ptr) {
                // if same multilinear extension is already added, just add a reference to it
                indexed_product.push(*index)
            } else {
                let curr_index = self.flattened_ml_extensions.len();
                self.flattened_ml_extensions.push(m.clone());
                self.raw_pointers_lookup_table.insert(m_ptr, curr_index);
                indexed_product.push(curr_index);
            }
        }
        self.products.push((coefficient, indexed_product));
    }

    /// Evaluate the polynomial at point `point`
    pub fn evaluate(&self, point: &[F]) -> F {
        self.products
            .iter()
            .map(|(c, p)| {
                *c * p
                    .iter()
                    .map(|&i| self.flattened_ml_extensions[i].evaluate(point).unwrap())
                    .product::<F>()
            })
            .sum()
    }
}
