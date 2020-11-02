//! Indexer

use ark_ff::Field;
use crate::ml_sumcheck::ahp::AHPForMLSumcheck;
use crate::data_structures::ml_extension::{MLExtension, ArithmeticCombination};
use ark_serialize::{CanonicalSerialize, SerializationError, Write};
use ark_std::marker::PhantomData;
use crate::error::invalid_args;

/// Index used for MLSumcheck
pub struct Index<F: Field> {
pub max_multiplicands: usize,
pub num_variables: usize,
/// sum of product of multilinear extensions
pub add_table: Vec<Vec<Vec<F>>>,
#[doc(hidden)] _marker: PhantomData<F>
}
#[derive(CanonicalSerialize)]
pub struct IndexInfo {
    pub max_multiplicands: usize,
    pub num_variables: usize
}

impl<F: Field> Index<F> {
    pub fn info(&self) -> IndexInfo {
        IndexInfo{
            max_multiplicands: self.max_multiplicands,
            num_variables: self.num_variables
        }
    }
}


impl<F: Field> AHPForMLSumcheck<F> {
    pub fn index<P: MLExtension<F>>(polynomial: &ArithmeticCombination<F, P>) -> Result<Index<F>, crate::Error>{
        let num_variables = polynomial.num_variables;
        let max_multiplicands = polynomial.max_multiplicands;
        let mut add_table = Vec::new();
        if polynomial.vector_of_products.len() < 1 {
            return Err(invalid_args("Input is empty."))
        }
        for product in polynomial.vector_of_products.iter() {
            if product.len() > max_multiplicands {
                return Err(invalid_args("invalid max_multiplicands"));
            }
            let mut mul_table = Vec::with_capacity(max_multiplicands);
            for single_poly in product.iter() {
                if unwrap_safe!(single_poly.num_variables()) != num_variables {
                    return Err(crate::Error::InvalidArgumentError(Some(
                        "polynomials should be same number of variables".into(),
                    )));
                }

                mul_table.push(unwrap_safe!(single_poly.table()));
            }
            add_table.push(mul_table);
        }
        Ok(
            Index{
                num_variables,
                max_multiplicands,
                add_table,
                _marker: PhantomData
            }
        )
    }
}