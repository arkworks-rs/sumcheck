//! Indexer for the r1cs argument protocol
use crate::ahp::MLProofForR1CS;
use crate::data_structures::r1cs_reader::MatrixExtension;
use crate::error::invalid_arg;
use ark_ec::PairingEngine;
use ark_ff::Field;
use ark_relations::r1cs::Matrix;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Read, SerializationError, Write};

/// Prover's Key
#[derive(Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct IndexPK<F: Field> {
    /// Matrix A
    pub matrix_a: MatrixExtension<F>,
    /// Matrix B
    pub matrix_b: MatrixExtension<F>,
    /// Matrix C
    pub matrix_c: MatrixExtension<F>,
    /// log(|v|+|w|)
    pub log_n: usize,
}

/// Verifier's Key for R1cs AxBx = Cx
#[derive(Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct IndexVK<F: Field> {
    /// Matrix A
    pub matrix_a: MatrixExtension<F>,
    /// Matrix B
    pub matrix_b: MatrixExtension<F>,
    /// Matrix C
    pub matrix_c: MatrixExtension<F>,
    /// log(|v|+|w|)
    pub log_n: usize,
}

impl<F: Field> IndexPK<F> {
    /// Get verifier key from prover key
    pub fn vk(&self) -> IndexVK<F> {
        IndexVK {
            matrix_a: self.matrix_a.clone(),
            matrix_b: self.matrix_b.clone(),
            matrix_c: self.matrix_c.clone(),
            log_n: self.log_n,
        }
    }
}

impl<E: PairingEngine> MLProofForR1CS<E> {
    /// Index the raw matrix into prover key and verifier key
    pub fn index(
        matrix_a: Matrix<E::Fr>,
        matrix_b: Matrix<E::Fr>,
        matrix_c: Matrix<E::Fr>,
    ) -> Result<IndexPK<E::Fr>, crate::Error> {
        // sanity check
        let n = matrix_a.len();
        // for simplicity, this protocol assume width of matrix (n) is a power of 2.
        if !n.is_power_of_two() {
            return Err(invalid_arg("Matrix width should be a power of 2."));
        }
        let log_n = ark_std::log2(n) as usize;

        let matrix_a = MatrixExtension::new(matrix_a, n)?;
        let matrix_b = MatrixExtension::new(matrix_b, n)?;
        let matrix_c = MatrixExtension::new(matrix_c, n)?;

        Ok(IndexPK {
            matrix_a,
            matrix_b,
            matrix_c,
            log_n,
        })
    }
}
