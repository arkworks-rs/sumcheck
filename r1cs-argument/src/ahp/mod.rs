//! Holographic proof for r1cs-argument
use ark_ec::PairingEngine;
use ark_std::marker::PhantomData;

pub mod indexer;
pub mod prover;
pub mod setup;
pub mod verifier;

#[cfg(test)]
mod tests;
/// Multilinear Proof for R1CS
pub struct MLProofForR1CS<E: PairingEngine>(#[doc(hidden)] PhantomData<E>);
