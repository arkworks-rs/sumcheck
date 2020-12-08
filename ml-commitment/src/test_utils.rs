use ark_bls12_381::Bls12_381;
use ark_ec::PairingEngine;

/// scalar field used for tests
pub type TestCurve = Bls12_381;
pub type TestCurveFr = <TestCurve as PairingEngine>::Fr;
