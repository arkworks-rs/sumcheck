// use std::fmt::Debug;
//
// use algebra::{CanonicalDeserialize, CanonicalSerialize, Field};
// use rand_core::RngCore;
//
// /// A degree-2 mask to hide a GKR Function
// ///
// /// This function has form `a0 + g1(x1) + g2(x2) + ... + g_l(x_l)` where `gi(.)` has degree of 2.
// /// i.e. `g_i(x_i) = a_i*x_i + b_i*((x_i)^2)`
// ///
// pub trait GKRMask<F>: Sized + Clone
// where
//     F: Field,
// {
//     /// Commitment DS
//     type Commitment: Clone + CanonicalSerialize + CanonicalDeserialize;
//     /// Proof Π to show that p(point) is indeed a point on committed polynomial p.
//     type Proof: Clone + CanonicalSerialize + CanonicalDeserialize;
//     /// Error Type
//     type Error: algebra::Error + From<crate::Error>;
//     /// Committer Key
//     type CommitterKey: Clone + Debug;
//     /// Verifier Key
//     type VerifierKey: Clone + Debug;
//     /// generate a random GKRMask (should have 2*dim variables)
//     fn rand_mask<R: RngCore>(dim: usize, rng: &mut R) -> Self;
//
//     /// Get commitment of this GKR mask.
//     fn commit_self<R: RngCore>(
//         &self,
//         ck: &Self::CommitterKey,
//         rng: &mut R,
//     ) -> Result<Self::Commitment, Self::Error>;
//
//     /// Evaluate this mask polynomial on point and generate the proof.
//     /// * `point`: the point that we want to evaluate at
//     /// * `ck`: committer key
//     /// * `opening_challenge`: as specified by the commitment scheme
//     fn open<R: RngCore>(
//         &self,
//         point: &[F],
//         ck: &Self::CommitterKey,
//         com: &Self::Commitment,
//         opening_challenge: F,
//         rng: &mut R,
//     ) -> Result<(F, Self::Proof), Self::Error>;
//
//     /// Verify that the point and evaluation is correct.
//     /// * `com`: commitment of poly
//     /// * `point`: the point that we want to evaluate at
//     /// * `ev`: evaluation
//     /// * `proof`: proof of evaluation
//     /// * `vk`: verifier key
//     /// * `opening_challenge`: as specified by the commitment scheme (should be same as open)
//     fn verify<R: RngCore>(
//         com: &Self::Commitment,
//         point: &[F],
//         ev: F,
//         proof: &Self::Proof,
//         vk: &Self::VerifierKey,
//         opening_challenge: F,
//         rng: &mut R,
//     ) -> Result<bool, Self::Error>;
//
//     /// Generate Key Pairs
//     fn keygen<R: RngCore>(
//         rng: &mut R,
//     ) -> Result<(Self::CommitterKey, Self::VerifierKey), Self::Error>;
//
//     /// return the constant term of the poly
//     fn a0(&self) -> F;
//
//     /// evaluate g_i(point)
//     ///
//     /// `i` starts from 1. If `i == 0`, return `a0`.
//     fn gi(&self, i: usize, point: F) -> Result<F, Self::Error>;
//
//     /// get sum of `gi(xi) + ... + g_l(x_l)` over `(xi, ... xl) in {0, 1}^{l-i+1}`
//     ///
//     /// This method is useful for sum-check at round i-1.
//     ///
//     /// When i = 0, return the whole sum.
//     fn tail_sum_from(&self, i: usize) -> Result<F, Self::Error>;
//
//     /// get sum of `z + gi(xi) + ... + g_l(x_l)` over `(xi, ... xl) in {0, 1}^{l-i+1}`
//     ///
//     /// This method is useful for sum-check at round i-1.
//     ///
//     /// When i = 0, return the whole sum.
//     fn tail_sum_from_with(&self, i: usize, z: F) -> Result<F, Self::Error>;
// }
//
// #[cfg(test)]
// pub mod tests {
//     use algebra::{test_rng, Field};
//     use poly_commit::PolynomialCommitment;
//
//     use crate::data_structures::mask::GKRMask;
//
//     /// test that makes sure methods `a0`, `gi`, `open`,`verify` and `tail_sum_from` are consistent with each other
//     /// * `dim`: number of variables in x
//     pub fn test_consistence<F: Field, G: GKRMask<F>>(num_iterations: usize, dim: usize) {
//         let mut rng = test_rng();
//         for _ in 0..num_iterations {
//             let poly = G::rand_mask(dim, &mut rng);
//             // get random query of size 'dim'
//             let (ck, vk) = G::keygen(&mut rng).unwrap();
//
//             // commit the poly
//             let com = poly.commit_self(&ck, &mut rng).expect("Unable to commit");
//
//             let point = fill_vec!(dim * 2, F::rand(&mut rng));
//             let opening_challenge = F::rand(&mut rng);
//             // open and verify
//             let (ev, proof) = poly
//                 .open(&point[..], &ck, &com, opening_challenge, &mut rng)
//                 .expect("Unable to open poly");
//             assert!(
//                 G::verify(
//                     &com,
//                     &point[..],
//                     ev,
//                     &proof,
//                     &vk,
//                     opening_challenge,
//                     &mut rng,
//                 )
//                 .unwrap(),
//                 "Verification Failed"
//             );
//             assert!(
//                 !G::verify(
//                     &com,
//                     &point[..],
//                     ev + F::one(),
//                     &proof,
//                     &vk,
//                     opening_challenge,
//                     &mut rng,
//                 )
//                 .unwrap(),
//                 "Verification should fail"
//             );
//
//             // test if gi, a0 works
//             let expected: F = point
//                 .iter()
//                 .enumerate()
//                 .map(|(i, x)| poly.gi(i + 1, *x).expect("Fail to evaluate"))
//                 .sum::<F>()
//                 + poly.a0();
//
//             assert_eq!(ev, expected);
//
//             // test tail sum using last 3 terms
//             let nv = 2 * dim;
//             assert_eq!(
//                 poly.tail_sum_from(nv).unwrap(),
//                 poly.gi(nv, F::zero()).unwrap() + poly.gi(nv, F::one()).unwrap()
//             );
//             assert_eq!(
//                 poly.tail_sum_from(nv - 1).unwrap(),
//                 poly.gi(nv - 1, F::zero()).unwrap()
//                     + poly.gi(nv, F::zero()).unwrap()
//                     + poly.gi(nv - 1, F::zero()).unwrap()
//                     + poly.gi(nv, F::one()).unwrap()
//                     + poly.gi(nv - 1, F::one()).unwrap()
//                     + poly.gi(nv, F::zero()).unwrap()
//                     + poly.gi(nv - 1, F::one()).unwrap()
//                     + poly.gi(nv, F::one()).unwrap()
//             );
//             assert_eq!(
//                 poly.tail_sum_from(nv - 2).unwrap(),
//                 poly.gi(nv - 2, F::zero()).unwrap()
//                     + poly.gi(nv - 1, F::zero()).unwrap()
//                     + poly.gi(nv, F::zero()).unwrap()
//                     + poly.gi(nv - 2, F::zero()).unwrap()
//                     + poly.gi(nv - 1, F::zero()).unwrap()
//                     + poly.gi(nv, F::one()).unwrap()
//                     + poly.gi(nv - 2, F::zero()).unwrap()
//                     + poly.gi(nv - 1, F::one()).unwrap()
//                     + poly.gi(nv, F::zero()).unwrap()
//                     + poly.gi(nv - 2, F::zero()).unwrap()
//                     + poly.gi(nv - 1, F::one()).unwrap()
//                     + poly.gi(nv, F::one()).unwrap()
//                     + poly.gi(nv - 2, F::one()).unwrap()
//                     + poly.gi(nv - 1, F::zero()).unwrap()
//                     + poly.gi(nv, F::zero()).unwrap()
//                     + poly.gi(nv - 2, F::one()).unwrap()
//                     + poly.gi(nv - 1, F::zero()).unwrap()
//                     + poly.gi(nv, F::one()).unwrap()
//                     + poly.gi(nv - 2, F::one()).unwrap()
//                     + poly.gi(nv - 1, F::one()).unwrap()
//                     + poly.gi(nv, F::zero()).unwrap()
//                     + poly.gi(nv - 2, F::one()).unwrap()
//                     + poly.gi(nv - 1, F::one()).unwrap()
//                     + poly.gi(nv, F::one()).unwrap()
//             );
//             let w = F::rand(&mut rng);
//             assert_eq!(
//                 poly.tail_sum_from_with(nv - 3, w).unwrap(),
//                 w + poly.gi(nv - 3, F::zero()).unwrap()
//                     + poly.gi(nv - 2, F::zero()).unwrap()
//                     + poly.gi(nv - 1, F::zero()).unwrap()
//                     + poly.gi(nv, F::zero()).unwrap()
//                     + w
//                     + poly.gi(nv - 3, F::zero()).unwrap()
//                     + poly.gi(nv - 2, F::zero()).unwrap()
//                     + poly.gi(nv - 1, F::zero()).unwrap()
//                     + poly.gi(nv, F::one()).unwrap()
//                     + w
//                     + poly.gi(nv - 3, F::zero()).unwrap()
//                     + poly.gi(nv - 2, F::zero()).unwrap()
//                     + poly.gi(nv - 1, F::one()).unwrap()
//                     + poly.gi(nv, F::zero()).unwrap()
//                     + w
//                     + poly.gi(nv - 3, F::zero()).unwrap()
//                     + poly.gi(nv - 2, F::zero()).unwrap()
//                     + poly.gi(nv - 1, F::one()).unwrap()
//                     + poly.gi(nv, F::one()).unwrap()
//                     + w
//                     + poly.gi(nv - 3, F::zero()).unwrap()
//                     + poly.gi(nv - 2, F::one()).unwrap()
//                     + poly.gi(nv - 1, F::zero()).unwrap()
//                     + poly.gi(nv, F::zero()).unwrap()
//                     + w
//                     + poly.gi(nv - 3, F::zero()).unwrap()
//                     + poly.gi(nv - 2, F::one()).unwrap()
//                     + poly.gi(nv - 1, F::zero()).unwrap()
//                     + poly.gi(nv, F::one()).unwrap()
//                     + w
//                     + poly.gi(nv - 3, F::zero()).unwrap()
//                     + poly.gi(nv - 2, F::one()).unwrap()
//                     + poly.gi(nv - 1, F::one()).unwrap()
//                     + poly.gi(nv, F::zero()).unwrap()
//                     + w
//                     + poly.gi(nv - 3, F::zero()).unwrap()
//                     + poly.gi(nv - 2, F::one()).unwrap()
//                     + poly.gi(nv - 1, F::one()).unwrap()
//                     + poly.gi(nv, F::one()).unwrap()
//                     + w
//                     + poly.gi(nv - 3, F::one()).unwrap()
//                     + poly.gi(nv - 2, F::zero()).unwrap()
//                     + poly.gi(nv - 1, F::zero()).unwrap()
//                     + poly.gi(nv, F::zero()).unwrap()
//                     + w
//                     + poly.gi(nv - 3, F::one()).unwrap()
//                     + poly.gi(nv - 2, F::zero()).unwrap()
//                     + poly.gi(nv - 1, F::zero()).unwrap()
//                     + poly.gi(nv, F::one()).unwrap()
//                     + w
//                     + poly.gi(nv - 3, F::one()).unwrap()
//                     + poly.gi(nv - 2, F::zero()).unwrap()
//                     + poly.gi(nv - 1, F::one()).unwrap()
//                     + poly.gi(nv, F::zero()).unwrap()
//                     + w
//                     + poly.gi(nv - 3, F::one()).unwrap()
//                     + poly.gi(nv - 2, F::zero()).unwrap()
//                     + poly.gi(nv - 1, F::one()).unwrap()
//                     + poly.gi(nv, F::one()).unwrap()
//                     + w
//                     + poly.gi(nv - 3, F::one()).unwrap()
//                     + poly.gi(nv - 2, F::one()).unwrap()
//                     + poly.gi(nv - 1, F::zero()).unwrap()
//                     + poly.gi(nv, F::zero()).unwrap()
//                     + w
//                     + poly.gi(nv - 3, F::one()).unwrap()
//                     + poly.gi(nv - 2, F::one()).unwrap()
//                     + poly.gi(nv - 1, F::zero()).unwrap()
//                     + poly.gi(nv, F::one()).unwrap()
//                     + w
//                     + poly.gi(nv - 3, F::one()).unwrap()
//                     + poly.gi(nv - 2, F::one()).unwrap()
//                     + poly.gi(nv - 1, F::one()).unwrap()
//                     + poly.gi(nv, F::zero()).unwrap()
//                     + w
//                     + poly.gi(nv - 3, F::one()).unwrap()
//                     + poly.gi(nv - 2, F::one()).unwrap()
//                     + poly.gi(nv - 1, F::one()).unwrap()
//                     + poly.gi(nv, F::one()).unwrap()
//             );
//             let two = F::one() + F::one();
//             assert_eq!(
//                 poly.tail_sum_from(0).unwrap(),
//                 poly.tail_sum_from(1).unwrap() + poly.a0() * two.pow(&[nv as u64])
//             );
//             for i in 1..(nv - 1) {
//                 assert_eq!(
//                     poly.tail_sum_from(i).unwrap(),
//                     poly.gi(i, F::zero()).unwrap() * two.pow(&[(nv - i) as u64])
//                         + poly.tail_sum_from(i + 1).unwrap()
//                         + poly.gi(i, F::one()).unwrap() * two.pow(&[(nv - i) as u64])
//                         + poly.tail_sum_from(i + 1).unwrap()
//                 );
//             }
//
//             assert_eq!(
//                 poly.tail_sum_from(0).unwrap(),
//                 poly.tail_sum_from_with(1, poly.a0()).unwrap()
//             )
//         }
//     }
// }
