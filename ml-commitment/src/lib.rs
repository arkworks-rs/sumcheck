//! A protocol of generating proofs for R1CS circuit using multilinear argument.
#![forbid(unsafe_code)]
#![cfg_attr(not(feature = "std"), no_std)]
#![deny(unused_import_braces, unused_qualifications, trivial_casts)]
#![deny(trivial_numeric_casts, private_in_public, variant_size_differences)]
#![deny(stable_features, unreachable_pub, non_shorthand_field_patterns)]
#![deny(unused_attributes, unused_mut)]
#![deny(missing_docs)]
#![deny(unused_imports)]
#![deny(renamed_and_removed_lints, stable_features, unused_allocation)]
#![deny(unused_comparisons, bare_trait_objects, unused_must_use, const_err)]

#[macro_use]
extern crate bench_utils;

#[macro_use]
#[allow(unused_imports)]
extern crate ark_std;

use ark_std::marker::PhantomData;

pub mod commit;
pub mod data_structures;
pub mod open;
pub mod setup;
pub mod verify;

pub mod error;
#[cfg(test)]
pub mod test_utils;

#[cfg(test)]
pub use test_utils::*;

use ark_ec::PairingEngine;
pub use error::*;

/// Commitment scheme for multilinear function in evaluation form.
pub struct MLPolyCommit<E: PairingEngine> {
    #[doc(hidden)]
    _marker: PhantomData<E>,
}

#[cfg(test)]
mod commit_bench {
    use crate::data_structures::{PublicParameter, VerifierParameter};
    use crate::MLPolyCommit;
    use crate::TestCurve;
    use ark_ec::PairingEngine;
    use ark_ff::test_rng;
    use ark_ff::UniformRand;
    use ark_serialize::{
        CanonicalDeserialize, CanonicalSerialize, Read, SerializationError, Write,
    };
    use ark_std::collections::LinkedList;
    use ark_std::fs::File;
    use ark_std::iter::FromIterator;
    use ark_std::path::Path;
    use linear_sumcheck::data_structures::MLExtensionArray;
    const NV_RANGE_LOW: usize = 8;
    const NV_RANGE_HIGH: usize = 15;
    type E = TestCurve;
    type Fr = <E as PairingEngine>::Fr;

    #[derive(CanonicalSerialize, CanonicalDeserialize)]
    struct ParameterPair {
        pp: PublicParameter<E>,
        vp: VerifierParameter<E>,
    }

    #[test]
    #[ignore]
    fn setup_bench() {
        let mut rng = test_rng();
        let nv_range = NV_RANGE_LOW..(NV_RANGE_HIGH + 1);
        let mut result = Vec::with_capacity(NV_RANGE_HIGH - NV_RANGE_LOW + 1);
        for nv in nv_range {
            let timer =
                start_timer!(|| format!("setup for {} variables (data size = {})", nv, 1 << nv));
            let param = MLPolyCommit::<E>::keygen(nv, &mut rng).expect("unable to setup");
            end_timer!(timer);
            result.push(ParameterPair {
                pp: param.0,
                vp: param.1,
            });
        }
        let path = Path::new("benchmark_cached_keys");
        let mut file = File::create(&path).expect("Unable to create cached setup key file. ");
        result
            .serialize_uncompressed(&mut file)
            .expect("cannot write to cached setup key file");
    }

    #[test]
    #[ignore]
    fn commit_open_verify_bench() {
        let mut file = {
            let result = File::open("benchmark_cached_keys");
            if result.is_ok() {
                result.unwrap()
            } else {
                setup_bench();
                File::open("benchmark_cached_keys").expect("fail to open cached keys")
            }
        };
        let timer = start_timer!(|| "reading cached parameters");
        let params = Vec::<ParameterPair>::deserialize_unchecked(&mut file)
            .expect("cannot decode setup keys");
        end_timer!(timer);
        let mut params = LinkedList::from_iter(params.into_iter());
        let nv_range = NV_RANGE_LOW..(NV_RANGE_HIGH + 1);
        let mut rng = test_rng();
        for nv in nv_range {
            // get parameters
            let param = params.pop_front().unwrap();
            let poly =
                MLExtensionArray::from_vec((0..(1 << nv)).map(|_| Fr::rand(&mut rng)).collect())
                    .unwrap();
            let poly_for_open = poly.clone();
            // commit polynomial
            let timer = start_timer!(|| format!(
                "commit polynomial of {} variables (size = {})",
                nv,
                1 << nv
            ));
            let commit = MLPolyCommit::commit(&param.pp, poly).expect("fail to commit");
            end_timer!(timer);
            let point: Vec<_> = (0..nv).map(|_| Fr::rand(&mut rng)).collect();
            let timer = start_timer!(|| format!(
                "Open Polynomial of {} variables (size = {})",
                nv,
                1 << nv
            ));
            let (eval_result, proof, _) =
                MLPolyCommit::open(&param.pp, poly_for_open, &point).expect("fail to open");
            end_timer!(timer);
            let timer = start_timer!(|| format!(
                "verify polynomial of {} variable (size = {})",
                nv,
                1 << nv
            ));
            assert!(
                MLPolyCommit::verify(&param.vp, &commit, &point, eval_result, proof)
                    .expect("fail to verify"),
                "verification failed"
            );
            end_timer!(timer);
        }
    }
}
