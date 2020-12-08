//! Commitment Scheme for multilinear function in evaluation form
use ark_std::marker::PhantomData;

pub mod data_structures;
pub mod setup;
pub mod commit;
pub mod open;
pub mod verify;

use ark_ec::PairingEngine;

/// Commitment scheme for multilinear function in evaluation form.
pub struct MLPolyCommit<E: PairingEngine> {
    #[doc(hidden)]
    _marker: PhantomData<E>,
}

#[cfg(test)]
mod commit_bench{
    use ark_ff::test_rng;
    use crate::test_utils::TestCurve;
    use crate::commitment::MLPolyCommit;
    use ark_std::path::Path;
    use ark_std::fs::File;
    use crate::commitment::data_structures::{PublicParameter, VerifierParameter};
    use ark_serialize::{Read, Write, CanonicalSerialize, CanonicalDeserialize, SerializationError};
    use ark_std::collections::LinkedList;
    use ark_std::iter::FromIterator;
    use linear_sumcheck::data_structures::MLExtensionArray;
    use ark_ec::PairingEngine;
    use ark_ff::UniformRand;
    const NV_RANGE_LOW: usize = 8;
    const NV_RANGE_HIGH: usize = 15;
    type E = TestCurve;
    type Fr = <E as PairingEngine>::Fr;

    #[derive(CanonicalSerialize, CanonicalDeserialize)]
    struct ParameterPair {
        pp: PublicParameter<E>,
        vp: VerifierParameter<E>
    }

    #[test]
    #[ignore]
    fn setup_bench() {
        let mut rng = test_rng();
        let nv_range = NV_RANGE_LOW..(NV_RANGE_HIGH + 1);
        let mut result = Vec::with_capacity(NV_RANGE_HIGH - NV_RANGE_LOW + 1);
        for nv in nv_range {
            let timer = start_timer!(|| format!("setup for {} variables (data size = {})", nv, 1 << nv));
            let param = MLPolyCommit::<E>::keygen(nv, &mut rng).expect("unable to setup");
            end_timer!(timer);
            result.push(ParameterPair{pp: param.0, vp: param.1});
        }
        let path = Path::new("benchmark_cached_keys");
        let mut file = File::create(&path).expect("Unable to create cached setup key file. ");
        result.serialize_uncompressed(&mut file).expect("cannot write to cached setup key file");
    }

    #[test]
    fn commit_open_verify_bench() {
        let mut file = {
            let result = File::open("benchmark_cached_keys");
            if result.is_ok() {
                result.unwrap()
            }else{
                setup_bench();
                File::open("benchmark_cached_keys").expect("fail to open cached keys")
            }
        };
        let timer = start_timer!(||"reading cached parameters");
        let params = Vec::<ParameterPair>::deserialize_unchecked(&mut file).expect("cannot decode setup keys");
        end_timer!(timer);
        let mut params = LinkedList::from_iter(params.into_iter());
        let nv_range = NV_RANGE_LOW..(NV_RANGE_HIGH + 1);
        let mut rng = test_rng();
        for nv in nv_range{
            // get parameters
            let param = params.pop_front().unwrap();
            let poly = MLExtensionArray::from_vec((0..(1<<nv)).map(|_|Fr::rand(&mut rng)).collect()).unwrap();
            let poly_for_open = poly.clone();
            // commit polynomial
            let timer = start_timer!(||format!("commit polynomial of {} variables (size = {})", nv, 1 << nv));
            let commit = MLPolyCommit::commit(&param.pp, poly).expect("fail to commit");
            end_timer!(timer);
            let point: Vec<_> = (0..nv).map(|_|Fr::rand(&mut rng)).collect();
            let timer = start_timer!(||format!("Open Polynomial of {} variables (size = {})", nv, 1 << nv));
            let (eval_result, proof,_)  = MLPolyCommit::open(&param.pp, poly_for_open, &point).expect("fail to open");
            end_timer!(timer);
            let timer = start_timer!(||format!("verify polynomial of {} variable (size = {})", nv, 1 << nv));
            assert!(MLPolyCommit::verify(&param.vp, &commit, &point, eval_result, proof).expect("fail to verify"), "verification failed");
            end_timer!(timer);
        }
    }


}

