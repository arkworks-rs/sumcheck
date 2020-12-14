//! Verifier for commitment scheme
use crate::commit::Commitment;
use crate::data_structures::VerifierParameter;
use crate::error::SResult;
use crate::open::Proof;
use crate::MLPolyCommit;
use ark_ec::msm::FixedBaseMSM;
use ark_ec::{AffineCurve, PairingEngine, ProjectiveCurve};
use ark_ff::PrimeField;
use ark_std::vec::Vec;
impl<E: PairingEngine> MLPolyCommit<E> {
    /// Verify the result of evaluation of polynomial at a point. Return true is the point is true.
    pub fn verify(
        vp: &VerifierParameter<E>,
        commitment: &Commitment<E>,
        point: &[E::Fr],
        eval: E::Fr,
        proof: Proof<E>,
    ) -> SResult<bool> {
        let left = E::pairing(
            commitment.g_product.into_projective() - &vp.g.mul(eval),
            vp.h,
        );
        // let mut right = E::Fqk::one();
        // for i in 0 .. vp.nv {
        //     right *= &E::pairing(vp.g_mask_random[i] - &vp.g.mul(point[i]), proof.proofs[i]);
        // }
        let scalar_size = E::Fr::size_in_bits();
        let window_size = FixedBaseMSM::get_mul_window_size(vp.nv);
        // let timer = start_timer!(|| "MSM");
        let vp_g_table =
            FixedBaseMSM::get_window_table(scalar_size, window_size, vp.g.into_projective());
        let vp_g_mul: Vec<E::G1Projective> =
            FixedBaseMSM::multi_scalar_mul(scalar_size, window_size, &vp_g_table, point); // may have overhead
        // end_timer!(timer);
        // let timer = start_timer!(|| "Pairing");
        // let timer2 = start_timer!(|| "Calculating Left");
        let pairing_lefts: Vec<_> = (0..vp.nv)
            .map(|i| vp.g_mask_random[i].into_projective() - &vp_g_mul[i])
            .collect();
        let pairing_lefts: Vec<E::G1Affine> =
            E::G1Projective::batch_normalization_into_affine(&pairing_lefts);
        let pairing_lefts: Vec<E::G1Prepared> = pairing_lefts
            .into_iter()
            .map(|x| E::G1Prepared::from(x))
            .collect();
        // end_timer!(timer2);
        // let timer2 = start_timer!(|| "Calculating right");
        let pairing_rights: Vec<E::G2Prepared> = proof
            .proofs
            .into_iter()
            .map(|x| E::G2Prepared::from(x))
            .collect();
        // end_timer!(timer2);
        // let timer2 = start_timer!(|| "calculating product of pairing");
        let pairings: Vec<_> = pairing_lefts
            .into_iter()
            .zip(pairing_rights.into_iter())
            .collect();
        let right = E::product_of_pairings(pairings.iter());
        // end_timer!(timer2);
        // end_timer!(timer);
        Ok(left == right)
    }
}

#[cfg(test)]
mod sanity {
    use crate::test_utils::TestCurve;
    use crate::MLPolyCommit;
    use ark_ec::{AffineCurve, PairingEngine};
    use ark_ff::{test_rng, One};
    use ark_ff::{UniformRand, Zero};
    use linear_sumcheck::data_structures::ml_extension::MLExtension;
    use linear_sumcheck::data_structures::MLExtensionArray;

    type E = TestCurve;
    type Fr = <TestCurve as PairingEngine>::Fr;
    #[test]
    fn sanity() {
        let nv = 10;
        let mut rng1 = test_rng();
        let (pp, vp, s) = MLPolyCommit::<E>::keygen(nv, &mut rng1).unwrap();
        let poly =
            MLExtensionArray::from_vec((0..(1 << nv)).map(|_| Fr::rand(&mut rng1)).collect())
                .unwrap();
        let point: Vec<_> = (0..nv).map(|_| Fr::rand(&mut rng1)).collect();
        let com = MLPolyCommit::commit(&pp, poly.clone()).expect("cannot commit");
        let (ev, pf, q) = MLPolyCommit::open(&pp, poly.clone(), &point).expect("cannot open");
        {
            // test if q is correct
            let fx = poly.eval_at(&s).unwrap();
            let ft = poly.eval_at(&point).unwrap();
            let mut rhs = Fr::zero();
            let g = vp.g;
            let h = pp.h;
            let lhs_pair = E::pairing(com.g_product.into_projective() - &g.mul(ft), h);
            let mut rhs_pair = <E as PairingEngine>::Fqk::one();
            for i in 0..nv {
                let k = nv - i;
                let q_i: Vec<_> = (0..(1 << k)).map(|a| q[k][a >> 1]).collect();
                let q_i = MLExtensionArray::from_vec(q_i).unwrap();
                rhs += (s[i] - point[i]) * q_i.eval_at(&s[i..]).unwrap();
                assert_eq!(
                    h.mul(q_i.eval_at(&s[i..]).unwrap()),
                    pf.proofs[i],
                    "open error"
                );
                rhs_pair *=
                    E::pairing(g.mul(s[i] - point[i]), h.mul(q_i.eval_at(&s[i..]).unwrap()));
            }
            assert!(fx - ft == rhs); // hmm, q seems correct
            assert_eq!(lhs_pair, rhs_pair); // this one should also pass
        }

        let result = MLPolyCommit::verify(&vp, &com, &point, ev, pf).expect("cannot verify");
        assert!(result);
    }
}
