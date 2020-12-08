use crate::MLArgumentForR1CS;
use ark_ff::test_rng;
use ark_relations::r1cs::ConstraintMatrices;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

use crate::data_structures::proof::Proof;
use crate::test_utils::{generate_circuit_with_random_input, TestCurve, TestCurveFr};
use ark_ec::PairingEngine;
use crate::ahp::MLProofForR1CS;

fn test_circuit<E: PairingEngine>(
    matrices: ConstraintMatrices<E::Fr>,
    v: Vec<E::Fr>,
    w: Vec<E::Fr>,
) -> Result<(), crate::Error> {
    #[cfg(feature="print-trace")]
    let config_str = format!(
        " (|v| = {}, |w| = {}, #non-zero-entries = {})",
        matrices.num_instance_variables,
        matrices.num_witness_variables,
        matrices.a_num_non_zero + matrices.b_num_non_zero + matrices.c_num_non_zero
    );

    let mut rng = test_rng();

    let timer = start_timer!(|| format!("Setup{}", config_str));
    let (pp, vp) = MLProofForR1CS::setup(ark_std::log2(matrices.a.len()) as usize, &mut rng)?;
        end_timer!(timer);

    let timer = start_timer!(|| format!("Index{}", config_str));
    let index_pk = MLArgumentForR1CS::<E>::index(matrices.a, matrices.b, matrices.c)?;
    let index_vk = index_pk.vk();
        end_timer!(timer);
    let timer = start_timer!(|| format!("Prove{}", config_str));
    let proof = MLArgumentForR1CS::<E>::prove(index_pk, v.to_vec(), w, &pp)?;
    let proof_serialized = {
        let mut data: Vec<u8> = Vec::new();
        proof.serialize(&mut data)?;
        data
    };
    end_timer!(timer);
    // test communication cost
    println!("Communication Cost: {} bytes", proof_serialized.len());
    let timer = start_timer!(|| format!("Verify{}", config_str));
    let proof = Proof::<E>::deserialize(&proof_serialized[..])?;
    let result = MLArgumentForR1CS::verify(index_vk, v, proof, &vp)?;
    assert!(result);
    end_timer!(timer);
    Ok(())
}

#[test]
#[ignore]
fn benchmark() {
    type E = TestCurve;
    type F = TestCurveFr;
    let mut rng = test_rng();


    println!(
        "Benchmark: Prover and Verifier Runtime with different matrix size with same sparsity\n"
    );
    for i in 7..16 {
        let (r1cs, v, w) =
            generate_circuit_with_random_input::<F, _>(32, (2 << i) - 32, true, 0, &mut rng);

        test_circuit::<E>(r1cs.to_matrices().unwrap(), v, w).expect("Failed to test circuit");
    }
    println!(
        "Benchmark: Prover and Verifier Runtime with same matrix size with different sparsity\n"
    );
    for i in 0..10 {
        let density = (255 * i / 10) as u8;
        let (r1cs, v, w) =
            generate_circuit_with_random_input::<F, _>(32, (2 << 10) - 32, true, density, &mut rng);

        test_circuit::<E>(r1cs.to_matrices().unwrap(), v, w).expect("Failed to test circuit");
    }
}
