use anyhow::Result;
use hashbrown::HashMap;
use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    iop::{
        challenger::{Challenger, RecursiveChallenger},
        target::Target,
    },
    plonk::{
        circuit_builder::CircuitBuilder,
        config::{AlgebraicHasher, GenericConfig},
    },
};
use starky::{
    config::StarkConfig,
    cross_table_lookup::{
        verify_cross_table_lookups, verify_cross_table_lookups_circuit, CrossTableLookup,
        CtlCheckVars, CtlCheckVarsTarget,
    },
    lookup::{get_grand_product_challenge_set, get_grand_product_challenge_set_target},
    proof::{StarkProofWithMetadata, StarkProofWithPublicInputsTarget},
    recursive_verifier::{
        add_virtual_stark_proof_with_pis, verify_stark_proof_with_challenges_circuit,
    },
    stark::Stark,
    verifier::verify_stark_proof_with_challenges,
};

use super::ctl_values::{sum_ctl_values, sum_ctl_values_circuit};

pub(crate) fn verify<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    S: Stark<F, D>,
    const D: usize,
>(
    stark: &S,
    config: &StarkConfig,
    cross_table_lookups: &[CrossTableLookup<F>],
    proof: &StarkProofWithMetadata<F, C, D>,
    public_inputs: &[F],
    extra_looking_values: &HashMap<usize, Vec<Vec<F>>>,
) -> Result<()>
where
{
    let mut challenger = Challenger::<F, C::Hasher>::new();
    challenger.observe_cap(&proof.proof.trace_cap);
    for x in public_inputs.iter() {
        challenger.observe_element(*x);
    }
    let ctl_challenges = get_grand_product_challenge_set(&mut challenger, config.num_challenges);

    let num_lookup_columns = stark.num_lookup_helper_columns(config);
    let (_, _, num_helpers_by_ctl) = CrossTableLookup::num_ctl_helpers_zs_all(
        cross_table_lookups,
        0,
        config.num_challenges,
        stark.constraint_degree(),
    );
    let num_helper_ctl_columns = num_helpers_by_ctl
        .into_iter()
        .map(|x| [x])
        .collect::<Vec<_>>();
    let ctl_vars_per_table = CtlCheckVars::from_proofs(
        &[proof.clone()],
        cross_table_lookups,
        &ctl_challenges,
        &[num_lookup_columns],
        &num_helper_ctl_columns,
    );
    let ctl_vars = ctl_vars_per_table[0].clone();

    challenger.compact();
    let stark_challenges =
        proof
            .proof
            .get_challenges(&mut challenger, Some(&ctl_challenges), true, config);

    verify_stark_proof_with_challenges(
        stark,
        &proof.proof,
        &stark_challenges,
        Some(&ctl_vars),
        &public_inputs,
        config,
    )?;
    let extra_looking_sums =
        sum_ctl_values(config.num_challenges, &ctl_challenges, extra_looking_values);
    verify_cross_table_lookups::<F, D, 1>(
        cross_table_lookups,
        [proof.proof.openings.ctl_zs_first.clone().unwrap()],
        &extra_looking_sums,
        config,
    )?;

    Ok(())
}

/// Returns the recursive STARK circuit.
pub(crate) fn recursive_verifier<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    S: Stark<F, D>,
    const D: usize,
>(
    builder: &mut CircuitBuilder<F, D>,
    stark: &S,
    degree_bits: usize,
    cross_table_lookups: &[CrossTableLookup<F>],
    config: &StarkConfig,
    extra_looking_values: &HashMap<usize, Vec<Vec<Target>>>,
) -> StarkProofWithPublicInputsTarget<D>
where
    C::Hasher: AlgebraicHasher<F>,
{
    let num_lookup_columns = stark.num_lookup_helper_columns(config);
    let (total_num_helpers, num_ctl_zs, num_helpers_by_ctl) =
        CrossTableLookup::num_ctl_helpers_zs_all(
            cross_table_lookups,
            0,
            config.num_challenges,
            stark.constraint_degree(),
        );
    let num_ctl_helper_zs = num_ctl_zs + total_num_helpers;
    let stark_proof_with_pi_target = add_virtual_stark_proof_with_pis(
        builder,
        stark,
        config,
        degree_bits,
        num_ctl_helper_zs,
        num_ctl_zs,
    );
    let stark_proof_target = stark_proof_with_pi_target.proof.clone();

    let mut challenger = RecursiveChallenger::<F, C::Hasher, D>::new(builder);
    challenger.observe_cap(&stark_proof_target.trace_cap);
    for x in &stark_proof_with_pi_target.public_inputs {
        challenger.observe_element(*x);
    }
    let ctl_challenges =
        get_grand_product_challenge_set_target(builder, &mut challenger, config.num_challenges);
    let ctl_vars = CtlCheckVarsTarget::from_proof(
        0,
        &stark_proof_target,
        cross_table_lookups,
        &ctl_challenges,
        num_lookup_columns,
        total_num_helpers,
        &num_helpers_by_ctl,
    );
    let challenges = stark_proof_target.get_challenges::<F, C>(
        builder,
        &mut challenger,
        Some(&ctl_challenges),
        true,
        config,
    );
    challenger.compact(builder);
    verify_stark_proof_with_challenges_circuit::<F, C, _, D>(
        builder,
        stark,
        &stark_proof_target,
        &stark_proof_with_pi_target.public_inputs, // public inputs
        challenges,
        Some(&ctl_vars),
        config,
    );

    let extra_looking_sums = sum_ctl_values_circuit(
        builder,
        config.num_challenges,
        &ctl_challenges,
        extra_looking_values,
    );

    verify_cross_table_lookups_circuit(
        builder,
        cross_table_lookups.to_vec(),
        [stark_proof_target.openings.ctl_zs_first.clone().unwrap()],
        &extra_looking_sums,
        config,
    );
    stark_proof_with_pi_target
}

#[cfg(test)]
mod tests {
    use plonky2::{
        field::{extension::Extendable, types::Field},
        hash::hash_types::RichField,
        iop::{target::Target, witness::PartialWitness},
        plonk::{
            circuit_builder::CircuitBuilder,
            circuit_data::CircuitConfig,
            config::{GenericConfig, PoseidonGoldilocksConfig},
        },
        util::timing::TimingTree,
    };
    use starky::{config::StarkConfig, recursive_verifier::set_stark_proof_target};
    use tiny_keccak::keccakf;

    use crate::keccak_stark::{
        ctl_values::set_ctl_values_target,
        keccak_stark::{KeccakStark, NUM_INPUTS},
        prover::{keccak_ctls, prove},
        utils::transpose_and_flattten,
        verifier::{recursive_verifier, verify},
    };
    use hashbrown::HashMap;
    use starky::cross_table_lookup::debug_utils::check_ctls;

    #[test]
    fn recursive_keccak_circuit() {
        const NUM_PERMS: usize = 80;
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;
        type S = KeccakStark<F, D>;
        let stark = S::default();
        let config = StarkConfig::standard_fast_config();

        let input: Vec<([u64; NUM_INPUTS], usize)> =
            (0..NUM_PERMS).map(|i| (rand::random(), i)).collect();

        let mut timing = TimingTree::default();
        let trace = stark.generate_trace(input.clone(), 8, &mut timing);

        let cross_table_lookups = keccak_ctls::<F>();
        let proof = prove::<F, C, _, D>(
            &stark,
            &config,
            &trace,
            &cross_table_lookups,
            &[],
            &mut timing,
        )
        .unwrap();

        // ctl check
        let mut e = HashMap::new();
        {
            let extra_looking_values_input = input
                .iter()
                .map(|(input, timestamp)| {
                    transpose_and_flattten(input.clone())
                        .iter()
                        .map(|i| F::from_canonical_u32(*i))
                        .chain([F::from_canonical_u64(*timestamp as u64)])
                        .collect::<Vec<_>>()
                })
                .collect();
            e.insert(0, extra_looking_values_input);
            let output = input
                .iter()
                .map(|(state, timestamp)| {
                    let mut state = state.clone();
                    keccakf(&mut state);
                    (state, *timestamp)
                })
                .collect::<Vec<_>>();
            let extra_looking_values_output = output
                .iter()
                .map(|(input, timestamp)| {
                    transpose_and_flattten(input.clone())
                        .iter()
                        .map(|i| F::from_canonical_u32(*i))
                        .chain([F::from_canonical_u64(*timestamp as u64)])
                        .collect::<Vec<_>>()
                })
                .collect();
            e.insert(1, extra_looking_values_output);
        }
        check_ctls(&[trace.to_vec()], &cross_table_lookups, &e);
        verify(&stark, &config, &cross_table_lookups, &proof, &[], &e).unwrap();

        let degree_bits = proof.proof.recover_degree_bits(&config);
        let circuit_config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(circuit_config);
        let e_target = add_ctl_values_target(&mut builder, NUM_PERMS);
        let proof_t = recursive_verifier::<F, C, _, D>(
            &mut builder,
            &stark,
            degree_bits,
            &cross_table_lookups,
            &config,
            &e_target,
        );
        let zero = builder.zero();
        let mut pw = PartialWitness::new();
        set_stark_proof_target(&mut pw, &proof_t.proof, &proof.proof, zero);
        set_ctl_values_target(&mut pw, &e_target, &e);
        let circuit = builder.build::<C>();
        let circuit_proof = circuit.prove(pw).unwrap();
        circuit.verify(circuit_proof).unwrap();
    }

    fn add_ctl_values_target<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        num_perms: usize,
    ) -> HashMap<usize, Vec<Vec<Target>>> {
        let inputs = (0..num_perms)
            .map(|_| {
                [(); NUM_INPUTS * 2 + 1] // plus one for the timestamp
                    .map(|_| builder.add_virtual_target())
                    .to_vec()
            })
            .collect::<Vec<_>>();
        let outputs = (0..num_perms)
            .map(|_| {
                [(); NUM_INPUTS * 2 + 1] // // plus one for the timestamp
                    .map(|_| builder.add_virtual_target())
                    .to_vec()
            })
            .collect::<Vec<_>>();
        let mut ctl_values_target = HashMap::new();
        ctl_values_target.insert(0, inputs);
        ctl_values_target.insert(1, outputs);
        ctl_values_target
    }
}
