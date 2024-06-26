use hashbrown::HashMap;
use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    iop::{
        generator::{GeneratedValues, SimpleGenerator},
        target::Target,
        witness::{PartitionWitness, Witness as _, WitnessWrite as _},
    },
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::CommonCircuitData,
        config::{AlgebraicHasher, GenericConfig},
    },
    util::timing::TimingTree,
};
use starky::{
    config::StarkConfig, proof::StarkProofTarget, recursive_verifier::set_stark_proof_target,
};

use crate::{
    circuit_utils::solidity_keccak256_with_perm_io_circuit,
    keccak_stark::{
        ctl_values::set_ctl_values_target,
        keccak_stark::{KeccakStark, NUM_ROUNDS},
        prover::keccak_ctls,
        utils::unflatten_and_transpose,
        verifier::recursive_verifier,
    },
    utils::{solidity_keccak256_with_perm_io, BLOCK_SIZE},
};

#[derive(Debug)]
pub(crate) struct Keccak256StarkProofGenerator<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    const D: usize,
> {
    pub(crate) inputs: Vec<Vec<Target>>,
    pub(crate) outputs: Vec<[Target; 8]>,
    pub(crate) extra_looking_values: HashMap<usize, Vec<Vec<Target>>>,
    pub(crate) stark_proof: StarkProofTarget<D>,
    pub(crate) zero: Target, // used for set_stark_proof_target
    _config: std::marker::PhantomData<C>,
}

impl<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize>
    Keccak256StarkProofGenerator<F, C, D>
{
    pub(crate) fn new(builder: &mut CircuitBuilder<F, D>, inputs: Vec<Vec<Target>>) -> Self
    where
        C::Hasher: AlgebraicHasher<F>,
    {
        let num_perms: usize = inputs
            .iter()
            .map(|input| input.len() / BLOCK_SIZE + 1)
            .sum();
        let mut perm_inputs = vec![];
        let mut perm_outputs = vec![];
        let mut outputs = vec![];
        for input in inputs.iter() {
            let (output, perm_input, perm_output) =
                solidity_keccak256_with_perm_io_circuit(builder, input);
            outputs.push(output);
            perm_inputs.extend(perm_input);
            perm_outputs.extend(perm_output);
        }
        assert_eq!(perm_inputs.len(), num_perms);
        assert_eq!(perm_outputs.len(), num_perms);

        // generate extra_looking_values
        let mut extra_looking_values = HashMap::new();
        let perm_inputs_with_timestamp = perm_inputs
            .iter()
            .enumerate()
            .map(|(timestamp, perm_input)| {
                let mut perm_input = perm_input.clone();
                perm_input.push(builder.constant(F::from_canonical_usize(timestamp)));
                perm_input
            })
            .collect::<Vec<_>>();
        let perm_outputs_with_timestamp = perm_outputs
            .iter()
            .enumerate()
            .map(|(timestamp, perm_output)| {
                let mut perm_input = perm_output.clone();
                perm_input.push(builder.constant(F::from_canonical_usize(timestamp)));
                perm_input
            })
            .collect::<Vec<_>>();
        extra_looking_values.insert(0, perm_inputs_with_timestamp);
        extra_looking_values.insert(1, perm_outputs_with_timestamp);

        let degree_bits = (NUM_ROUNDS * num_perms)
            .next_power_of_two()
            .trailing_zeros() as usize;
        let stark = KeccakStark::<F, D>::new();
        let config = StarkConfig::standard_fast_config();

        let stark_proof = recursive_verifier::<F, C, _, D>(
            builder,
            &stark,
            degree_bits,
            &keccak_ctls(),
            &config,
            &extra_looking_values,
        );
        let zero = builder.zero();
        Self {
            inputs,
            outputs,
            stark_proof: stark_proof.proof,
            extra_looking_values,
            zero,
            _config: std::marker::PhantomData,
        }
    }
}

impl<F, C, const D: usize> SimpleGenerator<F, D> for Keccak256StarkProofGenerator<F, C, D>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    C::Hasher: AlgebraicHasher<F>,
{
    fn id(&self) -> String {
        "Keccak256StarkProofGenerator".to_string()
    }

    fn dependencies(&self) -> Vec<Target> {
        self.inputs
            .clone()
            .into_iter()
            .flatten()
            .collect::<Vec<_>>()
    }

    fn run_once(&self, pw: &PartitionWitness<F>, out_buffer: &mut GeneratedValues<F>) {
        let num_perms: usize = self
            .inputs
            .iter()
            .map(|input| input.len() / BLOCK_SIZE + 1)
            .sum();
        let inputs = self
            .inputs
            .iter()
            .map(|input| {
                input
                    .iter()
                    .map(|v| pw.get_target(*v).to_canonical_u64() as u32)
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        let mut outputs = vec![];
        let mut perm_inputs = vec![];
        let mut perm_outputs = vec![];
        for input in inputs.iter() {
            let (output, perm_input, perm_output) = solidity_keccak256_with_perm_io(&input);
            outputs.push(output);
            perm_inputs.extend(perm_input);
            perm_outputs.extend(perm_output);
        }
        assert_eq!(perm_inputs.len(), num_perms);
        assert_eq!(perm_outputs.len(), num_perms);

        // generate extra_looking_values
        let mut extra_looking_values = HashMap::new();
        let perm_inputs_with_timestamp = perm_inputs
            .iter()
            .enumerate()
            .map(|(timestamp, perm_input)| {
                let mut perm_input = perm_input
                    .into_iter()
                    .map(|a| F::from_canonical_u32(*a))
                    .collect::<Vec<_>>();
                perm_input.push(F::from_canonical_usize(timestamp));
                perm_input
            })
            .collect::<Vec<_>>();
        let perm_outputs_with_timestamp = perm_outputs
            .iter()
            .enumerate()
            .map(|(timestamp, perm_output)| {
                let mut perm_output = perm_output
                    .into_iter()
                    .map(|a| F::from_canonical_u32(*a))
                    .collect::<Vec<_>>();
                perm_output.push(F::from_canonical_usize(timestamp));
                perm_output
            })
            .collect::<Vec<_>>();
        extra_looking_values.insert(0, perm_inputs_with_timestamp);
        extra_looking_values.insert(1, perm_outputs_with_timestamp);
        for (targets, witnesses) in self.outputs.iter().zip(outputs.iter()) {
            assert_eq!(targets.len(), witnesses.len());
            for (target, witness) in targets.iter().zip(witnesses.iter()) {
                out_buffer.set_target(*target, F::from_canonical_u32(*witness));
            }
        }
        let keccak_stark_input = perm_inputs
            .iter()
            .enumerate()
            .map(|(timestamp, input)| (unflatten_and_transpose(input), timestamp))
            .collect::<Vec<_>>();
        let stark = KeccakStark::<F, D>::new();
        let config = StarkConfig::standard_fast_config();
        let mut timing = TimingTree::default();
        let cross_table_lookups = keccak_ctls::<F>();
        let trace = stark.generate_trace(keccak_stark_input, 8, &mut timing);
        let stark_proof = crate::keccak_stark::prover::prove::<F, C, _, D>(
            &stark,
            &config,
            &trace,
            &cross_table_lookups,
            &[],
            &mut TimingTree::default(),
        )
        .unwrap();
        crate::keccak_stark::verifier::verify(
            &stark,
            &config,
            &cross_table_lookups,
            &stark_proof,
            &[],
            &extra_looking_values,
        )
        .unwrap();
        set_stark_proof_target(out_buffer, &self.stark_proof, &stark_proof.proof, self.zero);
        set_ctl_values_target(
            out_buffer,
            &self.extra_looking_values,
            &extra_looking_values,
        );
    }

    fn serialize(
        &self,
        _dst: &mut Vec<u8>,
        _data: &CommonCircuitData<F, D>,
    ) -> plonky2::util::serialization::IoResult<()> {
        unimplemented!()
    }

    fn deserialize(
        _src: &mut plonky2::util::serialization::Buffer,
        _data: &CommonCircuitData<F, D>,
    ) -> plonky2::util::serialization::IoResult<Self> {
        unimplemented!()
    }
}

#[cfg(test)]
mod tests {

    use plonky2::{
        field::types::Field,
        iop::{generator::SimpleGenerator as _, witness::PartialWitness},
        plonk::{
            circuit_builder::CircuitBuilder,
            circuit_data::CircuitConfig,
            config::{GenericConfig, PoseidonGoldilocksConfig},
        },
    };

    use crate::{
        generators::{
            single_generator::Keccak256SingleGenerator,
            stark_proof_generator::Keccak256StarkProofGenerator,
        },
        keccak_stark::keccak_stark::NUM_INPUTS,
    };

    #[test]
    fn keccak256_stark_proof_generator() {
        const NUM_PERMS: usize = 1;
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;
        let inputs: Vec<[u32; NUM_INPUTS * 2]> = (0..NUM_PERMS)
            .map(|_| [(); NUM_INPUTS * 2].map(|_| rand::random()))
            .collect::<Vec<_>>();
        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::default());
        let inputs_t = inputs
            .iter()
            .map(|input| {
                input
                    .iter()
                    .map(|v| builder.constant(F::from_canonical_u32(*v)))
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        let _outputs_t = inputs_t
            .iter()
            .map(|input_t| {
                let output_t = [(); 8].map(|_| builder.add_virtual_target());
                let generator = Keccak256SingleGenerator {
                    input: input_t.to_vec(),
                    output: output_t,
                };
                builder.add_generators(vec![plonky2::iop::generator::WitnessGeneratorRef::new(
                    generator.adapter(),
                )]);
                output_t
            })
            .collect::<Vec<_>>();
        let generator = Keccak256StarkProofGenerator::<F, C, D>::new(&mut builder, inputs_t);
        builder.add_generators(vec![plonky2::iop::generator::WitnessGeneratorRef::new(
            generator.adapter(),
        )]);
        let pw = PartialWitness::new();
        let circuit = builder.build::<C>();
        circuit.prove(pw).unwrap();
    }
}
