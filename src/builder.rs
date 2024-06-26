use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    iop::generator::SimpleGenerator as _,
    plonk::{
        circuit_builder::CircuitBuilder,
        config::{AlgebraicHasher, GenericConfig},
    },
    util::builder_hook::BuilderHookRef,
};

const KECCAK_HOOK_KEY: &str = "keccak hook";

use crate::{generators::single_generator::Keccak256SingleGenerator, hook::KeccakHook, U32Target};

pub trait BuilderKeccak256<F: RichField + Extendable<D>, const D: usize> {
    fn keccak256<C: GenericConfig<D, F = F> + 'static>(
        &mut self,
        input: &[U32Target],
    ) -> [U32Target; 8]
    where
        <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>;
}

impl<F: RichField + Extendable<D>, const D: usize> BuilderKeccak256<F, D> for CircuitBuilder<F, D> {
    /// Computes the keccak256 hash according to the Solidity specification.
    /// Both input and output are in big-endian format.
    /// NOTICE: It is necessary to additionally constrain each limb of the input
    /// to be 32 bits.
    fn keccak256<C: GenericConfig<D, F = F> + 'static>(
        &mut self,
        input: &[U32Target],
    ) -> [U32Target; 8]
    where
        <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
    {
        if self.get_hook(KECCAK_HOOK_KEY).is_none() {
            let hook = BuilderHookRef::new(KeccakHook::<F, C, D>::new());
            self.add_hook(KECCAK_HOOK_KEY, hook);
        }
        let output: [U32Target; 8] = [(); 8].map(|_| self.add_virtual_target());
        let hook = self
            .get_hook_mut(KECCAK_HOOK_KEY)
            .unwrap()
            .0
            .as_any_mut()
            .downcast_mut::<KeccakHook<F, C, D>>()
            .unwrap();
        hook.inputs.push(input.to_vec());
        hook.outputs.push(output);
        let generator = Keccak256SingleGenerator {
            input: input.to_vec(),
            output,
        };
        self.add_generators(vec![plonky2::iop::generator::WitnessGeneratorRef::new(
            generator.adapter(),
        )]);
        output
    }
}

#[cfg(test)]
mod tests {
    use crate::{builder::BuilderKeccak256 as _, utils::solidity_keccak256};
    use plonky2::{
        field::types::Field,
        iop::witness::{PartialWitness, WitnessWrite},
        plonk::{
            circuit_builder::CircuitBuilder,
            circuit_data::CircuitConfig,
            config::{GenericConfig, PoseidonGoldilocksConfig},
        },
    };
    use rand::Rng;

    #[test]
    fn keccak_builder() {
        let num_inputs = 10;
        let inputs_random_len_range = 10..=10;
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;
        let mut rng = rand::thread_rng();
        let inputs: Vec<Vec<u32>> = (0..num_inputs)
            .map(|_| {
                let random_len = rng.gen_range(inputs_random_len_range.clone());
                (0..random_len)
                    .map(|_| rng.gen::<u32>())
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        let expected_outputs = inputs
            .iter()
            .map(|input| solidity_keccak256(input))
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
        let outputs_t = inputs_t
            .iter()
            .map(|input_t| builder.keccak256::<C>(input_t))
            .collect::<Vec<_>>();
        let mut pw = PartialWitness::new();
        for (ouput_t, output) in outputs_t.iter().zip(expected_outputs.iter()) {
            for (t, w) in ouput_t.iter().zip(output.iter()) {
                pw.set_target(*t, F::from_canonical_u32(*w));
            }
        }
        let circuit = builder.build::<C>();
        circuit.prove(pw).unwrap();
    }
}
