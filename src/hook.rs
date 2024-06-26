use core::{any::Any, marker::PhantomData};
use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    plonk::{
        circuit_builder::CircuitBuilder,
        config::{AlgebraicHasher, GenericConfig},
    },
    util::builder_hook::BuilderHook,
};

use crate::U32Target;

#[derive(Debug)]
pub struct KeccakHook<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize>
where
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    pub(crate) inputs: Vec<Vec<U32Target>>,
    pub(crate) outputs: Vec<[U32Target; 8]>,
    _marker: PhantomData<(F, C)>,
}

impl<F: RichField + Extendable<D>, C: GenericConfig<D, F = F> + 'static, const D: usize>
    KeccakHook<F, C, D>
where
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    pub fn new() -> Self {
        Self {
            inputs: vec![],
            outputs: vec![],
            _marker: PhantomData,
        }
    }
}

impl<F: RichField + Extendable<D>, C: GenericConfig<D, F = F> + 'static, const D: usize>
    BuilderHook<F, D> for KeccakHook<F, C, D>
where
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    #[cfg(not(feature = "not-constrain-keccak"))]
    fn constrain(&self, builder: &mut CircuitBuilder<F, D>) {
        use crate::generators::stark_proof_generator::Keccak256StarkProofGenerator;
        use plonky2::iop::generator::{SimpleGenerator as _, WitnessGeneratorRef};

        let generator = Keccak256StarkProofGenerator::<F, C, D>::new(builder, self.inputs.clone());
        for (xs, ys) in self.outputs.iter().zip(generator.outputs.iter()) {
            for (x, y) in xs.iter().zip(ys.iter()) {
                builder.connect(*x, *y);
            }
        }
        builder.add_generators(vec![WitnessGeneratorRef::new(generator.adapter())]);
    }

    #[cfg(feature = "not-constrain-keccak")]
    fn constrain(&self, _builder: &mut CircuitBuilder<F, D>) {}

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
}
