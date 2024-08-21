use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    iop::{
        generator::{GeneratedValues, SimpleGenerator},
        target::Target,
        witness::{PartitionWitness, Witness as _, WitnessWrite as _},
    },
    plonk::circuit_data::CommonCircuitData,
    util::serialization::{Read, Write},
};

use crate::{utils::solidity_keccak256, U32Target};

#[derive(Clone, Debug, Default)]
pub struct Keccak256SingleGenerator {
    pub(crate) input: Vec<U32Target>,
    pub(crate) output: [U32Target; 8],
}

impl<F: RichField + Extendable<D>, const D: usize> SimpleGenerator<F, D>
    for Keccak256SingleGenerator
{
    fn id(&self) -> String {
        "Keccak256SingleGenerator".to_string()
    }

    fn dependencies(&self) -> Vec<Target> {
        self.input.to_vec()
    }

    // NOTICE: not generate constraints for the hash
    fn run_once(&self, pw: &PartitionWitness<F>, out_buffer: &mut GeneratedValues<F>) {
        let input = self
            .input
            .iter()
            .map(|v| pw.get_target(*v).to_canonical_u64() as u32)
            .collect::<Vec<_>>();
        let output = solidity_keccak256(&input);
        assert_eq!(self.output.len(), output.len());
        for (target, witness) in self.output.iter().zip(output) {
            out_buffer.set_target(*target, F::from_canonical_u32(witness));
        }
    }

    fn serialize(
        &self,
        dst: &mut Vec<u8>,
        _data: &CommonCircuitData<F, D>,
    ) -> plonky2::util::serialization::IoResult<()> {
        dst.write_target_vec(&self.input)?;
        dst.write_target_array(&self.output)?;

        Ok(())
    }

    fn deserialize(
        src: &mut plonky2::util::serialization::Buffer,
        _data: &CommonCircuitData<F, D>,
    ) -> plonky2::util::serialization::IoResult<Self> {
        let input = src.read_target_vec().unwrap();
        let output = src.read_target_array::<8>().unwrap();

        Ok(Self { input, output })
    }
}
