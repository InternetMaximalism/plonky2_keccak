use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    iop::target::{BoolTarget, Target},
    plonk::circuit_builder::CircuitBuilder,
};

use crate::{
    utils::{Keccak256Result, BLOCK_SIZE},
    U32Target,
};

/// Circuit version of `solidity_keccak256_with_perm_io` without keccakf
/// constraints. Computes the keccak256 hash according to the Solidity
/// specification. Both input and output are in big-endian format.
pub(crate) fn solidity_keccak256_with_perm_io_circuit<
    F: RichField + Extendable<D>,
    const D: usize,
>(
    builder: &mut CircuitBuilder<F, D>,
    input: &[U32Target],
) -> ([U32Target; 8], Vec<Vec<Target>>, Vec<Vec<Target>>) {
    let input = input
        .iter()
        .map(|v| {
            let w = builder.split_le(*v, 32);
            builder.le_sum(w.chunks(8).rev().flatten())
        })
        .collect::<Vec<_>>();
    let result = keccak256_circuit(builder, input);
    let output = result
        .output
        .iter()
        .map(|v| {
            let w = builder.split_le(*v, 32);
            builder.le_sum(w.chunks(8).rev().flatten())
        })
        .collect::<Vec<_>>();
    (
        output.try_into().unwrap(),
        result.perm_inputs,
        result.perm_outputs,
    )
}

///  circuit version of `keccak256` without keccakf constraints
fn keccak256_circuit<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    input: Vec<U32Target>,
) -> Keccak256Result<U32Target> {
    let mut perm_inputs = vec![];
    let mut perm_outputs = vec![];
    let zero = builder.zero();
    let one = builder.one();
    let c = builder.constant(F::from_canonical_u32(0x80 << 24));
    let num_blocks = input.len() / BLOCK_SIZE + 1;
    let mut padded = vec![zero; BLOCK_SIZE * num_blocks];
    padded[0..input.len()].copy_from_slice(&input);
    padded[input.len()] = one;
    *padded.last_mut().unwrap() = xor_circuit(builder, *padded.last().unwrap(), c);
    let mut state = [zero; 50];
    for i in 0..num_blocks {
        for j in 0..BLOCK_SIZE {
            state[j] = xor_circuit(builder, state[j], padded[i * BLOCK_SIZE + j]);
        }
        let input = state;
        let output = [(); 50].map(|_| builder.add_virtual_target());
        perm_inputs.push(input.to_vec());
        perm_outputs.push(output.to_vec());
        state = output;
    }
    Keccak256Result {
        output: state[0..8].try_into().unwrap(),
        perm_inputs,
        perm_outputs,
    }
}

/// Computes xor of two targets, assuming they are 32-bit integers.
fn xor_circuit<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    x: U32Target,
    y: U32Target,
) -> U32Target {
    let x_bit = builder.split_le(x, 32);
    let y_bit = builder.split_le(y, 32);
    let z_bit = x_bit
        .iter()
        .zip(y_bit.iter())
        .map(|(&x, &y)| {
            let sum = builder.add(x.target, y.target);
            let z = builder.arithmetic(-F::TWO, F::ONE, x.target, y.target, sum);
            BoolTarget::new_unsafe(z)
        })
        .collect::<Vec<_>>();
    builder.le_sum(z_bit.into_iter())
}
