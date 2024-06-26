/*
MIT License

Copyright (c) Polygon Zero

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.

---
Original source: https://github.com/0xPolygonZero/zk_evm
*/

use plonky2::{
    field::{extension::Extendable, packed::PackedField, types::PrimeField64},
    hash::hash_types::RichField,
    iop::ext_target::ExtensionTarget,
    plonk::circuit_builder::CircuitBuilder,
};

pub(crate) fn xor<F: PrimeField64, const N: usize>(xs: [F; N]) -> F {
    xs.into_iter().fold(F::ZERO, |acc, x| {
        debug_assert!(x.is_zero() || x.is_one());
        F::from_canonical_u64(acc.to_canonical_u64() ^ x.to_canonical_u64())
    })
}

/// Computes the arithmetic generalization of `xor(x, y)`, i.e. `x + y - 2 x y`.
pub(crate) fn xor_gen<P: PackedField>(x: P, y: P) -> P {
    x + y - x * y.doubles()
}

/// Computes the arithmetic generalization of `xor3(x, y, z)`.
pub(crate) fn xor3_gen<P: PackedField>(x: P, y: P, z: P) -> P {
    xor_gen(x, xor_gen(y, z))
}

/// Computes the arithmetic generalization of `xor(x, y)`, i.e. `x + y - 2 x y`.
pub(crate) fn xor_gen_circuit<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    x: ExtensionTarget<D>,
    y: ExtensionTarget<D>,
) -> ExtensionTarget<D> {
    let sum = builder.add_extension(x, y);
    builder.arithmetic_extension(-F::TWO, F::ONE, x, y, sum)
}

/// Computes the arithmetic generalization of `xor(x, y)`, i.e. `x + y - 2 x y`.
pub(crate) fn xor3_gen_circuit<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    x: ExtensionTarget<D>,
    y: ExtensionTarget<D>,
    z: ExtensionTarget<D>,
) -> ExtensionTarget<D> {
    let x_xor_y = xor_gen_circuit(builder, x, y);
    xor_gen_circuit(builder, x_xor_y, z)
}

pub(crate) fn andn<F: PrimeField64>(x: F, y: F) -> F {
    debug_assert!(x.is_zero() || x.is_one());
    debug_assert!(y.is_zero() || y.is_one());
    let x = x.to_canonical_u64();
    let y = y.to_canonical_u64();
    F::from_canonical_u64(!x & y)
}

pub(crate) fn andn_gen<P: PackedField>(x: P, y: P) -> P {
    (P::ONES - x) * y
}

pub(crate) fn andn_gen_circuit<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    x: ExtensionTarget<D>,
    y: ExtensionTarget<D>,
) -> ExtensionTarget<D> {
    // (1 - x) y = -xy + y
    builder.arithmetic_extension(F::NEG_ONE, F::ONE, x, y, y)
}
