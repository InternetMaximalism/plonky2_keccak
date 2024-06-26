# plonky2_keccak

This is a circuit gadget for plonky2 that calculates keccak256 compliant with Solidity.
It combines multiple permutations of keccak256 and proves them with starky.

# Usage

```rust
let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::default());
let input_target = (0..10).map(|_| builder.add_virtual_target()).collect::<Vec<_>>();
let output_target = builder.keccak256::<C>(&input_target);
```
