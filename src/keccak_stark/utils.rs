use super::keccak_stark::NUM_INPUTS;

#[cfg(test)]
pub(crate) fn transpose_and_flattten(input: [u64; NUM_INPUTS]) -> [u32; 2 * NUM_INPUTS] {
    let mut res = [0; 2 * NUM_INPUTS];
    for x in 0..5 {
        for y in 0..5 {
            let input_xy = input[y * 5 + x];
            let lo = (x + y * 5) * 2; // transpose here
            let hi = lo + 1;
            res[lo] = (input_xy & 0xFFFFFFFF) as u32;
            res[hi] = (input_xy >> 32) as u32;
        }
    }
    res
}

pub(crate) fn unflatten_and_transpose(input: &[u32]) -> [u64; NUM_INPUTS] {
    assert_eq!(input.len(), 2 * NUM_INPUTS);
    let mut res = [0; NUM_INPUTS];
    for x in 0..5 {
        for y in 0..5 {
            let lo = (x + y * 5) * 2;
            let hi = lo + 1;
            let input_xy = (input[hi] as u64) << 32 | input[lo] as u64;
            res[y * 5 + x] = input_xy; // transpose here
        }
    }
    res
}
