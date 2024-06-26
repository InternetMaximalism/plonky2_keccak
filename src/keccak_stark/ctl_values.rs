use hashbrown::HashMap;
use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    iop::{target::Target, witness::WitnessWrite},
    plonk::circuit_builder::CircuitBuilder,
};
use starky::lookup::GrandProductChallengeSet;

pub(crate) fn set_ctl_values_target<F: RichField, W: WitnessWrite<F>>(
    witness: &mut W,
    ctl_values_target: &HashMap<usize, Vec<Vec<Target>>>,
    ctl_values: &HashMap<usize, Vec<Vec<F>>>,
) {
    for index in 0..2 {
        let ctl_values_target = ctl_values_target.get(&index).unwrap();
        let ctl_values = ctl_values.get(&index).unwrap();
        assert_eq!(ctl_values_target.len(), ctl_values.len());
        for (ctl_t, ctl) in ctl_values_target.iter().zip(ctl_values.iter()) {
            assert_eq!(ctl_t.len(), ctl.len());
            for (ctl_t, ctl) in ctl_t.iter().zip(ctl.iter()) {
                witness.set_target(*ctl_t, *ctl);
            }
        }
    }
}

pub(crate) fn sum_ctl_values<F: RichField>(
    num_challenges: usize,
    ctl_challenges: &GrandProductChallengeSet<F>,
    ctl_values: &HashMap<usize, Vec<Vec<F>>>,
) -> HashMap<usize, Vec<F>> {
    let mut sums = HashMap::new();
    for (index, extra_looking_values) in ctl_values {
        let mut sum = vec![F::ZERO; num_challenges];
        for i in 0..num_challenges {
            for value in extra_looking_values {
                sum[i] += ctl_challenges.challenges[i].combine(value).inverse();
            }
        }
        sums.insert(*index, sum);
    }
    sums
}

pub(crate) fn sum_ctl_values_circuit<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    num_challenges: usize,
    ctl_challenges: &GrandProductChallengeSet<Target>,
    ctl_values: &HashMap<usize, Vec<Vec<Target>>>,
) -> HashMap<usize, Vec<Target>> {
    let mut sums = HashMap::new();
    for (index, extra_looking_values) in ctl_values {
        let mut sum = vec![builder.zero(); num_challenges];
        for i in 0..num_challenges {
            for value in extra_looking_values {
                let combined = ctl_challenges.challenges[i].combine_base_circuit(builder, &value);
                let inverse = builder.inverse(combined);
                sum[i] = builder.add(sum[i], inverse);
            }
        }
        sums.insert(*index, sum);
    }
    sums
}
