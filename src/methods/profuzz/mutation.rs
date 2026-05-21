#![allow(dead_code)]

use rand::Rng;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ProfuzzMutation {
    BitFlip { width_bits: usize },
    Arith { width_bits: usize },
    RandomBitFlip,
    Interest { width_bits: usize },
}

pub(crate) fn deterministic_mutations(seed: &str) -> Vec<String> {
    let len = seed.len();
    let mut mutations = Vec::new();
    for mutation in mutation_plan(len) {
        match mutation {
            ProfuzzMutation::BitFlip { width_bits } => {
                mutations.extend(bitflip(seed, width_bits));
            }
            ProfuzzMutation::Arith { width_bits } => {
                mutations.extend(arith(seed, width_bits, 1));
            }
            ProfuzzMutation::RandomBitFlip | ProfuzzMutation::Interest { .. } => {}
        }
    }
    mutations
}

pub(crate) fn havoc_mutation<R: Rng + ?Sized>(seed: &str, rng: &mut R) -> Option<String> {
    let plan = mutation_plan(seed.len());
    if plan.is_empty() {
        return None;
    }
    let mutation = plan[rng.gen_range(0..plan.len())];
    match mutation {
        ProfuzzMutation::BitFlip { width_bits } => bitflip(seed, width_bits).into_iter().next(),
        ProfuzzMutation::Arith { width_bits } => {
            let delta = rng.gen_range(0..=36);
            arith(seed, width_bits, delta).into_iter().next()
        }
        ProfuzzMutation::RandomBitFlip => random_bitflip(seed, rng),
        ProfuzzMutation::Interest { width_bits } => random_interest(seed, width_bits, rng),
    }
}

pub(crate) fn mutation_plan(bit_len: usize) -> Vec<ProfuzzMutation> {
    match bit_len {
        0 | 1 => Vec::new(),
        2..=3 => vec![
            ProfuzzMutation::BitFlip { width_bits: 1 },
            ProfuzzMutation::BitFlip { width_bits: 2 },
            ProfuzzMutation::RandomBitFlip,
        ],
        4..=7 => vec![
            ProfuzzMutation::BitFlip { width_bits: 1 },
            ProfuzzMutation::BitFlip { width_bits: 2 },
            ProfuzzMutation::BitFlip { width_bits: 4 },
            ProfuzzMutation::RandomBitFlip,
        ],
        8..=15 => vec![
            ProfuzzMutation::BitFlip { width_bits: 1 },
            ProfuzzMutation::BitFlip { width_bits: 2 },
            ProfuzzMutation::BitFlip { width_bits: 4 },
            ProfuzzMutation::BitFlip { width_bits: 8 },
            ProfuzzMutation::Interest { width_bits: 8 },
            ProfuzzMutation::RandomBitFlip,
            ProfuzzMutation::Arith { width_bits: 8 },
        ],
        16..=31 => vec![
            ProfuzzMutation::BitFlip { width_bits: 1 },
            ProfuzzMutation::BitFlip { width_bits: 2 },
            ProfuzzMutation::BitFlip { width_bits: 4 },
            ProfuzzMutation::RandomBitFlip,
            ProfuzzMutation::BitFlip { width_bits: 8 },
            ProfuzzMutation::Interest { width_bits: 8 },
            ProfuzzMutation::Interest { width_bits: 16 },
            ProfuzzMutation::Arith { width_bits: 8 },
        ],
        _ => vec![
            ProfuzzMutation::BitFlip { width_bits: 16 },
            ProfuzzMutation::BitFlip { width_bits: 32 },
            ProfuzzMutation::Arith { width_bits: 8 },
            ProfuzzMutation::Arith { width_bits: 16 },
            ProfuzzMutation::Arith { width_bits: 32 },
            ProfuzzMutation::RandomBitFlip,
            ProfuzzMutation::Interest { width_bits: 8 },
            ProfuzzMutation::Interest { width_bits: 16 },
            ProfuzzMutation::Interest { width_bits: 32 },
        ],
    }
}

fn bitflip(seed: &str, width_bits: usize) -> Vec<String> {
    if seed.len() < width_bits {
        return Vec::new();
    }
    let mut outputs = Vec::new();
    for idx in 0..=seed.len() - width_bits {
        let mut bits: Vec<_> = seed.chars().collect();
        for offset in 0..width_bits {
            bits[idx + offset] = flip(bits[idx + offset]);
        }
        outputs.push(bits.into_iter().collect());
    }
    outputs
}

fn arith(seed: &str, width_bits: usize, delta: u64) -> Vec<String> {
    if seed.len() < width_bits {
        return Vec::new();
    }
    let mut outputs = Vec::new();
    let mask = if width_bits == 64 {
        u64::MAX
    } else {
        (1u64 << width_bits) - 1
    };
    for idx in 0..=seed.len() - width_bits {
        let Ok(value) = u64::from_str_radix(&seed[idx..idx + width_bits], 2) else {
            continue;
        };
        let replaced = format!("{:0width$b}", (value + delta) & mask, width = width_bits);
        let mut candidate = String::with_capacity(seed.len());
        candidate.push_str(&seed[..idx]);
        candidate.push_str(&replaced);
        candidate.push_str(&seed[idx + width_bits..]);
        outputs.push(candidate);
    }
    outputs
}

fn random_bitflip<R: Rng + ?Sized>(seed: &str, rng: &mut R) -> Option<String> {
    if seed.is_empty() {
        return None;
    }
    let mut bits: Vec<_> = seed.chars().collect();
    let idx = rng.gen_range(0..bits.len());
    bits[idx] = flip(bits[idx]);
    Some(bits.into_iter().collect())
}

fn random_interest<R: Rng + ?Sized>(seed: &str, width_bits: usize, rng: &mut R) -> Option<String> {
    if seed.len() < width_bits {
        return None;
    }
    let idx = rng.gen_range(0..=seed.len() - width_bits);
    let mut bits: Vec<_> = seed.chars().collect();
    for offset in 0..width_bits {
        bits[idx + offset] = if rng.gen_bool(0.5) { '1' } else { '0' };
    }
    Some(bits.into_iter().collect())
}

fn flip(bit: char) -> char {
    match bit {
        '0' => '1',
        '1' => '0',
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use rand::{SeedableRng, rngs::StdRng};

    use super::{ProfuzzMutation, deterministic_mutations, havoc_mutation, mutation_plan};

    #[test]
    fn chooses_script_matching_mutation_plan_by_length() {
        assert_eq!(
            mutation_plan(3),
            vec![
                ProfuzzMutation::BitFlip { width_bits: 1 },
                ProfuzzMutation::BitFlip { width_bits: 2 },
                ProfuzzMutation::RandomBitFlip,
            ]
        );
        assert!(mutation_plan(32).contains(&ProfuzzMutation::Arith { width_bits: 32 }));
    }

    #[test]
    fn deterministic_bit_mutations_generate_candidates() {
        let outputs = deterministic_mutations("0000");
        assert!(outputs.contains(&"1000".to_string()));
        assert!(outputs.contains(&"1100".to_string()));
        assert!(outputs.contains(&"1111".to_string()));
    }

    #[test]
    fn havoc_preserves_seed_length() {
        let mut rng = StdRng::seed_from_u64(11);
        let output = havoc_mutation("0101010101010101", &mut rng).unwrap();
        assert_eq!(output.len(), 16);
    }
}
