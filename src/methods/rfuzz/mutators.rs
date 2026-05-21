#![allow(dead_code)]

use rand::Rng;

use super::input::RfuzzInputLayout;

const ARITH_MAX: i64 = 35;
const INTERESTING_8: &[i8] = &[-128, -1, 0, 1, 16, 32, 64, 100, 127];
const INTERESTING_16: &[i16] = &[
    -32768, -129, -128, -1, 0, 1, 16, 32, 64, 100, 127, 128, 255, 256, 32767,
];
const INTERESTING_32: &[i32] = &[
    i32::MIN,
    -32769,
    -32768,
    -129,
    -128,
    -1,
    0,
    1,
    16,
    32,
    64,
    100,
    127,
    128,
    255,
    256,
    32767,
    32768,
    i32::MAX,
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DeterministicMutation {
    BitFlip { width_bits: usize, step_bits: usize },
    Arith { width_bytes: usize },
}

pub(crate) fn deterministic_mutations(input: &[u8], layout: &RfuzzInputLayout) -> Vec<Vec<u8>> {
    let mut outputs = Vec::new();
    for mutation in [
        DeterministicMutation::BitFlip {
            width_bits: 1,
            step_bits: 1,
        },
        DeterministicMutation::BitFlip {
            width_bits: 2,
            step_bits: 1,
        },
        DeterministicMutation::BitFlip {
            width_bits: 4,
            step_bits: 1,
        },
        DeterministicMutation::BitFlip {
            width_bits: 8,
            step_bits: 8,
        },
        DeterministicMutation::BitFlip {
            width_bits: 16,
            step_bits: 8,
        },
        DeterministicMutation::BitFlip {
            width_bits: 32,
            step_bits: 8,
        },
        DeterministicMutation::Arith { width_bytes: 1 },
        DeterministicMutation::Arith { width_bytes: 2 },
        DeterministicMutation::Arith { width_bytes: 4 },
    ] {
        outputs.extend(apply_deterministic_mutation(input, layout, mutation));
    }
    outputs
}

pub(crate) fn apply_deterministic_mutation(
    input: &[u8],
    layout: &RfuzzInputLayout,
    mutation: DeterministicMutation,
) -> Vec<Vec<u8>> {
    match mutation {
        DeterministicMutation::BitFlip {
            width_bits,
            step_bits,
        } => bitflip_mutations(input, layout, width_bits, step_bits),
        DeterministicMutation::Arith { width_bytes } => arith_mutations(input, layout, width_bytes),
    }
}

fn bitflip_mutations(
    input: &[u8],
    layout: &RfuzzInputLayout,
    width_bits: usize,
    step_bits: usize,
) -> Vec<Vec<u8>> {
    let total_bits = input.len() * 8;
    if total_bits < width_bits {
        return Vec::new();
    }

    let mut outputs = Vec::new();
    for bit in (0..=total_bits - width_bits).step_by(step_bits) {
        let mut candidate = input.to_vec();
        for offset in 0..width_bits {
            flip_bit(&mut candidate, bit + offset);
        }
        outputs.push(layout.normalize(candidate));
    }
    outputs
}

fn arith_mutations(input: &[u8], layout: &RfuzzInputLayout, width_bytes: usize) -> Vec<Vec<u8>> {
    if input.len() < width_bytes {
        return Vec::new();
    }

    let mut outputs = Vec::new();
    for offset in 0..=input.len() - width_bytes {
        for delta in 1..=ARITH_MAX {
            for add in [false, true] {
                let mut le = input.to_vec();
                mutate_integer(&mut le[offset..offset + width_bytes], delta, add, false);
                outputs.push(layout.normalize(le));

                if width_bytes > 1 {
                    let mut be = input.to_vec();
                    mutate_integer(&mut be[offset..offset + width_bytes], delta, add, true);
                    outputs.push(layout.normalize(be));
                }
            }
        }
    }
    outputs
}

pub(crate) fn havoc_mutation<R: Rng + ?Sized>(
    input: &[u8],
    layout: &RfuzzInputLayout,
    rng: &mut R,
) -> Vec<u8> {
    let mut candidate = input.to_vec();
    let stacked = rng.gen_range(2..=128);
    for _ in 0..stacked {
        apply_havoc_step(&mut candidate, rng);
        if candidate.is_empty() {
            candidate.push(0);
        }
    }
    layout.normalize(candidate)
}

fn apply_havoc_step<R: Rng + ?Sized>(bytes: &mut Vec<u8>, rng: &mut R) {
    match rng.gen_range(0..10) {
        0 => {
            let bit = rng.gen_range(0..bytes.len() * 8);
            flip_bit(bytes, bit);
        }
        1 => {
            let idx = rng.gen_range(0..bytes.len());
            bytes[idx] = rng.r#gen();
        }
        2 => overwrite_interesting_8(bytes, rng),
        3 => overwrite_interesting_16(bytes, rng),
        4 => overwrite_interesting_32(bytes, rng),
        5 => random_arith(bytes, rng, 1),
        6 => random_arith(bytes, rng, 2),
        7 => random_arith(bytes, rng, 4),
        8 => delete_random_range(bytes, rng),
        _ => clone_or_overwrite_range(bytes, rng),
    }
}

fn flip_bit(bytes: &mut [u8], bit: usize) {
    bytes[bit / 8] ^= 1 << (bit % 8);
}

fn mutate_integer(bytes: &mut [u8], delta: i64, add: bool, big_endian: bool) {
    let mut value = read_int(bytes, big_endian);
    if add {
        value = value.wrapping_add(delta as u64);
    } else {
        value = value.wrapping_sub(delta as u64);
    }
    write_int(bytes, value, big_endian);
}

fn read_int(bytes: &[u8], big_endian: bool) -> u64 {
    let mut value = 0u64;
    if big_endian {
        for byte in bytes {
            value = (value << 8) | *byte as u64;
        }
    } else {
        for (idx, byte) in bytes.iter().enumerate() {
            value |= (*byte as u64) << (idx * 8);
        }
    }
    value
}

fn write_int(bytes: &mut [u8], value: u64, big_endian: bool) {
    let len = bytes.len();
    for (idx, byte) in bytes.iter_mut().enumerate() {
        let shift = if big_endian {
            (len - idx - 1) * 8
        } else {
            idx * 8
        };
        *byte = ((value >> shift) & 0xff) as u8;
    }
}

fn overwrite_interesting_8<R: Rng + ?Sized>(bytes: &mut [u8], rng: &mut R) {
    let idx = rng.gen_range(0..bytes.len());
    bytes[idx] = INTERESTING_8[rng.gen_range(0..INTERESTING_8.len())] as u8;
}

fn overwrite_interesting_16<R: Rng + ?Sized>(bytes: &mut [u8], rng: &mut R) {
    if bytes.len() < 2 {
        overwrite_interesting_8(bytes, rng);
        return;
    }
    let idx = rng.gen_range(0..=bytes.len() - 2);
    let value = INTERESTING_16[rng.gen_range(0..INTERESTING_16.len())];
    bytes[idx..idx + 2].copy_from_slice(&value.to_le_bytes());
}

fn overwrite_interesting_32<R: Rng + ?Sized>(bytes: &mut [u8], rng: &mut R) {
    if bytes.len() < 4 {
        overwrite_interesting_16(bytes, rng);
        return;
    }
    let idx = rng.gen_range(0..=bytes.len() - 4);
    let value = INTERESTING_32[rng.gen_range(0..INTERESTING_32.len())];
    bytes[idx..idx + 4].copy_from_slice(&value.to_le_bytes());
}

fn random_arith<R: Rng + ?Sized>(bytes: &mut [u8], rng: &mut R, width_bytes: usize) {
    if bytes.len() < width_bytes {
        return;
    }
    let idx = rng.gen_range(0..=bytes.len() - width_bytes);
    let delta = rng.gen_range(1..=ARITH_MAX);
    let add = rng.gen_bool(0.5);
    let big_endian = width_bytes > 1 && rng.gen_bool(0.5);
    mutate_integer(&mut bytes[idx..idx + width_bytes], delta, add, big_endian);
}

fn delete_random_range<R: Rng + ?Sized>(bytes: &mut Vec<u8>, rng: &mut R) {
    if bytes.len() <= 1 {
        return;
    }
    let start = rng.gen_range(0..bytes.len());
    let max_len = bytes.len() - start;
    let len = rng.gen_range(1..=max_len);
    bytes.drain(start..start + len);
}

fn clone_or_overwrite_range<R: Rng + ?Sized>(bytes: &mut Vec<u8>, rng: &mut R) {
    if bytes.is_empty() {
        return;
    }
    let src = rng.gen_range(0..bytes.len());
    let len = rng.gen_range(1..=bytes.len() - src);
    let fragment = bytes[src..src + len].to_vec();
    let dst = rng.gen_range(0..=bytes.len());
    if rng.gen_bool(0.5) {
        bytes.splice(dst..dst, fragment);
    } else {
        let overwrite_len = fragment.len().min(bytes.len() - dst.min(bytes.len()));
        if overwrite_len == 0 {
            bytes.extend(fragment);
        } else {
            bytes[dst..dst + overwrite_len].copy_from_slice(&fragment[..overwrite_len]);
        }
    }
}

#[cfg(test)]
mod tests {
    use rand::{SeedableRng, rngs::StdRng};

    use super::{
        DeterministicMutation, apply_deterministic_mutation, deterministic_mutations,
        havoc_mutation,
    };
    use crate::methods::rfuzz::input::RfuzzInputLayout;

    #[test]
    fn bitflip_1_1_generates_one_child_per_bit() {
        let layout = RfuzzInputLayout::new(8, None);
        let children = apply_deterministic_mutation(
            &[0],
            &layout,
            DeterministicMutation::BitFlip {
                width_bits: 1,
                step_bits: 1,
            },
        );
        assert_eq!(children.len(), 8);
        assert_eq!(children[0], vec![0b0000_0001]);
        assert_eq!(children[7], vec![0b1000_0000]);
    }

    #[test]
    fn bitflip_16_8_steps_by_byte() {
        let layout = RfuzzInputLayout::new(8, None);
        let children = apply_deterministic_mutation(
            &[0, 0, 0],
            &layout,
            DeterministicMutation::BitFlip {
                width_bits: 16,
                step_bits: 8,
            },
        );
        assert_eq!(children, vec![vec![0xff, 0xff, 0], vec![0, 0xff, 0xff]]);
    }

    #[test]
    fn arith_8_generates_add_and_sub_for_each_delta() {
        let layout = RfuzzInputLayout::new(8, None);
        let children = apply_deterministic_mutation(
            &[10],
            &layout,
            DeterministicMutation::Arith { width_bytes: 1 },
        );
        assert_eq!(children.len(), 70);
        assert!(children.contains(&vec![9]));
        assert!(children.contains(&vec![11]));
        assert!(children.contains(&vec![45]));
    }

    #[test]
    fn deterministic_stage_normalizes_children() {
        let layout = RfuzzInputLayout::new(17, None);
        let children = deterministic_mutations(&[0xaa], &layout);
        assert!(children.iter().all(|child| child.len() % 3 == 0));
    }

    #[test]
    fn havoc_normalizes_and_preserves_non_empty_input() {
        let layout = RfuzzInputLayout::new(17, Some(4));
        let mut rng = StdRng::seed_from_u64(7);
        let child = havoc_mutation(&[1, 2, 3, 4], &layout, &mut rng);
        assert!(!child.is_empty());
        assert_eq!(child.len() % 3, 0);
        assert!(child.len() <= 12);
    }
}
