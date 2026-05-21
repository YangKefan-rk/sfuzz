#![allow(dead_code)]

use std::fmt::{Display, Formatter};

use crate::seed::{
    InterruptEvent, InterruptKind, InterruptTrigger, SeedMetadata, SharedMemorySegment,
    StructuredSeed,
};

const MAGIC: &[u8; 4] = b"SFUZ";
const VERSION: u16 = 1;

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum SeedCodecError {
    UnexpectedEof,
    InvalidMagic([u8; 4]),
    UnsupportedVersion(u16),
    InvalidUtf8,
    InvalidInterruptKind(u8),
    InvalidTriggerKind(u8),
    LengthOverflow(&'static str),
}

impl Display for SeedCodecError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnexpectedEof => write!(f, "unexpected end of structured seed buffer"),
            Self::InvalidMagic(found) => write!(f, "invalid structured seed magic: {found:?}"),
            Self::UnsupportedVersion(version) => {
                write!(f, "unsupported structured seed version: {version}")
            }
            Self::InvalidUtf8 => write!(f, "invalid utf-8 in structured seed metadata"),
            Self::InvalidInterruptKind(kind) => write!(f, "invalid interrupt kind: {kind}"),
            Self::InvalidTriggerKind(kind) => write!(f, "invalid trigger kind: {kind}"),
            Self::LengthOverflow(field) => write!(f, "length overflow while encoding {field}"),
        }
    }
}

impl std::error::Error for SeedCodecError {}

pub(crate) fn encode_seed(seed: &StructuredSeed) -> Result<Vec<u8>, SeedCodecError> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(MAGIC);
    push_u16(&mut bytes, VERSION);
    push_u16(&mut bytes, 0);

    push_blob(&mut bytes, &seed.core0_prog, "core0_prog")?;
    push_blob(&mut bytes, &seed.core1_prog, "core1_prog")?;

    push_u32(
        &mut bytes,
        to_u32(seed.shared_mem_init.len(), "shared_mem_init_count")?,
    );
    for segment in &seed.shared_mem_init {
        push_u64(&mut bytes, segment.base_addr);
        push_blob(&mut bytes, &segment.bytes, "shared_mem_segment")?;
    }

    push_u32(
        &mut bytes,
        to_u32(seed.interrupt_plan.len(), "interrupt_plan_count")?,
    );
    for event in &seed.interrupt_plan {
        bytes.push(event.hart_id);
        bytes.push(interrupt_kind_to_u8(event.interrupt));
        match event.trigger {
            InterruptTrigger::Cycle(value) => {
                bytes.push(0);
                bytes.push(0);
                push_u64(&mut bytes, value);
            }
            InterruptTrigger::RetiredInstructions(value) => {
                bytes.push(1);
                bytes.push(0);
                push_u64(&mut bytes, value);
            }
        }
        push_u32(&mut bytes, event.duration_cycles);
        push_u64(&mut bytes, event.value);
    }

    push_string(&mut bytes, &seed.metadata.name, "metadata.name")?;
    push_string(
        &mut bytes,
        &seed.metadata.description,
        "metadata.description",
    )?;
    push_u32(
        &mut bytes,
        to_u32(seed.metadata.tags.len(), "metadata.tags")?,
    );
    for tag in &seed.metadata.tags {
        push_string(&mut bytes, tag, "metadata.tag")?;
    }

    Ok(bytes)
}

pub(crate) fn decode_seed(bytes: &[u8]) -> Result<StructuredSeed, SeedCodecError> {
    let mut decoder = Decoder::new(bytes);

    let magic = decoder.read_array::<4>()?;
    if &magic != MAGIC {
        return Err(SeedCodecError::InvalidMagic(magic));
    }

    let version = decoder.read_u16()?;
    if version != VERSION {
        return Err(SeedCodecError::UnsupportedVersion(version));
    }
    let _reserved = decoder.read_u16()?;

    let core0_prog = decoder.read_blob()?;
    let core1_prog = decoder.read_blob()?;

    let mut shared_mem_init = Vec::new();
    let shared_count = decoder.read_u32()? as usize;
    for _ in 0..shared_count {
        shared_mem_init.push(SharedMemorySegment {
            base_addr: decoder.read_u64()?,
            bytes: decoder.read_blob()?,
        });
    }

    let mut interrupt_plan = Vec::new();
    let interrupt_count = decoder.read_u32()? as usize;
    for _ in 0..interrupt_count {
        let hart_id = decoder.read_u8()?;
        let interrupt = u8_to_interrupt_kind(decoder.read_u8()?)?;
        let trigger_kind = decoder.read_u8()?;
        let _reserved = decoder.read_u8()?;
        let trigger_value = decoder.read_u64()?;
        let duration_cycles = decoder.read_u32()?;
        let value = decoder.read_u64()?;

        interrupt_plan.push(InterruptEvent {
            hart_id,
            interrupt,
            trigger: u8_to_trigger(trigger_kind, trigger_value)?,
            duration_cycles,
            value,
        });
    }

    let name = decoder.read_string()?;
    let description = decoder.read_string()?;
    let tag_count = decoder.read_u32()? as usize;
    let mut tags = Vec::with_capacity(tag_count);
    for _ in 0..tag_count {
        tags.push(decoder.read_string()?);
    }

    Ok(StructuredSeed {
        core0_prog,
        core1_prog,
        shared_mem_init,
        interrupt_plan,
        metadata: SeedMetadata {
            name,
            description,
            tags,
        },
    })
}

fn push_u16(bytes: &mut Vec<u8>, value: u16) {
    bytes.extend_from_slice(&value.to_le_bytes());
}

fn push_u32(bytes: &mut Vec<u8>, value: u32) {
    bytes.extend_from_slice(&value.to_le_bytes());
}

fn push_u64(bytes: &mut Vec<u8>, value: u64) {
    bytes.extend_from_slice(&value.to_le_bytes());
}

fn push_blob(bytes: &mut Vec<u8>, blob: &[u8], field: &'static str) -> Result<(), SeedCodecError> {
    push_u32(bytes, to_u32(blob.len(), field)?);
    bytes.extend_from_slice(blob);
    Ok(())
}

fn push_string(
    bytes: &mut Vec<u8>,
    value: &str,
    field: &'static str,
) -> Result<(), SeedCodecError> {
    push_blob(bytes, value.as_bytes(), field)
}

fn to_u32(value: usize, field: &'static str) -> Result<u32, SeedCodecError> {
    u32::try_from(value).map_err(|_| SeedCodecError::LengthOverflow(field))
}

fn interrupt_kind_to_u8(kind: InterruptKind) -> u8 {
    match kind {
        InterruptKind::Timer => 0,
        InterruptKind::Software => 1,
        InterruptKind::External => 2,
        InterruptKind::Debug => 3,
    }
}

fn u8_to_interrupt_kind(kind: u8) -> Result<InterruptKind, SeedCodecError> {
    match kind {
        0 => Ok(InterruptKind::Timer),
        1 => Ok(InterruptKind::Software),
        2 => Ok(InterruptKind::External),
        3 => Ok(InterruptKind::Debug),
        _ => Err(SeedCodecError::InvalidInterruptKind(kind)),
    }
}

fn u8_to_trigger(kind: u8, value: u64) -> Result<InterruptTrigger, SeedCodecError> {
    match kind {
        0 => Ok(InterruptTrigger::Cycle(value)),
        1 => Ok(InterruptTrigger::RetiredInstructions(value)),
        _ => Err(SeedCodecError::InvalidTriggerKind(kind)),
    }
}

struct Decoder<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Decoder<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn read_u8(&mut self) -> Result<u8, SeedCodecError> {
        let value = *self
            .bytes
            .get(self.offset)
            .ok_or(SeedCodecError::UnexpectedEof)?;
        self.offset += 1;
        Ok(value)
    }

    fn read_u16(&mut self) -> Result<u16, SeedCodecError> {
        Ok(u16::from_le_bytes(self.read_array::<2>()?))
    }

    fn read_u32(&mut self) -> Result<u32, SeedCodecError> {
        Ok(u32::from_le_bytes(self.read_array::<4>()?))
    }

    fn read_u64(&mut self) -> Result<u64, SeedCodecError> {
        Ok(u64::from_le_bytes(self.read_array::<8>()?))
    }

    fn read_array<const N: usize>(&mut self) -> Result<[u8; N], SeedCodecError> {
        let end = self
            .offset
            .checked_add(N)
            .ok_or(SeedCodecError::UnexpectedEof)?;
        let slice = self
            .bytes
            .get(self.offset..end)
            .ok_or(SeedCodecError::UnexpectedEof)?;
        let array = <[u8; N]>::try_from(slice).map_err(|_| SeedCodecError::UnexpectedEof)?;
        self.offset = end;
        Ok(array)
    }

    fn read_blob(&mut self) -> Result<Vec<u8>, SeedCodecError> {
        let len = self.read_u32()? as usize;
        let end = self
            .offset
            .checked_add(len)
            .ok_or(SeedCodecError::UnexpectedEof)?;
        let slice = self
            .bytes
            .get(self.offset..end)
            .ok_or(SeedCodecError::UnexpectedEof)?;
        self.offset = end;
        Ok(slice.to_vec())
    }

    fn read_string(&mut self) -> Result<String, SeedCodecError> {
        let blob = self.read_blob()?;
        String::from_utf8(blob).map_err(|_| SeedCodecError::InvalidUtf8)
    }
}

#[cfg(test)]
mod tests {
    use crate::seed::{InterruptEvent, InterruptKind, InterruptTrigger, StructuredSeed};

    use super::{SeedCodecError, decode_seed, encode_seed};

    #[test]
    fn round_trip_structured_seed() {
        let mut seed =
            StructuredSeed::new(vec![0x13, 0x00, 0x00, 0x00], vec![0x93, 0x00, 0x10, 0x00]);
        seed.add_shared_segment(0x8000_0000, vec![1, 2, 3, 4]);
        seed.add_interrupt(InterruptEvent {
            hart_id: 1,
            trigger: InterruptTrigger::Cycle(1024),
            interrupt: InterruptKind::Timer,
            duration_cycles: 8,
            value: 0x55,
        });
        seed.metadata.name = "smoke".to_string();
        seed.metadata.description = "round trip".to_string();
        seed.metadata.tags = vec!["litmus".to_string(), "amo".to_string()];

        let encoded = encode_seed(&seed).expect("encode should succeed");
        let decoded = decode_seed(&encoded).expect("decode should succeed");
        assert_eq!(decoded, seed);
    }

    #[test]
    fn reject_invalid_magic() {
        let err = decode_seed(b"BAD!\x01\x00\x00\x00").expect_err("invalid magic must fail");
        assert_eq!(err, SeedCodecError::InvalidMagic(*b"BAD!"));
    }

    #[test]
    fn round_trip_bytes_input() {
        let mut seed = StructuredSeed::new(vec![0xaa, 0xbb], vec![0xcc, 0xdd]);
        seed.add_shared_segment(0x9000_0000, vec![9, 8, 7, 6]);
        seed.add_interrupt(InterruptEvent {
            hart_id: 0,
            trigger: InterruptTrigger::RetiredInstructions(64),
            interrupt: InterruptKind::Software,
            duration_cycles: 2,
            value: 3,
        });

        let input = seed
            .to_bytes_input()
            .expect("bytes input conversion should succeed");
        let decoded = StructuredSeed::from_bytes_input(&input)
            .expect("structured seed decoding from bytes input should succeed");
        assert_eq!(decoded, seed);
    }

    #[test]
    fn encode_minimal_abi_smoke_seed_layout() {
        let mut seed = StructuredSeed::new(vec![0x73, 0x00, 0x10, 0x00], Vec::new());
        seed.metadata.name = "abi-smoke".to_string();
        seed.metadata.description = "minimal SFUZ seed for ABI smoke verification".to_string();

        let encoded = encode_seed(&seed).expect("encode should succeed");
        let expected = [
            b"SFUZ".as_slice(),
            &[0x01, 0x00],
            &[0x00, 0x00],
            &[0x04, 0x00, 0x00, 0x00],
            &[0x73, 0x00, 0x10, 0x00],
            &[0x00, 0x00, 0x00, 0x00],
            &[0x00, 0x00, 0x00, 0x00],
            &[0x00, 0x00, 0x00, 0x00],
            &[0x09, 0x00, 0x00, 0x00],
            b"abi-smoke",
            &[0x2c, 0x00, 0x00, 0x00],
            b"minimal SFUZ seed for ABI smoke verification",
            &[0x00, 0x00, 0x00, 0x00],
        ]
        .concat();

        assert_eq!(encoded, expected);

        let decoded = decode_seed(&encoded).expect("decode should succeed");
        assert_eq!(decoded, seed);
    }
}
