use libafl::inputs::{BytesInput, HasMutatorBytes};

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct StructuredSeed {
    pub core0_prog: Vec<u8>,
    pub core1_prog: Vec<u8>,
    pub shared_mem_init: Vec<SharedMemorySegment>,
    pub interrupt_plan: Vec<InterruptEvent>,
    pub metadata: SeedMetadata,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SharedMemorySegment {
    pub base_addr: u64,
    pub bytes: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct InterruptEvent {
    pub hart_id: u8,
    pub trigger: InterruptTrigger,
    pub interrupt: InterruptKind,
    pub duration_cycles: u32,
    pub value: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum InterruptTrigger {
    Cycle(u64),
    RetiredInstructions(u64),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum InterruptKind {
    Timer,
    Software,
    External,
    Debug,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct SeedMetadata {
    pub name: String,
    pub description: String,
    pub tags: Vec<String>,
}

impl StructuredSeed {
    pub(crate) fn new(core0_prog: Vec<u8>, core1_prog: Vec<u8>) -> Self {
        Self {
            core0_prog,
            core1_prog,
            shared_mem_init: Vec::new(),
            interrupt_plan: Vec::new(),
            metadata: SeedMetadata::default(),
        }
    }

    pub(crate) fn add_shared_segment(&mut self, base_addr: u64, bytes: Vec<u8>) {
        self.shared_mem_init
            .push(SharedMemorySegment { base_addr, bytes });
    }

    pub(crate) fn add_interrupt(&mut self, event: InterruptEvent) {
        self.interrupt_plan.push(event);
    }

    pub(crate) fn encode(&self) -> Result<Vec<u8>, crate::seed_codec::SeedCodecError> {
        crate::seed_codec::encode_seed(self)
    }

    pub(crate) fn decode(bytes: &[u8]) -> Result<Self, crate::seed_codec::SeedCodecError> {
        crate::seed_codec::decode_seed(bytes)
    }

    pub(crate) fn to_bytes_input(&self) -> Result<BytesInput, crate::seed_codec::SeedCodecError> {
        Ok(BytesInput::new(self.encode()?))
    }

    pub(crate) fn from_bytes_input(
        input: &BytesInput,
    ) -> Result<Self, crate::seed_codec::SeedCodecError> {
        Self::decode(input.mutator_bytes())
    }
}
