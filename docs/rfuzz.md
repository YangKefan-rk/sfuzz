# RFuzz Reproduction

This note describes the RFuzz method-level reproduction in SFuzz.  RFuzz is a
coverage-directed RTL fuzzer: it treats a test as raw bytes over top-level input
pins across time and uses mux-select toggle coverage as feedback.

The implementation lives under:

```text
src/methods/rfuzz/
  input.rs       # raw pin-stream input layout
  coverage.rs    # mux-select toggle tracking and global/valid maps
  feedback.rs    # interesting-input decision
  mutators.rs    # AFL-style deterministic and havoc mutations
```

## Input Model

RFuzz does not treat the DUT as a file parser.  One testcase is a sequence of
DUT input-pin values over multiple cycles:

- One cycle consumes `ceil(sum(top_input_bits) / 8)` bytes.
- A testcase is normalized to a whole number of cycles.
- Optional `max_cycles` truncates overlong mutations before padding.

This is modeled by `RfuzzInputLayout` in `input.rs`.

## Coverage Model

RFuzz uses mux-select toggle coverage.  The driver captures the initial sampled
mux-select state for a testcase and accumulates toggles against later samples:

```text
local_toggle_map |= initial_sample ^ current_sample
```

`ToggleTracker` implements this local testcase behavior.  `RfuzzCoverageMap`
keeps the fuzzer-side state split into:

- current local testcase coverage
- accumulated total coverage
- accumulated valid-input-only coverage for constrained interfaces

Keeping local and accumulated maps separate is important.  Interesting-input
decisions must compare the current testcase against global coverage; they must
not accidentally reuse accumulated coverage as if it came from one input.

## Feedback

`RfuzzOutcome` models the interesting-input decision:

- new total mux-toggle coverage is interesting
- for constrained interfaces, new valid coverage is interesting only when the
  testcase is valid
- crashes are always objectives

Timeout state is recorded so a runner can make a policy decision at the ABI
layer.

## Mutations

`mutators.rs` implements the RFuzz/AFL mutation set used by the RFuzz paper:

- deterministic bitflip `1/1`, `2/1`, `4/1`, `8/8`, `16/8`, `32/8`
- deterministic arithmetic `8`, `16`, `32`, with deltas `1..=35`
- havoc steps for random bitflip, interesting `8/16/32`, arithmetic
  `8/16/32`, random byte overwrite, delete, clone, and overwrite

Each mutated testcase is normalized through `RfuzzInputLayout` before it is
returned.

## SurgeFuzz Cross-Check

The local RFuzz reproduction mirrors these SurgeFuzz components:

- driver update: `surgefuzz/driver/include/method/rfuzz.hpp`
- fuzzer coverage map: `surgefuzz/fuzzer/include/coverage/rfuzz.hpp`
- prepare script metadata handling: `surgefuzz/script/prepare/method/rfuzz.py`

The Rust code intentionally stops at the method boundary.  A fully faithful
LinkNan run still needs a simulator ABI that exposes raw RFuzz pin-stream input
and mux-select samples to `src/methods/rfuzz/`.

## Current Integration Status

The method logic is unit-tested and ready to be used by future runners.  The
default `--fuzzing` path still uses the existing LibAFL byte-input harness, so
it should not be described as a fully faithful RFuzz runner yet.
