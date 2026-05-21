# RFuzz Reproduction

This note describes the RFuzz method-level reproduction in SFuzz. RFuzz is a
coverage-directed RTL fuzzer: it treats a test as raw bytes over top-level input
pins across time and uses mux-select toggle coverage as feedback.

This is not a complete LinkNan, Verilator, or VCS RFuzz runner. The Rust code
below provides testable building blocks for input normalization, toggle
coverage, feedback decisions, and mutation. It deliberately does not add a
placeholder runner or CLI until the simulator ABI and instrumentation pieces are
available.

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

- One cycle consumes `ceil(sum(top_input_bits) / 8)` bytes padded to the RFuzz
  artifact's 8-byte transport alignment.
- A testcase is normalized to a whole number of cycles.
- Optional `max_cycles` truncates overlong mutations before padding.
- Empty inputs normalize to one zero-filled cycle so mutators and future runner
  code never need to execute a zero-length testcase.

This is modeled by `RfuzzInputLayout` in `input.rs`. `RfuzzInputLayout::new`
uses the artifact-compatible 8-byte cycle alignment. Tests can use
`with_cycle_byte_align(..., 1)` only when they need to model a byte-tight ABI for
diagnostics; that is not the default RFuzz transport shape.

## Coverage Model

RFuzz uses mux-select toggle coverage. The driver captures the initial sampled
mux-select state for a testcase and accumulates toggles against later samples:

```text
local_toggle_map |= initial_sample ^ current_sample
```

`ToggleTracker` implements only this local testcase behavior. Callers must
reset it before each testcase. `RfuzzCoverageMap` keeps the fuzzer-side state
split into:

- `current_local`: the local toggle map for exactly the testcase that just ran
- `total_global`: accumulated coverage from the total corpus
- `valid_global`: accumulated coverage from valid-input-only corpus entries

Keeping local and accumulated maps separate is important. Interesting-input
decisions compare `current_local` against one of the accumulated maps, then
apply `current_local` into the chosen global map. The accumulated maps must not
be reused as if they were the coverage produced by one input.

The Rust API names this distinction explicitly with helpers such as
`set_current_from_tracker`, `current_local`, `total_global`, and
`valid_global`.

## Feedback

`RfuzzOutcome` models the interesting-input decision:

- new total mux-toggle coverage is interesting
- for constrained interfaces, new valid-only coverage is interesting only when
  the testcase is valid
- crashes are always objectives

For unconstrained interfaces, valid coverage is treated as the normal coverage
map and can be applied for every testcase. For constrained interfaces, callers
should apply `valid_global` only when the runner can prove the testcase is
valid. Timeout state is recorded so a runner can make a policy decision at the
ABI layer.

## Mutations

`mutators.rs` implements RFuzz/AFL-style mutation building blocks:

- deterministic bitflip `1/1`, `2/1`, `4/1`, `8/8`, `16/8`, `32/8`
- deterministic arithmetic `8`, `16`, `32`, matching the RFuzz artifact's
  `0..35` exclusive delta index (`0..=34`), including no-op children
- deterministic interesting `8/16/32` value overwrites matching the RFuzz
  artifact's interesting-value tables and endian handling
- havoc steps for random bitflip, interesting `8/16/32`, arithmetic
  `8/16/32`, random byte overwrite, delete, clone, and overwrite

Each mutated testcase is normalized through `RfuzzInputLayout` before it is
returned.

Known mutation fidelity boundary: havoc uses the same RFuzz/AFL operation
families, RFuzz-style stacked counts (`2, 4, 8, 16, 32, 64, 128`), and the
artifact's weighted havoc family table shape, but it is not yet a byte-for-byte
port of the original artifact's block-length scheduler. That exact scheduling
belongs with a future runner/scheduler integration and should be tested there.

## LinkNan/VCS Runner Status

`scripts/linknan/run.py rfuzz` is intentionally conservative. It can launch the
real LinkNan VCS `simv-run` path and record the real command status, logs,
cycles, and optional diagnostic coverage sources. It does not yet implement the
RFuzz paper runner ABI:

- it feeds LinkNan through `xmake simv-run --workload=<seed.sfuz>`, so the input
  is an SFUZ program image or memory payload rather than per-cycle raw top-level
  pin bytes
- it has no VCS DPI/PLI/shared-memory hook that samples a native `coverage`
  mux-select bus every cycle and returns the local toggle bitmap to the fuzzer
- it has no native valid/invalid decision exported from constrained LinkNan
  interfaces
- it does not run a campaign loop where total and valid-only RFuzz coverage maps
  decide corpus retention

The RFuzz CSV now records these boundaries explicitly:

```text
runner_abi              linknan-workload-simv-run today
requested_input_model   requested CLI label, for example sfuz-core0-payload
                        or raw-pin-stream
input_model             actual VCS path used today: sfuz-core0-payload,
                        sfuz-seed, or linknan-workload-file
toggle_bitmap_source    absent, manual, dev-generated, or vcs-native-abi
valid_source            unknown, unconstrained, manual, or vcs-native-abi
paper_faithful          true only when no required RFuzz ABI is missing
required_native_abi     semicolon-separated missing ABI pieces
```

Because the current runner is still the LinkNan SFUZ workload path,
`required_native_abi` includes `rfuzz_vcs_native_runner_abi` and
`rfuzz_raw_top_pin_stream_input_abi` even if `--rfuzz-input-model
raw-pin-stream` is requested; the output `input_model` records the actual path
that reached VCS. Supplying a manual bitmap with `--rfuzz-toggle-bitmap` is
useful for pipeline diagnostics, but it does not make the row paper-faithful.
VCS built-in line/toggle coverage, annotated-source counts, VCS logs, run
success, and cycle counts are likewise diagnostic only and must not be reported
as RFuzz paper coverage.

## SurgeFuzz Cross-Check

The local RFuzz reproduction mirrors these SurgeFuzz components:

- driver update: `surgefuzz/driver/include/method/rfuzz.hpp`
- fuzzer coverage map: `surgefuzz/fuzzer/include/coverage/rfuzz.hpp`
- prepare script metadata handling: `surgefuzz/script/prepare/method/rfuzz.py`

The Rust code intentionally stops at the method boundary. A fully faithful
LinkNan/Verilator/VCS run still needs:

- mux-select instrumentation generated from the RTL/FIRRTL pass
- a pin-stream ABI that maps testcase bytes onto top-level input pins every
  cycle
- a per-cycle simulator hook that samples mux-select coverage and feeds
  `ToggleTracker`
- reset/memory handling equivalent to RFuzz's `MetaReset` and `SparseMem`
  transforms
- a defined source for constrained-interface validity, including how invalid,
  timeout, and crash states are reported to `RfuzzOutcome`
- corpus/scheduler integration that decides when to apply total and valid
  coverage maps and how to persist interesting inputs

## Current Integration Status

The method logic is unit-tested and ready to be used by future runners. The
default `--fuzzing` path still uses the existing LibAFL byte-input harness, so
it should not be described as a fully faithful RFuzz runner yet.

Recommended README wording, when coordination allows: "RFuzz currently provides
method-level building blocks under `src/methods/rfuzz/`; a full RFuzz runner
still requires simulator pin-stream and mux-coverage integration."
