# RFuzz Reproduction

This note describes the RFuzz method-level reproduction in SFuzz. RFuzz is a
coverage-directed RTL fuzzer: it treats a test as raw bytes over top-level input
pins across time and uses mux-select toggle coverage as feedback.

This repository keeps the original RFuzz method components as reusable building
blocks, but the LinkNan/VCS runner is now intentionally scoped to processor
verification. LinkNan experiments use native `.bin`/ELF workloads, because the
DUT under study is a processor SoC. The RFuzz part that remains native to the
method is mux-select toggle feedback plus coverage-guided corpus retention and
mutation over LinkNan workloads.

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

`scripts/linknan/run.py rfuzz` launches the
real LinkNan VCS `simv-run` path in a campaign loop and records the real command
status, logs, natural finish/timeout state, corpus retention decisions, and
native mux-select toggle coverage. It no longer accepts SFUZ structured seeds
as RFuzz input. The current LinkNan bridge is the official processor workload
mode for these experiments:

- it feeds LinkNan through `xmake simv-run --workload=<input.bin|input.elf>`,
  so the input reaching DUT memory is a normal binary/ELF workload file rather
  than SFuzz's `.sfuz` container
- the adapter writes mutated bytes as workload `.bin` files and can seed from
  existing `.bin`/ELF workloads; this is the chosen LinkNan processor
  verification workload model, not the RFuzz paper's per-cycle top-level raw
  pin stream
- by default it builds `--firrtl-cov RFuzz.mux-toggle`, which inserts a VCS
  bind probe for each extracted 2:1 mux condition; each probe reports coverage
  only when the select has observed both `0` and `1` within the same testcase
- the VCS exporter writes `rfuzz_toggle_bitmap.bin` using bit-packed LSB0
  encoding plus `rfuzz_toggle_bitmap.json` metadata; the runner treats these
  case-local files as `toggle_bitmap_source=vcs-native-abi`
- it still has no native valid/invalid decision exported from constrained
  LinkNan interfaces. In LinkNan processor workload mode, `valid_source` defaults
  to `linknan-workload`, meaning accepted `.bin`/ELF inputs are treated as valid
  processor workloads for RFuzz corpus accounting.
- before each campaign the runner performs a static RFuzz ABI audit of the
  current LinkNan VCS harness. The current generated `SimTop` exposes only
  clock/reset, difftest/log/perf controls, and UART-related pins to `tb_top`;
  `xmake simv-run` injects testcase bytes through `+workload=` RAM/ELF loading.
  Therefore `raw_pin_stream_supported=false` for this path today.

The RFuzz CSV now records these boundaries explicitly:

```text
runner_abi              linknan-workload-binary-adapter today
requested_input_model   linknan-workload-binary-adapter
actual_input_abi        audited ABI actually used by the runner
input_model             actual workload format: binary-workload, elf-workload,
                        gzip-workload, or zstd-workload
raw_pin_stream_supported
                        true only when the audited LinkNan harness exposes
                        non-control top-level input pins to the fuzzer
raw_pin_stream_reason   static audit explanation for the current harness
top_input_pins          total audited SimTop input width, including controls
fuzzable_input_pins     audited non-control input width exposed by SimTop
pin_stream_driver_supported
                        whether a VCS RFuzz pin-stream driver is integrated
deterministic_reset_model
                        current reset model; not RFuzz MetaReset yet
sparse_memory_model     current memory model; not RFuzz SparseMem yet
cycle_limit             none when --no-cycle-limit is active; otherwise the
                        explicit VCS max-cycle bound
toggle_bitmap_source    absent, manual, dev-generated, or vcs-native-abi
valid_source            linknan-workload, unknown, unconstrained, manual,
                        vcs-good-trap, or vcs-native-abi
retained                true when an initial seed, new RFuzz coverage, or bug
                        objective is retained in the corpus
coverage_growth         increment in the accumulated RFuzz mux-toggle map
paper_faithful          true only when no required RFuzz ABI is missing
paper_faithful_scope    linknan-processor-workload
required_native_abi     semicolon-separated missing ABI pieces
```

The runner defaults to `--no-cycle-limit` for RFuzz, which means the wrapper does
not pass `--cycles` to `xmake simv-run`. LinkNan's `simv-run` task has an
internal `cycles` default of `0` and still emits `+max-cycles=0`; LinkNan's
README documents `0` as no max-cycle limit. Use `--timeout-sec` to bound wall
clock time in this mode. Supplying an explicit `--cycles N` overrides this and
is recorded as a bounded diagnostic run.

Supplying a manual bitmap with `--rfuzz-toggle-bitmap` is useful for pipeline
diagnostics, but it does not make the row paper-faithful. VCS built-in
line/toggle coverage, annotated-source counts, VCS logs, run success, and cycle
counts are likewise diagnostic only and must not be reported as RFuzz paper
coverage. For this project, `paper_faithful=true` means faithful to the
LinkNan-processor-workload RFuzz reproduction scope: LinkNan `.bin`/ELF workload
input, native mux-select toggle bitmap, and explicit validity policy. It does
not claim the original RFuzz raw pin-stream workload model.

## SurgeFuzz Cross-Check

The local RFuzz reproduction mirrors these SurgeFuzz components:

- driver update: `surgefuzz/driver/include/method/rfuzz.hpp`
- fuzzer coverage map: `surgefuzz/fuzzer/include/coverage/rfuzz.hpp`
- prepare script metadata handling: `surgefuzz/script/prepare/method/rfuzz.py`

The Rust code intentionally keeps original RFuzz raw-stream components for
reference and future submodule experiments. The LinkNan processor-workload
runner does not require these items, but a raw-stream RFuzz experiment would
still need:

- a pin-stream ABI that maps testcase bytes onto top-level input pins every
  cycle
- reset/memory handling equivalent to RFuzz's `MetaReset` and `SparseMem`
  transforms
- a defined source for constrained-interface validity, including how invalid,
  timeout, and crash states are reported to `RfuzzOutcome`
- corpus/scheduler integration that decides when to apply total and valid
  coverage maps and how to persist interesting inputs

## Current Integration Status

The method logic is unit-tested, and the LinkNan/VCS RFuzz runner now consumes
native mux-select toggle feedback from real simulation while using normal
LinkNan `.bin`/ELF workloads. This is the intended RFuzz reproduction scope for
processor-verification experiments in this project.
