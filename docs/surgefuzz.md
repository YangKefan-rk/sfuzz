# SurgeFuzz Reproduction

This note describes the SurgeFuzz method-level reproduction in SFuzz.
SurgeFuzz is a surge-aware directed fuzzer for CPU designs.  It aims to create
short time windows where bug-prone exceptional events occur frequently.

The implementation lives under:

```text
src/methods/surgefuzz/
  score.rs       # annotation parser, FREQ/CONSEC/COUNT scoring, score^2 energy
  coverage.rs    # ancestor-state coverage map and score-aware index rules
  metadata.rs    # Yosys instrument.csv metadata parser
  selector.rs    # distance and NMI-based ancestor-register selection
```

## Annotation Model

SurgeFuzz supports one user annotation in the original prototype:

- `SURGE_FREQ=1`: make a 1-bit event occur frequently.
- `SURGE_CONSEC=1`: make a 1-bit event remain active for many consecutive
  cycles.
- `SURGE_COUNT="MAX"`: maximize a multi-bit count-like signal, such as queue
  occupancy.

The Rust parser also accepts compact forms such as `SURGEFREQ=1`, but the
prototype uses the underscore spelling in the Yosys annotation pass.

## Score And Energy

`score.rs` implements the paper/prototype scoring rules:

- FREQ uses a rolling window count.  The prototype window is 256 cycles.
- CONSEC tracks the current run length of the active value.
- COUNT uses the annotated signal value directly for `MAX`.
- Energy is `score^2`.

The recorder is explicit state and must be reset between testcases in an
in-process runner.  The C++ prototype uses static variables in the driver; that
is dangerous if copied directly into a persistent Rust harness.

## Coverage

SurgeFuzz does not use RFuzz mux-toggle coverage and does not use DirectFuzz
module-distance coverage.  Its coverage is the state of ancestor registers that
influence the annotated signal.

The prototype driver computes coverage indices as:

```text
FREQ/CONSEC: (ancestor_state << 4) | (score & 0xf)
COUNT:       ancestor_state
```

`coverage.rs` models this as byte-indexed local/global coverage.  Inputs are
interesting when the local testcase bitmap adds a new global byte.

## Metadata And Selection

The Yosys pass emits `instrument.csv` with:

```text
name,width,src,depth,reg_depth,is_ctrl,cell_name
```

`metadata.rs` parses that file and identifies `dependent_N` ancestor signals.
`selector.rs` contains two selection modes:

- distance-based selection, ordered by register depth and dataflow depth
- distance plus normalized mutual information pruning, which removes redundant
  ancestor registers whose sampled values are highly correlated

The selector also parses profiling output shaped like:

```text
cycle,dependent_0,dependent_1,...,coverage_target
```

## Prototype Cross-Check

The local reproduction mirrors these SurgeFuzz artifact components:

- annotation parser: `surgefuzz/pass/annotation/annotation.cc`
- dependency search and instrumentation:
  `surgefuzz/pass/method/surgefuzz.cc`
- per-cycle driver update:
  `surgefuzz/driver/include/fuzz_driver.hpp`
- score recorder: `surgefuzz/driver/include/surge/surge.hpp`
- fuzzer-side coverage map:
  `surgefuzz/fuzzer/include/coverage/surgefuzz.hpp`
- profiling selector:
  `surgefuzz/script/profile/analyze.py`,
  `surgefuzz/script/profile/selector.py`

## Current Integration Status

The method-level algorithms are unit-tested.  A faithful LinkNan run still
needs simulator glue that can expose, per cycle:

- `coverage_target`, the annotated signal value
- `coverage`, the selected ancestor-state value
- profiling mode output for `fuzz_ancestors`

The current generic `--fuzzing` path does not provide that ABI yet.
