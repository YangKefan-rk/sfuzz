# SurgeFuzz Reproduction

This note describes the SurgeFuzz method-level reproduction in SFuzz.
SurgeFuzz is a surge-aware directed fuzzer for CPU designs.  It aims to create
short time windows where bug-prone exceptional events occur frequently.

The implementation lives under:

```text
src/methods/surgefuzz/
  score.rs       # annotation parser, FREQ/CONSEC/COUNT scoring, score^2 energy
  coverage.rs    # ancestor-state coverage map and score-aware index rules
  metadata.rs    # Yosys instrument.csv metadata parser, including artifact quirks
  selector.rs    # distance and NMI-based ancestor-register/slice selection
```

This is intentionally a method module, not a complete simulator runner.  It
does not claim to replace the artifact's patched LinkNan/Verilator/VCS driver
path yet.

## Annotation Model

SurgeFuzz supports one user annotation in the original prototype:

- `SURGE_FREQ=1`: make a 1-bit event occur frequently.
- `SURGE_CONSEC=1`: make a 1-bit event remain active for many consecutive
  cycles.
- `SURGE_COUNT="MAX"`: maximize a multi-bit count-like signal, such as queue
  occupancy.

The Rust parser also accepts compact forms such as `SURGEFREQ=1` and the
artifact patch style without values (`SURGE_FREQ`, `SURGE_CONSEC`,
`SURGE_COUNT`).  Bare FREQ/CONSEC default to active `1`, and bare COUNT defaults
to `MAX`.  The parser has a `MIN` direction for COUNT because the paper defines
`P=MIN`; however, the artifact annotation pass records only the annotation type
(`FREQ`, `CONSEC`, or `COUNT`) in the runtime environment, and its target
patches use `SURGE_COUNT` for maxima.  Treat `COUNT=MIN` as a paper-level
modeling extension, not an artifact-compatible runtime feature until the
simulator ABI carries the direction.

## Score And Energy

`score.rs` implements the paper/prototype scoring rules as reusable state:

- FREQ uses a rolling window count.  The prototype window is 256 cycles.
- CONSEC tracks the current run length of the active value.
- COUNT uses the annotated signal value directly for `MAX`.
- Energy is `score^2`.

For FREQ and CONSEC, the Rust model treats any non-zero annotated value as the
active boolean value.  The artifact C++ driver asserts that those annotated
signals are already 0 or 1.  This module keeps the booleanized behavior because
it is safer for method-level tests, but a paper/artifact-faithful ABI should
still expose a 1-bit signal for FREQ/CONSEC.

The recorder is explicit state and must be reset between testcases in an
in-process runner.  The C++ prototype uses static variables in the driver; that
is dangerous if copied directly into a persistent Rust harness.

The score bitmap is 256 bytes and is indexed by `score & 0xff`, matching the
artifact's truncation.  Scores larger than 255 therefore alias in the score
bitmap even though `best_score` keeps the full `u32`.

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

Artifact instrumentation starts by creating a placeholder `coverage` wire and a
`coverage_target` wire.  The profiling/rewrite script later rewrites
`coverage` to concatenate the selected ancestors; `coverage_target` remains the
annotated signal used for score updates.  This module models both names in
metadata, but `coverage_target` is not counted as an ancestor coverage bit.

## Metadata And Selection

The Yosys pass emits `instrument.csv` with:

```text
name,width,src,depth,reg_depth,is_ctrl,cell_name
```

The artifact sometimes writes 6-field rows for `coverage` and
`coverage_target`, omitting the empty `cell_name` column.  `metadata.rs`
accepts both 6-field and 7-field rows, fills missing `cell_name` with an empty
string, and identifies only `dependent_N` rows as ancestor signals.

`selector.rs` contains two selection modes:

- distance-based selection, ordered by register depth and dataflow depth
- distance plus normalized mutual information pruning, which removes redundant
  ancestor registers whose sampled values are highly correlated

The bit budget is exact.  If the next ancestor is wider than the remaining
budget, the selector chooses the low bits as a readable slice
(`dependent_N[acceptable_width-1:0]`) and the structured API records it as
`{ name, lsb, width }`.  This mirrors the artifact profiling scripts, which
emit low-bit slices for the final over-wide signal.

The selector also parses profiling output shaped like:

```text
cycle,dependent_0,dependent_1,...,coverage_target
```

There are two related NMI pruning strategies in the artifact:

- `selector.py` iteratively computes NMI against the most recently selected
  signal and drops candidates with `nmi > 0.7`.  The first reference is
  `coverage_target`.
- `analyze.py`'s `closer_mi` path filters later candidates with
  `0 < nmi < 0.35` after computing information against `coverage_target`.

The Rust method model implements the iterative selected-signal strategy with a
configurable threshold and uses `coverage_target` as the initial reference when
that column is present in the profiling CSV.  The Rust API still treats
`max_bits` as the returned ancestor-state bit budget.  The artifact's
`selector.py` starts its internal selected list with `coverage_target`, so its
coverage rewrite spends part of `COV_BIT` on the target bit before adding
ancestors.  This difference is documented rather than hidden because the paper
defines coverage as ancestor-register state, while the artifact rewrite keeps
the target signal in the concatenated `coverage` wire.  The Rust model does not
yet reproduce the separate `closer_mi` DataFrame filtering and graph-reporting
path.

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

## Paper-Faithful Vs Artifact-Faithful

The method code is explicit about the following differences:

- `P=0/MIN`: `COUNT=MIN` exists in Rust scoring so experiments can model
  minimizing a counter, but the artifact runtime annotation type has no MIN
  channel and the target patches use COUNT as MAX.
- FREQ/CONSEC non-zero handling: Rust booleanizes non-zero values; the artifact
  driver asserts 0/1 and should be fed a 1-bit signal.
- `coverage_target`: the artifact includes it as a public runtime signal and
  profiling CSV column.  The paper describes the coverage metric as ancestor
  registers only; the artifact `selector.py`/`instrument.py` rewrite can also
  put `coverage_target` into the concatenated `coverage` wire before selected
  ancestors.
- NMI pruning: Rust models the artifact `selector.py` iterative threshold
  pruning path, including the `coverage_target` initial reference when
  profiling data provides it.  It leaves the `closer_mi` reporting/filtering
  variant for a future profile pipeline.
- Score bitmap truncation: Rust keeps the artifact behavior of indexing the
  score bitmap by `score & 0xff`.

## Current Integration Status

The method-level algorithms are unit-tested.  A faithful LinkNan/Verilator/VCS
run still needs simulator glue that can expose, per cycle:

- `coverage_target`, the annotated signal value
- `coverage`, the selected ancestor-state value
- profiling mode output for `fuzz_ancestors`

The current generic `--fuzzing` path does not provide that ABI yet.  Still
missing, by design in this module:

- a per-cycle ABI for LinkNan/Verilator/VCS that calls score and coverage
  updates every simulated cycle
- a Yosys/FIRRTL annotation pass and instrumentation pass in this Rust codebase
- the profile -> NMI selection -> RTL rewrite pipeline that rewrites
  placeholder `coverage`
- runtime scheduler integration that consumes SurgeFuzz score energy and
  coverage feedback

The LinkNan CLI preserves a real VCS execution path, but it is deliberately
strict about provenance:

- no trace: `best_score` and `energy` are left unavailable; VCS log health is
  not used as a surrogate SurgeFuzz score.  These rows are `T0_vcs_smoke`,
  with `trace_source=no-trace`, `coverage_backend=none`, and
  `paper_faithful=false`.
- `--score-trace-dir` with the default `--trace-source offline-csv`: useful for
  checking the scoring/coverage data shape, but `paper_faithful=false`
- `--trace-is-dev-mock` or `--trace-source dev-mock`: development plumbing only,
  `paper_faithful=false`.  Use this for generated profile smoke tests, not for
  paper data.
- `--trace-source vcs-native-abi`: may be marked `paper_faithful=true` only when
  the CSV was exported by the real LinkNan/VCS per-cycle SurgeFuzz ABI

For T0 on LinkNan, run at least two real `.sfuz` corpus seeds without
`--score-trace-dir`; success means the seed is accepted by LinkNan VCS, the
run reaches the requested cycle cap or normal simulator report, and the output
records the missing native SurgeFuzz ABI instead of inventing score or ancestor
coverage from logs.  A dev smoke may additionally run
`gen-surgefuzz-dev-profile` plus `surgefuzz --score-trace-dir ... --trace-source
dev-mock`; that row must remain `paper_faithful=false`.

Until the native ABI and profile/rewrite pipeline exist, SurgeFuzz support here
should be described as method-level building blocks plus artifact-compatible
parsers/tests and a non-paper-faithful LinkNan smoke runner, not as a complete
paper-faithful runner.
