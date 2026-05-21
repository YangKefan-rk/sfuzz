# DirectFuzz Method Blocks

This note describes the DirectFuzz method-level building blocks in SFuzz.
DirectFuzz is a directed RTL fuzzer: it targets one module instance and biases
seed selection plus mutation energy toward coverage closer to that target.

Important integration boundary: the current runnable `--directed` path in
`src/directed.rs` is not the DirectFuzz paper algorithm. It is a SanCov/guard
directed heuristic for the current LinkNan C++ ABI. The files below are tested
DirectFuzz components that future runner integration can use; they are not a
complete DirectFuzz runtime by themselves.

The implementation lives under:

```text
src/methods/directfuzz/
  metadata.rs    # instance/signal/width/distance metadata
  energy.rs      # distance-based power schedule
  scheduler.rs   # target-priority and regular seed queues
```

## Target Model

DirectFuzz targets a module instance, not a module type.  If a module is
instantiated multiple times, each instance has its own position in the instance
connectivity graph and must be considered separately.

The static analysis pass is expected to provide one metadata row per coverage
instance:

```text
instance_name,coverage_signal_name,width,distance
```

`metadata.rs` can parse the SurgeFuzz CSV format directly.  A distance of `0`
marks the target instance.  The SurgeFuzz placeholder distance `256` is treated
as unreachable and stored as `None`; textual `undefined`, `unreachable`, and
`none` distances are accepted for the same state.

Metadata construction rejects empty metadata, zero-width coverage signals, and
metadata without at least one distance-`0` target instance. Runtime coverage is
validated against the metadata before distance/target statistics are computed:
the coverage array must have exactly one entry per metadata row, and each entry
must have the byte length implied by that row's bit width.

## Input Distance

For each testcase, DirectFuzz computes distance from local per-input coverage,
not from accumulated global coverage:

```text
d(input, target) =
  sum(covered_mux_bits(instance) * distance(instance, target)) /
  sum(covered_mux_bits(instance))
```

Unreachable instances are ignored because the paper defines distance only for
muxes whose instance can reach the target.  Coverage counting respects each
instance's declared bit width, so padding bits in packed bytes do not inflate
target coverage or distance.

The local-coverage rule is intentional. If testcase A covers target bits and
testcase B later covers only a nearby non-target instance, B's distance and
target-priority decision must be computed from B's own mux-toggle bytes. Using
an accumulated bitmap would incorrectly make B inherit A's target coverage and
receive target-priority scheduling.

## Power Scheduling

`energy.rs` implements the DirectFuzz power schedule:

```text
energy = maxE - ((maxE - minE) * d / dmax)
```

The default bounds are:

```text
minE = 0
maxE = 25
```

These match the energy constants used by the SurgeFuzz backend.  Inputs closer
to the target receive higher energy; inputs with no reachable coverage receive
minimum energy.

## Seed Scheduling

`scheduler.rs` implements the DirectFuzz two-queue policy:

- seeds covering at least one target-instance mux-select bit go to a
  target-priority FIFO
- other interesting seeds go to a regular FIFO
- target-priority seeds are selected before regular seeds
- after a configurable escape interval, default `10`, without target coverage
  progress, the scheduler escapes local minima by selecting the currently
  lowest-energy regular seed and marking it for default-energy mutation

The original DirectFuzz description calls this escape a random/default-energy
mutation step. This method block currently implements a deterministic
lowest-energy regular-seed escape so it stays reproducible and does not require
runner-level RNG plumbing. Treat that as an artifact difference until a full
runner decides how to supply randomness.

## SurgeFuzz Cross-Check

The local DirectFuzz reproduction mirrors these SurgeFuzz components:

- driver update: `surgefuzz/driver/include/method/directfuzz.hpp`
- metadata pass: `surgefuzz/pass/method/directfuzz.cc`
- fuzzer energy constants: `surgefuzz/fuzzer/include/coverage/directfuzz.hpp`
- prepare script metadata handling:
  `surgefuzz/script/prepare/method/directfuzz.py`

There is one important semantic correction: SurgeFuzz's fuzzer-side energy code
computes distance from the accumulated bitmap, while the DirectFuzz paper's
input-distance formula is per testcase.  SFuzz's reproduction uses local
per-input coverage for distance and target progress.

## Current Integration Status

The method logic is unit-tested and ready to be used by future runners, but a
faithful paper DirectFuzz run is still incomplete. In particular, SFuzz still
needs:

- a per-instance mux-toggle simulator ABI, not just SanCov/guard coverage
- a static analysis/pass pipeline that emits DirectFuzz instance distance
  metadata for the chosen target instance
- runner logic that feeds one testcase's local mux-toggle coverage into
  `src/methods/directfuzz/metadata.rs`
- mapping from DirectFuzz energy values to mutation budgets
- LibAFL scheduler/state integration for the two-queue policy and target
  progress accounting

Until those pieces exist, invoking `--directed` should be documented as the
current guard-based directed heuristic, not as a reproduction of the DirectFuzz
paper algorithm.
