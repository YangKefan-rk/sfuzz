# DirectFuzz Reproduction

This note describes the DirectFuzz method-level reproduction in SFuzz.
DirectFuzz is a directed RTL fuzzer: it targets one module instance and biases
seed selection plus mutation energy toward coverage closer to that target.

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
as unreachable and stored as `None`.

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
- after a configurable interval, default `10`, without target coverage
  progress, the scheduler escapes local minima by selecting a low-energy
  regular seed and marking it for default-energy mutation

This is deliberately different from the older `src/directed.rs` scheduler.
That file is a SanCov-guard directed scheduler for the current LinkNan C++ ABI;
it is not the paper DirectFuzz algorithm.

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

The method logic is unit-tested and ready to be used by future runners.  A fully
faithful LinkNan run still needs a simulator ABI that exposes per-instance
mux-toggle arrays to `src/methods/directfuzz/`.
