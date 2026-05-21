# PROFUZZ Reproduction

This note describes the PROFUZZ method-level reproduction in SFuzz.  PROFUZZ is
a directed hardware fuzzer built around target-site selection, ATPG-guided seed
generation, and target-site coverage feedback from hardware-native EDA flows.

The implementation lives under:

```text
src/methods/profuzz/
  target.rs      # target signal cost scoring and selection helpers
  pattern.rs     # 0/1/X ATPG pattern parsing and conflict-aware merge
  mutation.rs    # bit-string AFL-style mutations from the artifact scripts
  feedback.rs    # target coverage threshold and improvement policy
```

## Input And Target Model

PROFUZZ uses raw bit patterns produced from ATPG, not instruction streams and
not protocol transactions.  Patterns may contain `X` don't-care bits.  Those
bits are part of the seed-generation space and must be concretized or handled
explicitly before a simulator consumes the pattern.

Target sites are gate-level or RTL nets selected from the native hardware
design.  This is different from DirectFuzz, which targets mux-select coverage in
one module instance.

## Target Selection

The paper defines a design-independent target cost function over structural and
stochastic features:

```text
cost_i = cost_fun(FI_i, FO_i, H_i)
```

It also discusses controllability, observability, and topological depth.
`target.rs` provides a parameterized scoring helper with these fields so the
runner can reproduce top-percent or threshold-based target selection from
existing metadata.

The public PROFUZZ artifact contains target result files, but not the full
industrial-strength FI/FO/H extraction flow.  For high-quality integration,
SFuzz should prefer reading explicit target files first, then add automatic
netlist analysis later.

## ATPG Pattern Merge

`pattern.rs` models ATPG seed patterns as `0`, `1`, and `X` bits.  It implements:

- parsing and formatting 0/1/X patterns
- concrete-bit conflict detection
- vector merge where `X` is replaced by the other pattern's concrete value
- pairwise ATPG merge that chooses the 0-side or 1-side pattern with more `X`
  bits when both are compatible
- conflict-net tracking

This fills in the public artifact gap where `merge_patterns.py` calls
`can_merge` but does not define it.

## Mutation

`mutation.rs` implements the bit-string mutation strategy from the PROFUZZ
scripts rather than reusing RFuzz byte mutation:

- short seeds use 1-bit and 2-bit flips
- medium seeds add 4-bit, 8-bit, interesting, arithmetic, and random bit flips
- seeds at least 32 bits use 16/32-bit flips, arithmetic 8/16/32, random bit
  flip, and interesting 8/16/32

The artifact's interesting values are random bit strings, not AFL's fixed
interesting integer constants.  The Rust implementation keeps mutation
side-effect-free so tests and future runners can use it without temporary files.

## Feedback

PROFUZZ keeps seeds when target-site coverage improves.  The public script uses:

```text
stop when coverage > 90%
keep when coverage > previous * 1.025
```

`feedback.rs` models this policy as a configurable coverage threshold and
relative improvement ratio.

## Prototype Cross-Check

The local reproduction mirrors these PROFUZZ artifact components:

- target selection scripts:
  `PROFUZZ/Target Selection/node_extraction.py`
- ATPG command templates:
  `PROFUZZ/atpg_seed_gen/get_id.tcl`,
  `PROFUZZ/atpg_seed_gen/get_patterns.tcl`
- ATPG pattern merging:
  `PROFUZZ/atpg_seed_gen/merge_patterns.py`
- mutation scripts:
  `PROFUZZ/Fuzz_Scripts/atpg_mutate.py`,
  `PROFUZZ/Fuzz_Scripts/fuzz_mutate.py`
- feedback loop:
  `PROFUZZ/Fuzz_Scripts/fuzz.py`
- Xcelium/IMC coverage extraction:
  `PROFUZZ/Fuzz_Scripts/atpg_simulation.py`,
  `PROFUZZ/Fuzz_Scripts/imc.tcl`

## Current Integration Status

The method-level algorithms are unit-tested.  A faithful production runner still
needs an external toolchain boundary for:

- Synopsys TestMAX ATPG pattern generation
- Cadence Xcelium/VCS/Verilator target-site coverage extraction
- target submodule generation and name mapping
- conversion between ATPG pattern length, top-level input width, and cycle count

The current SFuzz `sim_main_with_input` ABI does not expose PROFUZZ target-site
coverage yet.
