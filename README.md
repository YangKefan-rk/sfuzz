# SFuzz

SFuzz is a LibAFL-based fuzzing runtime for multicore SoC simulation. It is
built as a Rust `staticlib` and linked into a LinkNan/Verilator emulator, where
it drives workloads through either the normal simulator entry point or the
in-memory `sim_main_with_input` fuzzing ABI.

## Layout

- `src/`: Rust fuzzing runtime, coverage plumbing, directed scheduler, SFUZ
  seed codec, and method reproductions.
- `src/methods/rfuzz/`: simulator-ABI-independent RFuzz algorithm modules.
- `src/methods/directfuzz/`: simulator-ABI-independent DirectFuzz algorithm
  modules.
- `src/methods/surgefuzz/`: simulator-ABI-independent SurgeFuzz algorithm
  modules.
- `src/methods/profuzz/`: simulator-ABI-independent PROFUZZ algorithm modules.
- `scripts/make_sfuz_seed.py`: builds SFUZ structured seed files from hex,
  raw binaries, ELF payloads, and shared-memory blobs.
- `scripts/litmus_to_c.py`: wraps `litmus7` to generate C source trees from
  RISC-V `.litmus` tests.
- `scripts/linknan_abi_smoke.py`: relinks SFuzz with a LinkNan Verilated model
  and runs a one-iteration ABI smoke check.
- `scripts/linknan_vcs_smoke.py`: builds/runs LinkNan VCS with a minimal SFUZ
  seed and checks that VCS reaches the SFUZ RAM expansion path.
- `scripts/linknan/`: LinkNan platform runners for SFuzz, RFuzz, DirectFuzz,
  SurgeFuzz, and the reserved PROFUZZ entry.  Shared LinkNan/VCS build, run,
  seed, config, and result-table helpers live beside method-specific runners
  under `scripts/linknan/methods/`.
- `config/sfuzz.toml`: local path and toolchain defaults for smoke flows.
- `docs/`: notes for the ABI smoke flow, litmus conversion flow, FIRRTL
  coverage runs, benchmark plan, SFuzz coverage points, and method
  reproductions.
- `vendor/`: vendored Rust dependencies for offline builds.

The current workspace layout is expected to be:

```text
~/SFUZZ/
  LinkNan/
  sfuzz/
    config/
    docs/
    scripts/
    src/
```

Most scripts still allow explicit overrides through environment variables when
your LinkNan or litmus trees live elsewhere.

## Build

```bash
cd ~/SFUZZ/sfuzz
cargo build --release --locked --offline
```

The output library is:

```text
target/release/libsfuzz.a
```

## RFuzz

The RFuzz reproduction is organized under `src/methods/rfuzz/`:

```text
src/methods/
  rfuzz/
    input.rs
    coverage.rs
    feedback.rs
    mutators.rs
```

These modules contain RFuzz raw pin-stream input normalization, mux-select
toggle coverage, interesting-input feedback, and AFL-style mutations.  See
`docs/rfuzz.md` for the paper/SurgeFuzz cross-check and the remaining LinkNan
harness boundary.

## DirectFuzz

The DirectFuzz reproduction is organized under `src/methods/directfuzz/`:

```text
src/methods/
  directfuzz/
    metadata.rs
    energy.rs
    scheduler.rs
```

These modules contain DirectFuzz instance-distance metadata, distance-based
energy, and target-priority seed queues.  See `docs/directfuzz.md` for the
paper/SurgeFuzz cross-check and the remaining LinkNan harness boundary.

## SurgeFuzz

The SurgeFuzz reproduction is organized under `src/methods/surgefuzz/`:

```text
src/methods/
  surgefuzz/
    score.rs
    coverage.rs
    metadata.rs
    selector.rs
```

These modules contain SurgeFuzz annotation scoring, `score^2` power scheduling,
ancestor-register coverage, instrument metadata parsing, and NMI-based ancestor
selection.  See `docs/surgefuzz.md` for the paper/prototype cross-check and the
remaining LinkNan harness boundary.

## PROFUZZ

The PROFUZZ reproduction is organized under `src/methods/profuzz/`:

```text
src/methods/
  profuzz/
    target.rs
    pattern.rs
    mutation.rs
    feedback.rs
```

These modules contain PROFUZZ target signal scoring, ATPG 0/1/X pattern merge,
bit-string mutation, and target coverage feedback policy.  See
`docs/profuzz.md` for the paper/artifact cross-check and the remaining EDA and
simulator boundary.

## Test

```bash
cd ~/SFUZZ/sfuzz
cargo test --locked --offline
python3 -m py_compile scripts/litmus_to_c.py scripts/make_sfuz_seed.py
```

## ABI Smoke Check

With `~/SFUZZ/LinkNan` present:

```bash
cd ~/SFUZZ/sfuzz
python3 scripts/linknan_abi_smoke.py
```

Useful overrides:

```bash
LINKNAN_ROOT=/path/to/LinkNan python3 scripts/linknan_abi_smoke.py
COVERAGE_NAME=FIRRTL.MSHR python3 scripts/linknan_abi_smoke.py
```

The smoke script proves that SFuzz routes LibAFL `BytesInput` through
`sim_main_with_input`, LinkNan sees the synthetic image name
`sfuzz-abi-buffer`, and `ram.cpp` expands an `SFUZ` structured seed into RAM.

## VCS Smoke Check

For a quick LinkNan/VCS smoke run:

```bash
cd ~/SFUZZ/sfuzz
python3 scripts/linknan_vcs_smoke.py
```

This builds LinkNan `simv` with `--no_build_chisel --no_diff --no_fsdb
--no_xprop --no_fgp`, generates a minimal `.sfuz` seed, runs it with
`xmake simv-run`, and checks for:

```text
The image is <seed>.sfuz
SFuzz structured seed detected. Expanding image into RAM
V C S   S i m u l a t i o n   R e p o r t
```

By default the run uses a short `--cycles=2000` limit. Useful overrides:

```bash
VCS_CYCLES=10000 python3 scripts/linknan_vcs_smoke.py
python3 scripts/linknan_vcs_smoke.py --rebuild-comp
python3 scripts/linknan_vcs_smoke.py --seed /path/to/app.sfuz
```

The VCS smoke is file-based: VCS owns the simulator `main`, so this is not the
same as the in-process Rust `sim_main_with_input` fuzzing ABI used by the
Verilator smoke path.

## LinkNan Platform Runs

For batch LinkNan/VCS data collection with SFuzz seeds:

```bash
cd ~/SFUZZ/sfuzz
python3 scripts/linknan/run.py sfuzz \
  --seed-dir /nfs/home/yangkefan/SFUZZ-subagents/subagent5/testcases/seeds \
  --limit 10 \
  --work-dir /tmp/sfuzz-linknan \
  --skip-build \
  --cycles 2000
```

The same platform entry point exposes method-specific commands:

```bash
python3 scripts/linknan/run.py rfuzz --raw-hex 73001000 --skip-build
python3 scripts/linknan/run.py directfuzz \
  --metadata /tmp/directfuzz_metadata.csv \
  --target-instance Tile0.mshr \
  --seed-dir /tmp/sfuzz-corpus \
  --skip-build
python3 scripts/linknan/run.py surgefuzz \
  --score-trace-dir /tmp/surgefuzz_profile \
  --seed-dir /tmp/sfuzz-corpus \
  --skip-build
python3 scripts/linknan/run.py profuzz
```

The script layout is intentionally split by responsibility:

```text
scripts/linknan/
  run.py                 # public CLI for LinkNan platform runs
  config.py              # TOML/path/environment resolution
  vcs.py                 # real LinkNan VCS build/run/log/coverage utilities
  seeds.py               # SFUZ seed collection and generated smoke seeds
  common.py              # result-table and small shared helpers
  methods/
    sfuzz.py
    rfuzz.py
    directfuzz.py
    surgefuzz.py
    profuzz.py
```

注意：这些入口保留真实 LinkNan VCS 构建和运行路径。RFuzz 当前只有外部
mux-select bitmap 才能表示论文定义的覆盖；DirectFuzz 必须接入 per-instance
mux-toggle 覆盖/反馈 ABI；SurgeFuzz 必须接入 per-cycle score 和 ancestor
coverage ABI；PROFUZZ 必须接入论文定义的目标点覆盖/反馈 ABI。凡使用 VCS log、
dev mock、VCS built-in coverage 或离线 trace 的结果，都只能作为调试/冒烟数据，
不能作为 paper-faithful 对比数据。

## Seed Creation

Create a minimal seed containing one little-endian RISC-V `ebreak` instruction:

```bash
python3 scripts/make_sfuz_seed.py \
  --output /tmp/sfuzz-corpus/seed.sfuz \
  --core0-hex 73001000 \
  --name abi-smoke
```

Import an ELF payload:

```bash
python3 scripts/make_sfuz_seed.py \
  --output /tmp/sfuzz-corpus/app.sfuz \
  --core0-elf /path/to/app.elf \
  --name app
```

## Litmus Flow

```bash
python3 scripts/litmus_to_c.py \
  --output-dir ./generated-litmus-c \
  --cores 2 \
  /path/to/test.litmus
```

By default the wrapper looks for `~/SFUZZ/litmus-tests-riscv`. Set
`SFUZZ_LITMUS_HOME`, `LITMUS`, or `LITMUS_LIBDIR` when using a different tree or
a just-built herdtools7 binary.
