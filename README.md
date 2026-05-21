# SFuzz

SFuzz is a LibAFL-based fuzzing runtime for multicore SoC simulation. It is
built as a Rust `staticlib` and linked into a LinkNan/Verilator emulator, where
it drives workloads through either the normal simulator entry point or the
in-memory `sim_main_with_input` fuzzing ABI.

## Layout

- `src/`: Rust fuzzing runtime, coverage plumbing, directed scheduler, and SFUZ
  seed codec.
- `scripts/make_sfuz_seed.py`: builds SFUZ structured seed files from hex,
  raw binaries, ELF payloads, and shared-memory blobs.
- `scripts/litmus_to_c.py`: wraps `litmus7` to generate C source trees from
  RISC-V `.litmus` tests.
- `scripts/linknan_abi_smoke.py`: relinks SFuzz with a LinkNan Verilated model
  and runs a one-iteration ABI smoke check.
- `scripts/sfuzz.toml`: local path and toolchain defaults for the smoke flow.
- `docs/`: notes for the ABI smoke flow, litmus conversion flow, and FIRRTL
  coverage experiments.
- `vendor/`: vendored Rust dependencies for offline builds.

The current workspace layout is expected to be:

```text
~/SFUZZ/
  LinkNan/
  sfuzz/
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
