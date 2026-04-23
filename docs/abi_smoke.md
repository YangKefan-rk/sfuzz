# SFuzz ABI Smoke Check

This smoke check verifies the current SFuzz in-memory ABI path against a real LinkNan Verilated model without waiting for a full RTL regeneration.

What it proves:
- SFuzz fuzzing mode routes `BytesInput` through `sim_main_with_input(...)`.
- LinkNan receives the ABI buffer as the synthetic image name `sfuzz-abi-buffer`.
- `ram.cpp` recognizes the incoming container as an `SFUZ` structured seed and expands it into simulation RAM.

Files:
- `scripts/make_sfuz_seed.py`: builds a standalone SFUZ container from simple CLI inputs.
- `scripts/linknan_abi_smoke.sh`: rebuilds the current LinkNan ABI slice, relinks it against a real Verilated model, runs one minimal SFUZ seed, and checks for the proof logs plus the selected coverage backend.

Default path assumptions:
- `sfuzz` root: current directory of the script.
- LinkNan release sources: `../LN-release/LinkNan_20260324`
- Real prebuilt Verilated model: `../LinkNan/sim/emu/comp`
- Matching generated headers: `../LinkNan/build/generated-src`

Run:
```bash
cd /nfs/home/yangkefan/Nanhu-V5.1/sfuzz
./scripts/linknan_abi_smoke.sh
```

Useful overrides:
- `LINKNAN_RELEASE=/path/to/LinkNan_20260324`
- `REAL_MODEL_ROOT=/path/to/legacy/LinkNan`
- `REAL_MODEL_COMP=/path/to/comp`
- `REAL_MODEL_GENERATED_SRC=/path/to/generated-src`
- `COVERAGE_NAME=llvm.branch`
- `WORK_DIR=/tmp/custom-smoke-dir`
- `CXX=clang++-18`
- `NUM_CORES=2`
- `EMU_THREAD=8`
- `VERILATOR_ROOT=/nfs/share/opt/verilator/share/verilator`

FIRRTL coverage validation:
- Build the real model with `--firrtl_cover` first so `sim/emu/comp` contains `firrtl-cover.o` and matching generated headers.
- Point `REAL_MODEL_GENERATED_SRC` at the matching generated directory for that build, for example `build-cover-validate-r2/generated-src`.
- Set `COVERAGE_NAME=FIRRTL.<group>` such as `FIRRTL.MSHR`.

Example:
```bash
cd /nfs/home/yangkefan/Nanhu-V5.1/sfuzz
COVERAGE_NAME=FIRRTL.MSHR LINKNAN_RELEASE=/nfs/home/yangkefan/Nanhu-V5.1/LinkNan REAL_MODEL_ROOT=/nfs/home/yangkefan/Nanhu-V5.1/LinkNan REAL_MODEL_COMP=/nfs/home/yangkefan/Nanhu-V5.1/LinkNan/sim/emu/comp REAL_MODEL_GENERATED_SRC=/nfs/home/yangkefan/Nanhu-V5.1/LinkNan/build-cover-validate-r2/generated-src ./scripts/linknan_abi_smoke.sh
```

Expected proof lines:
```text
The image is sfuzz-abi-buffer
SFuzz structured seed detected. Expanding image into RAM
COVERAGE: <selected coverage>, ...
```

Notes:
- The smoke script intentionally accepts a non-zero emulator exit code as long as the proof lines appear. With a legacy real-model build that still expects difftest configuration, later failures such as a missing `NEMU_HOME` can happen after the ABI proof point.
- The generated seed is minimal: `core0_prog` contains a single `ebreak` instruction (`0x00100073` in little endian), and every other SFUZ section is empty.
