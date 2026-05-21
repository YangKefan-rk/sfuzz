# Litmus to C Workflow

The official `litmus-tests-riscv` conversion path is not "use the prebuilt ELF files directly".
The repository Makefile expands the single-test flow to the diy `litmus7` command below:

```sh
litmus7 -mach ./riscv.cfg -avail <cores> -o <output-dir> <test>.litmus
```

In a checked-out upstream tree such as `~/SFUZZ/litmus-tests-riscv`, the two
equivalent entry points are:

```sh
make -n hw-single-test-src CORES=2 LITMUSFILE=tests/non-mixed-size/BASIC_2_THREAD/MP.litmus
make -n gcc-tests/MP-src CORES=2
```

Both expand to the same underlying `litmus7 -mach ./riscv.cfg -avail ... -o ... <test>.litmus` recipe.

## Direct use of litmus7

With the just-built herdtools7 binary, direct use works, but there are two runtime details:

1. The `-o` target directory must already exist.
2. A non-installed `litmus7` binary from the herdtools7 tree should be run with `-set-libdir <herdtools7>/litmus/libdir`.

For example:

```sh
cd ~/SFUZZ/herdtools7
mkdir -p /tmp/herdtools7-litmus-mp
./litmus7   -set-libdir "$PWD/litmus/libdir"   -mach ~/SFUZZ/litmus-tests-riscv/riscv.cfg   -avail 2   -o /tmp/herdtools7-litmus-mp   ~/SFUZZ/litmus-tests-riscv/tests/non-mixed-size/BASIC_2_THREAD/MP.litmus
```

That command was validated locally and generated files including `MP.c`, `run.c`, `Makefile`, and support C sources in `/tmp/herdtools7-litmus-mp`.

## Wrapper script

To avoid hardcoding corpus seeds in Rust, use `scripts/litmus_to_c.py` as the canonical wrapper:

```sh
python3 scripts/litmus_to_c.py   --litmus-home ~/SFUZZ/litmus-tests-riscv   --litmus-bin ~/SFUZZ/herdtools7/litmus7   --output-dir ./generated-litmus-c   --cores 2   ~/SFUZZ/litmus-tests-riscv/tests/non-mixed-size/BASIC_2_THREAD/MP.litmus
```

The wrapper now creates each `-o` directory before invocation and auto-detects `litmus/libdir` when the selected binary lives inside a herdtools7 checkout. If auto-detection ever fails, pass `--litmus-libdir <path>` explicitly.
Pass a directory instead of a file to convert every `.litmus` file below that directory.
Use `--dry-run` to print the exact `litmus7` commands without executing them.

## Downstream AM and SFUZ path

1. Generate C sources with `scripts/litmus_to_c.py`.
2. Build the generated C in the AM bare-metal environment to obtain the ELF you actually want to fuzz.
3. Import that ELF into SFUZ with `scripts/make_sfuz_seed.py --core0-elf <app.elf> ...`.

`make_sfuz_seed.py` now normalizes ELF PT_LOAD segments into a flat SFUZ payload and writes the container in a streaming fashion, so importing large binaries no longer requires assembling the entire seed in memory first.
The SFUZ v1 on-disk format still stores each blob length in a 32-bit field, so a single normalized payload must remain smaller than 4 GiB.
