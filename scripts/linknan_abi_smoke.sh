#!/usr/bin/env bash
set -euo pipefail

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
sfuzz_home=$(cd -- "${script_dir}/.." && pwd)

linknan_root_override=${LINKNAN_ROOT:-}
if [[ -n "${linknan_root_override}" ]]; then
  linknan_src_root="${linknan_root_override}"
  real_model_root=${REAL_MODEL_ROOT:-"${linknan_root_override}"}
else
  linknan_src_root=${LINKNAN_SRC_ROOT:-${LINKNAN_RELEASE:-"${sfuzz_home}/../LN-release/LinkNan_20260324"}}
  real_model_root=${REAL_MODEL_ROOT:-"${sfuzz_home}/../LinkNan"}
fi

real_model_build_dir=${REAL_MODEL_BUILD_DIR:-"${real_model_root}/build"}
real_model_sim_dir=${REAL_MODEL_SIM_DIR:-"${real_model_root}/sim"}
real_model_comp=${REAL_MODEL_COMP:-"${real_model_sim_dir}/emu/comp"}
real_model_generated_src=${REAL_MODEL_GENERATED_SRC:-"${real_model_build_dir}/generated-src"}

work_dir=${WORK_DIR:-/tmp/sfuzz-linknan-abi-smoke}
relink_dir="${work_dir}/relink"
corpus_dir="${work_dir}/corpus"
log_file="${work_dir}/run.log"
emu_bin="${relink_dir}/emu"
cxx_bin=${CXX:-clang++-18}
verilator_root=${VERILATOR_ROOT:-/nfs/share/opt/verilator/share/verilator}
num_cores=${NUM_CORES:-2}
emu_thread=${EMU_THREAD:-8}
xmake_jobs=${XMAKE_JOBS:-8}
build_no_diff=${BUILD_NO_DIFF:-1}
coverage_name=${COVERAGE_NAME:-llvm.branch}

num_cores_to_noc() {
  case "$1" in
    1) echo small ;;
    2) echo reduced ;;
    4) echo full ;;
    *)
      echo "unsupported NUM_CORES: $1" >&2
      exit 1
      ;;
  esac
}

use_firrtl_cover=false
if [[ "${coverage_name}" == *FIRRTL.* ]]; then
  use_firrtl_cover=true
fi

require_file() {
  if [[ ! -f "$1" ]]; then
    echo "missing required file: $1" >&2
    exit 1
  fi
}

require_dir() {
  if [[ ! -d "$1" ]]; then
    echo "missing required directory: $1" >&2
    exit 1
  fi
}

if ! command -v "${cxx_bin}" >/dev/null 2>&1; then
  echo "missing required compiler: ${cxx_bin}" >&2
  exit 1
fi

require_dir "${linknan_src_root}"
require_file "${sfuzz_home}/Cargo.toml"
require_file "${sfuzz_home}/scripts/make_sfuz_seed.py"
require_dir "${verilator_root}/include"
require_dir "${verilator_root}/include/vltstd"

if [[ ! -d "${real_model_comp}" || ! -d "${real_model_generated_src}" ]]; then
  require_dir "${real_model_root}"
  require_file "${real_model_root}/xmake.lua"
  noc_opt=$(num_cores_to_noc "${num_cores}")
  build_args=(emu -o "${real_model_build_dir}" --sim_dir "${real_model_sim_dir}" -j "${xmake_jobs}" -t "${emu_thread}" -N "${noc_opt}")
  if [[ "${build_no_diff}" == "1" ]]; then
    build_args+=(--no_diff)
  fi
  (
    cd "${real_model_root}"
    xmake "${build_args[@]}"
  )
fi

require_dir "${real_model_comp}"
require_dir "${real_model_generated_src}"
require_file "${real_model_comp}/VSimTop.h"
require_file "${real_model_comp}/VSimTop__ALL.a"
require_file "${real_model_comp}/verilated.o"
require_file "${real_model_comp}/verilated_dpi.o"
require_file "${real_model_comp}/verilated_threads.o"
if [[ "${use_firrtl_cover}" == true ]]; then
  require_file "${real_model_generated_src}/firrtl-cover.h"
  require_file "${real_model_comp}/firrtl-cover.o"
fi

rm -rf "${work_dir}"
mkdir -p "${relink_dir}" "${corpus_dir}"

(
  cd "${sfuzz_home}"
  cargo build --release --locked --offline
)

common_cxxflags=(
  -std=c++17
  -DVERILATOR
  "-DNUM_CORES=${num_cores}"
  -I"${verilator_root}/include"
  -I"${verilator_root}/include/vltstd"
  -I"${real_model_comp}"
  -I"${linknan_src_root}/dependencies/difftest/config"
  -I"${real_model_generated_src}"
  -I"${linknan_src_root}/dependencies/difftest/src/test/csrc/common"
  -I"${linknan_src_root}/dependencies/difftest/src/test/csrc/difftest"
  -I"${linknan_src_root}/dependencies/difftest/src/test/csrc/plugin/spikedasm"
  -I"${linknan_src_root}/dependencies/difftest/src/test/csrc/verilator"
  "-DNOOP_HOME=\\\"${linknan_src_root}\\\""
  -DREF_PROXY=NemuProxy
  "-DEMU_THREAD=${emu_thread}"
  -DFUZZER_LIB
  -DFUZZING
  -DLLVM_COVER
  -fsanitize-coverage=trace-pc-guard
  -fsanitize-coverage=pc-table
)

if [[ "${build_no_diff}" == "1" ]]; then
  common_cxxflags+=(-DCONFIG_NO_DIFFTEST)
fi

if [[ "${use_firrtl_cover}" == true ]]; then
  common_cxxflags+=(
    -DFIRRTL_COVER
    -DVM_COVERAGE=1
  )
fi

"${cxx_bin}" "${common_cxxflags[@]}" -c "${linknan_src_root}/dependencies/difftest/src/test/csrc/common/main.cpp" -o "${relink_dir}/main.o"
"${cxx_bin}" "${common_cxxflags[@]}" -c "${linknan_src_root}/dependencies/difftest/src/test/csrc/common/ram.cpp" -o "${relink_dir}/ram.o"

python3 "${sfuzz_home}/scripts/make_sfuz_seed.py" \
  --output "${corpus_dir}/seed.sfuz" \
  --core0-hex 73001000 \
  --name abi-smoke \
  --description "minimal SFUZ seed for ABI smoke verification"

mapfile -t user_objects < <(
  find "${real_model_comp}" -maxdepth 1 -name '*.o' \
    ! -name 'main.o' \
    ! -name 'ram.o' \
    ! -name 'verilated.o' \
    ! -name 'verilated_dpi.o' \
    ! -name 'verilated_threads.o' \
    ! -name 'verilated_cov.o' \
    | sort
)

if [[ ${#user_objects[@]} -eq 0 ]]; then
  echo "no relinkable object files found in ${real_model_comp}" >&2
  exit 1
fi

link_objects=(
  "${relink_dir}/main.o"
  "${relink_dir}/ram.o"
)

for obj in "${user_objects[@]}"; do
  link_objects+=("${obj}")
done

if [[ -f "${real_model_comp}/verilated_cov.o" ]]; then
  link_objects+=("${real_model_comp}/verilated_cov.o")
fi

"${cxx_bin}" \
  -fuse-ld=lld-18 \
  -fsanitize-coverage=trace-pc-guard \
  -fsanitize-coverage=pc-table \
  "${link_objects[@]}" \
  "${real_model_comp}/verilated.o" \
  "${real_model_comp}/verilated_dpi.o" \
  "${real_model_comp}/verilated_threads.o" \
  "${real_model_comp}/VSimTop__ALL.a" \
  -ldl -lrt -lpthread -lsqlite3 -lz -lzstd -latomic \
  "${sfuzz_home}/target/release/libsfuzz.a" \
  -o "${emu_bin}"

run_args=(
  --coverage "${coverage_name}"
  --fuzzing
  --verbose
  --max-iters 1
  --continue-on-errors
  --corpus-input "${corpus_dir}"
)

set +e
"${emu_bin}" "${run_args[@]}" >"${log_file}" 2>&1
run_rc=$?
set -e

cat "${log_file}"

grep -q "The image is sfuzz-abi-buffer" "${log_file}"
grep -q "SFuzz structured seed detected. Expanding image into RAM" "${log_file}"
grep -Fq "COVERAGE: ${coverage_name}," "${log_file}"

echo
echo "SFuzz ABI smoke check passed."
echo "coverage: ${coverage_name}"
echo "binary: ${emu_bin}"
echo "seed:   ${corpus_dir}/seed.sfuz"
echo "log:    ${log_file}"
echo "emu exit code: ${run_rc}"
