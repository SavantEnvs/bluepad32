#!/usr/bin/env bash
#
# mayhem/build.sh — builds the fuzz harnesses and the project's own test suite (run by mayhem/test.sh).
#
# Runs inside the commit image (mayhem/Dockerfile) as `mayhem` in /mayhem. The base image
# (ghcr.io/savantenvs/base) already exports the build contract — use these, don't redefine:
#   CC, CXX             stock clang / clang++
#   LIB_FUZZING_ENGINE  -fsanitize=fuzzer   (link into each harness that has a LLVMFuzzer entry)
#   SANITIZER_FLAGS     -fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer
#                       (ASan + UBSan, both set to HALT — so Mayhem catches memory AND UB defects)
#   DEBUG_FLAGS         -g -gdwarf-3   (DWARF debug info — always on for fuzz/standalone builds,
#                       independent of the sanitizer off-switch; DWARF version must be < 4)
#   RUST_DEBUG_FLAGS    -C debuginfo=2 -C force-frame-pointers=yes -C llvm-args=-gdwarf-3
#                       (thread through RUSTFLAGS on every cargo-fuzz build)
#   GO_DEBUG_FLAGS      -gcflags=all=-N -l
#                       (thread through go build / go-fuzz-build so the linked ELF keeps symbols)
#   SRC                 /mayhem (the repo source)
#
# Contract: build EVERYTHING here — one runnable binary per fuzz harness, AND the project's test
# suite (so mayhem/test.sh only has to RUN it, never compile). Keep it ADDITIVE (build upstream as
# upstream documents; don't edit upstream files). IMPORTANT: build the PROJECT ITSELF with
# $SANITIZER_FLAGS and $DEBUG_FLAGS (not just the harness) so the fuzzed code is instrumented
# AND carries DWARF < 4 symbols — otherwise ASan/UBSan only see the harness, not the library
# you're trying to find bugs in, and backtraces won't resolve project source lines. Build the TEST
# suite with the project's NORMAL flags (a clean, independent build) so test.sh stays an honest
# functional oracle and won't false-fail on benign UB. Leave the test binary/runner where test.sh
# expects it.
set -euo pipefail

# clang rejects SOURCE_DATE_EPOCH='' (empty) — it must be unset or a valid integer.
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

# Build knobs come from the ENVIRONMENT (overridable), with sane defaults — no if-statements,
# just parameter-expansion fallbacks. Default sanitizers are the base's ASan+UBSan (halting); override
# per build via the Dockerfile's `--build-arg SANITIZER_FLAGS="..."`.
# NB: SANITIZER_FLAGS uses `=` (no colon) on purpose — `=` only fills when the var is UNSET, so an
# explicit EMPTY value (`--build-arg SANITIZER_FLAGS=`) is honored and builds with NO sanitizers
# (useful when you want the program's natural crash / full backtrace, not an ASan report). The other
# knobs use `:=` (default on empty too). MAYHEM_JOBS sets build parallelism (falls back to nproc).
: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
# DEBUG_FLAGS carries DWARF debug info INDEPENDENTLY of the sanitizer off-switch (so an empty
# SANITIZER_FLAGS still yields DWARF symbols). DWARF MUST be < 4 (Mayhem triage can't read >=4); clang-19's
# plain `-g` emits DWARF-5, so `-gdwarf-3` is explicit. Apply $DEBUG_FLAGS to the fuzz/harness/standalone
# builds (NOT the test/oracle build). Rust/Go carry the same intent via their language flags below.
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${RUST_DEBUG_FLAGS:=-C debuginfo=2 -C force-frame-pointers=yes -C llvm-args=-gdwarf-3}"
: "${GO_DEBUG_FLAGS:=-gcflags=all=-N -l}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
# COVERAGE_FLAGS: empty by default → no effect on the normal oracle build. Set it via the Dockerfile's
# `--build-arg COVERAGE_FLAGS="-fprofile-instr-generate -fcoverage-mapping"` to instrument the TEST
# build for source-coverage measurement (how much of the project the test suite actually exercises —
# a quality signal for the oracle; complements the anti-reward-hack sabotage check). APPEND it to the
# test build's compile+link flags in step 3 (NOT the fuzz build); after `test.sh` runs, merge with
# `llvm-profdata` and report with `llvm-cov`. Empty value is honored (`=`, not `:=`).
: "${COVERAGE_FLAGS=}"
export SANITIZER_FLAGS DEBUG_FLAGS RUST_DEBUG_FLAGS GO_DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS

cd "$SRC"

# BTstack is upstream's git submodule; the Dockerfile caches it (patched, pinned) under /opt/toolchains/deps
# and the build resolves it from there, so nothing is fetched here and a re-run works offline.
BTSTACK=$(ls -d /opt/toolchains/deps/btstack-*/src | head -n 1)
[ -f "$BTSTACK/src/btstack.h" ] || { echo "BTstack not found under /opt/toolchains/deps" >&2; exit 1; }

# upstream's tests/CMakeLists.txt hardcodes BTSTACK_ROOT=<root>/external/btstack, so build from a staged
# root (all under the gitignored build/) whose external/btstack points at the cached copy. tests/ is
# copied so a re-run always starts from the committed sources.
STAGE="$SRC/build/stage"
rm -rf "$SRC/build"
mkdir -p "$STAGE/external"
ln -s "$BTSTACK" "$STAGE/external/btstack"
ln -s "$SRC/src" "$STAGE/src"
cp -r "$SRC/tests" "$STAGE/tests"

# 1) Project (libbluepad32 + BTstack) with the fuzz flags: sanitized, DWARF 3, and SanCov
#    (-fsanitize=fuzzer-no-link, unconditionally, even when $SANITIZER_FLAGS is empty) so the libraries
#    give coverage feedback, not just the harness TU. Upstream's own ENABLE_SANITIZERS switch is off so
#    $SANITIZER_FLAGS is the only source of sanitizer settings.
cmake -S "$STAGE/tests" -B "$SRC/build/fuzz" -G Ninja -DCMAKE_C_COMPILER="$CC" \
      -DENABLE_SANITIZERS=OFF -DCMAKE_C_FLAGS="$SANITIZER_FLAGS -fsanitize=fuzzer-no-link $DEBUG_FLAGS -O1" \
      -DCMAKE_EXE_LINKER_FLAGS="$SANITIZER_FLAGS" >/dev/null
cmake --build "$SRC/build/fuzz" -j"$MAYHEM_JOBS" --target bluepad32 btstack
LIBS=("$SRC/build/fuzz/libbluepad32/libbluepad32.a" "$SRC/build/fuzz/libbtstack.a")
for l in "${LIBS[@]}"; do [ -f "$l" ] || { echo "missing $l" >&2; exit 1; }; done

# 2) Harnesses, each linked twice: libFuzzer engine, and the run-once standalone reproducer.
$CXX $SANITIZER_FLAGS $DEBUG_FLAGS -c "$SRC/mayhem/lsan_off.cc" -o "$SRC/build/lsan_off.o"
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$STANDALONE_FUZZ_MAIN" -o "$SRC/build/standalone_main.o"
INCLUDES=(-I"$SRC/mayhem" -I"$STAGE/tests" -I"$SRC/src/components/bluepad32/include")
for d in src src/ble src/classic platform/posix platform/embedded 3rd-party/micro-ecc \
         3rd-party/bluedroid/decoder/include 3rd-party/bluedroid/encoder/include 3rd-party/lc3-google/include \
         3rd-party/md5 3rd-party/rijndael 3rd-party/yxml 3rd-party/tinydir chipset/realtek; do
  INCLUDES+=(-I"$BTSTACK/$d")
done
DEFS=(-DCONFIG_BLUEPAD32_PLATFORM_CUSTOM -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION)
for h in fuzz_hid_report fuzz_hid_descriptor fuzz_sdp_attribute; do
  $CC $SANITIZER_FLAGS $DEBUG_FLAGS -O1 "${DEFS[@]}" "${INCLUDES[@]}" $LIB_FUZZING_ENGINE \
      "$SRC/mayhem/$h.c" "$SRC/build/lsan_off.o" "${LIBS[@]}" -lm -o "$SRC/$h"
  $CC $SANITIZER_FLAGS $DEBUG_FLAGS -O1 "${DEFS[@]}" "${INCLUDES[@]}" \
      "$SRC/build/standalone_main.o" "$SRC/mayhem/$h.c" "$SRC/build/lsan_off.o" "${LIBS[@]}" -lm \
      -o "$SRC/$h-standalone"
done

# 3) The project's own test suite, upstream's CMake with its normal configuration minus the sanitizers
#    (the oracle must run under mayhem/test.sh's neutering shim). mayhem/test.sh runs build/test/test_*.
cmake -S "$STAGE/tests" -B "$SRC/build/test" -G Ninja -DCMAKE_C_COMPILER="$CC" \
      -DENABLE_SANITIZERS=OFF -DCMAKE_C_FLAGS="$COVERAGE_FLAGS" \
      -DCMAKE_EXE_LINKER_FLAGS="$COVERAGE_FLAGS" >/dev/null
cmake --build "$SRC/build/test" -j"$MAYHEM_JOBS"
