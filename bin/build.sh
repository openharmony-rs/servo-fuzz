#!/bin/bash
# Builds the fuzzing binaries from the Servo checkout in $SERVO: QuickJS and SpiderMonkey, checked-release with
# line tables (file:line and inlined frames in ASan reports and backtraces), ASan,
# into $TARGET_DIR/fuzz-<build> (default: $SERVO/target). FUZZ_CC/FUZZ_CXX pick the compilers (default: clang).
# C/C++ of target crates is instrumented through the bin/asan-cc wrappers (mach's TARGET_CFLAGS only
# applies when cross-compiling).
set -e
HERE=$(cd "$(dirname "$0")" && pwd)
SERVO=$(cd "${SERVO:?set SERVO to a Servo checkout whose mach has --js-engine}" && pwd)
TARGET_DIR=${TARGET_DIR:-$SERVO/target}
export FUZZ_CC=${FUZZ_CC:-clang} FUZZ_CXX=${FUZZ_CXX:-clang++}
LOGS=${LOGS:-$HERE/../data/build-logs}
mkdir -p "$LOGS"
cd "$SERVO"
build() {
    local name=$1; shift
    CARGO_TARGET_DIR=$TARGET_DIR/fuzz-$name CARGO_PROFILE_CHECKED_RELEASE_DEBUG=line-tables-only \
    CC_x86_64_unknown_linux_gnu=$HERE/asan-cc CXX_x86_64_unknown_linux_gnu=$HERE/asan-cxx \
    TARGET_CC=$FUZZ_CC TARGET_CXX=$FUZZ_CXX \
        ./mach build --profile checked-release --with-asan "$@" > "$LOGS/$name.log" 2>&1
}
for b in ${BUILDS:-qjs-asan sm-asan}; do
    case $b in
        qjs-asan) build qjs-asan --js-engine quickjs ;;
        sm-asan) build sm-asan ;;
    esac
    echo "$b: done $(date +%T)"
done
