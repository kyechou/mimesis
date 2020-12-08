#!/bin/bash

set -e
set -o nounset

SCRIPT_DIR="$(dirname $(realpath ${BASH_SOURCE[0]}))"
cd "$SCRIPT_DIR"

[ $UID -eq 0 ] && \
    (echo '[!] Please run this script without root privilege' >&2; exit 1)

echo [+] Compiling...
make driver.bc
make $1

echo [+] Starting KLEE...
sudo klee \
    --max-solver-time=1s \
    --simplify-sym-indices \
    --solver-backend=z3 \
    --solver-optimize-divides \
    --use-forked-solver \
    --use-independent-solver \
    --external-calls=concrete \
    --suppress-external-warnings \
    \
    --libc=none \
    --search=dfs \
    --exit-on-error-type=ReportError \
    --max-depth=100 --max-memory=$((100 * 1024)) --max-memory-inhibit=false \
    --max-time=1h \
    \
    --write-cov \
    --write-kqueries \
    --write-smt2s \
    --write-paths \
    --write-sym-paths \
    --write-test-info \
    \
    --link-llvm-lib=driver.bc \
    $@

    #--only-output-states-covering-new \
    #--posix-runtime \
    #--link-llvm-lib=/usr/lib/runtime_amd64.bc \

OUT_DIR="$(readlink -f klee-last)"
sudo chown -R $(id -u):$(id -g) "$OUT_DIR" klee-last
