#!/bin/bash

set -e
set -o nounset

SCRIPT_DIR="$(dirname $(realpath ${BASH_SOURCE[0]}))"
cd "$SCRIPT_DIR"

[ $UID -eq 0 ] && \
    (echo '[!] Please run this script without root privilege' >&2; exit 1)

KLEE_OUT_TXT=klee.console.txt

echo [+] Compiling...
make driver.bc
make $1

echo [+] Starting KLEE...
sudo /usr/bin/time -v klee \
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
    $@ > "$KLEE_OUT_TXT" 2>&1

OUT_DIR="$(readlink -f klee-last)"
sudo chown -R $(id -u):$(id -g) "$OUT_DIR" klee-last
mv "$KLEE_OUT_TXT" "$OUT_DIR"
