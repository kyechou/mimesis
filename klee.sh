#!/bin/bash
#
# KLEE wrapper script
#

set -e
set -o nounset

SCRIPT_DIR="$(dirname $(realpath ${BASH_SOURCE[0]}))"
cd "$SCRIPT_DIR"

[ $UID -eq 0 ] && \
    (echo '[!] Please run this script without root privilege' >&2; exit 1)

[ $# -lt 1 ] && \
    (echo "[!] Usage: $0 <program.bc> [ args... ]"; exit 1)

KLEE_OUT_TXT=console.txt

echo [+] Starting KLEE...
sudo /usr/bin/time -v klee \
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
    --max-memory=$((100 * 1024)) --max-time=1h \
    \
    --write-cov \
    --write-kqueries \
    --write-smt2s \
    --write-paths \
    --write-sym-paths \
    --write-test-info \
    \
    --link-llvm-lib=driver.bc \
    $@ 2>&1 | tee "$KLEE_OUT_TXT"

OUT_DIR="$(readlink -f klee-last)"
sudo chown -R $(id -u):$(id -g) "$OUT_DIR" klee-last
mv "$KLEE_OUT_TXT" "$OUT_DIR"
echo [+] Done!
