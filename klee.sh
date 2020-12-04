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
    --use-query-log=solver:kquery \
    --external-calls=concrete \
    --suppress-external-warnings \
    \
    --libc=none \
    --search=bfs \
    --exit-on-error-type=Abort --exit-on-error-type=ReportError \
    --max-depth=100 --max-memory=$((100 * 1024)) --max-memory-inhibit=false \
    --max-time=1h --watchdog \
    \
    --write-cov \
    --write-kqueries \
    --write-paths \
    --write-sym-paths \
    --only-output-states-covering-new \
    \
    --link-llvm-lib=driver.bc \
    $@

    #--search=random-path --search=nurs:covnew \

    #--posix-runtime \
    #--link-llvm-lib=/usr/lib/runtime_amd64.bc \
    #--use-batching-search --batch-time=5s --batch-instructions=10000 \
