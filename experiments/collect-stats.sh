#!/bin/bash

set -e
set -o nounset

SCRIPT_DIR="$(dirname $(realpath ${BASH_SOURCE[0]}))"
cd "$SCRIPT_DIR"

[ $UID -eq 0 ] && \
    (echo '[!] Please run this script without root privilege' >&2; exit 1)

DIRS=$(ls -d */ | sed 's/\/$//')

klee-stats --table-format csv --print-all ${DIRS[*]} | sed '$d'

echo 'Path,Peak RSS (KB),Test cases (paths)'
for dir in ${DIRS[@]}; do
    log="$dir/console.txt"
    mem="$(grep 'Maximum resident set size' "$log" | cut -d' ' -f6)"
    num_paths="$(grep 'generated tests' "$log" | cut -d' ' -f6)"
    echo $dir,$mem,$num_paths
done
