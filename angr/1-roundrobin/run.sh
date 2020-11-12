#!/bin/bash

set -e

SCRIPT_DIR="$(dirname $(realpath ${BASH_SOURCE[0]}))"
cd "$SCRIPT_DIR"

source "$SCRIPT_DIR/../../angr.venv/bin/activate"

make -j
for i in {0..9}; do
    /usr/bin/time python solve.py >solve.$i.log 2>&1
done
