#!/bin/bash

SCRIPT_DIR="$(dirname $(realpath ${BASH_SOURCE[0]}))"
cd "$SCRIPT_DIR"

source "$SCRIPT_DIR/../../angr.venv/bin/activate"

versions=('1.5.0' '1.6.0' '1.7.0' '1.8.0' '1.9.0' '2.0.0' '2.1.0')

for ver in ${versions[@]}; do
    /usr/bin/time python solve.py --target "haproxy-$ver" >solve.$ver.log 2>&1
done
