#!/bin/bash

SCRIPT_DIR="$(dirname $(realpath ${BASH_SOURCE[0]}))"
cd "$SCRIPT_DIR"

source "$SCRIPT_DIR/../../angr.venv/bin/activate"

/usr/bin/time python solve.py --target 'haproxy-2.0.7' >solve.2.0.7.log 2>&1
/usr/bin/time python solve.py --target 'haproxy-1.5.0' >solve.1.5.0.log 2>&1
