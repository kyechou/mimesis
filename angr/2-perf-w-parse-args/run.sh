#!/bin/bash

set -e

SCRIPT_DIR="$(dirname $(realpath ${BASH_SOURCE[0]}))"
cd "$SCRIPT_DIR"

source "$SCRIPT_DIR/../../angr.venv/bin/activate"

###
### NO parse args
###

cp main-no-parse-args.cpp src/lb/main.cpp
make -j
/usr/bin/time python solve.py >solve-no-parse-args.log 2>&1

###
### parse args
###

cp main-parse-args.cpp src/lb/main.cpp
make -j
/usr/bin/time python solve.py >solve-parse-args.log 2>&1
