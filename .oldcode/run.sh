#!/bin/bash

set -e
set -o nounset

SCRIPT_DIR="$(dirname $(realpath ${BASH_SOURCE[0]}))"
PROJECT_DIR="$(realpath "${SCRIPT_DIR}/..")"
cd "$PROJECT_DIR"

[ $UID -eq 0 ] && \
    (echo '[!] Please run this script without root privilege' >&2; exit 1)

PROGRAM_DEPTHS=(1 2 3)      # actual depths of statefulness
DEPTH_LIMITS=(1 2 3 4 5)    # depth limits of KLEE exploration

# actual depth of statefulness within the program
for program_depth in ${PROGRAM_DEPTHS[@]}; do
    PROGRAM_NAME="router-s${program_depth}"
    PROGRAM_BC="${PROGRAM_NAME}.bc"
    make ${PROGRAM_BC}

    # depth limit of KLEE exploration
    for depth_limit in ${DEPTH_LIMITS[@]}; do
        EXPERIMENT="${SCRIPT_DIR}/${PROGRAM_NAME}-d${depth_limit}"
        if [ -e "$EXPERIMENT" ]; then
            echo [-] \"$EXPERIMENT\" already exists\; skipping...
        else
            make DEPTH_LIMIT=${depth_limit} -B driver.bc
            ./klee.sh ${PROGRAM_BC}
            OUT_DIR="$(readlink -f klee-last)"
            mv "$OUT_DIR" "$EXPERIMENT"
            unlink klee-last
        fi
    done
done


### topdown (only as a reference)

# actual depth of statefulness within the program
for program_depth in ${PROGRAM_DEPTHS[@]}; do
    PROGRAM_NAME="topdown-router-s${program_depth}"
    PROGRAM_BC="${PROGRAM_NAME}.bc"
    make ${PROGRAM_BC}

    # depth limit of KLEE exploration
    for depth_limit in ${DEPTH_LIMITS[@]}; do
        EXPERIMENT="${SCRIPT_DIR}/${PROGRAM_NAME}-d${depth_limit}"
        if [ -e "$EXPERIMENT" ]; then
            echo [-] \"$EXPERIMENT\" already exists\; skipping...
        else
            make DEPTH_LIMIT=${depth_limit} -B driver.bc
            ./klee.sh ${PROGRAM_BC}
            OUT_DIR="$(readlink -f klee-last)"
            mv "$OUT_DIR" "$EXPERIMENT"
            unlink klee-last
        fi
    done
done
