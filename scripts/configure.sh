#!/usr/bin/env bash
#
# Configure for building Mimesis and target programs
#

set -euo pipefail

SCRIPT_DIR="$(dirname "$(realpath "${BASH_SOURCE[0]}")")"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
BUILD_DIR="${PROJECT_DIR}/build"

die() {
    echo -e "[!] ${1-}" >&2
    exit 1
}

[ $UID -eq 0 ] && die 'Please run this script without root privilege'

usage() {
    cat <<EOF
[!] Usage: $(basename "${BASH_SOURCE[0]}") [options]

    Options:
    -h, --help          Print this message and exit
    -d, --debug         Enable debugging
    --clean             Clean all build files without configuring
    --gcc               Use GCC
    --clang             Use Clang (default)
EOF
}

parse_args() {
    DEBUG=0
    CLEAN=0
    COMPILER=clang

    while :; do
        case "${1-}" in
        -h | --help)
            usage
            exit
            ;;
        -d | --debug)
            DEBUG=1
            ;;
        --clean)
            CLEAN=1
            ;;
        --gcc)
            COMPILER=gcc
            ;;
        --clang)
            COMPILER=clang
            ;;
        -?*) die "Unknown option: $1\n$(usage)" ;;
        *) break ;;
        esac
        shift
    done
}

reset_files() {
    local in_tree_submods=(
        "$PROJECT_DIR/third_party/inotify-cpp/inotify-cpp"
        "$PROJECT_DIR/third_party/sylvan/sylvan"
    )

    git -C "$PROJECT_DIR" submodule update --init --recursive
    for submod in "${in_tree_submods[@]}"; do
        git -C "$submod" clean -xdf
    done
    rm -rf "$BUILD_DIR"

    if [[ $CLEAN -ne 0 ]]; then
        exit 0
    fi
}

prepare_flags() {
    CMAKE_ARGS=(
        "-DCMAKE_GENERATOR=Ninja"
        "-DCMAKE_MAKE_PROGRAM=ninja"
    )

    if [[ $DEBUG -ne 0 ]]; then
        CMAKE_ARGS+=('-DCMAKE_BUILD_TYPE=Debug')
    fi
    if [[ "$COMPILER" = 'clang' ]]; then
        CMAKE_ARGS+=('-DCMAKE_C_COMPILER=clang' '-DCMAKE_CXX_COMPILER=clang++')
    elif [[ "$COMPILER" = 'gcc' ]]; then
        CMAKE_ARGS+=('-DCMAKE_C_COMPILER=gcc' '-DCMAKE_CXX_COMPILER=g++')
    fi

    export CMAKE_ARGS
}

main() {
    parse_args "$@"
    reset_files
    prepare_flags
    cmake -B "$BUILD_DIR" -S "$PROJECT_DIR" "${CMAKE_ARGS[@]}"
}

main "$@"

# vim: set ts=4 sw=4 et:
