#!/usr/bin/env bash
#
# Configure for building Mimesis and target programs
#

set -euo pipefail

SCRIPT_DIR="$(dirname "$(realpath "${BASH_SOURCE[0]}")")"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
BUILD_DIR="${PROJECT_DIR}/build"
DPDK_BUILD_DIR="${PROJECT_DIR}/build.dpdk"

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
    --dpdk              Configure DPDK instead
    --gcc               Use GCC
    --clang             Use Clang (default)
EOF
}

parse_args() {
    DEBUG=0
    CLEAN=0
    DPDK=0
    COMPILER=clang
    BOOTSTRAP_FLAGS=()

    while :; do
        case "${1-}" in
        -h | --help)
            usage
            exit
            ;;
        -d | --debug)
            DEBUG=1
            BOOTSTRAP_FLAGS+=("-d")
            ;;
        --clean)
            CLEAN=1
            ;;
        --dpdk)
            DPDK=1
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

    BOOTSTRAP_FLAGS+=("--compiler" "$COMPILER")
}

reset_files() {
    git -C "$PROJECT_DIR" submodule update --init --recursive

    if [[ $CLEAN -ne 0 ]]; then
        git -C "$PROJECT_DIR" submodule foreach --recursive git clean -xdf
        rm -rf "$BUILD_DIR" "$DPDK_BUILD_DIR"
        exit 0
    fi

    if [[ $DPDK -eq 1 ]]; then
        rm -rf "$DPDK_BUILD_DIR"
    else
        git -C "$PROJECT_DIR" submodule foreach --recursive git clean -xdf
        rm -rf "$BUILD_DIR"
    fi
}

prepare_flags() {
    local toolchain_file
    toolchain_file="$(get_generators_dir)/conan_toolchain.cmake"
    CMAKE_ARGS=(
        "-DCMAKE_TOOLCHAIN_FILE=$toolchain_file"
        "-DCMAKE_GENERATOR=Ninja"
    )
    MESON_ARGS=(
        "--prefix=$PROJECT_DIR/s2e/install"
        "--libdir=lib"
        "--default-library=static"
        "--warnlevel=0"    # 0, 1, 2, 3, everything
        "--optimization=g" # 0, g, 1, 2, 3, s
        "-Dplatform=generic"
        "-Dexamples=all"
    )

    if [[ $DEBUG -ne 0 ]]; then
        CMAKE_ARGS+=('-DCMAKE_BUILD_TYPE=Debug')
        MESON_ARGS+=('--buildtype=debug' '--debug')
    else
        CMAKE_ARGS+=('-DCMAKE_BUILD_TYPE=Release')
        MESON_ARGS+=('--buildtype=debugoptimized')
    fi
    if [[ "$COMPILER" = 'clang' ]]; then
        CMAKE_ARGS+=('-DCMAKE_C_COMPILER=clang' '-DCMAKE_CXX_COMPILER=clang++')
    elif [[ "$COMPILER" = 'gcc' ]]; then
        CMAKE_ARGS+=('-DCMAKE_C_COMPILER=gcc' '-DCMAKE_CXX_COMPILER=g++')
    fi

    export CMAKE_ARGS
}

main() {
    # Parse script arguments
    parse_args "$@"
    # Reset intermediate files if needed
    reset_files
    # Bootstrap the python and conan environment
    set +u
    source "$SCRIPT_DIR/bootstrap.sh"
    bootstrap "${BOOTSTRAP_FLAGS[@]}"
    # Activate the conan environment
    activate_conan_env
    # Prepare build parameters
    prepare_flags

    # Configure
    if [[ $DPDK -eq 1 ]]; then
        pushd "$PROJECT_DIR/third_party/dpdk" >/dev/null
        meson setup "${MESON_ARGS[@]}" "$DPDK_BUILD_DIR"
        popd >/dev/null
    else
        cmake -B "$BUILD_DIR" -S "$PROJECT_DIR" "${CMAKE_ARGS[@]}"
    fi
}

main "$@"

# vim: set ts=4 sw=4 et:
