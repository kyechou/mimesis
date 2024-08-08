#!/usr/bin/env bash

set -euo pipefail

die() {
    echo -e "[!] ${1-}" >&2
    exit 1
}

if [[ $UID -eq 0 ]]; then
    die 'Please run this script without root privilege'
fi

usage() {
    cat <<EOF
[!] Usage: $(basename "${BASH_SOURCE[0]}") [options]

    Options:
    -h, --help          Print this message and exit
EOF
}

parse_args() {
    while :; do
        case "${1-}" in
        -h | --help)
            usage
            exit
            ;;
        -?*) die "Unknown option: $1\n$(usage)" ;;
        *) break ;;
        esac
        shift
    done
}

convert_dot_to_png() {
    # Convert dot files to PNG.
    if command -v dot &>/dev/null; then
        find "$BUILD_DIR" -type f -name "*.dot" -exec dot -Tpng {} -o {}.png \;
    fi
}

main() {
    SCRIPT_DIR="$(dirname "$(realpath "${BASH_SOURCE[0]}")")"
    PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
    BUILD_DIR="${PROJECT_DIR}/build"
    DATA_DIR="${PROJECT_DIR}/tests/data"
    export DATA_DIR

    # Parse script arguments
    parse_args "$@"

    # Run the tests
    trap convert_dot_to_png EXIT
    "$BUILD_DIR/tests/libps_tests"
}

main "$@"

# vim: set ts=4 sw=4 et:
