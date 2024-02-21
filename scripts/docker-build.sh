#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(dirname "$(realpath "${BASH_SOURCE[0]}")")"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

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

main() {
    local image='kyechou/target-builder:latest'
    docker pull "$image"
    docker run -it --rm -u builder -v "$PROJECT_DIR:/mimesis" "$image" \
        -c "/mimesis/scripts/configure.sh && /mimesis/scripts/build.sh"
}

main "$@"

# vim: set ts=4 sw=4 et:
