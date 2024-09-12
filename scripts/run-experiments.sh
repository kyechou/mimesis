#!/usr/bin/env bash
#
# Run Mimesis experiments.
#

set -euo pipefail

msg() {
    echo -e "[+] ${1-}" >&2
}

die() {
    echo -e "[!] ${1-}" >&2
    exit 1
}

[ $UID -eq 0 ] && die 'Please run this script without root privilege'

main() {
    # # Parse script arguments
    # parse_args "$@"

    SCRIPT_DIR="$(dirname "$(realpath "${BASH_SOURCE[0]}")")"
    PROJECT_DIR="$(dirname "${SCRIPT_DIR}")"
    BUILD_DIR="$PROJECT_DIR/build"
    TARGETS_DIR="$BUILD_DIR/targets"
    # OUTPUT_DIR="$PROJECT_DIR/output"

    local target_programs=(
        user-demo-stateless
        user-demo-stateful
        user-l2-echo
        user-l2-forward
        user-ip-echo
        user-ip-stateless
        user-ip-stateful
        kernel-demo-stateless
        kernel-demo-stateful
        kernel-demo-stateful-d3
        kernel-ip-stateless
        kernel-ip-stateful
        kernel-demo-stateless-pcpp
        kernel-demo-stateful-pcpp
        kernel-ip-stateless-pcpp
        kernel-ip-stateful-pcpp
    )

    for program in "${target_programs[@]}"; do
        for max_depth in {1..2}; do
            "$SCRIPT_DIR/s2e.sh" -d "$max_depth" -n "$TARGETS_DIR/$program"
            "$SCRIPT_DIR/s2e.sh" -r
        done
    done
}

main "$@"

# vim: set ts=4 sw=4 et:
