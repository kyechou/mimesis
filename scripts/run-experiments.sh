#!/usr/bin/env bash
#
# Run Mimesis experiments.
#

set -xeuo pipefail

msg() {
    echo -e "[+] ${1-}" >&2
}

hurt() {
    echo -e "[-] ${1-}" >&2
}

die() {
    echo -e "[!] ${1-}" >&2
    exit 1
}

[ $UID -eq 0 ] && die 'Please run this script without root privilege'

run() {
    program="$1"
    depth="$2"
    ksymaddr="$3"
    local new_project_args=(
        -n
        -d "$depth"
        -kf      # always enable kernel forking
        -t 14400 # timeout: 2 hrs
    )
    if [[ "$ksymaddr" -eq 1 ]]; then
        new_project_args+=(-ks)
    fi
    new_project_args+=("$TARGETS_DIR/$program")
    msg "Creating new project.    ------- $(date) -------"
    "$SCRIPT_DIR/s2e.sh" "${new_project_args[@]}"
    msg "Start model extraction.  ------- $(date) -------"
    "$SCRIPT_DIR/s2e.sh" -c -r
    msg "Finish model extraction. ------- $(date) -------"
}

main() {
    export SCRIPT_DIR
    export PROJECT_DIR
    export BUILD_DIR
    export TARGETS_DIR
    SCRIPT_DIR="$(dirname "$(realpath "${BASH_SOURCE[0]}")")"
    PROJECT_DIR="$(dirname "${SCRIPT_DIR}")"
    BUILD_DIR="$PROJECT_DIR/build"
    TARGETS_DIR="$BUILD_DIR/targets"

    local target_programs=(
        # user-demo-stateless
        # user-demo-stateful
        # user-ip-stateless
        # user-ip-stateful
        # user-ip-echo
        # user-l2-echo
        # user-l2-forward
        # kernel-demo-stateless # -d 2 -kf -ks: oom killed
        # kernel-demo-stateful
        kernel-ip-stateless
        kernel-ip-stateful
        # ebpf-demo-stateless
        # ebpf-demo-stateful
        # ebpf-ip-stateless
        # ebpf-ip-stateful
    )

    program=kernel-ip-stateful
    depth=1
    for ksymaddr in 0 1; do
        run "$program" "$depth" "$ksymaddr"
    done

    for program in "${target_programs[@]}"; do
        depth=2
        # for depth in 1 2; do
        ksymaddr=0
        run "$program" "$depth" "$ksymaddr"
        # for ksymaddr in 0 1; do
        #     run "$program" "$depth" "$ksymaddr"
        # done
        # done
    done

    msg "Done!"
}

int_handler() {
    hurt "Interrupted by user"
    exit 1
}

trap int_handler SIGINT
main "$@"

# vim: set ts=4 sw=4 et:
