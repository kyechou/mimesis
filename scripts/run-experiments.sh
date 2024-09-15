#!/usr/bin/env bash
#
# Run Mimesis experiments.
#

set -xeuo pipefail

msg() {
    echo -e "[+] ${1-}" >&2
}

die() {
    echo -e "[!] ${1-}" >&2
    exit 1
}

[ $UID -eq 0 ] && die 'Please run this script without root privilege'

main() {
    SCRIPT_DIR="$(dirname "$(realpath "${BASH_SOURCE[0]}")")"
    PROJECT_DIR="$(dirname "${SCRIPT_DIR}")"
    BUILD_DIR="$PROJECT_DIR/build"
    TARGETS_DIR="$BUILD_DIR/targets"

    local target_programs=(
        user-demo-stateless
        user-demo-stateful
        user-ip-stateless
        user-ip-stateful
        user-ip-echo
        user-l2-echo
        user-l2-forward
        kernel-demo-stateless
        kernel-demo-stateful
        # kernel-demo-stateful-d3
        kernel-ip-stateless
        kernel-ip-stateful
        # ebpf-demo-stateless
        # ebpf-demo-stateful
        # ebpf-ip-stateless
        # ebpf-ip-stateful
    )

    for program in "${target_programs[@]}"; do
        for depth in 1 2; do
            for kfork in 0 1; do
                for ksymaddr in 0 1; do
                    local new_project_args=(
                        -n
                        -d "$depth"
                        -t 1800 # timeout: 30 min
                    )
                    if [[ "$kfork" -eq 1 ]]; then
                        new_project_args+=(-kf)
                    fi
                    if [[ "$ksymaddr" -eq 1 ]]; then
                        new_project_args+=(-ks)
                    fi
                    new_project_args+=("$TARGETS_DIR/$program")

                    msg "Creating new project.    ------- $(date) -------"
                    "$SCRIPT_DIR/s2e.sh" "${new_project_args[@]}"
                    msg "Start model extraction.  ------- $(date) -------"
                    "$SCRIPT_DIR/s2e.sh" -c -r
                    msg "Finish model extraction. ------- $(date) -------"
                done
            done
        done
    done

    msg "Done!"
}

main "$@"

# vim: set ts=4 sw=4 et:
