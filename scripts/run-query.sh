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

main() {
    export SCRIPT_DIR
    export PROJECT_DIR
    export BUILD_DIR
    export TARGETS_DIR
    SCRIPT_DIR="$(dirname "$(realpath "${BASH_SOURCE[0]}")")"
    PROJECT_DIR="$(dirname "${SCRIPT_DIR}")"
    BUILD_DIR="$PROJECT_DIR/build"
    OUTPUT_DIR="$PROJECT_DIR/output"
    QUERY_CSV="$OUTPUT_DIR/query.csv"

    local models=(
        user-demo-stateful-depth-1-kfork-ksymaddr.model
        user-demo-stateless-depth-1-kfork-ksymaddr.model
        user-ip-stateful-depth-1-kfork-ksymaddr.model
        user-ip-stateless-depth-1-kfork-ksymaddr.model
        ebpf-demo-stateful-depth-1-kfork-ksymaddr.model
        ebpf-demo-stateless-depth-1-kfork-ksymaddr.model
        ebpf-ip-stateful-depth-1-kfork-ksymaddr.model
        ebpf-ip-stateless-depth-1-kfork-ksymaddr.model
        kernel-demo-stateful-depth-1-kfork.model
        kernel-demo-stateless-depth-1-kfork.model
        kernel-ip-stateful-depth-1-kfork.model
        kernel-ip-stateless-depth-1-kfork.model
    )

    echo "model_name,total_time,import_model_time,query_time,memory" >"$QUERY_CSV"
    for model in "${models[@]}"; do
        "$BUILD_DIR/src/mimesis" -m "$OUTPUT_DIR/$model" >>"$QUERY_CSV"
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
