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
    -r, --reconfigure   Reconfigure the build
EOF
}

parse_args() {
    RECONF=0

    while :; do
        case "${1-}" in
        -h | --help)
            usage
            exit
            ;;
        -r | --reconfigure)
            RECONF=1
            ;;
        -?*) die "Unknown option: $1\n$(usage)" ;;
        *) break ;;
        esac
        shift
    done
}

main() {
    parse_args "$@"

    local target_builder_img='kyechou/target-builder:latest'
    local stp_builder_img='kyechou/stp-builder:latest'

    local target_build_cmd
    if [[ $RECONF -eq 0 ]]; then
        target_build_cmd='/mimesis/scripts/build.sh'
    else
        target_build_cmd='/mimesis/scripts/configure.sh && /mimesis/scripts/build.sh'
    fi
    docker pull "$target_builder_img"
    docker run -it --rm -u builder -v "$PROJECT_DIR:/mimesis" \
        "$target_builder_img" -c "$target_build_cmd"

    local stp_build_cmd
    stp_build_cmd="$(
        cat <<-EOM
        mkdir -p /mimesis/build/src
        cd /mimesis/build/src
        stap -r 4.9.3-s2e -g -p4 -m hello_world /mimesis/src/hello_world.stp &
        stap -r 4.9.3-s2e -g -p4 -m netif_receive_skb /mimesis/src/netif_receive_skb.stp &
        wait
        chown -R $(id -u):$(id -g) /mimesis/build/src
EOM
    )"
    docker pull "$stp_builder_img"
    docker run -it --rm -v "$PROJECT_DIR:/mimesis" "$stp_builder_img" \
        -c "$stp_build_cmd"
}

main "$@"

# vim: set ts=4 sw=4 et:
