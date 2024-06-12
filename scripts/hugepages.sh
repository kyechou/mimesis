#!/usr/bin/env bash
#
# Set up HugeTlbPage on the host system.
#

set -euo pipefail

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
    -n, --num N         Number of 2M huge pages (default: 512)
    -r, --reset         Reset and clean up huge pages
EOF
}

parse_args() {
    NUM_2M_PAGES=512
    RESET=0

    while :; do
        case "${1-}" in
        -h | --help)
            usage
            exit
            ;;
        -n | --num)
            NUM_2M_PAGES="${2-}"
            shift
            ;;
        -r | --reset)
            RESET=1
            ;;
        -?*) die "Unknown option: $1\n$(usage)" ;;
        *) break ;;
        esac
        shift
    done
}

main() {
    parse_args "$@"

    local mount_path="/dev/hugepages"

    if [[ $RESET -eq 1 ]]; then
        # Clean up huge pages
        echo 0 | sudo tee /proc/sys/vm/nr_hugepages >/dev/null

        # Unmount the huge pages
        if [[ -d "$mount_path" ]]; then
            sudo umount -q "$mount_path"
        fi
    else
        # Verify huge page size to be 2M.
        huge_page_size="$(
            grep Hugepagesize /proc/meminfo |
                cut -d: -f2 |
                sed -e 's/^ *//' -e 's/ *$//'
        )"
        if [[ "$huge_page_size" != "2048 kB" ]]; then
            die "Unsupported huge page size: $huge_page_size"
        fi

        # Set up huge pages
        echo "$NUM_2M_PAGES" | sudo tee /proc/sys/vm/nr_hugepages >/dev/null

        # Mount the huge pages as a file system
        mkdir -p "$mount_path"
        sudo umount -q "$mount_path" || true
        sudo mount -t hugetlbfs nodev -o mode=0775,gid=1000 "$mount_path"
    fi
}

main "$@"

# vim: set ts=4 sw=4 et:
