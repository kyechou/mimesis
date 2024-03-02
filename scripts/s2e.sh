#!/usr/bin/env bash
#
# Convenient script for interacting with S2E project
#

set -euo pipefail

die() {
    echo -e "[!] ${1-}" >&2
    exit 1
}

[ $UID -eq 0 ] && die 'Please run this script without root privilege'

# This must be consistent with the variable in scripts/build.sh.
MAX_INTFS=128

usage() {
    cat <<EOF
[!] Usage: $(basename "${BASH_SOURCE[0]}") [options] [<target program> [<arguments>]]

    Options:
    -h, --help          Print this message and exit
    -n, --new           (Re)Create a new S2E project (followed by target program and arguments)
    -c, --clean         Clean up all analysis output
    -r, --run           Run the S2E analysis
    -i, --intfs <N>     Number of interfaces to be spawned (default: 16)
    --rm                Remove all S2E projects
EOF
}

parse_args() {
    NEW=0
    CLEAN=0
    RUN=0
    INTERFACES=16
    RM=0

    while :; do
        case "${1-}" in
        -h | --help)
            usage
            exit
            ;;
        -n | --new)
            NEW=1
            ;;
        -c | --clean)
            CLEAN=1
            ;;
        -r | --run)
            RUN=1
            ;;
        -i | --intfs)
            INTERFACES="${2-}"
            shift
            ;;
        --rm)
            RM=1
            ;;
        -?*) die "Unknown option: $1\n$(usage)" ;;
        *) break ;;
        esac
        shift
    done

    if [[ $# -eq 0 ]]; then
        TARGET_PROGRAM=("--no-target")
    else
        TARGET_PROGRAM=("$(realpath "$1")")
        shift
        TARGET_PROGRAM+=("$@")
    fi

    if [[ $INTERFACES -gt $MAX_INTFS ]]; then
        die "The number of interfaces exceeds the current maximum $MAX_INTFS"
    fi
}

new_project() {
    # Remove the s2e project directory if it exists
    if [[ -e "$S2E_PROJ_DIR" ]]; then
        rm -rf "$S2E_PROJ_DIR"
    fi

    # Create a new s2e project
    local image='kyechou/s2e-builder:latest'
    local new_project_cmd
    new_project_cmd="$(
        cat <<-EOM
        set -euo pipefail
        source $SCRIPT_DIR/activate.sh
        s2e new_project -t linux -n $S2E_PROJ_NAME -i ubuntu-22.04-x86_64 \
            ${TARGET_PROGRAM[@]}
        _deactivate
EOM
    )"
    docker run -it --rm -u builder -v "$PROJECT_DIR:$PROJECT_DIR" "$image" \
        -c "$new_project_cmd"

    # Prepare systemtap kernel modules
    for mod in "$BUILD_DIR"/src/*.ko; do
        # Link all compiled kernel modules
        local target_path
        local mod_name
        local link_path
        target_path="$(realpath "$mod")"
        mod_name="$(basename "$mod")"
        link_path="$S2E_PROJ_DIR/$mod_name"
        ln -s "$target_path" "$link_path"

        # Patch bootstrap.sh to load systemtap kernel modules
        local stap_cmds="\${S2ECMD} get $mod_name\n"
        stap_cmds+="sudo staprun -o /dev/ttyS0 -D $mod_name\n"
        sed -i "$S2E_PROJ_DIR/bootstrap.sh" \
            -e "s,^\(execute \"\${TARGET_PATH}\"\),$stap_cmds\1,"
    done

    # Allow the analysis targets standard output/error
    sed -i "$S2E_PROJ_DIR/bootstrap.sh" \
        -e 's,\(> */dev/null \+2> */dev/null\),# \1,'

    # Disable QEMU snapshot
    sed -i "$S2E_PROJ_DIR/launch-s2e.sh" \
        -e 's,^QEMU_SNAPSHOT=.*$,QEMU_SNAPSHOT=,' \
        -e 's,^QEMU_EXTRA_FLAGS=.*$,QEMU_EXTRA_FLAGS=,'

    # TODO: Consider creating a snapshot to reduce the VM startup time for
    # analyses. Example snapshotting command from s2e/guest-images:
    # LD_PRELOAD=/home/kyc/cs/projects/mimesis/s2e/s2e/install/share/libs2e/libs2e-x86_64.so /home/kyc/cs/projects/mimesis/s2e/s2e/install/bin/qemu-system-x86_64 -enable-kvm -drive if=ide,index=0,file=/home/kyc/cs/projects/mimesis/s2e/s2e/images/ubuntu-22.04-x86_64/image.raw.s2e,format=s2e,cache=writeback -serial file:/home/kyc/cs/projects/mimesis/s2e/s2e/images/ubuntu-22.04-x86_64/serial_ready.txt -enable-serial-commands -net none -net nic,model=e1000 -m 256M -nographic -monitor null

}

run_s2e() {
    local image='kyechou/s2e-builder:latest'
    local qemu_flags=()
    for ((i = 1; i <= INTERFACES; ++i)); do
        qemu_flags+=("-nic tap,ifname=tap$i,script=no,downscript=no,model=virtio-net-pci")
    done
    local run_cmd
    run_cmd="$(
        cat <<-EOM
        set -euo pipefail
        pushd $S2E_PROJ_DIR >/dev/null
        echo '==> Creating tap interfaces...'
        for i in {1..$INTERFACES}; do
            sudo ip tuntap add mode tap tap\$i
        done

        echo '==> Launching S2E...'
        ./launch-s2e.sh ${qemu_flags[@]}

        echo '==> Deleting tap interfaces...'
        for i in {1..$INTERFACES}; do
            sudo ip tuntap del mode tap tap\$i
        done
        popd >/dev/null
EOM
    )"

    docker run -it --rm --privileged -u builder \
        -v "$PROJECT_DIR:$PROJECT_DIR" \
        "$image" \
        -c "$run_cmd"
}

main() {
    # Parse script arguments
    parse_args "$@"

    SCRIPT_DIR="$(dirname "$(realpath "${BASH_SOURCE[0]}")")"
    PROJECT_DIR="$(dirname "${SCRIPT_DIR}")"
    BUILD_DIR="$PROJECT_DIR/build"
    S2E_PROJ_NAME=mimesis
    S2E_PROJ_DIR="$PROJECT_DIR/s2e/s2e/projects/$S2E_PROJ_NAME"

    if [[ $RM -eq 1 ]]; then
        rm -rf "$PROJECT_DIR/s2e/s2e/projects"/*
    fi

    if [[ $NEW -eq 1 ]]; then
        new_project
    fi

    if [[ $CLEAN -eq 1 ]]; then
        sudo rm -rf "$S2E_PROJ_DIR/s2e-last" "$S2E_PROJ_DIR"/s2e-out-*
    fi

    if [[ $RUN -eq 1 ]]; then
        run_s2e
    fi
}

main "$@"

# vim: set ts=4 sw=4 et:
