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
    -i, --intfs <N>     Number of interfaces (default: 16) (only effective with --new)
    -n, --new           (Re)Create a new S2E project (followed by target program and arguments)
    -c, --clean         Clean up all analysis output
    -r, --run           Run the S2E analysis
    --rm                Remove all S2E projects
EOF
}

parse_args() {
    INTERFACES=16
    NEW=0
    CLEAN=0
    RUN=0
    RM=0

    while :; do
        case "${1-}" in
        -h | --help)
            usage
            exit
            ;;
        -i | --intfs)
            INTERFACES="${2-}"
            shift
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
    local systemtap_cmds=
    for mod in "$BUILD_DIR"/src/*.ko; do
        # Soft-link all compiled kernel modules
        local target_path
        local mod_name
        local link_path
        target_path="$(realpath "$mod")"
        mod_name="$(basename "$mod")"
        link_path="$S2E_PROJ_DIR/$mod_name"
        ln -s "$target_path" "$link_path"

        # Patch bootstrap.sh to load systemtap kernel modules
        systemtap_cmds+="\${S2ECMD} get $mod_name\n"
        systemtap_cmds+="sudo staprun -o /dev/ttyS0 -D $mod_name\n"
    done

    # Disable the default NIC flags. We will populate our NIC flags instead.
    sed -i "$S2E_PROJ_DIR/launch-s2e.sh" \
        -e 's,^QEMU_EXTRA_FLAGS=.*$,QEMU_EXTRA_FLAGS=,'

    # 1. Allow the analysis target output to standard output/error.
    # 2. Enable privileges for the target program. (Alternative: setuid)
    # 3. Load systemtap kernel modules before the target program.
    # 4. Turn on the interfaces before the target program.
    # 5. Mount the 9P_FS virtio file system.
    local capabilities='cap_sys_admin+pe cap_net_admin+pe cap_net_raw+pe cap_sys_ptrace+pe'
    local if_cmds="ip link | grep '^[0-9]\\\\+' | cut -d: -f2 | sed 's/ //g' | grep -v '^lo' | grep -v '^sit' | xargs -I{} sudo ip link set {} up\n"
    local guest_share_dir='/dev/shm/mimesis'
    local mount_cmds=
    mount_cmds+="mkdir -p $guest_share_dir\n"
    mount_cmds+="sudo mount -t 9p -o trans=virtio -o version=9p2000.L host0 $guest_share_dir\n"
    sed -i "$S2E_PROJ_DIR/bootstrap.sh" \
        -e 's,\(> */dev/null \+2> */dev/null\),# \1,' \
        -e "s,^\( *S2E_SYM_ARGS=\".*\"\),    sudo setcap \"$capabilities\" \"\${TARGET}\"\n\1," \
        -e "s,^\(execute \"\${TARGET_PATH}\"\),${systemtap_cmds}${if_cmds}${mount_cmds}\1,"

    # 1. Enable the custom plugin for Mimesis.
    # 2. Disable unused Lua plugins.
    local plugin_cfg=
    plugin_cfg+='add_plugin("Mimesis")\n'
    plugin_cfg+='pluginsConfig.Mimesis = {}\n'
    sed -i "$S2E_PROJ_DIR/s2e-config.lua" \
        -e "s,^\(-- .* User-specific scripts begin here .*\)$,\1\n$plugin_cfg," \
        -e 's,^\(.*add_plugin("Lua\(Bindings\|CoreEvents\)").*\)$,-- \1,'

    # TODO: kleeArgs:
    # --simplify-sym-indices \
    # --solver-backend=z3 \
    # --solver-optimize-divides \
    # --use-forked-solver \
    # --use-independent-solver \
    # --external-calls=concrete \
    # --suppress-external-warnings \
    # \
    # --libc=none \
    # --search=dfs \
    # --exit-on-error-type=ReportError \
    # --max-memory=$((100 * 1024)) --max-time=1h \
    # \
    # --write-cov \
    # --write-kqueries \
    # --write-smt2s \
    # --write-paths \
    # --write-sym-paths \
    # --write-test-info \

    # Set the number of interfaces
    echo "$INTERFACES" >"$NUM_INTFS_FILE"
    chmod 600 "$NUM_INTFS_FILE"
    # Create a QEMU snapshot to reduce VM startup time.
    create_qemu_snapshot
}

# Create a QEMU snapshot to reduce VM startup time.
create_qemu_snapshot() {
    if [[ ! -e "$NUM_INTFS_FILE" ]]; then
        die "File not found: $NUM_INTFS_FILE"
    fi

    local interfaces
    interfaces=$(<"$NUM_INTFS_FILE")
    local qemu_flags=()
    for ((i = 1; i <= interfaces; ++i)); do
        qemu_flags+=("-nic tap,ifname=tap$i,script=no,downscript=no,model=e1000")
    done

    local s2e_image_dir="$S2E_DIR/images/ubuntu-22.04-x86_64"
    local s2e_image="$s2e_image_dir/image.raw.s2e"
    local snapshot_intfs_file="$s2e_image_dir/snapshot_interfaces.txt"
    local image='kyechou/s2e-builder:latest'
    local snapshot_cmd

    # No need to create a snapshot if the number of interfaces is the same.
    if [[ -e "$snapshot_intfs_file" ]]; then
        local snapshot_intfs
        snapshot_intfs=$(<"$snapshot_intfs_file")
        if [[ $interfaces -eq $snapshot_intfs ]]; then
            return 0
        fi
    fi

    snapshot_cmd="$(
        cat <<-EOM
        set -euo pipefail
        for i in {1..$interfaces}; do
            sudo ip tuntap add mode tap tap\$i
        done

        mkdir $HOST_SHARE_DIR
        LD_PRELOAD=$S2E_INSTALL_DIR/share/libs2e/libs2e-x86_64.so \
            $S2E_INSTALL_DIR/bin/qemu-system-x86_64 \
            -enable-kvm -m 256M -nographic -monitor null \
            -drive file=$s2e_image,format=s2e,cache=writeback \
            -serial file:$s2e_image_dir/serial_ready.txt \
            -enable-serial-commands \
            ${qemu_flags[@]}

        for i in {1..$interfaces}; do
            sudo ip tuntap del mode tap tap\$i
        done
EOM
    )"
    docker run -it --rm --privileged -u builder \
        -v "$PROJECT_DIR:$PROJECT_DIR" \
        "$image" \
        -c "$snapshot_cmd"

    # Set the number of interfaces for the snapshot.
    echo "$interfaces" >"$snapshot_intfs_file"
    chmod 600 "$snapshot_intfs_file"
}

run_s2e() {
    local interfaces
    interfaces=$(<"$NUM_INTFS_FILE")
    local image='kyechou/s2e-builder:latest'
    local qemu_flags=()
    for ((i = 1; i <= interfaces; ++i)); do
        qemu_flags+=("-nic tap,ifname=tap$i,script=no,downscript=no,model=e1000")
    done
    qemu_flags+=("-virtfs local,path=$HOST_SHARE_DIR,mount_tag=host0,security_model=passthrough,id=host0")
    local run_cmd
    run_cmd="$(
        cat <<-EOM
        set -euo pipefail
        pushd $S2E_PROJ_DIR >/dev/null
        for i in {1..$interfaces}; do
            sudo ip tuntap add mode tap tap\$i
        done

        mkdir $HOST_SHARE_DIR
        ./launch-s2e.sh ${qemu_flags[@]}
        mv $HOST_SHARE_DIR/* $S2E_PROJ_DIR/

        for i in {1..$interfaces}; do
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
    S2E_DIR="$PROJECT_DIR/s2e/s2e"
    S2E_PROJ_DIR="$S2E_DIR/projects/$S2E_PROJ_NAME"
    S2E_INSTALL_DIR="$S2E_DIR/install"
    NUM_INTFS_FILE="$S2E_PROJ_DIR/num_interfaces.txt"
    HOST_SHARE_DIR='/dev/shm/mimesis'

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
