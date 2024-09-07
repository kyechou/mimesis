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
    -i, --intfs <N>     Number of interfaces (default: 8) (only effective with --new)
    -n, --new           (Re)Create a new S2E project (followed by target program and arguments)
    -c, --clean         Clean up all analysis output
    -r, --run           Run the S2E analysis
    --rm                Remove all S2E projects
EOF
}

parse_args() {
    INTERFACES=8
    NEW=0
    CLEAN=0
    RUN=0
    RM=0
    USERSPACE=0

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
        if [[ "$(basename "$1")" == user-* ]]; then
            USERSPACE=1
        fi

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
    local image='s2e:latest'
    local new_project_cmd
    new_project_cmd="$(
        cat <<-EOM
        set -euo pipefail
        export TERM=xterm-256color
        source $SCRIPT_DIR/activate.sh
        s2e new_project -t linux -n $S2E_PROJ_NAME -i ubuntu-22.04-x86_64 \
            ${TARGET_PROGRAM[@]}
        _deactivate
EOM
    )"
    docker run --rm -u builder -v "$PROJECT_DIR:$PROJECT_DIR" "$image" \
        -c "$new_project_cmd"

    # Prepare systemtap kernel modules
    local mod
    if [[ $USERSPACE -eq 1 ]]; then
        mod="$BUILD_DIR/src/$(basename "${TARGET_PROGRAM[0]//-/_}").ko"
    else
        mod="$BUILD_DIR/src/kernel_probes.ko"
    fi
    # Soft-link the compiled kernel module
    local target_path
    local mod_name
    local link_path
    target_path="$(realpath "$mod")"
    mod_name="$(basename "$mod")"
    link_path="$S2E_PROJ_DIR/$mod_name"
    ln -s "$target_path" "$link_path"
    # Patch bootstrap.sh to load systemtap kernel modules
    local systemtap_cmds=
    systemtap_cmds+="\${S2ECMD} get $mod_name\n"
    systemtap_cmds+="sudo staprun -o /dev/ttyS0 -D $mod_name\n"

    # Soft-link the packet sender daemon.
    ln -s "$(realpath "$BUILD_DIR/src/sender")" "$S2E_PROJ_DIR/"

    # Disable the default NIC flags. We will populate our NIC flags instead.
    sed -i "$S2E_PROJ_DIR/launch-s2e.sh" \
        -e 's,^QEMU_EXTRA_FLAGS=.*$,QEMU_EXTRA_FLAGS=,'

    # 1. Allow the analysis target output to standard output/error.
    # 2. Enable privileges for the target program. (Alternative: setuid)
    # 3. Disable IPv6.
    # 4. Turn on the interfaces before the target program.
    # 5. Load systemtap kernel modules before the target program.
    local capabilities='cap_sys_admin+pe cap_net_admin+pe cap_net_raw+pe cap_sys_ptrace+pe'
    local if_cmds="ip link | grep '^[0-9]\\\\+' | cut -d: -f2 | sed 's/ //g' | grep -v '^lo' | grep -v '^sit' | xargs -I{} sudo ip link set {} up\n"
    local ipv6_disable_cmd='sudo sysctl -w net.ipv6.conf.all.disable_ipv6=1 net.ipv6.conf.default.disable_ipv6=1'
    sed -i "$S2E_PROJ_DIR/bootstrap.sh" \
        -e 's,\(> */dev/null \+2> */dev/null\),# \1,' \
        -e "s,^\( *S2E_SYM_ARGS=\".*\"\),    sudo setcap \"$capabilities\" \"\${TARGET}\"\n\1," \
        -e "s,^\(.*sysctl -w debug.exception-trace.*\)$,\1\n$ipv6_disable_cmd," \
        -e "s,^\(execute \"\${TARGET_PATH}\"\),${if_cmds}${systemtap_cmds}\1,"

    # 1. Enable the custom plugin for Mimesis.
    # 2. Disable unused Lua plugins.
    # 3. Add KLEE arguments.
    local plugin_cfg=
    plugin_cfg+='add_plugin("Mimesis")\n'
    plugin_cfg+='pluginsConfig.Mimesis = {}\n'
    local klee_args=
    klee_args+='        "--const-array-opt",\n' # const array optimizations
    klee_args+='        "--debug-constraints",\n'
    # klee_args+='        "--debug-expr-simplifier",\n'
    klee_args+='        "--debug-log-state-merge",\n'
    klee_args+='        "--debug-validate-solver",\n'
    klee_args+='        "--enable-timeingsolver",\n' # measure query time
    klee_args+='        "--end-solver=z3",\n'
    klee_args+='        "--end-solver-increm=stack",\n' # none, stack, assumptions
    # klee_args+='        "--log-partial-queries-early",\n'
    klee_args+='        "--print-concretized-expression",\n'
    # klee_args+='        "--print-expr-simplifier",\n'
    # klee_args+='        "--print-mode-switch",\n'
    klee_args+='        "--s2e-debug-edge-detector",\n'
    klee_args+='        "--simplify-sym-indices",\n'
    klee_args+='        "--smtlib-abbreviation-mode=let",\n' # none, let, named
    klee_args+='        "--smtlib-display-constants=dec",\n' # bin, hex, dec
    klee_args+='        "--smtlib-human-readable",\n'
    klee_args+='        "--state-shared-memory",\n'
    klee_args+='        "--suppress-external-warnings",\n'
    klee_args+='        "--use-cache",\n'
    klee_args+='        "--use-cex-cache",\n'
    klee_args+='        "--use-dfs-search",\n'
    # klee_args+='        "--use-random-search",\n'
    klee_args+='        "--use-expr-simplifier",\n'
    # klee_args+='        "--use-fast-cex-solver",\n'
    klee_args+='        "--use-independent-solver",\n'
    klee_args+='        "--use-query-log=all:smt2,solver:smt2",\n'
    klee_args+='        "--use-visitor-hash",\n'
    klee_args+='        "--validate-expr-simplifier",\n'
    # klee_args+='        "--verbose-fork-info",\n'
    # klee_args+='        "--verbose-state-deletion",\n'
    # klee_args+='        "--verbose-state-switching",\n'
    # klee_args+='        "--z3-debug-solver-stack",\n'
    # klee_args+='        "--z3-array-cons-mode=ite",\n' # ite, stores, asserts
    # klee_args+='        "--z3-use-hash-consing",\n'
    # klee_args+='        "--help",\n' # "--help" to show the available options
    sed -i "$S2E_PROJ_DIR/s2e-config.lua" \
        -e "s,^\(-- .* User-specific scripts begin here .*\)$,\1\n$plugin_cfg," \
        -e 's,^\(.*add_plugin("Lua\(Bindings\|CoreEvents\)").*\)$,-- \1,' \
        -e "s|^\(.*kleeArgs = {.*\)$|\1\n${klee_args}|"

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
    local image='s2e:latest'
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
    local image='s2e:latest'
    local qemu_flags=()
    for ((i = 1; i <= interfaces; ++i)); do
        qemu_flags+=("-nic tap,ifname=tap$i,script=no,downscript=no,model=e1000")
    done
    local capabilities='cap_sys_admin+pe cap_net_admin+pe cap_net_raw+pe cap_sys_ptrace+pe'
    local run_cmd
    run_cmd="$(
        cat <<-EOM
        set -uo pipefail
        pushd $S2E_PROJ_DIR >/dev/null
        for i in {1..$interfaces}; do
            sudo ip tuntap add mode tap tap\$i
            sudo ip link set dev tap\$i up
        done

        sudo setcap '$capabilities' \$(realpath sender)
        ./sender &>$S2E_PROJ_DIR/sender.log &
        sleep 0.5 # Wait for the sender to create the command file

        date '+Timestamp: %s.%N'
        /usr/bin/time ./launch-s2e.sh ${qemu_flags[@]}
        date '+Timestamp: %s.%N'

        # Dump all pcap files into text form
        for pcap in *.pcap; do
            tcpdump -e -xx -r \$pcap &>$S2E_PROJ_DIR/\$pcap.log
        done

        for i in {1..$interfaces}; do
            sudo ip link set dev tap\$i down
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
    S2E_DIR="$PROJECT_DIR/s2e"
    S2E_PROJ_DIR="$S2E_DIR/projects/$S2E_PROJ_NAME"
    S2E_INSTALL_DIR="$S2E_DIR/install"
    NUM_INTFS_FILE="$S2E_PROJ_DIR/num_interfaces.txt"

    if [[ $RM -eq 1 ]]; then
        rm -rf "$PROJECT_DIR/s2e/projects"/*
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
