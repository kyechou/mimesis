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
    -h, --help              Print this message and exit
    -i, --intfs <N>         Number of interfaces (default: 4) (only effective with --new)
    -d, --maxdepth <N>      Maximum model depth (default: 1) (only effective with --new)
    -t, --timeout <N>       Execution timeout in seconds (default: 0, no timeout) (only effective with --new)
    -k, --kernel-fork       Allow kernel forking (default: disabled) (only effective with --new)
    -n, --new               (Re)Create a new S2E project (followed by target program and arguments)
    -c, --clean             Clean up all analysis output
    -r, --run               Run the S2E analysis
    -p, --protocol <proto>  Specify the protocol ["ethernet", "ip", "demo"]
    --rm                    Remove all S2E projects
EOF
}

parse_args() {
    export INTERFACES=4
    export MAX_DEPTH=1
    export TIMEOUT=0
    export ALLOW_KERNEL_FORKING=false
    export NEW=0
    export CLEAN=0
    export RUN=0
    export PROTOCOL=
    export RM=0
    export TARGET_PROGRAM=()

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
        -d | --maxdepth)
            MAX_DEPTH="${2-}"
            shift
            ;;
        -t | --timeout)
            TIMEOUT="${2-}"
            shift
            ;;
        -k | --kernel-fork)
            ALLOW_KERNEL_FORKING=true
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
        -p | --protocol)
            PROTOCOL="${2-}"
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

    if [[ $NEW -eq 1 ]]; then
        if [[ $# -eq 0 ]]; then
            TARGET_PROGRAM+=("--no-target")
        else
            TARGET_PROGRAM+=("$(realpath "$1")")
            shift
            TARGET_PROGRAM+=("$@")
        fi
    fi

    if [[ $INTERFACES -gt $MAX_INTFS ]]; then
        die "The number of interfaces exceeds the current maximum $MAX_INTFS"
    fi

    infer_target_program_properties
}

# This function infers or obtains the following variables for target program
# properties, which may be used by all other functions in this script.
#
#   - TARGET_PROGRAM
#   - USERSPACE
#   - PROTOCOL
#
infer_target_program_properties() {
    # Read the target program from file if it's not specified from the command
    # line. Here we assume all arguments are separated by whitespaces and
    # there's no whitespace within each argument.
    if [[ ${#TARGET_PROGRAM[@]} -eq 0 ]]; then
        mapfile -t TARGET_PROGRAM <"$TARGET_PROGRAM_FILE"
    fi
    local prog_name
    prog_name="$(basename "${TARGET_PROGRAM[0]}")"

    # Whether the target program runs purely in userspace.
    export USERSPACE=0
    if [[ "$prog_name" == user-* ]]; then
        USERSPACE=1
    fi

    # Infer protocol from the program name if it's not specified already.
    if [[ -z "$PROTOCOL" ]]; then
        if [[ "$prog_name" == *-eth-* ]] || [[ "$prog_name" == *-l2-* ]]; then
            PROTOCOL="ethernet"
        elif [[ "$prog_name" == *-ip-* ]]; then
            PROTOCOL="ip"
        elif [[ "$prog_name" == *-demo-* ]]; then
            PROTOCOL="demo"
        else
            die "Failed to infer protocol from the target program. Try specifying it with -p"
        fi
    fi

    # Check for protocol validity here.
    if [[ "$PROTOCOL" != "ethernet" ]] &&
        [[ "$PROTOCOL" != "ip" ]] &&
        [[ "$PROTOCOL" != "demo" ]]; then
        die "Invalid protocol: $PROTOCOL"
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
    # Soft-link the systemtap module
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
    # 5. Set the interfaces in promiscuous mode to receive packets from the sender. (pcap library automatically does this, including tcpdump and pcap++.)
    # 6. Load systemtap kernel modules before the target program.
    local capabilities='cap_sys_admin+pe cap_net_admin+pe cap_net_raw+pe cap_sys_ptrace+pe'
    local if_cmds="ip link | grep '^[0-9]\\\\+' | cut -d: -f2 | sed 's/ //g' | grep -v '^lo' | grep -v '^sit' | xargs -I{} sudo ip link set {} up\n"
    if_cmds+="ip link | grep '^[0-9]\\\\+' | cut -d: -f2 | sed 's/ //g' | grep -v '^lo' | grep -v '^sit' | xargs -I{} sudo ip link set {} promisc on\n"
    local ipv6_disable_cmd='sudo sysctl -w net.ipv6.conf.all.disable_ipv6=1 net.ipv6.conf.default.disable_ipv6=1'
    sed -i "$S2E_PROJ_DIR/bootstrap.sh" \
        -e 's,\(> */dev/null \+2> */dev/null\),# \1,' \
        -e "s,^\( *S2E_SYM_ARGS=\".*\"\),    sudo setcap \"$capabilities\" \"\${TARGET}\"\n\1," \
        -e "s,^\(.*sysctl -w debug.exception-trace.*\)$,\1\n$ipv6_disable_cmd," \
        -e "s,^\(execute \"\${TARGET_PATH}\"\),${if_cmds}${systemtap_cmds}\1,"

    # 1. Enable the custom plugin for Mimesis.
    # 2. Disable unused Lua plugins.
    # 3. Set console logging level to "info".
    # 4. Add KLEE arguments.
    local plugin_cfg=
    plugin_cfg+='add_plugin("Mimesis")\n'
    plugin_cfg+='pluginsConfig.Mimesis = {\n'
    plugin_cfg+='    -- Maximum stateful depth of the extracted model\n'
    plugin_cfg+="    maxdepth = $MAX_DEPTH,\n"
    plugin_cfg+='    -- Execution timeout in seconds (0: no timeout)\n'
    plugin_cfg+="    timeout = $TIMEOUT,\n"
    plugin_cfg+='    -- Whether kernel forking is allowed\n'
    plugin_cfg+="    allowKernelForking = $ALLOW_KERNEL_FORKING,\n"
    plugin_cfg+='}\n'
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
        -e "s|^\(-- .* User-specific scripts begin here .*\)$|\1\n$plugin_cfg|" \
        -e 's|^\(.*add_plugin("Lua\(Bindings\|CoreEvents\)").*\)$|-- \1|' \
        -e 's|console = "debug"|console = "info"|' \
        -e "s|^\(.*kleeArgs = {.*\)$|\1\n${klee_args}|"

    # Set the number of interfaces
    echo "$INTERFACES" >"$NUM_INTFS_FILE"
    chmod 600 "$NUM_INTFS_FILE"
    # Save the target program command arguments for reference.
    echo "${TARGET_PROGRAM[@]}" >"$TARGET_PROGRAM_FILE"
    chmod 600 "$TARGET_PROGRAM_FILE"

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

        if [[ $USERSPACE -eq 0 ]]; then
            sudo setcap '$capabilities' \$(realpath sender)
            ./sender -p $PROTOCOL &>$S2E_PROJ_DIR/sender.log &
            sleep 1 # Wait for the sender to create the command file
        fi

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
        -c "$run_cmd" | tee "$S2E_PROJ_DIR/console.log"

    # Save the output.
    if ls "$S2E_PROJ_DIR/"*.model >/dev/null 2>&1; then
        local name
        name="$(find "$S2E_PROJ_DIR" -name '*.model' -exec basename -s '.model' {} \; | head -n1)"
        mkdir -p "$OUTPUT_DIR"
        cp "$S2E_PROJ_DIR/"*.model* "$OUTPUT_DIR/"
        mv "$S2E_PROJ_DIR/console.log" "$OUTPUT_DIR/$name.log"
    fi
}

main() {
    SCRIPT_DIR="$(dirname "$(realpath "${BASH_SOURCE[0]}")")"
    PROJECT_DIR="$(dirname "${SCRIPT_DIR}")"
    BUILD_DIR="$PROJECT_DIR/build"
    OUTPUT_DIR="$PROJECT_DIR/output"
    S2E_PROJ_NAME=mimesis
    S2E_DIR="$PROJECT_DIR/s2e"
    S2E_PROJ_DIR="$S2E_DIR/projects/$S2E_PROJ_NAME"
    S2E_INSTALL_DIR="$S2E_DIR/install"
    NUM_INTFS_FILE="$S2E_PROJ_DIR/num_interfaces.txt"
    TARGET_PROGRAM_FILE="$S2E_PROJ_DIR/target_program.txt"

    # Parse script arguments
    parse_args "$@"

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
