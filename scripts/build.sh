#!/usr/bin/env bash
#
# Build Mimesis, S2E, systemtap programs, and the target programs
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
    -r, --reconfigure   Reconfigure the build
    -j, --parallel N    Number of parallel build tasks
    -a, --all           Build everything
    --target            Build the target programs (default: off)
    --stap              Build the systemtap scripts (default: off)
    --s2e               Build the S2E with plugins (default: off)
    --s2e-image         Build the S2E VM image (default: off)
EOF
}

parse_args() {
    RECONF=0
    NUM_TASKS=$(nproc)
    TARGET=0
    STAP=0
    S2E=0
    S2E_IMAGE=0

    while :; do
        case "${1-}" in
        -h | --help)
            usage
            exit
            ;;
        -j | --parallel)
            NUM_TASKS="${2-}"
            shift
            ;;
        -r | --reconfigure)
            RECONF=1
            ;;
        -a | --all)
            TARGET=1
            STAP=1
            S2E=1
            S2E_IMAGE=1
            ;;
        --target)
            TARGET=1
            ;;
        --stap)
            STAP=1
            ;;
        --s2e)
            S2E=1
            ;;
        --s2e-image)
            S2E_IMAGE=1
            ;;
        -?*) die "Unknown option: $1\n$(usage)" ;;
        *) break ;;
        esac
        shift
    done
}

#
# Output a short name of the Linux distribution
#
get_distro() {
    if test -f /etc/os-release; then # freedesktop.org and systemd
        . /etc/os-release
        echo "$NAME" | cut -f 1 -d ' ' | tr '[:upper:]' '[:lower:]'
    elif type lsb_release >/dev/null 2>&1; then # linuxbase.org
        lsb_release -si | tr '[:upper:]' '[:lower:]'
    elif test -f /etc/lsb-release; then
        # shellcheck source=/dev/null
        source /etc/lsb-release
        echo "$DISTRIB_ID" | tr '[:upper:]' '[:lower:]'
    elif test -f /etc/arch-release; then
        echo "arch"
    elif test -f /etc/debian_version; then
        # Older Debian, Ubuntu
        echo "debian"
    elif test -f /etc/SuSe-release; then
        # Older SuSE
        echo "opensuse"
    elif test -f /etc/fedora-release; then
        # Older Fedora
        echo "fedora"
    elif test -f /etc/redhat-release; then
        # Older Red Hat, CentOS
        echo "centos"
    elif type uname >/dev/null 2>&1; then
        # Fall back to uname
        uname -s
    else
        echo -e "[!] Unrecognizable distribution" >&2
    fi
}

build_target_programs() {
    local image='kyechou/target-builder:latest'
    local build_cmd=''
    if [[ $RECONF -eq 1 ]] || [[ ! -e "$BUILD_DIR" ]]; then
        build_cmd+="$PROJECT_DIR/scripts/configure.sh && "
    fi
    build_cmd+="cmake --build '$BUILD_DIR' -j $NUM_TASKS"
    docker pull "$image"
    docker run -it --rm -u builder -v "$PROJECT_DIR:$PROJECT_DIR" "$image" \
        -c "$build_cmd"
}

build_systemtap_programs() {
    local image='kyechou/stp-builder:latest'
    local build_cmd
    build_cmd="$(
        cat <<-EOM
        mkdir -p $PROJECT_DIR/build/src
        cd $PROJECT_DIR/build/src
        for stp_file in $PROJECT_DIR/src/*.stp; do 
            stap -r 4.9.3-s2e -g -p4 -m \$(basename -s .stp \$stp_file) \$stp_file &
        done
        wait
        chown -R $(id -u):$(id -g) $PROJECT_DIR/build/src
EOM
    )"
    docker pull "$image"
    docker run -it --rm -v "$PROJECT_DIR:$PROJECT_DIR" "$image" \
        -c "$build_cmd"
}

build_s2e() {
    # Use our own S2E in place of the manifest S2E repo.
    rsync -a --delete-after "$PROJECT_DIR/src/s2e/" "$S2E_DIR/source/s2e"

    # Apply patches
    local PATCH_DIR="$PROJECT_DIR/depends/patches"
    local out
    if [ "$DISTRO" = "arch" ]; then
        out="$(patch -d "$S2E_DIR/source/s2e" -Np1 \
            -i "$PATCH_DIR/05-s2e-s2ebios.patch")" ||
            echo "$out" | grep -q 'Skipping patch' ||
            die "$out"
        out="$(patch -d "$S2E_DIR/source/s2e" -Np1 \
            -i "$PATCH_DIR/06-s2e-s2ecmd-atomic.patch")" ||
            echo "$out" | grep -q 'Skipping patch' ||
            die "$out"
    fi

    # shellcheck source=/dev/null
    source "$S2E_ENV_DIR/venv/bin/activate"
    # shellcheck source=/dev/null
    source "$S2E_DIR/s2e_activate"
    if [[ $RECONF -eq 1 ]] || [[ ! -e "$S2E_DIR/build" ]]; then
        s2e build
    else
        S2E_PREFIX="$S2E_DIR/install" \
            make -C "$S2E_DIR/build" -f "$S2E_DIR/source/s2e/Makefile" install
    fi
    s2e_deactivate
    deactivate
}

build_s2e_image() {
    # shellcheck source=/dev/null
    source "$S2E_ENV_DIR/venv/bin/activate"
    # shellcheck source=/dev/null
    source "$S2E_DIR/s2e_activate"
    s2e image_build ubuntu-22.04-x86_64
    s2e_deactivate
    deactivate
}

main() {
    parse_args "$@"

    DISTRO="$(get_distro)"
    SCRIPT_DIR="$(dirname "$(realpath "${BASH_SOURCE[0]}")")"
    PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
    BUILD_DIR="$PROJECT_DIR/build"
    S2E_ENV_DIR="$PROJECT_DIR/s2e.$DISTRO/s2e-env"
    S2E_DIR="$PROJECT_DIR/s2e.$DISTRO/s2e"

    if [[ $TARGET -eq 1 ]]; then
        build_target_programs
    fi

    if [[ $STAP -eq 1 ]]; then
        build_systemtap_programs
    fi

    if [[ $S2E -eq 1 ]]; then
        build_s2e
    fi

    if [[ $S2E_IMAGE -eq 1 ]]; then
        build_s2e_image
    fi
}

main "$@"

# vim: set ts=4 sw=4 et:
