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

# This must be consistent with the variable in scripts/s2e.sh.
MAX_INTFS=128

usage() {
    cat <<EOF
[!] Usage: $(basename "${BASH_SOURCE[0]}") [options]

    Options:
    -h, --help          Print this message and exit
    -r, --reconfigure   Reconfigure the build
    -j, --parallel N    Number of parallel build tasks
    --mimesis           Build Mimesis (targets, sender, libps) (default: off)
    --stap              Build the systemtap scripts (default: off)
    --s2e-env           Build s2e-env (default: off)
    --s2e-init          Initialize S2E (default: off)
    --s2e-libps-deps    Build only S2E LLVM and KLEE for libps (default: off)
    --s2e               Build S2E (default: off)
    --s2e-local         Build S2E locally without s2e-env (default: off)
    --s2e-image         Build the S2E VM image (default: off)
EOF
}

parse_args() {
    RECONF=0
    NUM_TASKS=$(nproc)
    MIMESIS=0
    STAP=0
    S2E_ENV=0
    S2E_INIT=0
    S2E_LIBPS_DEPS=0
    S2E=0
    S2E_LOCAL=0
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
        --mimesis)
            MIMESIS=1
            ;;
        --stap)
            STAP=1
            ;;
        --s2e-env)
            S2E_ENV=1
            ;;
        --s2e-init)
            S2E_INIT=1
            ;;
        --s2e-libps-deps)
            S2E_LIBPS_DEPS=1
            ;;
        --s2e)
            S2E=1
            ;;
        --s2e-local)
            S2E_LOCAL=1
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

build_mimesis_programs() {
    local image='s2e:latest'
    local build_cmd
    build_cmd="$(
        cat <<-EOM
        set -eo pipefail
        if [[ $RECONF -eq 1 ]] || [[ ! -e '$BUILD_DIR/build.ninja' ]]; then
            '$PROJECT_DIR/scripts/configure.sh'
        fi
        cmake --build '$BUILD_DIR' -j $NUM_TASKS
        cmake --install '$BUILD_DIR' --prefix '$S2E_DIR/install'
EOM
    )"
    docker run -it --rm -u builder \
        -v "$PROJECT_DIR:$PROJECT_DIR" \
        "$image" \
        -c "$build_cmd"
}

build_systemtap_programs() {
    local image='systemtap:latest'
    local s2e_home='/home/s2e'
    local build_cmd
    build_cmd="$(
        cat <<-EOM
        set -euo pipefail

        mkdir -p $s2e_home
        export PATH=$s2e_home:\$PATH
        cp $PROJECT_DIR/build/targets/user-* $s2e_home/

        mkdir -p $PROJECT_DIR/build/src
        cd $PROJECT_DIR/build/src
        for stp_file in $PROJECT_DIR/src/*.stp; do
            stap -r 6.8.2-s2e -g -p4 -m \$(basename -s .stp \$stp_file) \$stp_file &
        done
        wait
        chown -R $(id -u):$(id -g) $PROJECT_DIR/build/src
EOM
    )"
    docker run -it --rm -v "$PROJECT_DIR:$PROJECT_DIR" "$image" \
        -c "$build_cmd"
}

build_s2e_env() {
    local image='s2e:latest'
    local build_cmd
    build_cmd="$(
        cat <<-EOM
        set -euo pipefail
        python3 -m venv --upgrade-deps $S2E_ENV_VENV_DIR
        source $S2E_ENV_VENV_DIR/bin/activate
        python3 -m pip install build installer wheel
        python3 -m pip install --compile $S2E_ENV_DIR
        deactivate
EOM
    )"
    git -C "$S2E_ENV_DIR" clean -xdf
    docker run -it --rm -u builder -v "$PROJECT_DIR:$PROJECT_DIR" "$image" \
        -c "$build_cmd"
}

s2e_init() {
    local image='s2e:latest'
    local build_cmd=
    if [[ $RECONF -eq 1 ]]; then
        build_cmd="$(
            cat <<-EOM
            set -euo pipefail
            source $S2E_ENV_VENV_DIR/bin/activate
            s2e init -f --skip-dependencies $S2E_DIR
            deactivate
EOM
        )"
    elif [[ ! -e "$S2E_DIR" ]]; then
        build_cmd="$(
            cat <<-EOM
            set -euo pipefail
            source $S2E_ENV_VENV_DIR/bin/activate
            s2e init --skip-dependencies $S2E_DIR
            deactivate
EOM
        )"
    fi
    docker run -it --rm -u builder -v "$PROJECT_DIR:$PROJECT_DIR" "$image" \
        -c "$build_cmd"

    local s2e_repos=(
        decree
        guest-images
        qemu
        s2e-env
        s2e-linux-kernel
        scripts
    )
    local s2e_repo_commits=(
        a523ec2ec1ca1e1369b33db755bed135af57e09c # decree
        94831c833b80ff2050df12d69a3f1aca3b72b491 # guest-images
        6a865ba1b1c9f5e32cd2cd9dc12ed5972addd567 # qemu
        f9815b1c4ad3ac9d9f50b120272a8d5e2d10a55c # s2e-env
        ec84db78b9ccb658c00f5a3b3c75647ada95f061 # s2e-linux-kernel
        2e61f0e026f156a3df5fd46b625d150ce30c0b85 # scripts
    )

    # Check out the specified revisions.
    for ((i = 0; i < ${#s2e_repos[@]}; ++i)); do
        git -C "$S2E_DIR/source/${s2e_repos[i]}" \
            reset --hard "${s2e_repo_commits[i]}"
    done

    # Apply patches
    local PATCH_DIR="$PROJECT_DIR/depends/patches"
    local out
    out="$(patch -d "$S2E_DIR/source/scripts" -Np1 \
        -i "$PATCH_DIR/00-fix-qemu-config.patch")" ||
        echo "$out" | grep -q 'Skipping patch' ||
        die "$out"
    out="$(patch -d "$S2E_DIR/source/qemu" -Np1 \
        -i "$PATCH_DIR/01-qemu-glfs_ftruncate.patch")" ||
        echo "$out" | grep -q 'Skipping patch' ||
        die "$out"
    out="$(patch -d "$S2E_DIR/source/qemu" -Np1 \
        -i "$PATCH_DIR/02-qemu-glfs_io_cbk.patch")" ||
        echo "$out" | grep -q 'Skipping patch' ||
        die "$out"
    out="$(patch -d "$S2E_DIR/source/guest-images" -Np1 \
        -i "$PATCH_DIR/04-s2e-guest-images-ubuntu-packages.patch")" ||
        echo "$out" | grep -q 'Skipping patch' ||
        die "$out"
    out="$(patch -d "$S2E_DIR/source/s2e-linux-kernel" -Np1 \
        -i "$PATCH_DIR/05-s2e-linux-kernel-enable-uprobes.patch")" ||
        echo "$out" | grep -q 'Skipping patch' ||
        die "$out"
    out="$(patch -d "$S2E_DIR/source/s2e-linux-kernel" -Np1 \
        -i "$PATCH_DIR/06-s2e-linux-kernel-disable-apparmor.patch")" ||
        echo "$out" | grep -q 'Skipping patch' ||
        die "$out"

    # Change the maximum number of interfaces allowed in QEMU.
    sed -i "$S2E_DIR/source/qemu/include/net/net.h" \
        -e "s,^#define \+MAX_NICS .*$,#define MAX_NICS $MAX_INTFS,"

    # TODO:
    # Some commands (e.g., basic block coverage) requrie a disassembler, in
    # which case we need to configure ida or binary ninja in $S2E_DIR/s2e.yaml.
    # See https://github.com/s2e/s2e-env#prerequisites and
    # https://github.com/S2E/s2e-env#configuring
}

# This will build llvm, z3, and klee from within S2E.
build_s2e_libps_deps() {
    local image='s2e:latest'
    local build_cmd
    build_cmd="$(
        cat <<-EOM
        set -euo pipefail
        export S2EDIR=$S2E_DIR
        export S2E_PREFIX=$S2E_DIR/install
        export BUILD_SCRIPTS_SRC=$S2E_DIR/scripts
        export S2E_BUILD=$S2E_DIR/build
        export S2E_SRC=$PROJECT_DIR/src/s2e
        make -C \$S2E_BUILD -f \$S2E_SRC/Makefile stamps/klee-release-make
EOM
    )"
    docker run -it --rm -u builder -v "$PROJECT_DIR:$PROJECT_DIR" "$image" \
        -c "$build_cmd"
}

build_s2e() {
    local image='s2e:latest'
    local build_cmd
    build_cmd="$(
        cat <<-EOM
        set -euo pipefail

        # Use our own S2E in place of the manifest S2E repo.
        rsync -a --delete-after $PROJECT_DIR/src/s2e/ $S2E_DIR/source/s2e

        source $S2E_ENV_VENV_DIR/bin/activate
        source $S2E_DIR/s2e_activate
        s2e build
        s2e_deactivate
        deactivate
EOM
    )"
    docker run -it --rm -u builder -v "$PROJECT_DIR:$PROJECT_DIR" "$image" \
        -c "$build_cmd"
}

# Build S2E locally in tree without using s2e-env.
# This is mostly used for populating the correct compile commands database for
# development environments.
build_s2e_local() {
    local image='s2e:latest'
    local build_cmd
    build_cmd="$(
        cat <<-EOM
        set -euo pipefail
        export S2EDIR=$S2E_DIR
        export S2E_PREFIX=$S2E_DIR/install
        export BUILD_SCRIPTS_SRC=$S2E_DIR/scripts
        export S2E_SRC=$PROJECT_DIR/src/s2e
        export S2E_BUILD=$PROJECT_DIR/build/s2e
        mkdir -p \$S2E_BUILD
        make -C \$S2E_BUILD -f \$S2E_SRC/Makefile all install
EOM
    )"
    docker run -it --rm -u builder -v "$PROJECT_DIR:$PROJECT_DIR" "$image" \
        -c "$build_cmd"
}

build_s2e_image() {
    local image='s2e:latest'
    local build_cmd
    build_cmd="$(
        cat <<-EOM
        set -euo pipefail
        source $S2E_ENV_VENV_DIR/bin/activate
        source $S2E_DIR/s2e_activate
        s2e image_build ubuntu-22.04-x86_64
        s2e_deactivate
        deactivate
EOM
    )"
    docker run -it --rm --privileged \
        -u builder \
        --group-add "$(getent group docker | cut -d: -f3)" \
        --group-add "$(getent group kvm | cut -d: -f3)" \
        -v "$PROJECT_DIR:$PROJECT_DIR" \
        -v /var/run/docker.sock:/var/run/docker.sock \
        "$image" \
        -c "$build_cmd"
}

main() {
    parse_args "$@"

    SCRIPT_DIR="$(dirname "$(realpath "${BASH_SOURCE[0]}")")"
    PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
    BUILD_DIR="$PROJECT_DIR/build"
    S2E_ENV_DIR="$PROJECT_DIR/src/s2e-env"
    S2E_ENV_VENV_DIR="$PROJECT_DIR/.s2e.venv"
    S2E_DIR="$PROJECT_DIR/s2e"

    if [[ $MIMESIS -eq 1 ]]; then
        build_mimesis_programs
    fi

    if [[ $STAP -eq 1 ]]; then
        build_systemtap_programs
    fi

    if [[ $S2E_ENV -eq 1 ]]; then
        build_s2e_env
    fi

    if [[ $S2E_INIT -eq 1 ]]; then
        s2e_init
    fi

    if [[ $S2E_LIBPS_DEPS -eq 1 ]]; then
        build_s2e_libps_deps
    fi

    if [[ $S2E -eq 1 ]]; then
        build_s2e
    fi

    if [[ $S2E_LOCAL -eq 1 ]]; then
        build_s2e_local
    fi

    if [[ $S2E_IMAGE -eq 1 ]]; then
        build_s2e_image
    fi
}

main "$@"

# vim: set ts=4 sw=4 et:
