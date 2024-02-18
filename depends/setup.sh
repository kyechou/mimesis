#!/bin/bash
#
# Set up the development environment
#

set -euo pipefail

SCRIPT_DIR="$(dirname "$(realpath "${BASH_SOURCE[0]}")")"

cd "$SCRIPT_DIR"

msg() {
    echo -e "[+] ${1-}" >&2
}

die() {
    echo -e "[!] ${1-}" >&2
    exit 1
}

[ $UID -eq 0 ] && die 'Please run this script without root privilege'

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
        die 'Unable to determine the distribution'
    fi
}

#
# Build and install the package with PKGBUILD
#
makepkg_arch() {
    TARGET="$1"
    shift
    msg "Building $TARGET..."
    pushd "$TARGET"
    makepkg -sri "$@"
    popd # "$TARGET"
}

element_in() {
    local e match="$1"
    shift
    for e in "$@"; do [[ "$e" == "$match" ]] && return 0; done
    return 1
}

#
# Build and install the package with PKGBUILD
#
makepkg_manual() {
    MAKEFLAGS="-j$(nproc)"
    export MAKEFLAGS
    [[ -z "${CFLAGS+x}" ]] && export CFLAGS=""
    [[ -z "${CXXFLAGS+x}" ]] && export CXXFLAGS=""

    TARGET="$1"
    shift
    msg "Building $TARGET..."
    pushd "$TARGET"
    # shellcheck disable=SC2016
    sed -i PKGBUILD \
        -e 's|\<python\> |python3 |g' \
        -e '/[[:space:]]*rm -rf .*\$pkgdir\>.*$/d'
    # shellcheck source=/dev/null
    source PKGBUILD
    srcdir="$(realpath src)"
    pkgdir=/
    mkdir -p "$srcdir"
    # prepare the sources
    i=0
    # shellcheck disable=SC2154
    for s in "${source[@]}"; do
        target=${s%%::*}
        url=${s#*::}
        if [[ "$target" == "$url" ]]; then
            target=$(basename "${url%%#*}" | sed 's/\.git$//')
        fi
        # fetch the source files if they do not exist already
        if [[ ! -e "$target" ]]; then
            # only support common tarballs and git sources
            if [[ "$url" == git+http* ]]; then
                # shellcheck disable=SC2001
                git clone "$(echo "${url%%#*}" | sed -e 's/^git+//')" "$target"
                # check out the corresponding revision if there is a fragment
                fragment=${url#*#}
                if [[ "$fragment" != "$url" ]]; then
                    pushd "$target"
                    git checkout "${fragment#*=}"
                    popd
                fi
            elif [[ "$url" == *.tar.* ]]; then
                curl -L "$url" -o "$target" >/dev/null 2>&1
            else
                die "Unsupported source URL $url"
            fi
        fi
        # create links in the src directory
        ln -sf "../$target" "$srcdir/$target"
        # extract tarballs if the target is not in noextract
        # shellcheck disable=SC2154
        if [[ "$target" == *.tar.* ]] &&
            ! element_in "$target" "${noextract[@]}"; then
            tar -C "$srcdir" -xf "$srcdir/$target"
        fi
        i=$((i + 1))
    done
    # execute the PKGBUILD functions
    pushd "$srcdir"
    [ "$(type -t prepare)" = "function" ] && prepare
    [ "$(type -t build)" = "function" ] && build
    [ "$(type -t check)" = "function" ] && check
    sudo bash -c "pkgdir=\"$pkgdir\"; srcdir=\"$srcdir\";
                  source \"$srcdir/../PKGBUILD\"; package"
    popd # "$srcdir"
    popd # "$TARGET"
}

#
# Build and install package from AUR
#
aur_install() {
    TARGET="$1"
    shift
    if [[ -d "$TARGET" ]]; then
        cd "$TARGET"
        git pull
        cd ..
    else
        git clone "https://aur.archlinux.org/$TARGET.git"
    fi

    DISTRO="$(get_distro)"
    if [ "$DISTRO" = "arch" ]; then
        (makepkg_arch "$TARGET" "$@")
    else
        (makepkg_manual "$TARGET" "$@")
    fi
    rm -rf "$TARGET"
}

setup_s2e_env() {
    local S2E_ENV_URL='https://github.com/s2e/s2e-env.git'
    local S2E_ENV_REV='81aeeaa58b827f0464530232a3e417d214d85dcb'
    local DIST_DIR="$S2E_ENV_DIR/dist"

    if [[ ! -e "$S2E_ENV_DIR" ]]; then
        git clone "$S2E_ENV_URL" "$S2E_ENV_DIR"
    fi
    git -C "$S2E_ENV_DIR" reset --hard "$S2E_ENV_REV"
    python3 -m venv --upgrade-deps "$S2E_ENV_DIR/venv"
    # shellcheck source=/dev/null
    source "$S2E_ENV_DIR/venv/bin/activate"
    python3 -m pip install build installer wheel
    python3 -m build --wheel --outdir "$DIST_DIR" "$S2E_ENV_DIR"
    python3 -m pip install --compile "$DIST_DIR"/*.whl
    # Tests
    if [[ ! -e "$S2E_ENV_DIR/venv-test" ]]; then
        pushd "$S2E_ENV_DIR"
        "$S2E_ENV_DIR/test.sh"
        popd # "$S2E_ENV_DIR"
    fi
    deactivate

    msg "Finished setting up s2e-env"
}

setup_s2e() {
    # shellcheck source=/dev/null
    source "$S2E_ENV_DIR/venv/bin/activate"
    # If the s2e directory already exists, assume the initialization step was
    # done successfully last time, so skip the initialization. Alternatively, we
    # may pass `-f` to `s2e init` to force re-init the s2e directory.
    if [[ ! -e "$S2E_DIR" ]]; then
        if [[ "$DISTRO" == "arch" ]]; then
            s2e init --skip-dependencies "$S2E_DIR"
        else
            s2e init "$S2E_DIR"
        fi
    fi

    # Apply patches
    local PATCH_DIR="$SCRIPT_DIR/patches"
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
    out="$(patch -d "$S2E_DIR/source/qemu" -Np1 \
        -i "$PATCH_DIR/03-qemu-x11-window-type.patch")" ||
        echo "$out" | grep -q 'Skipping patch' ||
        die "$out"
    if [ "$DISTRO" = "arch" ]; then
        out="$(patch -d "$S2E_DIR/source/s2e" -Np1 \
            -i "$PATCH_DIR/04-s2e-s2ecmd-atomic.patch")" ||
            echo "$out" | grep -q 'Skipping patch' ||
            die "$out"
    fi
    out="$(patch -d "$S2E_DIR/source/s2e" -Np1 \
        -i "$PATCH_DIR/05-s2e-s2ebios.patch")" ||
        echo "$out" | grep -q 'Skipping patch' ||
        die "$out"
    # NOTE: Remove this patch once https://github.com/S2E/guest-images/pull/45
    # is merged.
    out="$(patch -d "$S2E_DIR/source/guest-images" -Np1 \
        -i "$PATCH_DIR/06-s2e-guest-images-ubuntu-iso.patch")" ||
        echo "$out" | grep -q 'Skipping patch' ||
        die "$out"

    # TODO:
    # Some commands (e.g., basic block coverage) requrie a disassembler, in
    # which case we need to configure ida or binary ninja in $S2E_DIR/s2e.yaml.
    # See https://github.com/s2e/s2e-env#prerequisites and
    # https://github.com/S2E/s2e-env#configuring

    # shellcheck source=/dev/null
    source "$S2E_DIR/s2e_activate"
    s2e build

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
    DISTRO="$(get_distro)"
    PROJECT_DIR="$(dirname "${SCRIPT_DIR}")"
    S2E_ENV_DIR="$PROJECT_DIR/s2e.$DISTRO/s2e-env"
    S2E_DIR="$PROJECT_DIR/s2e.$DISTRO/s2e"

    mkdir -p "$PROJECT_DIR/s2e.$DISTRO"

    if [ "$DISTRO" = "arch" ]; then
        if ! pacman -Q paru >/dev/null 2>&1; then
            aur_install paru --asdeps --needed --noconfirm --removemake
        fi

        script_deps=(base-devel curl git)
        s2e_deps=(
            # s2e build dependencies
            base-devel cmake wget curl git texinfo flex bison python python-pip
            unzip autoconf libtool automake
            # s2e dependencies
            libdwarf libelf lib32-libelf binutils readline boost zlib jemalloc
            nasm pkgconf memcached libmemcached-awesome vde2 postgresql glibc
            lib32-glibc protobuf libbsd libsigc++ glib2 lib32-glib2 qemu-full
            mingw-w64-binutils mingw-w64-crt mingw-w64-gcc mingw-w64-headers
            mingw-w64-winpthreads gcc pixman ncurses lib32-ncurses
            ncurses5-compat-libs lib32-ncurses5-compat-libs libpng
            # s2e dependencies for building images
            cloud-image-utils libguestfs
            # (qemu): librbd xfsprogs rdma-core
            # s2e-env dependencies
            git gcc python lcov jq
            # testing dependencies
            wine-stable
            # other dependencies
            fuse3 python-docutils sdl12-compat lib32-sdl12-compat pxz-git
            python-distro
        )
        build_deps=(clang cmake)
        style_deps=(clang yapf)
        # depends=(time)
        depends=("${script_deps[@]}" "${s2e_deps[@]}" "${build_deps[@]}"
            "${style_deps[@]}")

        paru -S --asdeps --needed --noconfirm --removemake "${depends[@]}"
        makepkg_arch mimesis-dev -srcfi --asdeps --noconfirm "$@"

    elif [ "$DISTRO" = "ubuntu" ]; then
        script_deps=(build-essential curl git)
        s2e_env_deps=(git gcc python3 python3-dev python3-venv)
        build_deps=(clang python3-venv cmake pkgconf)
        style_deps=(clang-format yapf3)
        # depends=(time)
        depends=("${script_deps[@]}" "${s2e_env_deps[@]}" "${build_deps[@]}"
            "${style_deps[@]}")

        sudo apt update -y -qq
        sudo apt install -y -qq "${depends[@]}"

    else
        die "Unsupported distribution: $DISTRO"
    fi

    setup_s2e_env
    setup_s2e
    build_s2e_image
    msg "Finished"
}

main "$@"

# vim: set ts=4 sw=4 et:
