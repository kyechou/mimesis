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

build_s2e_builder() {
    pushd "$SCRIPT_DIR/docker" >/dev/null
    make s2e-builder
    make clean
    popd >/dev/null
}

build_docker_images() {
    pushd "$SCRIPT_DIR/docker" >/dev/null
    make
    make clean
    popd >/dev/null
}

main() {
    #
    # See the following places for required dependencies.
    #   https://github.com/S2E/s2e-env/blob/master/s2e_env/dat/config.yaml
    #   https://github.com/S2E/s2e/blob/master/Dockerfile
    #   https://github.com/S2E/scripts/blob/master/Dockerfile.dist
    #
    DISTRO="$(get_distro)"
    PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

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
        build_deps=(clang cmake ninja docker)
        style_deps=(clang yapf)
        # depends=(time)
        depends=("${script_deps[@]}" "${s2e_deps[@]}" "${build_deps[@]}"
            "${style_deps[@]}")

        paru -S --asdeps --needed --noconfirm --removemake "${depends[@]}"
        makepkg_arch mimesis-dev -srcfi --asdeps --noconfirm "$@"

    elif [ "$DISTRO" = "ubuntu" ]; then
        script_deps=(build-essential curl git)
        s2e_env_deps=(git gcc python3 python3-dev python3-venv)
        s2e_deps=(
            # Build dependencies
            build-essential cmake wget curl git texinfo flex bison python3
            python3-dev python3-pip unzip autoconf libtool automake
            # Image build dependencies
            libguestfs-tools genisoimage xz-utils docker.io p7zip-full
            libhivex-bin jigdo-file cloud-image-utils
            # S2E dependencies
            libdwarf-dev libelf-dev libelf-dev:i386 libiberty-dev binutils-dev
            libreadline-dev libboost-dev zlib1g-dev libjemalloc-dev nasm
            pkg-config libmemcached-dev libvdeplug-dev libpq-dev libc6-dev-i386
            libboost-system-dev libboost-serialization-dev libboost-regex-dev
            libprotobuf-dev protobuf-compiler libbsd-dev libsigc++-2.0-dev
            libglib2.0-dev libglib2.0-dev:i386 libglib2.0-0:i386 qemu mingw-w64
            gcc-multilib g++-multilib libpixman-1-dev libtinfo5 libpng-dev
            # s2e-env dependencies
            lcov jq
            # Testing dependencies
            wine-stable
            # Ubuntu 22
            fuse3 python3-docutils libsdl1.2-dev
        )
        build_deps=(clang cmake ninja-build pkgconf docker.io)
        style_deps=(clang-format yapf3)
        # depends=(time)
        depends=("${script_deps[@]}" "${s2e_env_deps[@]}" "${build_deps[@]}"
            "${style_deps[@]}")

        sudo apt update -y -qq
        sudo apt install -y -qq "${depends[@]}"

    else
        die "Unsupported distribution: $DISTRO"
    fi

    build_s2e_builder
    "$PROJECT_DIR/scripts/build.sh" --s2e-env
    "$PROJECT_DIR/scripts/build.sh" --s2e-init
    "$PROJECT_DIR/scripts/build.sh" --s2e
    "$PROJECT_DIR/scripts/build.sh" --s2e-image
    build_docker_images
    "$PROJECT_DIR/scripts/build.sh" --s2e
    msg "Finished"
}

main "$@"

# vim: set ts=4 sw=4 et:
