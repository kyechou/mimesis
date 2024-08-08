#!/bin/bash
#
# Set up the development environment
#

set -euo pipefail

SCRIPT_PATH="$(realpath "${BASH_SOURCE[0]}")"
SCRIPT_DIR="$(dirname "$(realpath "${BASH_SOURCE[0]}")")"
cd "$SCRIPT_DIR"

msg() {
    echo -e "[+] ${1-}" >&2
}

die() {
    echo -e "[!] ${1-}" >&2
    exit 1
}

if [[ $UID -eq 0 ]]; then
    die 'Please run this script without root privilege'
fi

#
# Output a short name (v:DISTRO) of the Linux distribution
#
get_distro() {
    export DISTRO
    if test -f /etc/os-release; then # freedesktop.org and systemd
        source /etc/os-release
        DISTRO="$(echo "$NAME" | cut -f 1 -d ' ' | tr '[:upper:]' '[:lower:]')"
    elif type lsb_release >/dev/null 2>&1; then # linuxbase.org
        DISTRO="$(lsb_release -si | tr '[:upper:]' '[:lower:]')"
    elif test -f /etc/lsb-release; then
        # shellcheck source=/dev/null
        source /etc/lsb-release
        DISTRO="$(echo "$DISTRIB_ID" | tr '[:upper:]' '[:lower:]')"
    elif test -f /etc/arch-release; then
        DISTRO="arch"
    elif test -f /etc/debian_version; then
        # Older Debian, Ubuntu
        DISTRO="debian"
    elif test -f /etc/SuSe-release; then
        # Older SuSE
        DISTRO="opensuse"
    elif test -f /etc/fedora-release; then
        # Older Fedora
        DISTRO="fedora"
    elif test -f /etc/redhat-release; then
        # Older Red Hat, CentOS
        DISTRO="centos"
    elif type uname >/dev/null 2>&1; then
        # Fall back to uname
        DISTRO="$(uname -s)"
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

    if [[ "$DISTRO" == "arch" ]]; then
        (makepkg_arch "$TARGET" "$@")
    else
        (makepkg_manual "$TARGET" "$@")
    fi
    rm -rf "$TARGET"
}

# Set up docker engine quick and dirty
get_docker() {
    if command -v docker >/dev/null 2>&1; then
        return
    fi
    curl -fsSL https://get.docker.com -o get-docker.sh
    sudo sh ./get-docker.sh
    rm -f ./get-docker.sh
}

# Add the current user to group `docker` if they aren't in it already.
set_docker_group() {
    if ! getent group docker | grep -qw "$USER"; then
        sudo gpasswd -a "$USER" docker
    fi
}

build_s2e_docker_image() {
    pushd "$SCRIPT_DIR/docker" >/dev/null
    make s2e
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
    get_distro
    PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
    git -C "$PROJECT_DIR" submodule update --init --recursive
    git -C "$PROJECT_DIR" submodule foreach --recursive git clean -xdf

    if [[ "$DISTRO" == "arch" ]]; then
        if ! pacman -Q paru >/dev/null 2>&1; then
            aur_install paru --asdeps --needed --noconfirm --removemake
        fi

        script_deps=(base-devel curl git)
        build_deps=(gcc clang cmake ninja python-jinja docker python boost
            graphviz)
        style_deps=(clang yapf)
        # experiment_deps=(time python-matplotlib python-numpy python-pandas python-networkx)
        depends=("${script_deps[@]}" "${build_deps[@]}" "${style_deps[@]}")

        paru -Sy --asdeps --needed --noconfirm --removemake "${depends[@]}"
        makepkg_arch mimesis-dev -srcfi --asdeps --noconfirm

    elif [[ "$DISTRO" == "ubuntu" ]]; then
        script_deps=(build-essential curl git)
        build_deps=(g++ clang cmake ninja-build python3-jinja2 pkgconf
            python3-venv libboost-all-dev graphviz)
        style_deps=(clang-format yapf3)
        # experiment_deps=(time python3-matplotlib python3-numpy python3-pandas python3-networkx)
        depends=("${script_deps[@]}" "${build_deps[@]}" "${style_deps[@]}")

        sudo apt-get update -y -qq
        sudo apt-get install -y -qq "${depends[@]}"
        get_docker

    else
        die "Unsupported distribution: $DISTRO"
    fi

    # Make sure docker is working by this point.
    set_docker_group
    if ! docker ps &>/dev/null; then
        exec sg docker "$SCRIPT_PATH"
    fi

    build_s2e_docker_image
    "$PROJECT_DIR/scripts/build.sh" --s2e-env
    "$PROJECT_DIR/scripts/build.sh" --s2e-init
    "$PROJECT_DIR/scripts/build.sh" --s2e-libps-deps
    "$PROJECT_DIR/scripts/build.sh" --mimesis
    "$PROJECT_DIR/scripts/build.sh" --s2e
    "$PROJECT_DIR/scripts/build.sh" --s2e-image
    build_docker_images
    msg "Finished"
}

main "$@"

# vim: set ts=4 sw=4 et:
