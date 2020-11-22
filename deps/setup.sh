#!/bin/bash
#
# Set up the development environment
#

set -e
set -o nounset

SCRIPT_DIR="$(dirname $(realpath ${BASH_SOURCE[0]}))"
cd "$SCRIPT_DIR"

[ $UID -eq 0 ] && \
    (echo '[!] Please run this script without root privilege' >&2; exit 1)

# dependencies with local PKGBUILDs
local_depends=(cxx-common remill anvill mcsema)

depends=()


#
# Output a short name of the Linux distribution
#
get_distro() {
    if test -f /etc/os-release; then # freedesktop.org and systemd
        . /etc/os-release
        echo $NAME | cut -f 1 -d ' ' | tr '[:upper:]' '[:lower:]'
    elif type lsb_release >/dev/null 2>&1; then # linuxbase.org
        lsb_release -si | tr '[:upper:]' '[:lower:]'
    elif test -f /etc/lsb-release; then
        . /etc/lsb-release
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
        echo "$(uname -s)"
    else
        echo '[-] Unable to determine the distribution' >&2
        exit 1
    fi
}

#
# Check if the AUR package exists (0: yes; 1: no)
#
aur_pkg_exists() {
    RETURN_CODE="$(curl -I "https://aur.archlinux.org/packages/$1" 2>/dev/null \
        | head -n1 | cut -d ' ' -f 2)"
    if [ "$RETURN_CODE" = "200" ]; then
        return 0    # package found
    elif [ "$RETURN_CODE" = "404" ]; then
        return 1    # package not found
    else
        echo "[-] AUR HTTP $RETURN_CODE for $1" >&2
        exit 1
    fi
    unset RETURN_CODE
}

#
# Build and install the package with PKGBUILD
#
makepkg_arch() {
    TARGET="$1"
    shift
    echo "[+] Building $TARGET..."
    pushd "$TARGET"
    makepkg -sri $@
    popd # "$TARGET"
}

#
# Build and install the package with PKGBUILD
#
makepkg_ubuntu() {
    TARGET="$1"
    shift
    echo "[+] Building $TARGET..."
    pushd "$TARGET"
    source PKGBUILD
    srcdir="$(realpath src)"
    pkgdir=/
    mkdir -p "$srcdir"
    # prepare the sources
    i=0
    for s in ${source[@]}; do
        target=$(echo ${s%%::*})
        url=$(echo ${s#*::})
        if [[ "$target" == "$url" ]]; then
            target=$(basename "$url" | sed 's/\.git$//')
        fi
        # fetch the source files if they do not exist already
        if [[ ! -e "$target" ]]; then
            # only support common tarballs and git sources
            if [[ "$url" == git+http* ]]; then
                git clone ${url#git+} $target
            elif [[ "$url" == *.tar.gz ]]; then
                curl -L "$url" -o "$target" >/dev/null 2>&1
            else
                echo "[-] Unsupported source URL $url" >&2
                return 1
            fi
        fi
        # create links in the src directory
        ln -sf "../$target" "$srcdir/$target"
        # extract tarballs
        if [[ "$target" == *.tar.gz ]]; then
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
    if ! aur_pkg_exists "$TARGET"; then
        echo "[-] AUR package $TARGET not found" >&2
        return 1
    fi
    if [[ -d "$TARGET" ]]; then
        cd "$TARGET"; git pull; cd ..
    elif
        git clone "https://aur.archlinux.org/$TARGET.git"
    fi
    makepkg_$(get_distro) "$TARGET" $@
    rm -rf "$TARGET"
}

main() {
    DISTRO="$(get_distro)"

    if [ "$DISTRO" = "arch" ]; then
        script_depends=(base-devel curl git)
        sudo pacman -Syy --needed --noconfirm --asdeps ${script_depends[@]}

        # local dependencies
        for dep in ${local_depends[@]}; do
            makepkg_$DISTRO "$dep" --needed --noconfirm --asdeps
        done

    elif [ "$DISTRO" = "ubuntu" ]; then
        script_depends=(build-essential curl git)
        cxx_common_deps=(python3 python3-pip ninja-build liblzma-dev libssl-dev clang git)
        sudo apt update -y -qq
        sudo apt install -y -qq ${script_depends[@]}
        sudo apt install -y -qq ${cxx_common_deps[@]}

        # local dependencies
        for dep in ${local_depends[@]}; do
            makepkg_$DISTRO "$dep" --needed --noconfirm --asdeps
        done

    else
        echo "[-] Unsupported distribution: $DISTRO" >&2
        exit 1
    fi

    echo '[+] DONE.'
}


main $@

# vim: set ts=4 sw=4 et:
