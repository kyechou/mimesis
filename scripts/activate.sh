#!/bin/bash
#
# Activate the S2E environment
#

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

_activate() {
    local distro
    local script_dir
    local project_dir
    local s2e_env_activate
    local s2e_activate
    distro="$(get_distro)"
    script_dir="$(dirname "$(realpath "${BASH_SOURCE[0]}")")"
    project_dir="$(dirname "${script_dir}")"
    s2e_env_activate="$project_dir/s2e.$distro/s2e-env/venv/bin/activate"
    s2e_activate="$project_dir/s2e.$distro/s2e/s2e_activate"

    if [[ $distro != 'arch' ]] && [[ $distro != 'ubuntu' ]]; then
        echo -e "[!] Unsupported distribution: '$distro'" >&2
        return
    fi

    if [[ ! -f "$s2e_env_activate" ]]; then
        echo -e "[!] $s2e_env_activate doesn't exist or isn't a file" >&2
        return
    fi

    if [[ ! -f "$s2e_activate" ]]; then
        echo -e "[!] $s2e_activate doesn't exist or isn't a file" >&2
        return
    fi

    # shellcheck source=/dev/null
    source "$s2e_env_activate" || true
    # shellcheck source=/dev/null
    source "$s2e_activate" || true
}

_deactivate() {
    if command -v s2e_deactivate &>/dev/null; then
        s2e_deactivate || true
    fi

    if command -v deactivate &>/dev/null; then
        deactivate || true
    fi
}

_activate

# vim: set ts=4 sw=4 et:
