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

usage() {
    cat <<EOF
[!] Usage: $(basename "${BASH_SOURCE[0]}") [options] [<target program> [<arguments>]]

    Options:
    -h, --help          Print this message and exit
    -n, --new           (Re)Create a new S2E project (followed by target program and arguments)
    -c, --clean         Clean up all analysis output
    -r, --run           Run the S2E analysis
    --rm                Remove all S2E projects
EOF
}

parse_args() {
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

    TARGET_PROGRAM=("$@")
    if [[ "${#TARGET_PROGRAM[@]}" -eq 0 ]]; then
        TARGET_PROGRAM=("--no-target")
    fi
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

main() {
    # Parse script arguments
    parse_args "$@"

    local distro
    local script_dir
    local project_dir
    local s2e_proj_name
    local s2e_proj_dir
    distro="$(get_distro)"
    script_dir="$(dirname "$(realpath "${BASH_SOURCE[0]}")")"
    project_dir="$(dirname "${script_dir}")"
    build_dir="$project_dir/build"
    s2e_proj_name=mimesis
    s2e_proj_dir="$project_dir/s2e.$distro/s2e/projects/$s2e_proj_name"

    if [[ $RM -eq 1 ]]; then
        rm -rf "$project_dir/s2e.$distro/s2e/projects"/*
    fi

    if [[ $NEW -eq 1 ]]; then
        # Remove the s2e project directory if it exists
        if [[ -e "$s2e_proj_dir" ]]; then
            rm -rf "$s2e_proj_dir"
        fi

        # Create a new s2e project
        source "$script_dir/activate.sh"
        s2e new_project -t linux -n "$s2e_proj_name" -i ubuntu-22.04-x86_64 \
            "${TARGET_PROGRAM[@]}"
        _deactivate

        for mod in "$build_dir"/src/*.ko; do
            # Link all compiled kernel modules
            local target_path
            local mod_name
            local link_path
            target_path="$(realpath "$mod")"
            mod_name="$(basename "$mod")"
            link_path="$s2e_proj_dir/$mod_name"
            ln -s "$target_path" "$link_path"

            # # Patch bootstrap.sh to load systemtap kernel modules
            # local stap_cmds="\${S2ECMD} get $mod_name\n"
            # stap_cmds+="sudo staprun -o /dev/ttyS0 -D $mod_name\n"
            # sed -i "$s2e_proj_dir/bootstrap.sh" \
            #     -e "s,^\(execute \"\${TARGET_PATH}\"\),$stap_cmds\1,"
        done

    fi

    if [[ $CLEAN -eq 1 ]]; then
        rm -rf "$s2e_proj_dir/s2e-last" "$s2e_proj_dir"/s2e-out-*
    fi

    if [[ $RUN -eq 1 ]]; then
        pushd "$s2e_proj_dir" >/dev/null
        ./launch-s2e.sh
        popd >/dev/null
    fi
}

main "$@"

# vim: set ts=4 sw=4 et:
