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

    if [[ $# -eq 0 ]]; then
        TARGET_PROGRAM=("--no-target")
    else
        TARGET_PROGRAM=("$(realpath "$1")")
        shift
        TARGET_PROGRAM+=("$@")
    fi
}

new_project() {
    # Remove the s2e project directory if it exists
    if [[ -e "$S2E_PROJ_DIR" ]]; then
        rm -rf "$S2E_PROJ_DIR"
    fi

    # Create a new s2e project
    local image='kyechou/s2e-builder:latest'
    local new_project_cmd
    new_project_cmd="$(
        cat <<-EOM
        set -euo pipefail
        source $SCRIPT_DIR/activate.sh
        s2e new_project -t linux -n $S2E_PROJ_NAME -i ubuntu-22.04-x86_64 \
            ${TARGET_PROGRAM[@]}
        _deactivate
EOM
    )"
    docker pull "$image"
    docker run -it --rm -u builder -v "$PROJECT_DIR:$PROJECT_DIR" "$image" \
        -c "$new_project_cmd"

    # Prepare systemtap kernel modules
    for mod in "$BUILD_DIR"/src/*.ko; do
        # Link all compiled kernel modules
        local target_path
        local mod_name
        local link_path
        target_path="$(realpath "$mod")"
        mod_name="$(basename "$mod")"
        link_path="$S2E_PROJ_DIR/$mod_name"
        ln -s "$target_path" "$link_path"

        # Patch bootstrap.sh to load systemtap kernel modules
        local stap_cmds="\${S2ECMD} get $mod_name\n"
        stap_cmds+="sudo staprun -o /dev/ttyS0 -D $mod_name\n"
        sed -i "$S2E_PROJ_DIR/bootstrap.sh" \
            -e "s,^\(execute \"\${TARGET_PATH}\"\),$stap_cmds\1,"
    done

    # Allow the analysis targets standard output/error
    sed -i "$S2E_PROJ_DIR/bootstrap.sh" \
        -e 's,\(> */dev/null \+2> */dev/null\),# \1,'
}

run_s2e() {
    local image='kyechou/s2e-builder:latest'
    local run_cmd
    run_cmd="$(
        cat <<-EOM
        set -euo pipefail
        pushd $S2E_PROJ_DIR >/dev/null
        ./launch-s2e.sh
        popd >/dev/null
EOM
    )"
    docker pull "$image"
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
    S2E_PROJ_DIR="$PROJECT_DIR/s2e/s2e/projects/$S2E_PROJ_NAME"

    if [[ $RM -eq 1 ]]; then
        rm -rf "$PROJECT_DIR/s2e/s2e/projects"/*
    fi

    if [[ $NEW -eq 1 ]]; then
        new_project
    fi

    if [[ $CLEAN -eq 1 ]]; then
        rm -rf "$S2E_PROJ_DIR/s2e-last" "$S2E_PROJ_DIR"/s2e-out-*
    fi

    if [[ $RUN -eq 1 ]]; then
        run_s2e
    fi
}

main "$@"

# vim: set ts=4 sw=4 et:
