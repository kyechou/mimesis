#!/usr/bin/env bash
#
# Activate the S2E environment
#

_activate() {
    local script_dir
    local project_dir
    local s2e_env_activate
    local s2e_activate
    script_dir="$(dirname "$(realpath "${BASH_SOURCE[0]}")")"
    project_dir="$(dirname "${script_dir}")"
    s2e_env_activate="$project_dir/.s2e.venv/bin/activate"
    s2e_activate="$project_dir/s2e/s2e_activate"

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
