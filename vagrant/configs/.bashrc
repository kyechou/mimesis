#
# ~/.bashrc
#

# prompt
PS1='\[\e[92m\]\u\[\e[0m\] @ \[\e[94m\]\h\[\e[0m\] : \w\n\$ '
PROMPT_COMMAND='printf "\033]0;%s@%s:%s\007" "${USER}" "${HOSTNAME%%.*}" "${PWD/#$HOME/\~}"'

# umask
umask 022

# environment variables
export LANG=en_US.UTF-8
export LC_ALL=en_US.UTF-8
export EDITOR=vim
export VISUAL=vim
export PAGER='less -R'
export TERM='xterm-256color'
GPG_TTY=$(tty)
export GPG_TTY
export DEBUGINFOD_URLS="https://debuginfod.archlinux.org/"

# bash completion
if [[ "${BASH#*bash}" != "$BASH" ]] &&
    [[ -r /usr/share/bash-completion/bash_completion ]]; then
    . /usr/share/bash-completion/bash_completion
fi

# history settings
HISTCONTROL=ignoreboth
HISTSIZE=1000
HISTFILESIZE=1000

shopt -s checkwinsize # check window size after each external command
shopt -s histappend   # append the history file
shopt -s globstar     # globstar **
set -o vi             # start vi mode

# aliases
alias l='ls --color=auto -F'
alias la='ls --color=auto -AF'
alias ll='ls --color=auto -lAF'
alias ls='ls --color=auto -F'
alias cp='cp --sparse=auto'
alias grep='grep --color=auto'
alias fgrep='fgrep --color=auto'
alias egrep='egrep --color=auto'
alias pacman='pacman --color auto'
