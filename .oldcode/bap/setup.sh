#!/bin/bash

set -e

opam init --compiler 4.05.0
eval $(opam env)
sudo pacman -S --asdeps --needed --noconfirm \
    clang curl llvm7 m4 ncurses perl pkg-config time which zlib
opam install bap

# Python bindings
pushd python-bindings
makepkg -srci --asdeps --noconfirm
popd
sudo pacman -S --asdeps --needed --noconfirm \
    python-networkx # needed for tutorial

# C bindings
opam install ctypes ctypes-build ctypes-foreign
pushd c-bindings
makepkg -srci --asdeps --noconfirm
popd
