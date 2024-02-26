# This is used to build S2E.

FROM ubuntu:22.04

LABEL org.opencontainers.image.authors="kychou2@illinois.edu"

RUN dpkg --add-architecture i386 && \
    apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    # build dependencies
    ca-certificates sudo apt-file build-essential curl wget flex bison \
    lsb-release autoconf automake libtool gcc g++ cmake git mingw-w64 \
    # S2E dependencies
    libdwarf-dev libelf-dev libelf-dev:i386 libboost-dev zlib1g-dev \
    libjemalloc-dev nasm pkg-config libmemcached-dev libpq-dev libc6-dev \
    libc6-dev-i386 binutils-dev libboost-system-dev libboost-serialization-dev \
    libboost-regex-dev libbsd-dev libpixman-1-dev libglib2.0-dev \
    libglib2.0-dev:i386 python3-docutils libpng-dev gcc-multilib g++-multilib \
    # S2E Z3 dependencies
    libgomp1 unzip \
    # python dependencies
    python3 python3-dev python3-pip python3-venv python3-distro python3-yaml \
    python3-matplotlib python3-lxml python3-pip python-is-python3 \
    python3-setuptools python3-wheel \
    # other dependencies
    netcat vim apport psmisc p7zip-full unzip libsvn1 libcurl4 gdb libssl-dev \
    libstdc++6:i386 libpixman-1-0 libxml2-dev libicu-dev libxslt1-dev \
    libffi-dev lsof libgettextpo0 libpcre3 libpcre3-dev libpcre3:i386 \
    liblua5.1-0 liblua5.2-0 libsigc++-2.0-dev jq libpng16-16 time \
    libsdl1.2-dev libmagic1 \
    # qemu dependencies
    $(apt-cache depends qemu-system-x86 | grep Depends | sed "s/.*ends:\ //" \
    | grep -v '<' | tr '\n' ' ') \
    && \
    apt-get clean && \
    apt-file update

RUN python3 -m pip install --upgrade pip setuptools wheel

# In libtcg/CMakeLists.txt, pkg-config (pkg_check_modules) fails the find the
# correct include directories. This is a workaround.
RUN mkdir -p /usr/lib/glib-2.0/include && \
    ln -s /usr/lib/x86_64-linux-gnu/glib-2.0/include/glibconfig.h \
    /usr/lib/glib-2.0/include/glibconfig.h

# Add a user for building without root privileges
RUN useradd -m -s /bin/bash builder

ENTRYPOINT ["/bin/bash"]

# # Build LLVM first (to avoid rebuilding it for every change)
# RUN mkdir s2e
# RUN mkdir s2e-build
# COPY Makefile s2e/
# COPY scripts/determine_clang_binary_suffix.py s2e/scripts/
#
# RUN cd s2e-build && \
#     make -f ../s2e/Makefile S2E_PREFIX=/opt/s2e stamps/llvm-release-make
#
# # Build S2E dependencies
# RUN cd s2e-build && \
#     make -f ../s2e/Makefile S2E_PREFIX=/opt/s2e stamps/soci-make
#
# RUN cd s2e-build && \
#     make -f ../s2e/Makefile S2E_PREFIX=/opt/s2e stamps/z3
#
# RUN cd s2e-build && \
#     make -f ../s2e/Makefile S2E_PREFIX=/opt/s2e stamps/protobuf-make
#
# RUN cd s2e-build && \
#     make -f ../s2e/Makefile S2E_PREFIX=/opt/s2e stamps/libdwarf-make
#
# RUN cd s2e-build && \
#     make -f ../s2e/Makefile S2E_PREFIX=/opt/s2e stamps/rapidjson-make
#
# # Build and install everything else
# RUN cd s2e-build && \
#     make -f ../s2e/Makefile S2E_PREFIX=/opt/s2e install
