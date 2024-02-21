# This is used to build an image used to compile the target programs, as the
# programs must be built in the same environment to make sure they work within
# the S2E images.

FROM ubuntu:22.04

LABEL org.opencontainers.image.authors="kychou2@illinois.edu"
LABEL RUN docker run -it --rm -v <mimesis>:/mimesis IMAGE

ARG STAP_VER=3.2

RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    sudo apt-file texinfo flex bison patch python3 unzip git bc bzip2 wget \
    less g++ gcc file libc6-dev make fakeroot build-essential devscripts \
    libncurses5-dev libdw-dev elfutils gettext apt-utils \
    build-essential curl git clang cmake ninja-build pkgconf && \
    apt-get clean && \
    apt-file update

COPY systemtap-3.2.patch /

RUN curl -LO https://sourceware.org/ftp/systemtap/releases/systemtap-${STAP_VER}.tar.gz && \
    tar xf systemtap-${STAP_VER}.tar.gz && \
    cd systemtap-${STAP_VER} && \
    patch -Np1 -i /systemtap-3.2.patch && \
    mkdir build && cd build && \
    ../configure \
    --enable-pie \
    --disable-docs \
    --disable-refdocs \
    --disable-htmldocs \
    --with-python3 \
    CFLAGS="-Wno-ignored-qualifiers" \
    CXXFLAGS="-Wno-ignored-qualifiers -Wno-catch-value" \
    && \
    make -j $(nproc) && \
    sudo make install

COPY *.deb /kernel-packages/

RUN DEBIAN_FRONTEND=noninteractive apt-get install -y --allow-downgrades \
    /kernel-packages/*.deb

# Clean up
RUN rm -rf systemtap-${STAP_VER}* /kernel-packages

# Add a user for building without root privileges
RUN useradd -m -s /bin/bash builder

ENTRYPOINT ["/bin/bash", "-l", "-c"]
