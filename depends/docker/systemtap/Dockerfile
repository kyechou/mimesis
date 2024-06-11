# This is used to compile the systemtap scripts.

FROM debian:12.5

LABEL org.opencontainers.image.authors="kychou2@illinois.edu"

RUN echo "deb http://archive.debian.org/debian/ stretch main contrib non-free" > /etc/apt/sources.list
RUN echo "deb-src http://archive.debian.org/debian/ stretch main contrib non-free" >> /etc/apt/sources.list

RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    sudo apt-file flex bison patch python python-setuptools unzip git bc bzip2 \
    wget less g++ gcc file libc6-dev make fakeroot build-essential devscripts \
    libncurses5-dev pahole libdw-dev elfutils gettext rsync cpio kmod \
    libssl-dev debhelper-compat && \
    apt-get clean && \
    apt-file update

ARG STAP_VER=5.1

RUN git clone https://github.com/S2E/systemtap.git && \
    cd systemtap && \
    git checkout release-${STAP_VER} && \
    git reset --hard release-${STAP_VER} && \
    mkdir build && cd build && \
    ../configure --disable-docs --disable-refdocs --disable-htmldocs && \
    make -j $(nproc) && \
    sudo make install

COPY *.deb /kernel-packages/

RUN DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    --allow-downgrades \
    /kernel-packages/*.deb

# Clean up
RUN rm -rf systemtap /kernel-packages

ENTRYPOINT ["/bin/bash"]
