# This is used to compile the systemtap scripts.

FROM debian:9.3

LABEL org.opencontainers.image.authors="kychou2@illinois.edu"

RUN echo "deb http://archive.debian.org/debian/ stretch main contrib non-free" > /etc/apt/sources.list
RUN echo "deb-src http://archive.debian.org/debian/ stretch main contrib non-free" >> /etc/apt/sources.list

RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    sudo apt-file flex bison patch python python-setuptools unzip git bc bzip2 \
    wget less g++ gcc file libc6-dev make fakeroot build-essential devscripts \
    libncurses5-dev libdw-dev elfutils gettext apt-utils vim curl && \
    apt-get clean && \
    apt-file update

ARG STAP_VER=4.9

RUN curl --insecure -LO https://sourceware.org/ftp/systemtap/releases/systemtap-${STAP_VER}.tar.gz && \
    tar xf systemtap-${STAP_VER}.tar.gz && \
    cd systemtap-${STAP_VER} && \
    mkdir build && cd build && \
    ../configure --disable-docs --disable-refdocs --disable-htmldocs && \
    make -j $(nproc) && \
    sudo make install

COPY *.deb /kernel-packages/

RUN DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    --allow-downgrades \
    /kernel-packages/*.deb

# Clean up
RUN rm -rf systemtap-${STAP_VER}* /kernel-packages

ENTRYPOINT ["/bin/bash"]
