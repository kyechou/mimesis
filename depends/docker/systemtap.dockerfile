# This is used to build SystemTap programs.

FROM s2e:latest

LABEL org.opencontainers.image.authors="kychou2@illinois.edu"

RUN dpkg --add-architecture i386 && \
    apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    # SystemTap dependencies
    sudo apt-file texinfo flex bison patch python3 python3-setuptools unzip \
    git bc bzip2 wget less g++ gcc file libc6-dev make fakeroot \
    build-essential devscripts libncurses5-dev libdw-dev elfutils gettext \
    libdebuginfod-dev libnss3-dev apt-utils vim curl \
    && \
    apt-get clean && \
    apt-file update

ARG STAP_VER=5.0

# Install SystemTap
RUN git clone git://sourceware.org/git/systemtap.git && \
    cd systemtap && \
    git checkout release-${STAP_VER} && \
    mkdir build && cd build && \
    ../configure --disable-docs --disable-refdocs --disable-htmldocs \
    --enable-pie --with-debuginfod --without-avahi --without-python2-probes \
    --without-python3-probes --with-bpf --without-java && \
    make -j $(nproc) && \
    sudo make install

COPY linux-*.deb /kernel-packages/

RUN DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    --allow-downgrades \
    /kernel-packages/linux-*.deb

RUN rm -rf systemtap /kernel-packages

ENTRYPOINT ["/bin/bash"]
