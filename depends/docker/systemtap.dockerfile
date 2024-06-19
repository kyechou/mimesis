# This is used to build SystemTap programs.

FROM s2e:latest

LABEL org.opencontainers.image.authors="kychou2@illinois.edu"

RUN dpkg --add-architecture i386 && \
    apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    # SystemTap dependencies
    sudo apt-file texinfo flex bison patch python3 python3-setuptools unzip \
    git bc bzip2 wget less g++ gcc file libc6-dev make fakeroot \
    build-essential devscripts libncurses5-dev gettext rsync cpio kmod \
    libssl-dev libnss3-dev apt-utils vim \
    # (Built from source): libdw-dev elfutils libdebuginfod-dev
    # Elfutils dependencies
    autopoint debhelper autoconf automake lsb-release bzip2 zlib1g-dev \
    libbz2-dev liblzma-dev m4 gettext po-debconf gawk dpkg-dev gcc-multilib \
    libc6-dbg flex bison pkg-config libarchive-dev libmicrohttpd-dev \
    libcurl4-gnutls-dev libsqlite3-dev \
    && \
    apt-get clean && \
    apt-file update

ARG ELFUTILS_VER=elfutils-0.191
ARG STAP_VER=5.1

# Install elfutils
RUN git clone git://sourceware.org/git/elfutils.git && \
    cd elfutils && \
    git checkout ${ELFUTILS_VER} && \
    autoreconf -i -f && \
    ./configure --enable-maintainer-mode --enable-libdebuginfod --enable-debuginfod && \
    make -j $(nproc) && \
    make check && \
    sudo make install && \
    cp /usr/local/lib/*.so* /usr/local/lib/*.a /usr/lib/x86_64-linux-gnu/ && \
    cp /usr/local/lib/pkgconfig/* /usr/lib/x86_64-linux-gnu/pkgconfig/

# Install SystemTap
RUN git clone git://sourceware.org/git/systemtap.git && \
    cd systemtap && \
    git checkout release-${STAP_VER} && \
    mkdir build && cd build && \
    ../configure --disable-docs --disable-refdocs --disable-htmldocs \
    --with-debuginfod --with-python3 --without-python2-probes \
    --without-python3-probes && \
    make -j $(nproc) && \
    sudo make install

COPY linux-*.deb /kernel-packages/

RUN DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    --allow-downgrades \
    /kernel-packages/linux-*.deb

RUN rm -rf elfutils systemtap /kernel-packages

ENTRYPOINT ["/bin/bash"]
