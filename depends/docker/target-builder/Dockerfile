# This is used to compile the target programs, as the programs must be built in
# the same environment to make sure they work within the S2E images.

FROM ubuntu:22.04

LABEL org.opencontainers.image.authors="kychou2@illinois.edu"

# g++ gcc libc6-dev apt-utils vim \
RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    apt-file build-essential curl git clang cmake ninja-build pkgconf sudo && \
    apt-get clean && \
    apt-file update

# Add a user for building without root privileges
RUN useradd -m -s /bin/bash builder

ENTRYPOINT ["/bin/bash"]
