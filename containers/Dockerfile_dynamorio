FROM ubuntu:20.04
RUN apt-get -qq update && \
    DEBIAN_FRONTEND=noninteractive apt-get -qq install -y \
    build-essential vim emacs nano \
    cmake g++ g++-multilib doxygen git zlib1g-dev libunwind-dev \
    git

RUN git clone https://github.com/DynamoRIO/dynamorio.git /dynamorio/src/
# Make a separate build directory.  Building in the source directory is not
# supported.
RUN mkdir -p /dynamorio/build

WORKDIR /dynamorio/build/

RUN cmake ../src/
RUN make -j

# Run echo under DR to see if it works.  If you configured for a debug or 32-bit
# build, your path will be different.  For example, a 32-bit debug build would
# put drrun in ./bin32/ and need -debug flag to run debug build.
RUN ./bin64/drrun echo hello world
