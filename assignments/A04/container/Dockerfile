# Modified dockerfile from CDDA which will pull the repo and build it

#HOWTO:
# run this from the root of the cdda repo using `docker build -f build-scripts/Dockerfile.debian-build . -t cdda`
# (note: the -t cdda is optional but convenient. It tags the resulting image with `cdda`)
# (note: the `.` is required and orients Docker to the file/dir struture you want to bring into the image with COPY once the setup is done)

# basing the build on debian testing is an easy way to bring in clang-6.0. Debian testing is quite stable.
# (We want clang for faster builds)
FROM debian:testing

# read latest package index on repos
RUN apt-get -qq update

# we want apt-fast because it makes apt installs way faster by downloading many packages at once, and these packages are used for a fast/easy install of apt-fast
RUN apt-get -qq install curl openssl ca-certificates sudo wget --no-install-recommends
# we strip 'sudo' calls out of the script so we don't have to bother with sudo even though it's installed, and we avoid the recommended packages from the apt install in the script as they tend to be bloat on a server-like setup like this build image
RUN curl -sL https://git.io/vokNn | sed s/'sudo '//g | sed s/'apt-get install'/'apt-get install --no-install-recommends'/g | bash && echo "DOWNLOADBEFORE=true" >> /etc/apt-fast.conf

# ensure we know about the latest packages
RUN apt-fast -qq update

# random convenience packages
RUN apt-fast -qq install --no-install-recommends aptitude man software-properties-common gpg

# CDDA: for building
RUN apt-fast -qq install --no-install-recommends build-essential clang cmake ccache
# we probably don't want gcc/g++ so we don't accidentally build with them; note, we may find that we might actually want them
RUN apt-get -qq remove gcc g++ && apt-get -qq autoremove

# CDDA: general stuff; gettext is required for localization
RUN apt-fast -qq install --no-install-recommends gettext

# CDDA: libraries for curses-based terminal cdda
RUN apt-fast -qq install --no-install-recommends libncurses5-dev libncursesw5-dev

# general packages for a much nicer time inside the container (we install psmisc for `killall`)
RUN apt-fast -qq install --no-install-recommends tree watch tmux fish colormake vim emacs git silversearcher-ag lsof psmisc dstat

# install opensssh-server and prepare for running it
#TODO: find a nice way of getting ssh keys into the image - by grabbing .pub keys from somewhere?
RUN apt-fast -qq install --no-install-recommends openssh-server && mkdir -p /run/sshd

# DPA: necessary tools, profilers and git
RUN apt-fast -qq install --no-install-recommends valgrind git

RUN git clone https://github.com/CleverRaven/Cataclysm-DDA.git -b cdda-experimental-2022-03-01-1530 --depth=1

RUN apt-fast -qq install --no-install-recommends  libsdl2-dev libsdl2-ttf-dev libsdl2-image-dev libsdl2-mixer-dev libfreetype6-dev

# DPA: also install perf
RUN apt-fast -qq install --no-install-recommends linux-perf

RUN mkdir cmake-build-debug
WORKDIR /cmake-build-debug
RUN env CC=clang CXX=clang++ cmake /Cataclysm-DDA/
RUN make -j $(nproc)
