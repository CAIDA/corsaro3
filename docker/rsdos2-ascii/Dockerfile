# This software is Copyright © 2019 The Regents of the University of
# California. All Rights Reserved. Permission to copy, modify, and distribute
# this software and its documentation for educational, research and non-profit
# purposes, without fee, and without a written agreement is hereby granted,
# provided that the above copyright notice, this paragraph and the following
# three paragraphs appear in all copies. Permission to make commercial use of
# this software may be obtained by contacting:
#
# Office of Innovation and Commercialization
# 9500 Gilman Drive, Mail Code 0910
# University of California
# La Jolla, CA 92093-0910
# (858) 534-5815
# invent@ucsd.edu
#
# This software program and documentation are copyrighted by The Regents of the
# University of California. The software program and documentation are supplied
# "as is", without any accompanying services from The Regents. The Regents does
# not warrant that the operation of the program will be uninterrupted or
# error-free. The end-user understands that the program was developed for
# research purposes and is advised not to rely exclusively on the program for
# any reason.
#
# IN NO EVENT SHALL THE UNIVERSITY OF CALIFORNIA BE LIABLE TO ANY PARTY FOR
# DIRECT, INDIRECT, SPECIAL, INCIDENTAL, OR CONSEQUENTIAL DAMAGES, INCLUDING
# LOST PROFITS, ARISING OUT OF THE USE OF THIS SOFTWARE AND ITS DOCUMENTATION,
# EVEN IF THE UNIVERSITY OF CALIFORNIA HAS BEEN ADVISED OF THE POSSIBILITY OF
# SUCH DAMAGE. THE UNIVERSITY OF CALIFORNIA SPECIFICALLY DISCLAIMS ANY
# WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE. THE SOFTWARE PROVIDED
# HEREUNDER IS ON AN "AS IS" BASIS, AND THE UNIVERSITY OF CALIFORNIA HAS NO
# OBLIGATIONS TO PROVIDE MAINTENANCE, SUPPORT, UPDATES, ENHANCEMENTS, OR
# MODIFICATIONS.


FROM ubuntu:bionic

ENV DEBIAN_FRONTEND=noninteractive
WORKDIR /rsdosconv

RUN apt-get -y update && apt-get -y install apt-transport-https \
               curl lsb-release gnupg sudo

RUN curl -1sLf 'https://dl.cloudsmith.io/public/wand/libwandio/cfg/setup/bash.deb.sh' | bash
RUN curl -1sLf 'https://dl.cloudsmith.io/public/wand/libwandder/cfg/setup/bash.deb.sh' | bash
RUN curl -1sLf 'https://dl.cloudsmith.io/public/wand/libtrace/cfg/setup/bash.deb.sh' | bash

RUN echo "deb https://pkg.caida.org/os/ubuntu $(lsb_release -sc) main" | tee /etc/apt/sources.list.d/caida.list

RUN curl -so /etc/apt/trusted.gpg.d/caida.gpg https://pkg.caida.org/os/ubuntu/keyring.gpg

RUN apt-get -y update && apt-get -y install \
        autoconf \
        automake \
        autotools-dev \
        bison \
        build-essential \
        default-jdk \
        emacs \
        flex \
        gdb \
        git \
        grep \
        iproute2 \
        less \
        libavro-dev \
        libgoogle-perftools-dev \
        libjansson-dev \
        libjudy-dev \
        libpcap-dev \
        librdkafka-dev \
        libtool \
        libwandio1-dev \
        libyaml-dev \
        libzmq3-dev \
        nano \
        passwd \
        pkg-config \
        pwgen \
        python3 \
        python-swiftclient \
        screen \
        strace \
        tcpdump \
        unzip \
        uthash-dev \
        valgrind \
        vim \
        wandio1-tools

RUN git clone https://github.com/LibtraceTeam/libtrace && cd libtrace && git checkout develop
RUN cd libtrace && ./bootstrap.sh && ./configure && make && make install && ldconfig

RUN git clone https://github.com/CAIDA/corsaro3 && cd corsaro3 && git checkout v2 && git submodule init && git submodule update
RUN cd corsaro3 && autoreconf -vfi && ./configure --with-slash-eight=0 --with-dos --enable-debug && make && make install && ldconfig

RUN rm -rf corsaro3/

# Remove 'corsaro' binary, as we don't really want people using this to create
# data files with a legacy format
RUN rm /usr/local/bin/corsaro

RUN mkdir /rsdosconv/output && mkdir /rsdosconv/tmp/

COPY rsdos2csv.py /usr/local/sbin/
COPY entrypoint.sh /entrypoint.sh
COPY convert_ucsd_month.sh /rsdosconv/
ENTRYPOINT ["/entrypoint.sh"]

