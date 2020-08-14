FROM ubuntu:bionic AS builder

ENV DEBIAN_FRONTEND=noninteractive

WORKDIR /report

RUN apt-get -y update && apt-get -y install apt-transport-https \
               curl lsb-release gnupg sudo

RUN echo "deb https://dl.bintray.com/wand/general $(lsb_release -sc) main" | tee -a /etc/apt/sources.list.d/wand.list
RUN echo "deb https://dl.bintray.com/wand/libtrace $(lsb_release -sc) main" | tee -a /etc/apt/sources.list.d/wand.list

RUN curl --silent "https://bintray.com/user/downloadSubjectPublicKey?username=wand" | apt-key add -

RUN echo "deb https://pkg.caida.org/os/ubuntu $(lsb_release -sc) main" | tee /etc/apt/sources.list.d/caida.list

RUN curl -so /etc/apt/trusted.gpg.d/caida.gpg https://pkg.caida.org/os/ubuntu/keyring.gpg

RUN apt-get -y update && apt-get -y install \
        autoconf \
        automake \
        autotools-dev \
        build-essential \
        cmake \
        gdb \
        git \
        grep \
        iproute2 \
        less \
        libavro-dev \
        libgoogle-perftools-dev \
        libipmeta2-dev \
        libjansson-dev \
        libjudy-dev \
        libndagserver-dev \
        librdkafka-dev \
        libsnappy-dev \
        libtimeseries0-dev \
        libtool \
        libtrace4-tools \
        libtrace4-dev \
        libpacketdump4-dev \
        libwandio1-dev \
        libyaml-dev \
        libzmq3-dev \
        passwd \
        pkg-config \
        pwgen \
        python3 \
        python3-swiftclient \
        screen \
        sed \
        strace \
        tcpdump \
        unzip \
        uthash-dev \
        vim \
        wandio1-tools \
        zlib1g-dev

TODO: switch back to using debian packages
RUN git clone https://github.com/CAIDA/corsaro3 && cd corsaro3 && git submodule init && git submodule update

RUN cd corsaro3 && autoreconf -vfi && ./configure && make && make install && ldconfig

RUN tar -cvf /report/libcorsaro.tar /usr/local/lib/libcorsaro*

FROM ubuntu:bionic

WORKDIR /report

RUN apt-get -y update && apt-get -y install apt-transport-https \
                curl lsb-release gnupg sudo

RUN echo "deb https://dl.bintray.com/wand/general $(lsb_release -sc) main" | tee -a /etc/apt/sources.list.d/wand.list
RUN echo "deb https://dl.bintray.com/wand/libtrace $(lsb_release -sc) main" | tee -a /etc/apt/sources.list.d/wand.list

RUN curl --silent "https://bintray.com/user/downloadSubjectPublicKey?username=wand" | apt-key add -

RUN echo "deb https://pkg.caida.org/os/ubuntu $(lsb_release -sc) main" | tee /etc/apt/sources.list.d/caida.list

RUN curl -so /etc/apt/trusted.gpg.d/caida.gpg https://pkg.caida.org/os/ubuntu/keyring.gpg

RUN apt-get -y update && apt-get -y install \
        libavro23 \
        libgoogle-perftools4 \
        libipmeta2 \
        libjansson4 \
        libjudydebian1 \
        libndagserver \
        librdkafka1 \
        libsnappy1v5 \
        libtimeseries0 \
        libtrace4 \
        libpacketdump4 \
        libwandio1 \
        libyaml-0-2 \
        libzmq5 \
        sed \
        zlib1g

COPY --from=builder /usr/local/bin/corsarotrace /usr/local/bin/
COPY --from=builder /report/*.tar /report/

RUN tar -xvf /report/libcorsaro.tar --strip-components=3 -C /usr/local/lib/ && ldconfig

COPY entrypoint.sh /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
