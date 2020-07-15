#!/bin/bash

cd /flowtuple/avro/lang/c
mkdir build

sed -i "s/Z_BEST_COMPRESSION/Z_BEST_SPEED/" src/codec.c
cd build
cmake .. -DCMAKE_INSTALL_PREFIX=/usr/local -DCMAKE_BUILD_TYPE=RelWithDebInfo
make
make install && ldconfig
