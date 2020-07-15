#!/bin/bash
set -e

if [ -f /report/swiftcreds ]; then
        source /report/swiftcreds
fi

if [ ! -f /report/baseconfig.yaml ]; then
        echo "Please mount a corsarotrace config file at /report/baseconfig.yaml"
        exit 1
fi

cp /report/baseconfig.yaml /report/config.yaml
if [[ $# -gt 0 ]]; then
        sed -i "s#PCAPURI#${1}#" /report/config.yaml
fi

exec /usr/local/bin/corsarotrace -c /report/config.yaml
