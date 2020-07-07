#!/bin/bash
set -e

if [[ $# -ne 3 ]]; then
        echo "Requires 3 arguments: pcapuri, outputprefix, and monitorid"
        exit 1
fi

if [ -f /flowtuple/swiftcreds ]; then
        source /flowtuple/swiftcreds
fi

sed -i "s#PCAPURI#${1}#" /flowtuple/config.yaml
sed -i "s#OUTPREFIX#${2}#" /flowtuple/config.yaml
sed -i "s#MONITORID#${3}#" /flowtuple/config.yaml

exec /flowtuple/offlineft.sh
