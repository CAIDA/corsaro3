#!/bin/bash
set -e

if [[ $# -ne 2 ]]; then
        echo "Requires 2 arguments: a year and a month"
        exit 1
fi

if [ -f /rsdosconv/swiftcreds ]; then
        source /rsdosconv/swiftcreds
fi

exec /rsdosconv/convert_ucsd_month.sh ${1} ${2}

