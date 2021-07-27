#!/bin/bash

for i in `swift list data-telescope-meta-dos -p datasource=ucsd-nt/year=$1/month=$2/`; do
        outf=${i#*/*/*/};
        nextdir=${outf%/*};
        outname=${outf%.*.*};

        echo ${outname}

        mkdir -p /rsdosconv/output/${nextdir}
        wandiocat swift://data-telescope-meta-dos/${i} > ./input.dos.cors.gz
        cors2ascii ./input.dos.cors.gz > ./input.txt 2>/dev/null
        python3 /usr/local/sbin/rsdos2csv.py ./input.txt /rsdosconv/output/${outname}.csv
        gzip -f -1 /rsdosconv/output/${outname}.csv

done
rm ./input.dos.cors.gz ./input.txt

