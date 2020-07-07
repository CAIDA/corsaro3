#!/bin/bash

/usr/local/bin/corsarotrace -c /flowtuple/config.yaml

shopt -s nullglob
array=(/flowtuple/tmp/*--0)

for f in "${array[@]}"; do
        base=${f::-3}
        stripped=${base##*/}
        /usr/local/bin/corsaroftmerge -o /flowtuple/output/${stripped} ${f} ${base}--1 ${base}--2 ${base}--3
        
done

