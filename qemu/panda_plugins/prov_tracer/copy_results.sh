#!/bin/bash

logfile="f"
base="run"
fmt="%s%02d"

for i in $(seq 1 99); do
    d="$(printf "$fmt" "$base" "$i")"
    [ -d "$d" ] && continue
    mkdir -p "$d"

    cp -v ../../"$logfile" "$d"
    cp -v ../../prov_out.raw "$d"
    ./raw2ttl.py < "$d"/prov_out.raw > "$d"/lol.ttl
    ./provToolbox/bin/provconvert -verbose -layout circo -infile "$d"/lol.ttl -outfile "$d"/lol.pdf
    [ "$#" -gt 0 ] && echo "$1" > "$d"/readme.txt

    echo "Results in $d..."
    break
done
