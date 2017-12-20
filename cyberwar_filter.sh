#!/bin/sh

cp $1 input_ip
./cyberwar_findips
awk 'FNR==NR { a[$NF]; next } !($NF in a)' output_ip input_ip > $2
