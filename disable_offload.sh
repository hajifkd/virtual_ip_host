#!/bin/bash

for device in $(ip link show| egrep '^[0-9]+'|awk '{print $2}'); do
        for option in lro tso rx tx sg ufo gso gro; do
            sudo ethtool -K ${device:0:-1} $option off
        done
done