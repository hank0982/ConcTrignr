#!/bin/bash

# PIN=/home/hui/stembary/pin
# GCE=/home/hui/stembary/gce_triton
# PINTOOL=/home/hui/stembary/build

PIN=/home/neil/pin
PINTOOL=/home/neil/Triton/build

LB=/home/neil/ConcTriton/programs
CODE=$LB/$1

LD_BIND_NOW=1 $PIN/pin.sh -t $PINTOOL/libpintool.so -script triton.py -prog $CODE -- $CODE 1

# LD_BIND_NOW=1 $PIN/pin.sh -ifeellucky -t $PINTOOL/libpintool.so -script stembary.py -prog $1 -- $1 $2
