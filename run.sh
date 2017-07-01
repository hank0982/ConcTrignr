#!/bin/bash

cd scripts

PIN=/home/hui/stembary/pin
GCE=/home/hui/stembary/gce_triton
PINTOOL=/home/hui/stembary/build
#LB=/home/hui/logic_bomb/build/bombs
LB=/home/hui/opaque_predicate/build/opaque_predicate
CODE=$LB/symarray_l2
#CODE=$LB/floatpoint_1
#CODE=$LB/covpro_file
#CODE=$LB/paraprog
#CODE=$LB/paraprog_fork



if [$1 == ""]; then
    LD_BIND_NOW=1 $PIN/pin.sh -t $PINTOOL/libpintool.so -script triton.py -prog $CODE -- $CODE 1
else 
    LD_BIND_NOW=1 $PIN/pin.sh -ifeellucky -t $PINTOOL/libpintool.so -script stembary.py -prog $1 -- $1 $2
fi
