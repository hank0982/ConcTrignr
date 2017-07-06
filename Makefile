PIN=/home/neil/pin
PINTOOL=/home/neil/Triton/build

LB=/home/neil/ConcTriton/programs
CODE=$(LB)/$P

run: run.py
	$(PIN)/pin.sh -t $(PINTOOL)/libpintool.so -script run.py -- $(CODE)

example:
	$(PIN)/pin.sh -t $(PINTOOL)/libpintool.so -script example.py -- $(CODE)

triton:
	$(PINTOOL)/triton $S $(CODE)
