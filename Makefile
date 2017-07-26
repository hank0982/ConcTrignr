PIN=/home/neil/pin
PINTOOL=/home/neil/Triton/build

PD=programs
BIN=$(PD)/$P

CC = gcc

all: array thread

array: $(PD)/array.c
	$(CC) -o $(PD)/a.out $(PD)/array.c

thread: $(PD)/multi_thread.c
	$(CC) -o $(PD)/m.out $(PD)/multi_thread.c -lpthread

float: $(PD)/float.c
	$(CC) -o $(PD)/f.out $(PD)/float.c

overflow: $(PD)/overflow.c
	$(CC) -o $(PD)/o.out $(PD)/overflow.c

signed: $(PD)/signed.c
	$(CC) -o $(PD)/s.out $(PD)/signed.c

context: $(PD)/context.c
	$(CC) -o $(PD)/c.out $(PD)/context.c

test: $(PD)/test.c
	$(CC) -o $(PD)/t.out $(PD)/standard.c


triton:
	echo "=== Using Triton ==="
	$(PINTOOL)/triton run_triton.py $(BIN)

angr: run_angr.py
	echo "=== Using angr ==="
	python run_angr $(BIN)

clean:
	rm -f core
	rm -f $(PD)/*.out $(PD)/*.s $(PD)/core
