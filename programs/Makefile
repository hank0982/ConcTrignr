CC = gcc

all: array simple complex vector thread

array: array.c
	$(CC) -o a.out array.c
	$(CC) -S array.c

simple: standard.c
	$(CC) -o b.out standard.c
	$(CC) -S standard.c

complex: complex.c
	$(CC) -o c.out complex.c
	$(CC) -S complex.c

test_atoi: test_atoi.c
	$(CC) -o test_atoi.out test_atoi.c
	$(CC) -S test_atoi.c

vector: vector.cpp
	g++ -o v.out vector.cpp

thread: thread.c
	$(CC) -o p.out thread.c -lpthread
