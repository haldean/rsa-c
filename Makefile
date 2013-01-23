CC=clang
CFLAGS=-g -Wall
EXE=rsa_test

all: lib

lib:
	$(CC) -c $(CFLAGS) rsa.c

test: lib
	$(CC) -o $(EXE) $(CFLAGS) rsa.o rsa_test.c -lgmp
	@echo
	./$(EXE)

clean:
	rm $(EXE) rsa.o
