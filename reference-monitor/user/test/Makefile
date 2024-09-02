CC=gcc 
CFLAGS=-Wall

all: utils testing	

testing: testing.c ../lib/utils.o
	gcc -o testing testing.c ../lib/utils.o

utils: ../lib/utils.c
	gcc -o ../lib/utils.o -c ../lib/utils.c

clean: 
	rm -f testing testing.o ../lib/utils.o
	
run: 
	./testing
