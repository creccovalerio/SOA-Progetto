CC=gcc 
CFLAGS=-Wall

all: syscall utils user	

syscall: lib/syscall.c
	gcc -o lib/syscall.o -c lib/syscall.c

utils: lib/utils.c
	gcc -o lib/utils.o -c lib/utils.c

user: user.c lib/syscall.o lib/utils.o
	gcc -o user user.c lib/syscall.o lib/utils.o

clean: 
	rm -f user user.o lib/syscall.o lib/utils.o
	
run: 
	./user
