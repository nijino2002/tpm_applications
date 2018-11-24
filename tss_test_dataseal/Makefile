#this file will generate executable file main

CC = gcc
LIB_DIR = ../TspiProgLib/
INCLUDE_DIR = ../TspiProgLib/
LIB = -ltspiprog -ltspi

.PHONY : main main.o
main : main.o
	$(CC) -o main main.o -L$(LIB_DIR) $(LIB)

main.o : 
	$(CC) -c main.c -I$(INCLUDE_DIR) -L$(LIB_DIR) $(LIB)
	
.PHONY : clean
clean : 
	rm -rf main main.o
