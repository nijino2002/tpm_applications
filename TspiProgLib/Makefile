#This file will produce a static library named libtspiprog.a
CC = gcc
AR = ar

libtspiprog.a : tspiproglib.o
	$(AR) -crv libtspiprog.a
	
tspiproglib.o : tspiproglib.h tpm_general_inc.h
	$(CC) -c tspiproglib.c
	
.PHONY : clean
clean :
	rm libtspiprog.a tspiproglib.o
