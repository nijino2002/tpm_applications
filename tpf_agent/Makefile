#this file will generate executable file main

CC = gcc
CXX = g++
LIB_DIR1 = ../TspiProgLib/
LIB_DIR2 = /home/ludi/dev/tpm-tools-1.3.9.1/lib
INCLUDE_DIR1 = ../TspiProgLib/
INCLUDE_DIR2 = /home/ludi/dev/tpm-tools-1.3.9.1/include
LIB = -ltspiprog -ltspi -ltpm -lcrypto

.PHONY : tpf_agent tpf_agent.o
tpf_agent : tpf_agent.o
	$(CXX) -o tpf_agent tpf_agent.o -L$(LIB_DIR1) -L$(LIB_DIR2) $(LIB)

tpf_agent.o : 
	$(CXX) -c tpf_agent.cpp -I$(INCLUDE_DIR1) -I$(INCLUDE_DIR2) -L$(LIB_DIR1) -L$(LIB_DIR2) $(LIB)
	
.PHONY : clean
clean : 
	rm -rf tpf_agent tpf_agent.o
