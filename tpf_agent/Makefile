#this file will generate executable file main

CC = gcc
CXX = g++
LIB_DIR = ../TspiProgLib/
INCLUDE_DIR = ../TspiProgLib/
LIB = -ltspiprog -ltspi

.PHONY : tpf_agent tpf_agent.o
tpf_agent : tpf_agent.o
	$(CXX) -o tpf_agent tpf_agent.o -L$(LIB_DIR) $(LIB)

tpf_agent.o : 
	$(CXX) -c tpf_agent.cpp -I$(INCLUDE_DIR) -L$(LIB_DIR) $(LIB)
	
.PHONY : clean
clean : 
	rm -rf tpf_agent tpf_agent.o
