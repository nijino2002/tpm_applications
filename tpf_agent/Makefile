#this file will generate executable file main

CC = gcc
CXX = g++
#LIB_DIR1 = ../TspiProgLib/
LIB_DIR2 = /home/ludi/dev/tpm-tools-1.3.9.1/lib
LIB_DIR3 = /home/ludi/dev/testsuite-0.3/tcg/common
#INCLUDE_DIR1 = ../TspiProgLib/
INCLUDE_DIR2 = /home/ludi/dev/tpm-tools-1.3.9.1/include
INCLUDE_DIR3 = /home/ludi/dev/testsuite-0.3
LIB = -ltspi -ltpm -ltestsuite_common -lcrypto

all: tpf_agent load_AIK_by_uuid tpf_agent.o load_AIK_by_uuid.o
.PHONY : all

tpf_agent : tpf_agent.o
	$(CXX) -o tpf_agent tpf_agent.o -L$(LIB_DIR2) -L$(LIB_DIR3) $(LIB) -fpermissive

tpf_agent.o : 
	$(CXX) -c tpf_agent.cpp -I$(INCLUDE_DIR2) -I$(INCLUDE_DIR3) -L$(LIB_DIR1) -L$(LIB_DIR2) -L$(LIB_DIR3) $(LIB) -fpermissive

load_AIK_by_uuid : load_AIK_by_uuid.o
	$(CXX) -o load_AIK_by_uuid load_AIK_by_uuid.o -L$(LIB_DIR2) -L$(LIB_DIR3) $(LIB) -fpermissive

load_AIK_by_uuid.o : 
	$(CXX) -c load_AIK_by_uuid.cpp -I$(INCLUDE_DIR2) -I$(INCLUDE_DIR3) -L$(LIB_DIR2) -L$(LIB_DIR3) $(LIB) -fpermissive

.PHONY : clean
clean : 
	rm -rf tpf_agent load_AIK_by_uuid *.o
