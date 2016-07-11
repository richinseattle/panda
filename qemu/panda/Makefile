# Note: LDFLAGS go before object files during linking. LDLIBS go after.

RM=rm -f
CC=gcc
CXX=g++
PROTOCC=protoc-c
PROTOPYC=protoc
PROTOPARSE=../../scripts/pp.py

CPPFLAGS+=-I.. -DPANDALOG_READER
CFLAGS+=-g -O0
CXXFLAGS+=-g -O0 -std=c++11
LDLIBS+=-L/usr/local/lib -lprotobuf-c -lz 

PANDALOG_TOOLS=pandalog_reader stuw #tainted_instr
PANDALOG_COMMON_OBJS=pandalog.o pandalog.pb-c.o
PANDALOG_READER_OBJS=pandalog_print.o pandalog_reader.o
PANDALOG_PROTO_IN=$(wildcard ../panda_plugins/*/*.proto)
PANDALOG_CLEAN_EXTRA=$(PANDALOG_TOOLS) pandalog.pb-c.c pandalog_pb2.py pandalog.proto


.PHONY: all clean

all: $(PANDALOG_TOOLS) pandalog_pb2.py

# PANDALOG_PROTO_IN contains all the plugins - even inactive ones.
# This may trigger some unneeded recompilations.
pandalog.proto: $(PANDALOG_PROTO_IN)
	$(PROTOPARSE) ../panda_plugins $(@)

pandalog.pb-c.c: pandalog.proto
	$(PROTOCC) --c_out=. $(<)

pandalog_pb2.py: pandalog.proto
	$(PROTOPYC) --python_out=. $(<)

pandalog_reader: $(PANDALOG_COMMON_OBJS) $(PANDALOG_READER_OBJS)

tainted_instr: $(PANDALOG_COMMON_OBJS)

stuw: $(PANDALOG_COMMON_OBJS)

clean:
	$(RM) $(PANDALOG_COMMON_OBJS) $(PANDALOG_READER_OBJS) $(PANDALOG_CLEAN_EXTRA)

