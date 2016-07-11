PLUGIN_NAME=file_taint_sink
include ../panda.mak

QEMU_CXXFLAGS+=-std=c++11 -Wall -Wunused -Wunused-but-set-variable -Wuninitialized
CPPFLAGS+=-I../taint2 -I../osi -I../osi_linux -I../syscalls2

PLUGIN_OBJFILES=$(PLUGIN_OBJ_DIR)/$(PLUGIN_NAME).o \
				$(PLUGIN_OBJ_DIR)/utils.o

.PHONY: all

$(PLUGIN_OBJFILES): $(wildcard *.h)

$(PLUGIN_TARGET_DIR)/panda_$(PLUGIN_NAME).so: $(PLUGIN_OBJFILES)
	$(call quiet-command,$(CXX) $(QEMU_CXXFLAGS) -shared -o $@ $^ $(LDFLAGS) $(LIBS),"  PLUGIN  $@")

all: $(PLUGIN_OBJ_DIR) $(PLUGIN_TARGET_DIR)/panda_$(PLUGIN_NAME).so
