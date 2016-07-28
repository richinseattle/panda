# Don't forget to add your plugin to config.panda!
PLUGIN_NAME=prov_tracer

# Include the PANDA Makefile rules
include ../panda.mak

# Set compiler flags.
QEMU_CFLAGS+=-g
# Don't need to repeat QEMU_CFLAGS in QEMU_CXXFLAGS.
#QEMU_CXXFLAGS+=
#CFLAGS+=-DXXX
CXXFLAGS+=-std=c++11
LIBS+=-ldistorm3

# temporary - remove optimizations
#QEMU_CFLAGS:=$(filter-out -O2, $(QEMU_CFLAGS))
#QEMU_CXXFLAGS:=$(filter-out -O2, $(QEMU_CXXFLAGS))

# Dynamic libraries for translating system calls.
# Use gen_tables_linux.py script to generate these.
SYSCALLENTS_DL=$(foreach f,\
	$(addsuffix .so,$(basename $(notdir $(wildcard syscalls/syscallents_*.c)))),\
	$(PLUGIN_TARGET_DIR)/panda_$(PLUGIN_NAME)_$(f)\
)

# All object files used by the plugin.
PLUGIN_OBJFILES=$(PLUGIN_OBJ_DIR)/$(PLUGIN_NAME).o\
				$(PLUGIN_OBJ_DIR)/process_info.o\
				$(PLUGIN_OBJ_DIR)/syscall_info.o\
				$(PLUGIN_OBJ_DIR)/file_info.o \
				$(PLUGIN_OBJ_DIR)/utils.o

.PHONY: all

$(PLUGIN_TARGET_DIR)/panda_$(PLUGIN_NAME)_syscallents_%.so: syscalls/syscallents_%.c
	$(call quiet-command,$(CC) -shared -o $@ $^,"  SYSCALL DEFS  $@")

$(PLUGIN_TARGET_DIR)/panda_$(PLUGIN_NAME).so: $(PLUGIN_OBJFILES)
	$(call quiet-command,$(CXX) $(filter-out $(CXXFLAGS_EXCLUDE), $(QEMU_CFLAGS)) -shared -o $@ $^ $(LDFLAGS) $(LIBS),"  PLUGIN  $@")

all: $(PLUGIN_OBJ_DIR) $(SYSCALLENTS_DL) $(PLUGIN_TARGET_DIR)/panda_$(PLUGIN_NAME).so

