# Don't forget to add your plugin to config.panda!
PLUGIN_NAME=psstrmatch

# Include the PANDA Makefile rules
include ../panda.mak

# Set compiler flags.
#QEMU_CFLAGS+=
# Don't need to repeat QEMU_CFLAGS in QEMU_CXXFLAGS.
#QEMU_CXXFLAGS+=
#CFLAGS+=-DXXX
CXXFLAGS+=-std=c++11
#LIBS+=-ldistorm3

# temporary - remove optimizations
#QEMU_CFLAGS:=$(filter-out -O2, $(QEMU_CFLAGS))
#QEMU_CXXFLAGS:=$(filter-out -O2, $(QEMU_CXXFLAGS))

# Dynamic libraries for translating system calls.
# Use gen_tables_linux.py script to generate these.
# All object files used by the plugin.
PLUGIN_OBJFILES=$(PLUGIN_OBJ_DIR)/$(PLUGIN_NAME).o

.PHONY: all

$(PLUGIN_TARGET_DIR)/panda_$(PLUGIN_NAME).so: $(PLUGIN_OBJFILES)
	$(call quiet-command,$(CXX) $(filter-out $(CXXFLAGS_EXCLUDE), $(QEMU_CFLAGS)) -shared -o $@ $^ $(LIBS),"  PLUGIN  $@")

all: $(PLUGIN_OBJ_DIR) $(PLUGIN_TARGET_DIR)/panda_$(PLUGIN_NAME).so

