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
QEMU_CFLAGS:=$(filter-out -O2, $(QEMU_CFLAGS))
QEMU_CXXFLAGS:=$(filter-out -O2, $(QEMU_CXXFLAGS))

# Dynamic libraries for translating system calls.
# Use gen_tables_linux.py script to generate these.
SYSCALLENTS_DL=$(foreach f,\
	$(addsuffix .so,$(basename $(notdir $(wildcard syscalls/syscallents_*.c)))),\
	$(PLUGIN_TARGET_DIR)/panda_$(PLUGIN_NAME)_$(f)\
)

	#$(subst .c,.so,$(wildcard syscalls/syscallents_*.c)),\
# All object files used by the plugin.
PLUGIN_OBJFILES=$(PLUGIN_TARGET_DIR)/$(PLUGIN_NAME).o

.PHONY: all checkflags

$(PLUGIN_TARGET_DIR)/$(PLUGIN_NAME)/%.o: linux_vmi/%.c
	@[ -d  $(dir $@) ] || mkdir -p $(dir $@)
	$(call quiet-command,$(CC) $(QEMU_INCLUDES) $(QEMU_CFLAGS) $(CFLAGS) -c -o $@ $^,"  LINUX VMI CC $@")

$(PLUGIN_TARGET_DIR)/$(PLUGIN_NAME)/%.o: $(PLUGIN_SRC_ROOT)/linux_vmi/%.cpp
	@[ -d  $(dir $@) ] || mkdir -p $(dir $@)
	$(call quiet-command,$(CXX) $(filter-out $(CXXFLAGS_EXCLUDE), $(QEMU_INCLUDES) $(QEMU_CFLAGS) $(QEMU_CXXFLAGS) $(CXXFLAGS)) -c -o $@ $^,"  LINUX VMI CXX $@")

$(PLUGIN_TARGET_DIR)/$(PLUGIN_NAME).o: $(PLUGIN_SRC_ROOT)/$(PLUGIN_NAME)/$(PLUGIN_NAME).cpp

$(PLUGIN_TARGET_DIR)/panda_$(PLUGIN_NAME)_syscallents_%.so: syscalls/syscallents_%.c
	$(call quiet-command,$(CC) -shared -o $@ $^,"  SYSCALL DEFS  $@")

$(PLUGIN_TARGET_DIR)/panda_$(PLUGIN_NAME).so: $(PLUGIN_OBJFILES)
	$(call quiet-command,$(CXX) $(filter-out $(CXXFLAGS_EXCLUDE), $(QEMU_CFLAGS)) -shared -o $@ $^ $(LIBS),"  PLUGIN  $@")

all: $(PLUGIN_TARGET_DIR)/panda_$(PLUGIN_NAME).so $(SYSCALLENTS_DL)

checkflags:
ifeq (,$(findstring -DCONFIG_PANDA_VMI,$(QEMU_CFLAGS)))
	@printf "Flag %s not set in %s. To fix this:\n" "CONFIG_PANDA_VMI" "QEMU_CLFAGS"
	@printf "\t- Do a \"make clean\" in the qemu directory.\n"
	@printf "\t- Edit build.sh and append \"%s\" to %s.\n" "-DCONFIG_PANDA_VMI" "\"extra-cflags\""
	@printf "\t- Run build.sh to rebuild PANDA.\n\n"
	@false
endif
ifeq (,$(findstring -DCONFIG_PANDA_VMI,$(QEMU_CXXFLAGS)))
	@printf "Flag %s not set in %s. To fix this:\n" "CONFIG_PANDA_VMI" "QEMU_CXXLFAGS"
	@printf "\t- Do a \"make clean\" in the qemu directory.\n"
	@printf "\t- Edit build.sh and append \"%s\" to %s.\n" "-DCONFIG_PANDA_VMI" "\"extra-cxxflags\""
	@printf "\t- Run build.sh to rebuild PANDA.\n\n"
	@false
endif
