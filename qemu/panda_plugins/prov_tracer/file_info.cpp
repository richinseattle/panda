#include "platform.h"
#include "prov_tracer.h"
extern "C" {
#include "config.h"
#include "qemu-common.h"
#include "cpu.h"
}
#include <glib.h>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <unordered_map>

#include "../osi/osi_types.h"		/**< Introspection data types. */
#include "syscalls/syscallents.h"
#include "accounting.h"
#include "prov_log.h"			/**< Macros for logging raw provenance. */

extern "C" {
extern struct syscall_entry *syscalls;      /**< Syscalls info table. */
}

// *******************************************************************
// FileInfo definitions
// *******************************************************************
FileInfo::FileInfo(char *name) {
	this->name = name;
}

