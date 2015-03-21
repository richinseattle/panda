#include "platform.h"
#include "prov_tracer.h"
extern "C" {
#include "config.h"
#include "qemu-common.h"
#include "cpu.h"
}
#include <sys/types.h>
#include <sys/stat.h>

#include "accounting.h"
#include "prov_log.h"			/**< Macros for logging raw provenance. */

// *******************************************************************
// FileInfo definitions
// *******************************************************************
FileInfo::FileInfo(char *name, int flags) {
	this->name = name;
	this->flags = flags;
	this->written = 0;
	this->read = 0;
	this->truncated = false;

	// Check for truncation.
	if ( (this->flags & O_WRONLY) || (this->flags & O_RDWR) ) {
		if (this->flags & O_TRUNC) {
			this->truncated = true;
		}
	}
}

FileInfo::~FileInfo() {
	g_free(this->name);
}
