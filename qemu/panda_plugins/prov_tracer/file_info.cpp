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
}

FileInfo::~FileInfo() {
	g_free(this->name);
}

bool FileInfo::flag_set(char c) const {
	if (c == 'w')
		return ( (this->flags & O_WRONLY) || (this->flags & O_RDWR) );
	else if (c == 'r')
		return ( !(this->flags & O_WRONLY) );
	else if (c == 't')
		return ( ((this->flags & O_WRONLY) || (this->flags & O_RDWR)) && (this->flags & O_TRUNC) );
	else
		return false;
}

