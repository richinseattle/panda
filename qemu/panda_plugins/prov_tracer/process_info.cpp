extern "C" {
#include "config.h"
#include "qemu-common.h"
#include "cpu.h"
}
#include <glib.h>
#include <unordered_map>

#include "../osi/osi_types.h"		/**< Introspection data types. */
#include "process_info.h"

ProcInfo::ProcInfo(OsiProc *p) {
	copy_osiproc_g(p, &this->p);
}

ProcInfo::~ProcInfo(void) {
	g_free(this->p.name);
}
