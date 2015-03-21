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
// ProcInfo definitions
// *******************************************************************
ProcInfo::ProcInfo(OsiProc *p) {
	copy_osiproc_g(p, &this->p);
	this->syscall = NULL;

	PROVLOG_EXEC(this);
}

ProcInfo::~ProcInfo(void) {
	PROVLOG_QUIT(this);

	g_free(this->p.name);
	if (this->syscall != NULL) delete this->syscall;
}

std::string ProcInfo::label() const {
    std::stringstream ss;
    ss << this->p.name << (this->is_fresh ? "*(" : "(") << this->p.pid << ")";
    return ss.str();
}

void ProcInfo::syscall_start(CPUState *env) {
#if defined(TARGET_I386)
    if (this->syscall != NULL) {
	LOG_WARN("%s: \"%s\" was pending when \"%s\" (" TARGET_FMT_ld ") started!",
		this->label().c_str(), this->syscall->get_name(),
		SyscallInfo(this, env).get_name(), env->regs[R_EAX]
	);
	delete this->syscall;
    }
    this->syscall = new SyscallInfo(this, env);
#endif
}

void ProcInfo::syscall_end(CPUState *env) {
#if defined(TARGET_I386)
    if (unlikely(this->syscall == NULL)) {
	// This may occur at the beginning of replay.
	LOG_INFO("%s: Unknown syscall completed.", this->label().c_str());
	return;
    }

    LOG_INFO("%s: syscall completed: %s", this->label().c_str(), this->syscall->c_str(true));

    int rval = this->syscall->get_ret();
    union syscall_arg arg;

    // Handle cases based on the prov_tracer specific nr.
    // Using this custom nr is meant to simplify handling.
    switch(syscalls[this->syscall->nr].nr) {
	case SYSCALL_OPEN:
	{
	    // open failed
	    if (unlikely(rval < 0)) break;

	    arg = this->syscall->get_arg(0, 128);
	    PERMIT_UNUSED char *filename = arg.sval;
	    arg = this->syscall->get_arg(1, 0);
	    PERMIT_UNUSED int flags = arg.intval;
	    //arg = this->syscall->get_arg(2, 0);
	    //PERMIT_UNUSED int mode = arg.intval;

	    PROVLOG_OPEN(this->p.asid, filename, flags);
	    g_free(filename);
	}
	break;

	case SYSCALL_CLOSE:
	{

	}
	break;

	case SYSCALL_READ:
	{
	    // nothing read
	    if (unlikely(rval <= 0)) break;

	    arg = this->syscall->get_arg(0, 0);
	    PERMIT_UNUSED int fd = arg.intval;
	    //arg = this->syscall->get_arg(1, 128);
	    //PERMIT_UNUSED uint8_t *buf = arg.buf;
	    //arg = this->syscall->get_arg(2, 0);
	    //PERMIT_UNUSED int count = arg.intval;

	    //PROVLOG_READ(this->p.asid, fd);
	    //g_free(buf);
	}
	break;

	case SYSCALL_WRITE:
	{

	}
	break;

	case SYSCALL_OTHER:
	    // ignore
	break;

	default:
	    LOG_WARN("%s:No handling for the completed syscall.", this->label().c_str());
	break;
    }

    delete this->syscall;
    this->syscall = NULL;

    return;
#endif
}

