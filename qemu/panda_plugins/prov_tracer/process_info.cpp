#include "platform.h"
#include "prov_tracer.h"
extern "C" {
#include "config.h"
#include "qemu-common.h"
#include "cpu.h"
}
#include <iostream>
#include <sstream>
#include <iomanip>

#include "accounting.h"
#include "prov_log.h"						/**< Macros for logging raw provenance. */

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
	// For open/close, only FileInfo entries are created.
	// Actual provenance is dumped when process exits.
    switch(syscalls[this->syscall->nr].nr) {
	case SYSCALL_OPEN:
	{
	    // Check return status.
	    if (unlikely(rval < 0)) break;

		// Retrieve arguments.
	    arg = this->syscall->get_arg(0, 128);
	    PERMIT_UNUSED char *filename = arg.sval;
	    arg = this->syscall->get_arg(1, 0);
	    PERMIT_UNUSED int flags = arg.intval;
	    //arg = this->syscall->get_arg(2, 0);
	    //PERMIT_UNUSED int mode = arg.intval;

		// Check for existing mapping for fd.
		// This may (?) happen if fd closed due to an error.
		auto fdpair = this->fmap.find(rval);
		if (unlikely(fdpair != this->fmap.end())) {
			LOG_WARN("%s: fd %d is already mapped to %s.", this->label().c_str(), rval, (*fdpair).second->name);
			this->fhist.push_back( (*fdpair).second );
			this->fmap.erase(fdpair);
		}

		// Add new fd mapping.
		this->fmap.insert(std::make_pair(rval, new FileInfo(filename, flags)));
	}
	break;

	case SYSCALL_CLOSE:
	{
	    // Check return status.
	    if (unlikely(rval < 0)) break;

		// Retrieve arguments.
	    arg = this->syscall->get_arg(0, 0);
	    PERMIT_UNUSED int fd = arg.intval;

		// Move file to history.
		auto fdpair = this->fmap.find(fd);
		if (unlikely(fdpair == this->fmap.end())) {
			LOG_WARN("%s: no mapping found for fd %d during %s.", this->label().c_str(), fd, this->syscall->get_name());
			break;
		}
		this->fhist.push_back( (*fdpair).second );
		this->fmap.erase(fdpair);
	}
	break;

	case SYSCALL_READ:
	{
	    // Check return status.
	    if (unlikely(rval <= 0)) break;

		// Retrieve arguments.
	    arg = this->syscall->get_arg(0, 0);
	    PERMIT_UNUSED int fd = arg.intval;
	    //arg = this->syscall->get_arg(1, 128);
	    //PERMIT_UNUSED uint8_t *buf = arg.buf;
	    //g_free(buf);
	    arg = this->syscall->get_arg(2, 0);
	    PERMIT_UNUSED int count = arg.intval;

		// Increase the read count for the file.
		auto fdpair = this->fmap.find(fd);
		if (unlikely(fdpair == this->fmap.end())) {
			LOG_WARN("%s: no mapping found for fd %d during %s.", this->label().c_str(), fd, this->syscall->get_name());
			break;
		}
		(*fdpair).second->read += rval;
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

