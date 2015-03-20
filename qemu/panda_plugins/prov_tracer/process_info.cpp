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
#include "process_info.h"
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
		SyscallInfo(env).get_name(), env->regs[R_EAX]
	);
	delete this->syscall;
    }
    this->syscall = new SyscallInfo(env);
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

    // Handle cases based on the prov_tracer specific nr.
    // Using this custom nr is meant to simplify handling.
    union syscall_arg arg;
    switch(syscalls[this->syscall->nr].nr) {
	case SYSCALL_OPEN:
	{
	    arg = this->syscall->get_arg(0, 128);
	    char *filename = arg.sval;

	    prov_out << "o:" << filename << ":" << this->syscall->nr << std::endl;
	    g_free(filename);
	    //PROVLOG_OPEN();
	}
	break;

	case SYSCALL_READ:
	{
	    arg = this->syscall->get_arg(0, 0);
	    int fd = arg.intval;
	    prov_out << "r:" << fd << std::endl;
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




// *******************************************************************
// FileInfo definitions
// *******************************************************************
FileInfo::FileInfo(char *name) {
	this->name = name;
}




// *******************************************************************
// SyscallInfo definitions
// *******************************************************************
SyscallInfo::SyscallInfo(CPUState *env) {
#if defined(TARGET_I386)
    // XXX: OSDEP: On Windows and Linux, the system call id is in EAX.
    //      OSDEP: On Linux, system call arguments are passed in registers.
    this->nr = env->regs[R_EAX];
    static int argidx[6] = {R_EBX, R_ECX, R_EDX, R_ESI, R_EDI, R_EBP};
    this->env = env;

    int syscall_nargs = syscalls[this->nr].nargs;
    for (int i=0; i<syscall_nargs; i++) {
        auto arg = env->regs[argidx[i]];
        switch (syscalls[this->nr].args[i]) {
            case SYSCALL_ARG_INT:
		this->args[i].intval = arg;
                break;

            case SYSCALL_ARG_PTR:
            case SYSCALL_ARG_STR:
		this->args[i].pval = (TARGET_PTR)arg;
                break;

            default:
                EXIT_ON_ERROR(1, "Unexpected syscall argument type %d.", syscalls[this->nr].args[i]);
                break;
        }
    }
#else
    // XXX: ARM
	#warning "ARM syscall decoding has not been implemented."
#endif
}

union syscall_arg SyscallInfo::get_arg(int n, size_t sz) const {
    union syscall_arg r;
    switch (syscalls[this->nr].args[n]) {
	case SYSCALL_ARG_INT:
	    r.intval = (target_int)this->args[n].intval;
	break;

	case SYSCALL_ARG_STR:
	    r.sval = g_strdup(panda_virtual_memory_smart_read(this->env, this->args[n].pval, sz));
	break;

	case SYSCALL_ARG_PTR:
	    if (sz == 0) {
		// only interested in the value of the pointer
		r.pval = (TARGET_PTR)this->args[n].pval;
	    }
	    else{
		// interested in the actual data
		r.buf = (uint8_t *)g_malloc(sz);
		panda_virtual_memory_rw(this->env, this->args[n].pval, r.buf, sz, 0);
	    }
	break;

	default:
	    EXIT_ON_ERROR(1 == 1, "Huh?");
	break;
    }
    return r;
}

std::ostream& SyscallInfo::dump(std::ostream& o) const {
    int nargs = syscalls[this->nr].nargs;
    o << syscalls[this->nr].name << "(";
    for (int i=0; i<nargs; i++) {
        if (i>0) o << ", ";

        switch (syscalls[this->nr].args[i]) {
            case SYSCALL_ARG_INT:
                o << std::dec << (target_int)this->args[i].intval;
            break;

            case SYSCALL_ARG_PTR:
                o   << "0x" << std::hex << std::setfill('0')
		    << std::setw(2*sizeof(TARGET_PTR))
		    << this->args[i].pval;
            break;

            case SYSCALL_ARG_STR:
		if (this->args[i].pval) {
		    o << panda_virtual_memory_smart_read(this->env, this->args[i].pval, 32);
		}
                else { o << "NULL"; }
            break;

            default:
                EXIT_ON_ERROR(1, "Unexpected syscall argument type.");
            break;
        }
    }
    o << ")";
    return o;
}

std::string SyscallInfo::str(bool include_rval) const {
    std::stringstream ss;
#if defined(TARGET_I386)
    if (include_rval)
	ss << env->regs[R_EAX] << " = ";
#endif
    ss << this;
    return ss.str();
}

std::string SyscallInfo::str() const {
    std::stringstream ss;
    ss << this;
    return ss.str();
}

const char *SyscallInfo::c_str(bool include_rval) const {
    std::stringstream ss;
#if defined(TARGET_I386)
    if (include_rval)
	ss << env->regs[R_EAX] << " = ";
#endif
    ss << this;

    // The pointer returned by c_str() may be invalidated by further calls.
    // It's caller's responsibility to copy the string before any such calls.
    return ss.str().c_str();
}

const char *SyscallInfo::c_str() const {
    std::stringstream ss;
    ss << this;

    // The pointer returned by c_str() may be invalidated by further calls.
    // It's caller's responsibility to copy the string before any such calls.
    return ss.str().c_str();
}

const char *SyscallInfo::get_name() const {
    return syscalls[this->nr].name;
}

