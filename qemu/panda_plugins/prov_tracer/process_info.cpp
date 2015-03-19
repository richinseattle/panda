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

extern "C" {
extern struct syscall_entry *syscalls;      /**< Syscalls info table. */
}


// *******************************************************************
// ProcInfo definitions
// *******************************************************************
ProcInfo::ProcInfo(OsiProc *p) {
	copy_osiproc_g(p, &this->p);
}

ProcInfo::~ProcInfo(void) {
	g_free(this->p.name);
	if (this->syscall != NULL) delete this->syscall;
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
		    o << panda_virtual_memory_smart_read(this->env, this->args[i].pval, 16);
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

