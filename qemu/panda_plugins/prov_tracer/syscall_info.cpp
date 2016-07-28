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
#include "prov_log.h"					/**< Macros for logging raw provenance. */

extern "C" {
extern struct syscall_entry *syscalls;	/**< Syscalls info table. */
}



// *******************************************************************
// SyscallInfo definitions
// *******************************************************************
SyscallInfo::SyscallInfo(ProcInfo *pi, CPUState *env) {
#if defined(TARGET_I386)
	// XXX:	OSDEP: On Windows and Linux, the system call id is in EAX.
	//		OSDEP: On Linux, system call arguments are passed in registers.
	this->nr = env->regs[R_EAX];
	static int argidx[6] = {R_EBX, R_ECX, R_EDX, R_ESI, R_EDI, R_EBP};
	this->env = env;
	this->pi = pi;

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

int SyscallInfo::get_ret() const {
#if defined(TARGET_I386)
	return (target_int)this->env->regs[R_EAX];
#else
	// XXX: ARM
	#warning "ARM syscall decoding has not been implemented."
	return -1;
#endif
}

union syscall_arg SyscallInfo::get_arg(int n, size_t sz) const {
	union syscall_arg r;

	switch (syscalls[this->nr].args[n]) {
		case SYSCALL_ARG_INT:
			r.intval = (target_int)this->args[n].intval;
		break;

		case SYSCALL_ARG_STR:
			r.sval = (gchar *)g_malloc(sz * sizeof(gchar));
			guest_strncpy(this->env, r.sval, sz, this->args[n].pval);
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
				o   << std::dec << (target_int)this->args[i].intval;
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
	std::ostringstream ss;
#if defined(TARGET_I386)
	if (include_rval)
	ss << (target_int)env->regs[R_EAX] << " = ";
#endif
	ss << this;
	return ss.str();
}

std::string SyscallInfo::str() const {
	std::ostringstream ss;
	ss << this;
	return ss.str();
}

const char *SyscallInfo::get_name() const {
	return syscalls[this->nr].name;
}

/* vim:set tabstop=4 softtabstop=4 noexpandtab */
