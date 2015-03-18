#include "platform.h"
extern "C" {
#include "config.h"
#include "qemu-common.h"
#include "cpu.h"
}
#include <glib.h>
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
		//this->args[i].sval = panda_virtual_memory_str_read(env, arg);
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
                if (this->args[i].pval) { o << '#' << std::hex << this->args[i].pval; }
                else { o << "NULL"; }
                break;

            case SYSCALL_ARG_STR:
                if (this->args[i].pval) { o << '$' << std::hex << this->args[i].pval; }
                else { o << "NULL"; }
                break;
#if 0
            case SYSCALL_ARG_STR:
                if (this->args[i].pval) {
		    int j;
		    s[0] = '\0';

                    // read blindly SYSCALL_MAX_STRLEN data
                    int rstatus = panda_virtual_memory_rw(env, arg, s, SYSCALL_STRSAMPLE_LEN, 0);
                    CHECK_WARN((rstatus < 0), "Couldn't read syscall string argument.");

		    // find printable chars at the beginning of the string
		    for (j=0; j<SYSCALL_STRSAMPLE_LEN && isprint(s[j]) && s[j]!='\0'; j++) {}

		    // append results to the buffer
		    if (s[j] == '\0') { o << '"' << s << '"'; }    // properly terminated string
		    else if (j == 0) { o << "...<bin>..."; }	    // nothing but garbage
		    else {					    // some ascii followed by garbage
			j = j<SYSCALL_STRSAMPLE_LEN ? j : j-1;
			s[j] = '\0';
			o << '"' << s << '"' << "...<bin>...";
		    }
                }
                else { o << "NULL"; }
                break;
#endif

            default:
                EXIT_ON_ERROR(1, "Unexpected syscall argument type.");
                break;
        }
    }
    o << ")";
    return o;
}

std::string SyscallInfo::str() const {
    std::stringstream ss;
    ss << this;
    return ss.str();
    //ss << 'X' << this;
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

