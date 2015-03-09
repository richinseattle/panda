#ifndef SYSCALLS_DECODE_H
#define SYSCALLS_DECODE_H


extern void *syscalls_dl;                   /**< DL handle for syscalls table. */
extern struct syscall_entry *syscalls;      /**< Syscalls table. */


/* 
	http://www.tldp.org/LDP/tlk/ds/ds.html

	thread_info struct starts on %ESP & 0xffffe000 (8k stack).
	Its first element is a pointer to a task_struct struct.

	task_struct contains the pid/gid of the running process, however their exact 
        location is kernel-specific. I.e. it will be different depending of the flags
	set during kernel compilation.


    http://wiki.osdev.org/SYSENTER
*/

static inline const char *syscall2str(CPUState *env, TARGET_PTR pc) {
#if defined(TARGET_I386)
    // XXX: OSDEP: On Windows and Linux, the system call id is in EAX.
    int syscall_nr = env->regs[R_EAX];

    // XXX: OSDEP: On Linux, system call arguments are passed in registers.
    static int argidx[6] = {R_EBX, R_ECX, R_EDX, R_ESI, R_EDI, R_EBP};

    // Buffer for printing syscall string arguments.
    static unsigned char s[SYSCALL_STRSAMPLE_LEN];

    int syscall_nargs = syscalls[syscall_nr].nargs;
    std::stringstream ss;

    ss << syscalls[syscall_nr].name << "(";

    for (int i=0; i<syscall_nargs; i++) {
        auto arg = env->regs[argidx[i]];
        int rstatus;

        switch (syscalls[syscall_nr].args[i]) {
            case SYSCALL_ARG_INT:
                ss << std::dec << (target_int)arg;
                break;

            case SYSCALL_ARG_PTR:
                if (arg) { ss << '#' << std::hex << arg; }
                else { ss << "NULL"; }
                break;

            case SYSCALL_ARG_STR:
                if (arg) {
		    int j;
		    s[0] = '\0';

                    // read blindly SYSCALL_MAX_STRLEN data
                    rstatus = panda_virtual_memory_rw(env, arg, s, SYSCALL_STRSAMPLE_LEN, 0);
                    CHECK_WARN((rstatus < 0), "Couldn't read syscall string argument.");

		    // find printable chars at the beginning of the string
		    for (j=0; j<SYSCALL_STRSAMPLE_LEN && isprint(s[j]) && s[j]!='\0'; j++) {}

		    // append results to the buffer
		    if (s[j] == '\0') { ss << '"' << s << '"'; }    // properly terminated string
		    else if (j == 0) { ss << "...<bin>..."; }	    // nothing but garbage
		    else {					    // some ascii followed by garbage
			j = j<SYSCALL_STRSAMPLE_LEN ? j : j-1;
			s[j] = '\0';
			ss << '"' << s << '"' << "...<bin>...";
		    }
                }
                else { ss << "NULL"; }
                break;

            default:
                EXIT_ON_ERROR(1, "Unexpected syscall argument type.");
                break;
        }
        ss << ", ";
    }

    // rewind to overwrite the last ", "
    if (syscall_nargs > 0) { ss.seekp(-2, ss.end); }
    ss << ")";

    // Note: According to the C++ docs, the pointer returned by
    // c_str() may be invalidated by further calls.
    // It is caller's responsibility to copy the string before any
    // such calls.
    return ss.str().c_str();
#else
    // have the function compiled, although initialization should fail earlier.
    // XXX: ARM
    std::stringstream ss;
    ss << "(Not implemented on ARM)";
    return ss.str().c_str();
#endif
}

#endif
