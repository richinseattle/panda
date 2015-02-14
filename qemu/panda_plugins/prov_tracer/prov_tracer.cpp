#include "platform.h"
#include "prov_tracer.h"

extern "C" {
#include "config.h"
#include "qemu-common.h"
#include "cpu.h"

#include "panda_plugin.h"
#include "panda_plugin_plugin.h"
#include "../osi/osi_types.h"		/**< Introspection data types. */
#include "../osi/osi_ext.h"		/**< Introspection API. */
#include "../osi/os_intro.h"		/**< Introspection callbacks. */
#include "syscallents.h"

#include <stdio.h>
#include <glib.h>
#include <dlfcn.h>
#include <ctype.h>
#include <strings.h>
#include <errno.h>
}
#include <iostream>
#include <fstream>
#include <sstream>

/*
 * Functions interfacing with QEMU/PANDA should be linked as C.
 * C++ function name mangling breaks linkage.
 */
extern "C" {
bool init_plugin(void *);
void uninit_plugin(void *);
void on_new_process(CPUState *, OsiProc *);
}


void *syscalls_dl;                      /**< DL handle for syscalls table. */
struct syscall_entry *syscalls;		/**< Syscalls table. */

/* 
	http://www.tldp.org/LDP/tlk/ds/ds.html

	thread_info struct starts on %ESP & 0xffffe000 (8k stack).
	Its first element is a pointer to a task_struct struct.

	task_struct contains the pid/gid of the running process, however their exact 
        location is kernel-specific. I.e. it will be different depending of the flags
	set during kernel compilation.


    http://wiki.osdev.org/SYSENTER
*/

static inline const char *syscall2str(CPUState *env, PTR pc) {
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
    return ss.str().c_str();
#endif
}



bool ins_translate_callback(CPUState *env, PTR pc) {
#if defined(TARGET_I386)
    const int nbytes = 32;      // number of bytes to attempt to decode. sysenter/sysexit are 2 bytes long.
    const int ndecode = 1;      // number of instructions to decode
    unsigned int ndecoded;      // number of instructions actually decoded
    _DInst ins_decoded[ndecode];// the decoded instructions
    _DInst *ins;

    // with the DF_STOP_ON_SYS feature, decoding will stop on the first syscall related instruction
    // TODO: add a static buffer to decompose_from_mem() so that we don't need to read memory for every call
    ndecoded = decompose_from_mem(env, pc, nbytes, ins_decoded, ndecode, DF_STOP_ON_SYS);
    CHECK_WARN((ndecoded == 0), "0 instructions decoded. This shouldn't happen.");

    // we requested decoding 1 instruction - no loop needed
    ins = &ins_decoded[0];
    if (ins->flags == FLAG_NOT_DECODABLE) {
        return false;
    }

    // check the decoded instruction class instead of the specific opcode
    switch(META_GET_FC(ins->meta)) {
        case FC_SYS:
            return true;

        default:
	    return false;
    }
#else
    // have the function compiled, although initialization should fail earlier.
    // XXX: ARM
    return false;
#endif
}


int ins_exec_callback(CPUState *env, PTR pc) {
#if defined(TARGET_I386)
    const int nbytes = 32;      // number of bytes to attempt to decode. sysenter/sysexit are 2 bytes long.
    const int ndecode = 1;      // number of instructions to decode
    unsigned int ndecoded;      // number of instructions actually decoded
    unsigned int nundecodable = 0;
    _DInst ins_decoded[ndecode];// the decoded instructions
    _DInst *ins;

    // with the DF_STOP_ON_SYS feature, decoding will stop on the first syscall related instruction
    ndecoded = decompose_from_mem(env, pc, nbytes, ins_decoded, ndecode, DF_STOP_ON_SYS);
    CHECK_WARN((ndecoded == 0), "0 instructions decoded. This shouldn't happen.");

    // loop through decoded instructions
    for (unsigned int i=0; i<ndecoded; i++) {
        ins = &ins_decoded[i];
        if (ins->flags == FLAG_NOT_DECODABLE) {
            nundecodable++;
            continue;
        }

	int pid = 0;		    // XXX: properly fill pid
	char procname[] = "foo";    // XXX: properly fill name

        switch(ins->opcode) {
            case distorm::I_SYSENTER:
            {
                // On Windows and Linux, the system call id is in EAX.
                //
                // On Linux, the PC will point to the same location for
                // each syscall: At kernel initialization time the routine
                // sysenter_setup() is called. It sets up a non-writable
                // page and writes code for the sysenter instruction if
                // the CPU supports that, and for the classical int 0x80
                // otherwise. Thus, the C library can use the fastest type
                // of system call by jumping to a fixed address in the
                // vsyscall page.
                // (http://www.win.tue.nl/~aeb/linux/lk/lk-4.html)
                //
		//PTLOG("PGD:" TARGET_FMT_plx " SYSENTER:%s", _PGD, syscall2str(env, pc));
                LOG_INFO("%s " PID_FMT "(%s) PGD=" PTR_FMT " PC=" PTR_FMT " %s",
                    _CPU_MODE, pid, procname, _PGD, pc, syscall2str(env, pc)
                );
            }
            break;

            case distorm::I_SYSEXIT:
            {
		//PTLOG("PGD:" TARGET_FMT_plx " SYSEXIT", _PGD);
                LOG_INFO("%s " PID_FMT "(%s) PGD=" PTR_FMT " PC=" PTR_FMT " %s",
                    _CPU_MODE, pid, procname, _PGD, pc, "SYSEXIT"
                );
            }
            break;

            default:
            {
		LOG_WARN("Unexpected instrumented instruction: %s",
		    GET_MNEMONIC_NAME(ins->opcode)
		);
	    }
            break;
        }
    }

    return 0;
#else
    // have the function compiled, although initialization should fail earlier.
    // XXX: ARM
    return 0;
#endif
}

int vmi_pgd_changed(CPUState *env, target_ulong oldval, target_ulong newval) {
    LOG_INFO("PGD Update (%s): " PTR_FMT " " PTR_FMT, _CPU_MODE, oldval, newval);
    if (_IN_KERNEL) {	// this check is redundant - PGD only changed in kernel mode
	OsiProc *proc = get_current_process(env);
	LOG_INFO("LOL");
	LOG_INFO("Current process: %s, PID:" PID_FMT ", PPID:" PID_FMT,
	    proc->name, (int)proc->pid, (int)proc->ppid
	);
    }
    else {
	LOG_INFO("WTF2");
    }
    return 0;
}



int before_block_exec_cb(CPUState *env, TranslationBlock *tb) {
	//ptout << std::hex << env->regs[R_ESP] << ":" << (0xffffe000 & env->regs[R_ESP]) <<  std::endl;
	return 0;
}


void on_new_process(CPUState *env, OsiProc *p) {
    LOG_INFO("NEW: %s", p->name);
}

void on_finished_process(CPUState *env, OsiProc *p) {
    LOG_INFO("FINISHED: %s", p->name);
}

bool init_plugin(void *self) {
    // retrieve plugin arguments
    panda_arg_list *plugin_args = panda_get_args(PLUGIN_NAME);
    char *guest_os = g_strdup(panda_parse_string(plugin_args, "guest", "linux"));
    if (plugin_args != NULL) panda_free_args(plugin_args);

    // load syscalls table
    char *syscalls_dlname = NULL;
    if (g_strcmp0(guest_os, "linux") == 0) {
	syscalls_dlname = g_strdup_printf("panda_%s_syscallents_%s.so", PLUGIN_NAME, SYSCALLS_LINUX);
	ERRNO_CLEAR;
	if (
	    ((syscalls_dl = dlopen(syscalls_dlname, RTLD_NOW)) == NULL) ||
	    ((syscalls = (struct syscall_entry *)dlsym(syscalls_dl, "syscalls")) == NULL)
	) {
	    LOG_ERROR("%s", dlerror());
	    goto error1;
	}
    }
    else {
	LOG_ERROR("Unsupported OS: %s", guest_os);
	goto error0;
    }

    // initialize osi api
    if (!init_osi_api()) {
	LOG_ERROR("OSI API failed to initialize.");
	goto error1;
    }

#if defined(TARGET_I386)
    // initialize panda stuff
    panda_cb pcb;

    //pcb.before_block_exec = before_block_exec_cb;
    //panda_register_callback(self, PANDA_CB_BEFORE_BLOCK_EXEC, pcb);

    pcb.insn_translate = ins_translate_callback;
    panda_register_callback(self, PANDA_CB_INSN_TRANSLATE, pcb);

    pcb.insn_exec = ins_exec_callback;
    panda_register_callback(self, PANDA_CB_INSN_EXEC, pcb);

    //pcb.after_PGD_write = vmi_pgd_changed;
    //panda_register_callback(self, PANDA_CB_VMI_PGD_CHANGED, pcb);

    PPP_REG_CB("osi", on_new_process, on_new_process);
    PPP_REG_CB("osi", on_finished_process, on_finished_process);

    return true;
#else
    LOG_ERROR("%s does not support target %s.", PLUGIN_NAME, TARGET_ARCH);
#endif


error1:
    g_free(syscalls_dlname);
    if (syscalls_dl != NULL) dlclose(syscalls_dl);

error0:
    g_free(guest_os);
    return false;
}

void uninit_plugin(void *self) {
    ERRNO_CLEAR;
    CHECK_WARN(dlclose(syscalls_dl) != 0, "%s", dlerror());
}

