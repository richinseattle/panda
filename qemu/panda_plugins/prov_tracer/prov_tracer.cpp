#include <distorm.h>
namespace distorm {
#include <mnemonics.h>
}

extern "C" {
#include "config.h"
#include "qemu-common.h"
#include "cpu.h"

#include <byteswap.h>

#include "panda_plugin.h"
#include "syscallents.h"

extern int task_struct_tasks_offset;
extern int task_struct_pid_offset;
extern int task_struct_stack_offset;
extern int task_struct_mm_offset;
extern int mm_struct_pgd_offset;

extern int task_struct_thread_group_offset;
//extern int task_struct_group_leader_offset;
//extern int task_struct_real_parent_offset;
}



#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <ctype.h>
#include <strings.h>
#include <errno.h>
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
}

#define PTLOG(fmt, args...) fprintf(ptout, "%s:%s: " fmt "\n", __FILE__, __func__, ## args)
#define PTLOG_FLUSH fflush(ptout)

/*
 * Error handling macros.
 */
#define WARN_ON_ERROR(cond, txt) if (cond) {\
    PTLOG("WARNING: %s", txt);\
    PTLOG_FLUSH;\
}
#define EXIT_ON_ERROR(cond, txt) if (cond) {\
    PTLOG("FATAL ERROR: %s", txt);\
    PTLOG_FLUSH;\
    exit(1);\
}
#define ERRNO_CLEAR errno = 0

#define PROCNAME_LEN 256
#define PLUGIN_NAME "panda_prov_tracer"
#define DLNAME_LEN 256
#define PROV_TRACER_DEFAULT_OUT "prov_tracer.txt"

/*
 *	--------------------
 *	Panda API cheatsheet
 *	--------------------
 *	void panda_register_callback(void *plugin, PANDA_CB_USER_AFTER_SYSCALL, panda_cb cb);
 *	int panda_physical_memory_rw(target_phys_addr_t addr, uint8_t *buf, int len, int is_write);
 *	target_phys_addr_t panda_virt_to_phys(CPUState *env, target_ulong addr);
 *	int panda_virtual_memory_rw(CPUState *env, target_ulong addr, uint8_t *buf, int len, int is_write);
 *
 *	--------------------
 *	QEMU formats and types cheatsheet
 *	--------------------
 *	Formats (from cpu.h):
 *	  TARGET_FMT_lx
 *	  TARGET_FMT_ld
 *	  TARGET_FMT_lu
 *	Types:
 *	  target_int
 */

#if defined(TARGET_I386)
void *syscalls_dl;                      // DL handle for syscalls table
struct syscall_entry *syscalls;         // syscalls table
FILE *ptout;                            // logfile handle
_DecodeType distorm_dt = Decode32Bits;  // decoding mode for Distorm
unsigned int ts;                        // internal timestamp - mostly for debugging

/* 
	http://www.tldp.org/LDP/tlk/ds/ds.html

	thread_info struct starts on %ESP & 0xffffe000 (8k stack).
	Its first element is a pointer to a task_struct struct.

	task_struct contains the pid/gid of the running process, however their exact 
        location is kernel-specific. I.e. it will be different depending of the flags
	set during kernel compilation.


    http://wiki.osdev.org/SYSENTER
*/

static inline const char *syscall2str(CPUState *env, target_ulong pc) {
    // OSDEP: On Windows and Linux, the system call id is in EAX.
    int syscall_nr = env->regs[R_EAX];

    // OSDEP: On Linux, system call arguments are passed in registers.
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
                    WARN_ON_ERROR((rstatus < 0), "Couldn't read syscall string argument.");

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
                EXIT_ON_ERROR((1), "Unexpected syscall argument type.");
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
}

static inline bool in_kernelspace(CPUState *env) {
#if defined(TARGET_I386)
    // check the Current Privillege Level in the flags register
    return ((env->hflags & HF_CPL_MASK) == 0);
#elif defined(TARGET_ARM)
    // check for supervisor mode in the Current Program Status register
    return ((env->uncached_cpsr & CPSR_M) == ARM_CPU_MODE_SVC);
#else
    return false;
#endif
}

static inline unsigned int decompose_from_mem(CPUState *env, target_ulong mloc, unsigned int len, _DInst *ins_decoded, unsigned int ins_decoded_max, unsigned int feats) {
    unsigned char *buf;
    unsigned int ndecoded;
    _CodeInfo ci;

    // read from memory
    ERRNO_CLEAR;
    buf = (unsigned char *)malloc(len*sizeof(unsigned char));
    EXIT_ON_ERROR(buf == NULL, "malloc failed");
    WARN_ON_ERROR((panda_virtual_memory_rw(env, mloc, buf, len, 0) < 0), "qemu failed to read memory");

    // decode read bytes
    ci.code = buf;
    ci.codeLen = len;
    ci.codeOffset = 0;
    ci.dt = distorm_dt;         // global flag
    ci.features = feats;

    // decode_result is ignored as it is of little use
    /* _DecodeResult decode_result = */distorm_decompose(&ci, ins_decoded, ins_decoded_max, &ndecoded);

    free(buf);
    return ndecoded;       // the number of instructions returned is always non-zero
}


void process_info(CPUState *env, target_ulong pc) {
    if (in_kernelspace(env)) {                                                                                  
    }
    else {
	PTLOG("L8R");
    }
}


bool ins_translate_callback(CPUState *env, target_ulong pc) {
    const int nbytes = 32;      // number of bytes to attempt to decode. sysenter/sysexit are 2 bytes long.
    const int ndecode = 1;      // number of instructions to decode
    unsigned int ndecoded;      // number of instructions actually decoded
    _DInst ins_decoded[ndecode];// the decoded instructions
    _DInst *ins;

    ts++;

    // with the DF_STOP_ON_SYS feature, decoding will stop on the first syscall related instruction
    // TODO: add a static buffer to decompose_from_mem() so that we don't need to read memory for every call
    ndecoded = decompose_from_mem(env, pc, nbytes, ins_decoded, ndecode, DF_STOP_ON_SYS);
    WARN_ON_ERROR((ndecoded > ndecode), "unexpected number of decoded instructions");

    ins = &ins_decoded[0];

    // we requested decoding 1 instruction - no loop needed
    if (ins->flags == FLAG_NOT_DECODABLE) {
        return false;
    }

    // check the decoded instruction class instead of the specific opcode
    switch(META_GET_FC(ins->meta)) {
        case FC_SYS:
            return true;

        default:
            if (ins->ops[0].type == O_REG && ins->ops[0].index == distorm::R_CR3 ) {
                return true;
	    }
            else
                return false;
    }
}

int ins_exec_callback(CPUState *env, target_ulong pc) {
    const int nbytes = 32;      // number of bytes to attempt to decode. sysenter/sysexit are 2 bytes long.
    const int ndecode = 1;      // number of instructions to decode
    unsigned int ndecoded;      // number of instructions actually decoded
    unsigned int nundecodable = 0;
    _DInst ins_decoded[ndecode];// the decoded instructions
    _DInst *ins;

    // Test to see if precise panda_enable_precise_pc() makes any difference.
    //if (pc != env->panda_guest_pc) { fprintf(stderr, "PC inconsistent.\n"); exit(1); }

    // with the DF_STOP_ON_SYS feature, decoding will stop on the first syscall related instruction
    ndecoded = decompose_from_mem(env, pc, nbytes, ins_decoded, ndecode, DF_STOP_ON_SYS);
    WARN_ON_ERROR((ndecoded > ndecode), "unexpected number of decoded instructions");

    // loop through decoded instructions
    for (unsigned int i=0; i<ndecoded; i++) {
        ins = &ins_decoded[i];
        if (ins->flags == FLAG_NOT_DECODABLE) {
            nundecodable++;
            continue;
        }

	int pid = 0;
	char procname[] = "foo";

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
                // ++ add ifs
		//PTLOG("CR3:" TARGET_FMT_plx " SYSENTER:%s", env->cr[3], syscall2str(env, pc));
                fprintf(ptout, "@%05u %s %5u(%s) CR3=" TARGET_FMT_plx " PC=" TARGET_FMT_plx " %s\n",
                    ts, in_kernelspace(env) ? "K" : "U",
                    (unsigned int)pid, procname,
                    (long unsigned int)env->cr[3], (long unsigned int)pc, syscall2str(env, pc)
                );
            }
            break;

            case distorm::I_SYSEXIT:
            {
		//PTLOG("CR3:" TARGET_FMT_plx " SYSEXIT", env->cr[3]);
                fprintf(ptout, "@%05u %s %5u(%s) CR3=" TARGET_FMT_plx " PC=" TARGET_FMT_plx " %s\n",
                    ts, in_kernelspace(env) ? "K" : "U",
                    (unsigned int)pid, procname,
                    (long unsigned int)env->cr[3], (long unsigned int)pc, "SYSEXIT"
                );
            }
            break;

            default:
            {
                if (ins->ops[0].type == O_REG && ins->ops[0].index == distorm::R_CR3 ) {
		    PTLOG("");
		    PTLOG("CR3=" TARGET_FMT_lx, env->cr[3]);
		    process_info(env, pc);

                }
		else { PTLOG("OTHER"); }
	    }
            break;
        }
	PTLOG_FLUSH;
    }

    return 0;
}

int before_block_exec_cb(CPUState *env, TranslationBlock *tb) {
	// test
	//ptout << std::hex << env->regs[R_ESP] << ":" << (0xffffe000 & env->regs[R_ESP]) <<  std::endl;
	return 0;
}
#endif

bool init_plugin(void *self) {
    int i;
    panda_arg_list *plugin_args = panda_get_args(PLUGIN_NAME);

#if defined(TARGET_I386)
    // i386-specific settings
    char *guest_os = NULL;
#endif

    // handle plugin arguments
    if (plugin_args != NULL ) {
        for (i=0; i<plugin_args->nargs; i++) {
            panda_arg a = plugin_args->list[i];
#if defined(TARGET_I386)
            // i386-specific arguments
            if (0 == strcmp(a.key, "guest")) {
                ERRNO_CLEAR;
                guest_os = strdup(a.value);
                EXIT_ON_ERROR(guest_os == NULL, "strdup");
            }
#else
            // arguments available to all targets
            if (1 == 0) { }
#endif
            else {
                fprintf(stderr, "Unknown PANDA plugin argument: %s=%s.\n", a.key, a.value);
            }
        }
        panda_free_args(plugin_args);
    }



#if defined(TARGET_I386)
    // load syscall entries
    int n;
    char syscalls_dlname[DLNAME_LEN];
    ERRNO_CLEAR;
    n = snprintf(syscalls_dlname, DLNAME_LEN, "%s_syscallents_%s.so", PLUGIN_NAME, guest_os);
    EXIT_ON_ERROR(!(n > -1 && n < DLNAME_LEN), "snprintf failed");
    syscalls_dl = dlopen(syscalls_dlname, RTLD_NOW);
    EXIT_ON_ERROR(syscalls_dl == NULL, dlerror());
    syscalls = (struct syscall_entry *)dlsym(syscalls_dl, "syscalls");
    EXIT_ON_ERROR(syscalls == NULL, dlerror());

    // open output file
    ptout = fopen(PROV_TRACER_DEFAULT_OUT, "w");    
    if(ptout == NULL) return false;

    // set Distorm decode mode
    if (strstr(guest_os, "64")) { distorm_dt = Decode64Bits; }
    else { distorm_dt = Decode64Bits; }

    // initialize panda stuff
    panda_cb pcb;

    // this doesn't seem to have any effect for us - disable
    panda_enable_precise_pc();

    //pcb.before_block_exec = before_block_exec_cb;
    //panda_register_callback(self, PANDA_CB_BEFORE_BLOCK_EXEC, pcb);

    pcb.insn_translate = ins_translate_callback;
    panda_register_callback(self, PANDA_CB_INSN_TRANSLATE, pcb);

    pcb.insn_exec = ins_exec_callback;
    panda_register_callback(self, PANDA_CB_INSN_EXEC, pcb);

    return true;
#else
    std::cerr << "WARN: Target not supported for panda_prov_tracer plugin." << std::endl;
    return false;
#endif
}

void uninit_plugin(void *self) {
#if defined(TARGET_I386)
    int n;

    ERRNO_CLEAR;
    n = dlclose(syscalls_dl);
    WARN_ON_ERROR(n != 0, dlerror());
	n = fclose(ptout);
    WARN_ON_ERROR(n != 0, "fclose failed");

#endif
}

