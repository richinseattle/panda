#include "platform.h"
#include "prov_tracer.h"
extern "C" {
#include "config.h"
#include "qemu-common.h"
#include "cpu.h"

#include "panda_plugin.h"
#include "panda_plugin_plugin.h"
#include "../osi/osi_types.h"		/**< Introspection data types. */
#include "../osi/osi_ext.h"			/**< Introspection API. */
#include "../osi/os_intro.h"		/**< Introspection callbacks. */
#include "../osi_linux/osi_linux_ext.h"	/**< Linux specific introspection API. */
#include "syscalls/syscallents.h"

#include <stdio.h>
#include <glib.h>
#include <dlfcn.h>
#include <ctype.h>
#include <strings.h>
#include <errno.h>
}
#include <iostream>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <chrono>
#include <ctime>
#include "accounting.h"

/*
 * Functions interfacing with QEMU/PANDA should be linked as C.
 * C++ function name mangling breaks linkage.
 */
extern "C" {
bool init_plugin(void *);
void uninit_plugin(void *);
void on_new_process(CPUState *, OsiProc *);
}

void *syscalls_dl;					/**< DL handle for syscalls table. */
struct syscall_entry *syscalls;		/**< Syscalls table. */
ProcInfoMap pimap;
std::ofstream prov_out;				/**< Provenance output stream. */


// ****************************************************************************
// Helpers
// ****************************************************************************
std::string panda_virtual_memory_smart_read(CPUState *env, target_ulong addr, size_t n) {
	std::ostringstream ss;
	uint8_t *p = (uint8_t *)g_malloc(TARGET_PAGE_SIZE);

	size_t n_rd = 0;
	do {
	// read next chunk of memory
	int chunk_sz = n_rd + TARGET_PAGE_SIZE > n ? n-n_rd : TARGET_PAGE_SIZE;
	if ( -1 == panda_virtual_memory_rw(env, addr, p, chunk_sz, 0) )
		goto error;

	// find printable chars at the beginning of the string
	int j;
	for (j=0; n_rd == 0 && j<chunk_sz && isprint(p[j]) && p[j]!='\0'; j++) {}

	if (j>SMART_READ_MIN_STRLEN && p[j] == '\0') {
		// print as string if at least 3 printable characters were found
		ss << (char *)p;
		goto starts_w_string;
	}
	else if (! (strncmp((char *)p, ".", 2) && strncmp((char *)p, "..", 3)) ) {
		// special case -- allow "." and ".." strings (useful for filenames)
		ss << (char *)p;
		goto starts_w_string;
	}
	else if (j == chunk_sz && p[j-1] != '\0') {
		// all printable characters, but no terminator
		char c = (char)p[j-1];
		p[j-1] = '\0';
		ss << (char *)p << c << "...<cont>...";
		p[j-1] = c;

		// XXX: This is not handled properly in the case where
		//		n is bigger than TARGET_PAGE_SIZE. In that case we should
		//		continue reading another chunk until a terminator is found
		//		or n is exceeded.
		//		However this is a corner case which would make the code
		//		much more complicated.
		goto starts_w_string;
	}
	else { j = 0; }

	// continue printing as hex
	ss << "[";
	for (int i = j; i<chunk_sz; i++) {
		if (i>j && (i%4 == 0)) ss << '|';
		ss << std::hex << std::setw(2) << std::setfill('0') << (int)p[i];
	}
	n_rd += chunk_sz;
	} while(n_rd < n);
	ss << "]";

starts_w_string:
	g_free(p);
	return ss.str();

error:
	g_free(p);
	ss << "ERR";
	return ss.str();
}




// ****************************************************************************
// Unused/debug callbacks
// ****************************************************************************
int vmi_pgd_changed(CPUState *env, target_ulong oldval, target_ulong newval) {
	LOG_INFO("PGD Update (%s): " TARGET_PTR_FMT " " TARGET_PTR_FMT, _CPU_MODE, oldval, newval);
	if (_IN_KERNEL) {	// this check is redundant - PGD only changed in kernel mode
		OsiProc *proc = get_current_process(env);
		LOG_INFO("Current process: %s, PID:" TARGET_PID_FMT ", PPID:" TARGET_PID_FMT,
			proc->name, (int)proc->pid, (int)proc->ppid
		);
	}
	else { LOG_ERROR("PGD updated in user mode???"); }
	return 0;
}

int before_block_exec_cb(CPUState *env, TranslationBlock *tb) {
	return 0;
}
// ****************************************************************************





bool ins_translate_callback(CPUState *env, TARGET_PTR pc) {
#if defined(TARGET_I386)
	const int nbytes = 32;	  // number of bytes to attempt to decode. sysenter/sysexit are 2 bytes long.
	const int ndecode = 1;	  // number of instructions to decode
	unsigned int ndecoded;	  // number of instructions actually decoded
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

int ins_exec_callback(CPUState *env, TARGET_PTR pc) {
#if defined(TARGET_I386)
	const int nbytes = 32;	  // number of bytes to attempt to decode. sysenter/sysexit are 2 bytes long.
	const int ndecode = 1;	  // number of instructions to decode
	unsigned int ndecoded;	  // number of instructions actually decoded
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

		auto pi_it = pimap.find(_PGD);
		if (pi_it == pimap.end()) {
			// This may occur at the beginning of replay.
			LOG_WARN("No ProcessInfo associated with " TARGET_PTR_FMT ".", _PGD);
			return 0;
		}
		ProcInfo *pi = (*pi_it).second;

		// Update pi with missing info. Can only run in kernel mode.
		// XXX: We store the task struct address in OsiProc struct.
		//	Maybe we can use it to update OsiProc at any point in time.
		if (_IN_KERNEL && pi->is_fresh) {
			OsiProc *p_update = get_current_process(env);

			g_free(pi->p.name);
			pi->p.name = g_strdup(p_update->name);
			pi->is_fresh = false;

			free_osiproc(p_update);
		}
		else if (!_IN_KERNEL) {
			// test the new impl
			/*
			OsiProc *p_update = get_current_process(env);
			LOG_INFO("TEST:" TARGET_PTR_FMT ":%s", p->asid, p->name);
			LOG_INFO("TEST:" TARGET_PTR_FMT ":%s", p_update->asid, p_update->name);
			free_osiproc(p_update);
			*/
		}

		switch(ins->opcode) {
		case distorm::I_SYSENTER:
			pi->syscall_start(env);
			break;

		case distorm::I_SYSEXIT:
			pi->syscall_end(env);
			break;

		default:
			LOG_WARN("Unexpected instrumented instruction: %s", GET_MNEMONIC_NAME(ins->opcode));
			break;
		}
	} /* for all decoded instructions */
	return 0;
#else
	// have the function compiled, although initialization should fail earlier.
	// XXX: ARM
	return 0;
#endif
}

void on_new_process(CPUState *env, OsiProc *p) {
	// asid addresses are in the kernel space - can be translated to physical addresses at any time
	TARGET_PTR asid_ph = panda_virt_to_phys(env, p->asid);

	LOG_INFO("PROV:NEWPROC: %-16s %5d %5d\t" TARGET_PTR_FMT " " TARGET_PTR_FMT,
	p->name, (int)p->pid, (int)p->ppid, p->asid, asid_ph
	);

	// create ProcInfo
	ProcInfo *pi = new ProcInfo(p);

	// insert ProcInfo - use asid_ph as the key
	auto inserted = pimap.insert(std::make_pair(asid_ph, pi));
	EXIT_ON_ERROR(inserted.second == false, "Duplicate key (" TARGET_PTR_FMT ") for new process %s (%d).", asid_ph, p->name, (int)p->pid);
}

void on_finished_process(CPUState *env, OsiProc *p) {
	TARGET_PTR asid_ph = panda_virt_to_phys(env, p->asid);
	LOG_INFO("PROV:EXITPROC: %-16s %5d %5d\t" TARGET_PTR_FMT " " TARGET_PTR_FMT,
	p->name, (int)p->pid, (int)p->ppid, p->asid, asid_ph
	);

	auto pi_it = pimap.find(asid_ph);
	EXIT_ON_ERROR(pi_it == pimap.end(), "Unknow key (" TARGET_PTR_FMT ") for terminating process %s (%d).", asid_ph, p->name, (int)p->pid);
	ProcInfo *pi = (*pi_it).second;
	pimap.erase(pi_it);

	// XXX: compare OsiProc for changes?
	delete pi;
}


void EXTERN_API_INIT_process_info();

bool init_plugin(void *self) {
	// timestamp
	std::time_t start_time = std::time(NULL);

	// retrieve plugin arguments
	panda_arg_list *plugin_args = panda_get_args(PLUGIN_NAME);
	char *guest_os = g_strdup(panda_parse_string(plugin_args, "guest", "linux"));
	char *prov_out_filename = g_strdup(panda_parse_string(plugin_args, "prov_out", "prov_out.raw"));
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

	// initialize osi_linux extra api
	if (!init_osi_linux_api()) {
		LOG_ERROR("OSI Linux API failed to initialize.");
		goto error1;
	}

	// initialize plugin apis in other source files
	EXTERN_API_INIT_process_info();

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

#ifdef OSI_PROC_EVENTS
	PPP_REG_CB("osi", on_new_process, on_new_process);
	PPP_REG_CB("osi", on_finished_process, on_finished_process);
#else
#error "Process Event Callbacks not enabled!"
#endif

#else
	LOG_ERROR("%s does not support target %s.", PLUGIN_NAME, TARGET_ARCH);
#endif

	// open provenance output stream
	prov_out.open(prov_out_filename, std::ofstream::trunc);
	prov_out << "# " << std::ctime(&start_time);

	return true;

error1:
	g_free(syscalls_dlname);
	if (syscalls_dl != NULL) dlclose(syscalls_dl);

error0:
	g_free(guest_os);
	return false;
}

void uninit_plugin(void *self) {
	// delete ProcessInfo objects to dump pending prov
	prov_out << "# end of replay - dumping pending items" << std::endl;
	for (auto pi_it=pimap.begin(); pi_it!=pimap.end(); ++pi_it) {
		delete (*pi_it).second;
	}

	std::time_t end_time = std::time(NULL);
	prov_out << "# " << std::ctime(&end_time);
	prov_out.close();

	ERRNO_CLEAR;
	CHECK_WARN(dlclose(syscalls_dl) != 0, "%s", dlerror());
}

/* vim:set tabstop=4 softtabstop=4 noexpandtab */
