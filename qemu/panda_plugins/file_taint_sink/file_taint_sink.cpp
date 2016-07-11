/*!
 * @file file_taint_sink.cpp
 * @brief PANDA logging of tainted writes to files.
 *
 * @author Manolis Stamatogiannakis <manolis.stamatogiannakis@vu.nl>
 * @copyright This work is licensed under the terms of the GNU GPL, version 2.
 * See the COPYING file in the top-level directory.
 */

#define __STDC_FORMAT_MACROS

extern "C" {
#include "qemu-common.h"
#include "cpu.h"
#include "rr_log.h"

#include "panda_common.h"
#include "panda_plugin.h"
#include "panda_plugin_plugin.h"
#include "panda_addr.h"
#include "pandalog.h"

// generic osi headers
#include "osi_types.h"
#include "osi_ext.h"

// extended osi-linux api (fd resolution)
#include "osi_linux_ext.h"

#include <glib.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
}

// taint2 headers
#include "taint2.h"
#include "taint2_ext.h"

// syscalls2 headers
#include "gen_syscalls_ext_typedefs.h"

#include <iostream>
#include <vector>
#include <map>
#include <string>

// Functions interfacing with QEMU/PANDA should be linked as C.
extern "C" {
	bool init_plugin(void *);
	void uninit_plugin(void *);
}

// Signatures for utils.cpp.
uint32_t guest_strncpy(CPUState *env, char *buf, size_t maxlen, target_ulong guest_addr);
uint32_t guest_wstrncpy(CPUState *env, char *buf, size_t maxlen, target_ulong guest_addr);

// TODO: Convert make_*addr functions from taint_processor.cpp to inlines in panda_addr.h.
Addr make_maddr(uint64_t a) {
	Addr ma;
	ma.typ = MADDR;
	ma.val.ma = a;
	ma.off = 0;
	ma.flag = (AddrFlag) 0;
	return ma;
}

#define PP_NAME "file_taint_sink"
#define PP_LOG_PREFIX PP_NAME ": "

static bool debug = true;

const char *taint_filename = 0;
bool positional_labels = true;
bool no_taint = true;
bool enable_taint_on_open = false;

extern uint64_t replay_get_guest_instr_count(void);

#define MAX_FILENAME 256
bool saw_open = false;
uint32_t the_asid = 0;
uint32_t the_fd;

uint32_t end_label = 1000000;
uint32_t start_label = 0;

uint64_t first_instr = 0;
std::map< std::pair<uint32_t, uint32_t>, char *> asidfd_to_filename;
std::map <target_ulong, OsiProc> running_procs;



// label this virtual address.  might fail, so
// returns true iff byte was labeled
bool label_byte(CPUState *env, target_ulong virt_addr, uint32_t label_num) {
	target_phys_addr_t pa = panda_virt_to_phys(env, virt_addr);
	if (pa == (target_phys_addr_t) -1) {
		printf ("label_byte: virtual addr " TARGET_FMT_lx " not available\n", virt_addr);
		return false;
	}
	if (no_taint) {
		// don't print a message -- you'd have too many in this case
		return false;
	}
	if (positional_labels) {
		taint2_label_ram(pa, label_num);
	}
	else {
		taint2_label_ram(pa, 1);
	}
	if (pandalog) {
		Panda__LogEntry ple = PANDA__LOG_ENTRY__INIT;
		ple.has_taint_label_virtual_addr = 1;
		ple.has_taint_label_physical_addr = 1;
		ple.has_taint_label_number = 1;
		ple.taint_label_virtual_addr = virt_addr;
		ple.taint_label_physical_addr = pa;
		if (positional_labels) {
			ple.taint_label_number = label_num;
		}
		else {
			ple.taint_label_number = 1;
		}
		pandalog_write_entry(&ple);
	}
	return true;
}


char *last_open_filename;
uint32_t last_open_asid;

#ifdef TARGET_I386
// This is our proxy for file position. Approximate because of fseek etc.
uint64_t file_pos = 0;

#if 0
void open_enter(CPUState *env, target_ulong pc, std::string filename, int32_t flags, int32_t mode) {
	if (!filename.empty()) {
		if (debug) printf ("open_enter: saw open of [%s]\n", filename.c_str());
	}
	if (filename.find(taint_filename) != std::string::npos) {
		saw_open = true;
		printf ("saw open of file we want to taint: [%s] insn %" PRId64 "\n", taint_filename, rr_get_guest_instr_count());
		the_asid = panda_current_asid(env);
		if (enable_taint_on_open && !no_taint && !taint2_enabled()) {
			uint64_t ins = replay_get_guest_instr_count();
			taint2_enable_taint();
			if (debug) printf ("file_taint: enabled taint2 @ ins  %" PRId64 "\n", ins);
		}
	}
}
void open_return(CPUState* env, uint32_t fd) {
	//	printf ("returning from open\n");
	if (saw_open && the_asid == panda_current_asid(env)) {
		saw_open = false;
		// get return value, which is the file descriptor for this file
		the_fd = fd;
		//		printf ("saw return from open of [%s]: asid=0x%x  fd=%d\n", taint_filename, the_asid, the_fd);
	}

}
#endif
#if 0
bool saw_read = false;
uint32_t last_read_buf;
uint64_t last_pos = (uint64_t) -1;
void read_enter(CPUState* env, target_ulong pc, std::string filename, uint64_t pos, uint32_t buf, uint32_t count) {
	// these things are only known at enter of read call
	the_asid = panda_current_asid(env);
	last_read_buf = buf;
	last_pos = pos;
	saw_read = false;
	if (debug) printf ("read_enter filename=[%s]\n", filename.c_str());
	if (filename.find(taint_filename) != std::string::npos) {
		//	if (0 == strcmp(filename.c_str(), taint_filename)) {
		if (debug) printf ("read_enter: asid=0x%x saw read of %d bytes in file we want to taint\n", the_asid, count);
		saw_read = true;
	}
}
// 3 long sys_read(unsigned int fd, char __user *buf, size_t count);
// typedef void (*on_sys_read_return_t)(CPUState* env,target_ulong pc,uint32_t fd,target_ulong buf,uint32_t count);
void read_return(CPUState* env, target_ulong pc, uint32_t buf, uint32_t actual_count) {
	if (saw_read && panda_current_asid(env) == the_asid) {
		// These are the start and end of the current range of labels.
		uint32_t read_start = last_pos;
		uint32_t read_end = last_pos + actual_count;
		if (debug) printf ("returning from read of [%s] count=%u\n", taint_filename, actual_count);
		// check if we overlap the range we want to label.
		if (read_start < end_label && read_end > start_label) {
			uint32_t range_start = std::max(read_start, start_label);
			uint32_t range_end = std::min(read_end, end_label);
			printf("*** applying %s taint labels %u..%u to buffer @ %lu\n",
					positional_labels ? "positional" : "uniform",
					range_start, range_end - 1, rr_get_guest_instr_count());
			uint32_t num_labeled = 0;
			uint32_t i = 0;
			for (uint32_t l = range_start; l < range_end; l++) {
				if (label_byte(env, last_read_buf + i,
							   positional_labels ? l : 1))
					num_labeled ++;
				i ++;
			}
			printf("%u bytes labeled for this read\n", range_end - range_start);
		}
		last_pos += actual_count;
		//		printf (" ... done applying labels\n");
		saw_read = false;
	}
}
#endif
#endif

int file_taint_enable(CPUState *env, target_ulong pc) {
	if (!no_taint && !taint2_enabled()) {
		uint64_t ins = replay_get_guest_instr_count();
		if (ins > first_instr) {
			taint2_enable_taint();
			if (debug) printf (" enabled taint2 @ ins  %" PRId64 "\n", ins);
		}
	}
	return 0;
}


#if 0
// get current process before each bb executes
// which will probably help us actually know the current process
int osi_foo(CPUState *env, TranslationBlock *tb) {
	if (panda_in_kernel(env)) {
		OsiProc *p = get_current_process(env);
		//some sanity checks on what we think the current process is
		// this means we didnt find current task
		if (p->offset == 0) return 0;
		// or the name
		if (p->name == 0) return 0;
		// weird -- this is just not ok
		if (((int) p->pid) == -1) return 0;
		uint32_t n = strnlen(p->name, 32);
		// yuck -- name is one char
		if (n<2) return 0;
		uint32_t np = 0;
		for (uint32_t i=0; i<n; i++) {
			np += (isprint(p->name[i]) != 0);
		}
		// yuck -- name doesnt consist of solely printable characters
		if (np != n) return 0;
		target_ulong asid = panda_current_asid(env);
		if (running_procs.count(asid) == 0) {
			if (debug) printf ("adding asid=0x%x to running procs.  cmd=[%s]  task=0x%x\n", (unsigned int)  asid, p->name, (unsigned int) p->offset);
		}
		if (running_procs.count(asid) != 0) {
			/*
			OsiProc *p2 = running_procs[asid];
			// something there already
			if (p2)
				free_osiproc(p2);
			*/
		}
		running_procs[asid] = *p;
	}
	return 0;
}
#endif


#ifdef TARGET_I386
#if 0
void linux_read_enter(CPUState *env, target_ulong pc, uint32_t fd, uint32_t buf, uint32_t count) {
	target_ulong asid = panda_current_asid(env);
	if (running_procs.count(asid) == 0) {
		if (debug) printf ("linux_read_enter for asid=0x%x fd=%d -- dont know about that asid.  discarding \n", (unsigned int) asid, (int) fd);
		return;
	}
	OsiProc& proc = running_procs[asid];
	char *filename = osi_linux_fd_to_filename(env, &proc, fd);
	uint64_t pos = osi_linux_fd_to_pos(env, &proc, fd);
	if (filename==NULL) {
		if (debug)
			printf ("linux_read_enter for asid=0x%x pid=%d cmd=[%s] fd=%d -- that asid is known but resolving fd failed.  discarding\n",
					(unsigned int) asid, (int) proc.pid, proc.name, (int) fd);
		return;
	}
	if (debug) printf ("linux_read_enter for asid==0x%x fd=%d filename=[%s] count=%d pos=%u\n", (unsigned int) asid, (int) fd, filename, count, (unsigned int) pos);
	read_enter(env, pc, filename, pos, buf, count);
}
void linux_read_return(CPUState *env, target_ulong pc, uint32_t fd, uint32_t buf, uint32_t count) {
	read_return(env, pc, buf, EAX);
}
void linux_open_enter(CPUState *env, target_ulong pc, uint32_t filename, int32_t flags, int32_t mode) {
	char the_filename[MAX_FILENAME];
	guest_strncpy(env, the_filename, MAX_FILENAME, filename);
	if (debug) printf ("linux open asid=0x%x filename=[%s]\n", (unsigned int) panda_current_asid(env), the_filename);
	open_enter(env, pc, the_filename, flags, mode);
}
#endif
void linux_write_enter(CPUState* env, target_ulong pc, uint32_t fd, uint32_t buf, uint32_t count) {
	std::cout << PP_LOG_PREFIX << __FUNCTION__ <<
		" panda_in_kernel=" << panda_in_kernel(env) <<
		std::endl;

	OsiProc *proc = get_current_process(env);
	if (proc == NULL) {
		std::cerr << PP_LOG_PREFIX "couldn't get process" << std::endl;
		return;
	}
	else {
		std::cerr << PP_LOG_PREFIX "write by " <<
			" pid="	<< proc->pid << "[" << proc->name << "]" <<
			" fd="	<< fd << "[" << "???" << "]" <<
			std::endl;

	}

	char *filename = osi_linux_fd_to_filename(env, proc, fd);
	if (filename == NULL) {
		std::cerr << PP_LOG_PREFIX "couldn't get filename" << std::endl;
		free_osiproc(proc);
		return;
	}

	for (uint32_t i=0; i<count; i++) {
		uint8_t c;
		uint32_t pa = panda_virt_to_phys(env, buf+i);

		std::cout << PP_LOG_PREFIX "w(" <<
			" pid="	<< proc->pid << "[" << proc->name << "]" <<
			" fd="	<< fd << "[" << filename << "]" <<
			std::endl << std::flush;

		//std::cout << ":0x" << std::hex << buf;
		//std::cout << ":" << std::dec << count << std::endl;
		panda_virtual_memory_rw(env, buf+i, &c, 1, 0);
		std::cout << c << ":" << taint2_query(make_maddr(pa)) << std::endl;
	}

	g_free(filename);
	free_osiproc(proc);
	return;
}
void linux_write_return(CPUState* env, target_ulong pc, uint32_t fd, uint32_t buf, uint32_t count) {
	std::cout << PP_LOG_PREFIX << __FUNCTION__ <<
		" panda_in_kernel=" << panda_in_kernel(env) <<
		std::endl;
}
#endif /* TARGET_I386 */


bool init_plugin(void *self) {
	std::cout << PP_LOG_PREFIX "initializing" << std::endl;

#ifdef TARGET_I386
	panda_require("osi");
	assert(init_osi_api());
	panda_require("syscalls2");

	switch (panda_os_type) {
		case OST_LINUX:
			panda_require("osi_linux");
			assert(init_osi_linux_api());
			PPP_REG_CB("syscalls2", on_sys_write_enter, linux_write_enter);
			PPP_REG_CB("syscalls2", on_sys_write_return, linux_write_return);
			//PPP_REG_CB("syscalls2", on_sys_open_enter, linux_open_enter);
			//PPP_REG_CB("syscalls2", on_sys_read_enter, linux_read_enter);
			//PPP_REG_CB("syscalls2", on_sys_read_return, linux_read_return);
		break;

		case OST_UNKNOWN:
			std::cerr << PP_LOG_PREFIX "you must use '-os os_name' argument to specify the guest os" << std::endl;
			return false;
		break;

		default:
			std::cerr << PP_LOG_PREFIX "the specified guest os is not supported" << std::endl;
			return false;
		break;
	}

#if 0
	// argument parsing - inside ifdef TARGET_I386
	//panda_cb pcb;
	panda_arg_list *args;
	args = panda_get_args("file_taint");
	taint_filename = panda_parse_string(args, "filename", "abc123");
	positional_labels = panda_parse_bool(args, "pos");
	// used to just find the names of files that get
	no_taint = panda_parse_bool(args, "notaint");
	end_label = panda_parse_ulong(args, "max_num_labels", 1000000);
	end_label = panda_parse_ulong(args, "end", end_label);
	start_label = panda_parse_ulong(args, "start", 0);
	enable_taint_on_open = panda_parse_bool(args, "enable_taint_on_open");
	first_instr = panda_parse_uint64(args, "first_instr", 0);

	printf ("taint_filename = [%s]\n", taint_filename);
	printf ("positional_labels = %d\n", positional_labels);
	printf ("no_taint = %d\n", no_taint);
	printf ("end_label = %d\n", end_label);
	printf ("first_instr = %" PRId64 " \n", first_instr);
#endif

#if 0
	// this sets up the taint api fn ptrs so we have access
	if (!no_taint) {
		if (debug) printf ("file_taint: initializing taint2 plugin\n");
		panda_require("taint2");
		assert(init_taint2_api());
		if (!enable_taint_on_open && first_instr == 0) {
			if (debug) printf ("file_taint: turning on taint at replay beginning\n");
			taint2_enable_taint();
		}
	}

	if (!no_taint && first_instr > 0) {
		if (debug) printf ("file_taint: turning on taint at instruction %" PRId64 "\n", first_instr);
		// only need this callback if we are turning on taint late
		pcb.before_block_translate = file_taint_enable;
		panda_register_callback(self, PANDA_CB_BEFORE_BLOCK_TRANSLATE, pcb);
	}
#endif

	//panda_cb pcb = { .before_block_exec = osi_foo };
	//panda_register_callback(self, PANDA_CB_BEFORE_BLOCK_EXEC, pcb);
	return true;
#else
	std::cerr << PP_LOG_PREFIX "only i386 target is supported" << std::endl;
	return false;
#endif
}



void uninit_plugin(void *self) {
}

/* vim:set tabstop=4 softtabstop=4 noexpandtab */
