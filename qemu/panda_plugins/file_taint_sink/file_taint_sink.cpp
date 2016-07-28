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

// plugin headers
#include "file_taint_sink.h"

#include <iostream>
#include <string>
#include <unordered_map>
#include <unordered_set>

// plugin state
typedef struct {
	bool track_all;								// ignore set of sinks and track everything
	SinkSet sinks;								// set of sinks
	//sinkfds									// set of pid:fd pairs to watch
	AsidSet asid_fresh;							// asids for which we don't have complete info
	int n_asid_fresh;							// number of asids for which we don't have complete info
	ProcessStateMap pmap;						// maps asids to processes
	bool debug;									// debug mode
} plugin_state;

// globals
plugin_state fts;

inline bool update_fresh_processes(CPUState* env, plugin_state* fts) {
	// no fresh processes or not in kernel mode - return
	if (!(fts->n_asid_fresh > 0 && panda_in_kernel(env))) return false;

	// check if asid is fresh
	target_ulong asid = panda_current_asid(env);
	auto asid_it = fts->asid_fresh.find(asid);

	// asid not fresh - return
	if (asid_it == fts->asid_fresh.end()) return false;

	// get process info
	OsiProc *p = get_current_process(env);
	if (p == NULL) {
		std::cerr << DEBUG_PREFIX "couldn't get process" << std::endl;
		return false;
	}

	// update process in map
	auto ps_it = fts->pmap.find(asid);
	assert(ps_it != fts->pmap.end());
	(*ps_it).second->refresh(p);
	free_osiproc_g(p);

	// remove from fresh
	fts->n_asid_fresh--;
	fts->asid_fresh.erase(asid_it);
	return true;
}

int asid_change_cb(CPUState *env, target_ulong oldval, target_ulong newval) {
	bool updated = update_fresh_processes(env, &fts);
	std::cout << DEBUG_PREFIX << "updated=" << updated << std::endl;

	// current process was in the fresh list - return
	if (updated) return 0;

	// not in kernel - return
	if (!panda_in_kernel(env)) {
		std::cout << DEBUG_PREFIX << "not in kernel" << std::endl;
		return 0;
	}

	// already have the process - return
	target_ulong asid = panda_current_asid(env);
	auto ps_it = fts.pmap.find(asid);
	if (ps_it != fts.pmap.end()) return 0;

	// add new process to map
	OsiProc *p = get_current_process(env);
	if (p == NULL) {
		std::cout << DEBUG_PREFIX << "failed to get process" << std::endl;
		return 0;
	}
	auto inserted = fts.pmap.insert(std::make_pair(asid, new ProcessState(p)));

	// make sure that we notice when replacing a process
	assert(inserted.second == true);

	// add to pending list
	fts.asid_fresh.insert(asid);
	fts.n_asid_fresh++;
	return 0;
}


#ifdef TARGET_I386
void linux_write_enter(CPUState* env, target_ulong pc, uint32_t fd, uint32_t buf, uint32_t count) {
	target_ulong asid = panda_current_asid(env);
	std::cout << DEBUG_PREFIX << "asid=0x" << std::hex << asid << std::endl;

#if 0
	char *filename = osi_linux_fd_to_filename(env, proc, fd);
	if (filename == NULL) {
		std::cerr << DEBUG_PREFIX "couldn't get filename" << std::endl;
		free_osiproc(proc);
		return;
	}

	for (uint32_t i=0; i<count; i++) {
		uint8_t c;
		uint32_t pa = panda_virt_to_phys(env, buf+i);

		std::cout << DEBUG_PREFIX "w(" <<
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
	std::cout << DEBUG_PREFIX << fd << ":" << std::hex << buf << ":" << std::dec << count << std::endl;
#endif
}

void linux_write_return(CPUState* env, target_ulong pc, uint32_t fd, uint32_t buf, uint32_t count) {
	target_ulong asid = panda_current_asid(env);
	std::cout << DEBUG_PREFIX << "asid=0x" << std::hex << asid << std::endl;

	auto ps_it = fts.pmap.find(asid);

	if (ps_it == fts.pmap.end()) {std::cout << DEBUG_PREFIX "nope!" << std::endl; return;}
	assert(ps_it != fts.pmap.end());

	ProcessState *ps = ps_it->second;

	std::cout << DEBUG_PREFIX "w(" <<
		"p=" << ps->p->name <<
		" pid=" << ps->p->pid <<
		" fd="	<< fd << 
		" buf=" << std::hex << buf <<
		" count=" << std::dec << count <<
		" count2=" << std::dec << env->regs[R_EAX] <<
		")";
	for (uint32_t i=0; i<count; i++) {
		//uint8_t c;
		//panda_virtual_memory_rw(env, buf+i, &c, 1, 0);
		uint32_t pa = panda_virt_to_phys(env, buf+i);
		std::cout << " " << taint2_query(make_maddr(pa));
	}
	std::cout << std::endl;

	//std::cout << DEBUG_PREFIX << fd << ":" << std::hex << buf << ":" << std::dec << count << ":" << env->regs[R_EAX] << std::endl;
}


void linux_open_return(CPUState* env, target_ulong pc, uint32_t filename, int32_t flags, int32_t mode) {
	// check return value
	int32_t fd = env->regs[R_EAX];
	if (fd < 0) return;

	// get process
	target_ulong asid = panda_current_asid(env);
	auto ps_it = fts.pmap.find(asid);
	if (ps_it == fts.pmap.end()) {
		std::cout << DEBUG_PREFIX "No process for asid: " << std::hex << asid << std::dec << std::endl;
		return;
	}
	ProcessState *ps = ps_it->second;

	// resolve returned fd
	char *filename_real = osi_linux_fd_to_filename(env, ps->p, fd);

	// get filename from open arguments
	gchar *filename_arg = (gchar *)g_malloc(GUEST_MAX_FILENAME * sizeof(gchar));
	guest_strncpy(env, filename_arg, GUEST_MAX_FILENAME, filename);

	// look for file in the sinks
	gchar *basename = NULL;
	bool watch = false;

	// look if real filename is in the sink set
	// note: real filename may not be available (delayed kernel structure update?)
	//       or different from arg filename (symlink). this means that in some corner
	//       cases, we may miss a file we want to watch.
	if (filename_real != NULL) {
	    basename = g_path_get_basename(filename_real);
	    if (fts.sinks.find(basename) != fts.sinks.end()) { watch = true; }
	    else { g_free(basename); }
	}

	// look for argument filename in the sink set
	if (! watch) {
	    basename = g_path_get_basename(filename_arg);
	    if (fts.sinks.find(basename) != fts.sinks.end()) { watch = true; }
	    else { g_free(basename); }
	}

	if (watch) {
	    gchar *f = filename_real != NULL ? filename_real : filename_arg;
	    std::cout << DEBUG_PREFIX << "WWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWW " << f << std::endl;
	    g_free(basename);
	}

	g_free(filename_real);
	g_free(filename_arg);
}
#endif /* TARGET_I386 */



int block_exec_cb(CPUState *env, TranslationBlock *tb) {
	if (!panda_in_kernel(env)) {
		std::cout << DEBUG_PREFIX << "block changed but not in kernel mode" << std::endl;
		return 0;
	}

	OsiProc *p = get_current_process(env);
	if (p == NULL) {
		std::cout << DEBUG_PREFIX << "failed to get process" << std::endl;
		return 0;
	}

	std::cout << DEBUG_PREFIX << "EXE " << p->name << "[" << p->pid << "]" << std::endl;
	free_osiproc(p);
	return 0;
}


bool init_plugin(void *self) {
	std::cout << DEBUG_PREFIX "initializing" << std::endl;
#ifdef TARGET_I386
	panda_cb pcb;
	panda_arg_list *args = panda_get_args("file_taint_sink");

	const gchar *sink_str = panda_parse_string(args, "sink", NULL);
	if (sink_str != NULL) {
		// use "+" to delimit filenames (most other delimiters are already in use)
		gchar **sink_lst = g_strsplit_set(sink_str, "+", -1);
		for (gchar **s=sink_lst; *s!=NULL; s++) {
			fts.sinks.insert(*s);
		}
		g_strfreev(sink_lst);
	}
	else {
		fts.track_all = true;
	}

	fts.debug = false;

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
			PPP_REG_CB("syscalls2", on_sys_open_return, linux_open_return);
		break;

		case OST_UNKNOWN:
			std::cerr << DEBUG_PREFIX "you must use '-os os_name' argument to specify the guest os" << std::endl;
			return false;
		break;

		default:
			std::cerr << DEBUG_PREFIX "the specified guest os is not supported" << std::endl;
			return false;
		break;
	}
	panda_require("taint2");
	assert(init_taint2_api());

	//pcb.before_block_exec = block_exec_cb;
	//panda_register_callback(self, PANDA_CB_BEFORE_BLOCK_EXEC, pcb);

	pcb.after_PGD_write = asid_change_cb;
	panda_register_callback(self, PANDA_CB_VMI_PGD_CHANGED, pcb);

	//panda_free_args(panda_arg_list *args);
	//release memory allocated by panda_get_args

	return true;
#else
	std::cerr << DEBUG_PREFIX "only i386 target is supported" << std::endl;
	return false;
#endif
}

//char *f = osi_linux_fd_to_filename(env, &ps, fd);
//uint64_t pos = osi_linux_fd_to_pos(env, &ps, fd);

void uninit_plugin(void *self) {
}

/* vim:set tabstop=4 softtabstop=4 noexpandtab */
