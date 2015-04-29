//
// The plugin attributes a value identified by stringsearch to a process.
// To get the plugin working, your plugin pipeline should look like this:
//	-panda 'osi;osi_linux;callstack_instr;stringsearch;psstrmatch'
//	

#include "psstrmatch.h"
extern "C" {
#include "config.h"
#include "qemu-common.h"
#include "cpu.h"

#include "panda_plugin.h"
#include "panda_plugin_plugin.h"

// Plugins with C linkage.
#include "../osi/osi_types.h"		/**< Introspection data types. */
#include "../osi/osi_ext.h"			/**< Introspection API. */
#include "../osi/os_intro.h"		/**< Introspection callbacks. */

// C headers.
#include <stdio.h>
#include <glib.h>
#include <dlfcn.h>
#include <ctype.h>
#include <strings.h>
#include <errno.h>

// QEMU/PANDA functions with C linkage.
bool init_plugin(void *);
void uninit_plugin(void *);
}

// C++ headers.
#include <iostream>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <unordered_map>

// Plugins with C++ linkage.
#include "../stringsearch/stringsearch.h"			/**< String search plugin. */

// Globals.
typedef std::unordered_map<target_ulong, OsiProc *> OsiProcMap;
OsiProcMap pmap;
std::ofstream ttlout;

// String match callback.
void on_ssm(CPUState *env, target_ulong pc, target_ulong addr, uint8_t *matched_string, uint32_t matched_string_lenght, bool is_write) {
	auto asid_physical = _PGD;
	auto p_it = pmap.find(asid_physical);
	EXIT_ON_ERROR(p_it == pmap.end(), "No process match.");

	OsiProc *p = (*p_it).second;

	// Write ttl.
	if (ttlout.is_open()) {
		ttlout << "<exe://" << p->name << "~" << p->pid << "> "
			<< ":hasMemText" << " \"" << (char *)matched_string << "\" ."
			<< std::endl;
	}

	// Write stdout log.
	std::cout << PLUGIN_NAME << ":" << p->name << "(" << p->pid << "):"
		<< (is_write ? 'w' : 'r') << ":" << (char *)matched_string
		<< std::endl;
}

// PGD write callback.
int vmi_pgd_changed(CPUState *env, target_ulong oldval, target_ulong newval) {
	OsiProc *p = get_current_process(env);
	EXIT_ON_ERROR(p == NULL, "Couldn't get process on PGD write.");

	auto asid_physical = panda_virt_to_phys(env, p->asid);
	auto p_it = pmap.find(asid_physical);

	if (p_it != pmap.end()) {
		free_osiproc((*p_it).second);
		(*p_it).second = NULL;
		pmap.erase(p_it);
	}

	auto inserted = pmap.insert(std::make_pair(asid_physical, p));
	EXIT_ON_ERROR(inserted.second == false, "WTF?");

	return 0;
}

bool init_plugin(void *self) {
	// retrieve plugin arguments
	panda_arg_list *plugin_args = panda_get_args(PLUGIN_NAME);
	const char *ttlout_f = panda_parse_string(plugin_args, "ttl", NULL);
	if (ttlout_f) {
		ttlout.open (ttlout_f);
		EXIT_ON_ERROR(ttlout.is_open() == false, "Couldn't open %s for writing ttl.", ttlout_f);
		ttlout << "@prefix dt: <http://https://m000.github.com/ns/v1/desktop#> ." <<  std::endl;
	}
	if (plugin_args != NULL) panda_free_args(plugin_args);

	// Initialize osi API.
	if (!init_osi_api()) {
		LOG_ERROR("OSI API failed to initialize.");
		goto error1;
	}

	// Register stringsearch callback.
	PPP_REG_CB("stringsearch", on_ssm, on_ssm);

	// Register callback on PGD write.
	panda_cb pcb;
	pcb.after_PGD_write = vmi_pgd_changed;
	panda_register_callback(self, PANDA_CB_VMI_PGD_CHANGED, pcb);

	return true;

error1:
	return false;
}

void uninit_plugin(void *self) {
	if (ttlout.is_open()) { ttlout.close(); }
}

/* vim:set tabstop=4 softtabstop=4 noexpandtab */
