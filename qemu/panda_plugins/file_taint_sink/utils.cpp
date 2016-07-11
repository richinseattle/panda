#define __STDC_FORMAT_MACROS

extern "C" {
#include "qemu-common.h"
#include "cpu.h"
#include "panda_common.h"
#include "panda_plugin.h"
#include "panda_addr.h"

}
#include "file_taint_sink.h"
#include <glib.h>
#include <iostream>

uint32_t guest_strncpy(CPUState *env, char *buf, size_t maxlen, target_ulong guest_addr) {
	buf[0] = 0;
	unsigned i;
	for (i=0; i<maxlen; i++) {
		uint8_t c;
		panda_virtual_memory_rw(env, guest_addr+i, &c, 1, 0);
		buf[i] = c;
		if (c==0) {
			break;
		}
	}
	buf[maxlen-1] = 0;
	return i;
}

uint32_t guest_wstrncpy(CPUState *env, char *buf, size_t maxlen, target_ulong guest_addr) {
	buf[0] = 0;
	unsigned i;
	for (i=0; i<maxlen; i++) {
		panda_virtual_memory_rw(env, guest_addr + 2 * i, (uint8_t *)&buf[i], 1, 0);
		if (buf[i] == 0) {
			break;
		}
	}
	buf[maxlen-1] = 0;
	return i;
}

// TODO: Convert make_*addr functions from taint_processor.cpp to inlines in panda_addr.h.
Addr make_maddr(uint64_t a) {
	Addr ma;
	ma.typ = MADDR;
	ma.val.ma = a;
	ma.off = 0;
	ma.flag = (AddrFlag) 0;
	return ma;
}

// ProcessState implementation
ProcessState::ProcessState(OsiProc *p, bool copy) {
	std::cout << "new instance " << std::hex << this << std::endl;
	if (copy) {
		this->p = (OsiProc *)g_malloc0(sizeof(OsiProc));
		copy_osiproc_g(p, this->p);
	}
	else {
		this->p = p;
	}
	this->fresh = true;
}
ProcessState::~ProcessState() {
	free_osiproc_g(this->p);
	this->p = NULL;
}
bool ProcessState::refresh(OsiProc *p) {
	if (! this->fresh) return false;

	g_free(this->p->name);
	this->p->name = g_strdup(p->name);
	this->fresh = false;
	return true;
}

