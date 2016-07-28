#define __STDC_FORMAT_MACROS
#include "platform.h"
#include "prov_tracer.h"
extern "C" {
#include "config.h"
#include "qemu-common.h"
#include "cpu.h"
}
#include <iomanip>
#include <sstream>

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

