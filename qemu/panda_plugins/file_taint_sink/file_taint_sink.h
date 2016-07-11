#ifndef _FILETAINT_SINK_H_
#define _FILETAINT_SINK_H_
#define __STDC_FORMAT_MACROS

extern "C" {
#include "panda_addr.h"
#include "osi_types.h"

// PANDA signatures that use C linkage.
bool init_plugin(void *);
void uninit_plugin(void *);
}

#include <set>
#include <unordered_map>

// Signatures for utils.cpp.
uint32_t guest_strncpy(CPUState *env, char *buf, size_t maxlen, target_ulong guest_addr);
uint32_t guest_wstrncpy(CPUState *env, char *buf, size_t maxlen, target_ulong guest_addr);
Addr make_maddr(uint64_t a); // also in taint2.h and taint_processor.cpp

#define PP_NAME "file_taint_sink"
#define LOG_PREFIX PP_NAME ": "
#define DEBUG_PREFIX std::dec << __FILE__ << ":" << __FUNCTION__ << ":" << __LINE__ << ": "

// process state and asid map
class ProcessState {
public:
	ProcessState(OsiProc *p, bool copy=false);
	~ProcessState();
	bool refresh(OsiProc *p);

	OsiProc *p;
	bool fresh;

private:
};

// set of asids
typedef std::set<target_ulong> AsidSet;

// maps asid to process state
typedef std::unordered_map<target_ulong, ProcessState*> ProcessStateMap;
#endif
