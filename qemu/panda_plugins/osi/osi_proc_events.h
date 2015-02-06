#ifndef OSI_PROC_EVENTS_H
#define OSI_PROC_EVENTS_H

#ifdef __cplusplus
extern "C" {
#endif

#include "config.h"
#include "qemu-common.h"
#include "osi_types.h"

#ifdef __cplusplus
}
#endif

/*!
 * @brief Branch prediction hint macros.
*/
#define likely(x)       __builtin_expect(!!(x), 1)
#define unlikely(x)     __builtin_expect(!!(x), 0)

#ifdef __cplusplus
#include <set>
#include <unordered_map>
typedef std::set<target_ulong> PidSet;
typedef std::unordered_map<target_ulong, OsiProc *> ProcMap;

class ProcState {
	public:
		ProcState();
		~ProcState();
		void update(OsiProcs *ps);
		void update(OsiProcs *ps, OsiProcs **in, OsiProcs **out);

	private:
		PidSet *pid_set = NULL;
		ProcMap *proc_map = NULL;
		static OsiProcs *OsiProcsSubset(ProcMap *, PidSet *);
		static OsiProc *OsiProcCopy(OsiProc *from, OsiProc *to);
	
};
#else
typedef struct ProcState ProcState;
#endif



#ifdef __cplusplus
extern "C" {
#endif

extern ProcState pstate;

/*!
 * @brief C wrapper for updating the global process state.
 */
void procstate_update(OsiProcs *);
#ifdef __cplusplus
}
#endif

#endif
