#include "osi_proc_events.h"

extern "C" {
#include <osi_int_fns.h>
}

#include <glib.h>
#include <string.h>
#include <algorithm>
#include <iterator>
#include <set>
#include <map>

/*! @brief The global process state. */
ProcState pstate;

/*! @brief Constructor. */
ProcState::ProcState(void) {
	this->pid_set = new PidSet();
	this->proc_map = new ProcMap();
	return;
}

/*! @brief Destructor. */
ProcState::~ProcState(void) {
	if (this->pid_set != NULL) delete this->pid_set;
	if (this->proc_map != NULL) delete this->proc_map;

	// This destructor is called at the end of the replay.
	// Calling free_osiprocs() may cause a segfault at that point.
	// Use the generic free macro instead.
	FREE_OSIPROCS_GENERIC(this->ps);
}

/*! @brief Gets a subset of the processes in `ProcMap`. */
OsiProcs *ProcState::OsiProcsSubset(ProcMap *m, PidSet *s) {
	int notfound = 0;
	OsiProcs *ps = (OsiProcs *)g_malloc0(sizeof(OsiProcs));

	// ProcState::OsiProcCopy attempts to free OsiProc members.
	// ps->proc array must be zeroed-out to avoid this.
	ps->proc = g_new0(OsiProc, s->size());

	for (auto it=s->begin(); it!=s->end(); ++it) {
		auto p_it = m->find(*it);
		if (unlikely(p_it == m->end())) {
			notfound++;
			continue;
		}
		ProcState::OsiProcCopy(p_it->second, &ps->proc[ps->num++]);
	}

	if (ps->num == 0) goto error;

	// XXX: Log a warning if notfound > 0.
	return ps;
	
error:
	free_osiprocs(ps);
	return NULL;
}

/*! @brief Copies an OsiProc struct. */
OsiProc *ProcState::OsiProcCopy(OsiProc *from, OsiProc *to) {
	if (from == NULL || to == NULL) goto error;

	// destination struct is expected to be either valid or zeroed-out
	g_free(to->name);
	g_free(to->pages);

	memcpy(to, from, sizeof(OsiProc));
	to->name = g_strdup(from->name);
	to->pages = NULL; // OsiPage - TODO
	return to;

error:
	return NULL;
}

/*! @brief Updates the ProcState with the new process set.
 * If `in` and `out` are not NULL, the new and finished processes
 * will be returned through them.
 * 
 * @note For efficiency, the passed `ps` becomes part of the
 * ProcState and must not be freed by the caller.
 */
void ProcState::update(OsiProcs *ps, OsiProcs **in, OsiProcs **out){
	PidSet *pid_set_new = new PidSet();
	ProcMap *proc_map_new = new ProcMap();

	// copy data to c++ containers
	for (unsigned int i=0; i<ps->num; i++) {
		OsiProc *p = &ps->proc[i];
		target_ulong pid = p->pid;

		pid_set_new->insert(pid);
		auto ret = proc_map_new->insert(std::make_pair(pid, p));

		// ret type is pair<iterator, bool>
		if (!ret.second) {
			printf("DUP %d\n", (int)pid);
		}
	}

	// extract OsiProcs
	if (likely(in != NULL && out != NULL)) {
		// free old data
		if (*in != NULL) free_osiprocs(*in);
		if (*out != NULL) free_osiprocs(*out);

		// find the pids of incoming/outgoing process
		PidSet pid_in, pid_out;
		std::set_difference(
			pid_set_new->begin(), pid_set_new->end(),
			this->pid_set->begin(), this->pid_set->end(),
			std::inserter(pid_in, pid_in.begin())
		);
		std::set_difference(
			this->pid_set->begin(), this->pid_set->end(),
			pid_set_new->begin(), pid_set_new->end(),
			std::inserter(pid_out, pid_out.begin())
		);

		*in = ProcState::OsiProcsSubset(proc_map_new, &pid_in);
		*out = ProcState::OsiProcsSubset(this->proc_map, &pid_out);
	}

	// update ProcState
	delete this->pid_set;
	delete this->proc_map;
	free_osiprocs(this->ps);
	this->pid_set = pid_set_new;
	this->proc_map = proc_map_new;
	this->ps = ps;

	return;
}

/*!
 * @brief C wrapper for updating the global process state.
 */
void procstate_update(OsiProcs *ps, OsiProcs **in, OsiProcs **out) {
	pstate.update(ps, in, out);
}

