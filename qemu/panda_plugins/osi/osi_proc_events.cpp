#include "osi_proc_events.h"

#include <string.h>
#include <osi_int.h>
#include <algorithm>
#include <iterator>
#include <set>
#include <map>

/*! @brief The global process state. */
ProcState pstate;


/*! @brief Constructor. */
ProcState::ProcState(void) {
	// nothing
	return;
}

/*! @brief Destructor. */
ProcState::~ProcState(void) {
	if (this->pid_set != NULL) delete this->pid_set;
	if (this->proc_map != NULL) delete this->proc_map;
}

/*! @brief Gets a subset of the processes in `ProcMap`. */
OsiProcs *ProcState::OsiProcsSubset(ProcMap *m, PidSet *s) {
	int notfound = 0;
	OsiProcs *ps = (OsiProcs *)g_malloc0(sizeof(OsiProcs));
	ps->proc = g_new(OsiProc, s->size());

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
	if (in != NULL && out != NULL) {
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

	// update

	return;
}

void procstate_update(OsiProcs *ps) {
	pstate.update(ps, NULL, NULL);
}


