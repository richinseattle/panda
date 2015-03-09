#ifndef __OSI_INT_FNS_H__
#define __OSI_INT_FNS_H__

// returns operating system introspection info for each process in an array
OsiProcs *get_processes(CPUState *env);

// gets the currently running process
OsiProc *get_current_process(CPUState *env);

// returns operating system introspection info for each kernel module currently loaded
OsiModules *get_modules(CPUState *env);

// returns operating system introspection info for each userspace loaded library in the specified process
// returns the same type as get_modules
OsiModules *get_libraries(CPUState *env, OsiProc *p);

// Free memory allocated by other library functions
void free_osiproc(OsiProc *p);
void free_osiprocs(OsiProcs *ps);
void free_osimodules(OsiModules *ms);

/*
 * Generic inlines for handling OsiProc, OsiProcs structs.
 * It is left to the OS-specific modules to use them or not.
 */

/*! @brief Frees an OsiProc struct. */
static inline void free_osiproc_g(OsiProc *p) {
	if (p == NULL) return;
	g_free(p->name);
	g_free(p);
	return;
}

/*! @brief Frees an OsiProcs struct. */
static inline void free_osiprocs_g(OsiProcs *ps) {
	uint32_t i;
	if (ps == NULL) return;
	for (i=0; i< ps->num; i++) {
		g_free(ps->proc[i].name);
	}
	g_free(ps->proc);
	g_free(ps);
	return;
}

/*! @brief Copies an OsiProc struct. Returns a pointer to the destination location.
 *
 * @note Members of `to` struct must have been freed to avoid memory leaks.
 */
static inline OsiProc *copy_osiproc_g(OsiProc *from, OsiProc *to) {
	if (from == NULL) return NULL;
	if (to == NULL) to = (OsiProc *)g_malloc0(sizeof(OsiProc));

	memcpy(to, from, sizeof(OsiProc));
	to->name = g_strdup(from->name);
	to->pages = NULL; // OsiPage - TODO
	return to;
}

#endif
