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
 * Generic macros for freeing OsiProc, OsiProcs structs.
 * It is left to the OS-specific modules to use them or not.
 */
#define FREE_OSIPROC_GENERIC(p)		do {\
	if (p == NULL) break;\
	g_free(p->name);\
	g_free(p);\
} while(0)
#define FREE_OSIPROCS_GENERIC(ps)	do {\
	uint32_t i;\
	if (ps == NULL) break;\
	for (i=0; i< ps->num; i++) {\
		g_free(ps->proc[i].name);\
	}\
	g_free(ps->proc);\
	g_free(ps);\
} while(0)

#endif
