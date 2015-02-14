#ifndef OS_INTRO_H
#define OS_INTRO_H
#include <glib.h>

typedef void (*on_get_processes_t)(CPUState *, OsiProcs **);
typedef void (*on_get_current_process_t)(CPUState *, OsiProc **);
typedef void (*on_get_modules_t)(CPUState *, OsiModules **);
typedef void (*on_get_libraries_t)(CPUState *, OsiProc *, OsiModules**);
typedef void (*on_free_osiproc_t)(OsiProc *p);
typedef void (*on_free_osiprocs_t)(OsiProcs *ps);
typedef void (*on_free_osimodules_t)(OsiModules *ms);
#ifdef OSI_PROC_EVENTS
typedef void (*on_new_process_t)(CPUState *, OsiProc *);
typedef void (*on_finished_process_t)(CPUState *, OsiProc *);
#endif 

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
