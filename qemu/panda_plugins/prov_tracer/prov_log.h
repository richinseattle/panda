#ifndef PROVLOG_H
#define PROVLOG_H
#include "prov_tracer.h"

/* min/max macros for general use */
#if !defined(MIN)
#define MIN(a,b) (((a)<(b))?(a):(b))
#endif
#if !defined(MAX)
#define MAX(a,b) (((a)>(b))?(a):(b))
#endif

/* macros related to stdin/stdout/stderr */
#define STDFD_MAX ( MAX( MAX(STDIN_FILENO, STDOUT_FILENO), STDERR_FILENO ) + 1 )
#define IS_STDFD(fd) ( (fd == STDOUT_FILENO) || (fd == STDIN_FILENO) || (fd == STDERR_FILENO) )


typedef uint32_t ufd_t;
#if 0
/**** data types and externals ************************************/

/* Array that maps fds to ufds. */
typedef struct {
    std::array<ufd_t, MAX_OPEN_FILES> map;
    ufd_t next = 1;
    decltype(map[0]) get(int fd){ if (map[fd]==0) map[fd] = next++; return map[fd]; }
    void del(int fd) { map[fd] = 0; }
} ufdmap_t;
extern ufdmap_t ufdmap;

/* Counters for stdin/stdout/stderr. */
extern off_t stdcount[STDFD_MAX];
#endif


/**** output macros and inlines ***********************************/

/* inline functions for raw provenance logging */
static inline void PROVLOG_OPEN(const TARGET_PTR asid, const char *filename, const int flags) {
#if 0
#endif
}
static inline void PROVLOG_READ(const TARGET_PTR asid, const char *filename) {

}
static inline void PROVLOG_WRITE(const TARGET_PTR asid, const char *filename) {

}
	
	//prov_out << "o:" << asid << ":" << filename << std::endl;
#if 0
	// Unless the the O_WRONLY flag is on, the file descriptor can be read.
	if (! (flags&O_WRONLY) )
		prov_out << "u:" << "the real exename"  << ":" << fdname << std::endl;
	
	// Emit a generated line if needed.
#endif
static inline void PROVLOG_CLOSE(const ufd_t ufd) {
	prov_out << "c:ufd" << ufd << std::endl;
}
static inline void PROVLOG_EXEC(const ProcInfo *pi) {
	prov_out << "x:" << pi->p.asid << ":" << pi->p.pid << std::endl;
}
static inline void PROVLOG_QUIT(const ProcInfo *pi) {
	prov_out << "q:" << pi->p.asid << ":" << pi->p.pid << ":" << pi->p.name << std::endl;
}
#endif
