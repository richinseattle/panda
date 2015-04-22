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
static inline void PROVLOG_COMMENT(const std::string s) {
	prov_out << "# " << s << std::endl;
}
static inline void PROVLOG_EXEC(const ProcInfo *pi) {
	prov_out << "x:" << pi->p.asid << ":" << pi->label() << std::endl;
}
static inline void PROVLOG_QUIT(const ProcInfo *pi) {
	prov_out << "q:" << pi->p.asid << ":" << pi->label() << ":"
		<< pi->started_pts() << ":" << pi->ended_pts()
	<< std::endl;
}
static inline void PROVLOG_P2F(const ProcInfo *pi, const FileInfo *fi, const char mode) {
	switch(mode) {
		case 'g':
			prov_out << "g:"
				<< pi->p.asid << ":" << pi->label() << ":"
				<< fi->name_escaped() << ":" << fi->written()
			<< std::endl;
		break;
		case 'u':
			prov_out << "u:"
				<< pi->p.asid << ":" << pi->label() << ":"
				<< fi->name_escaped() << ":" << fi->read()
			<< std::endl;
		break;
		default:
			prov_out << "# unused file:"
				<< pi->p.asid << ":" << pi->label() << ":" << fi->name_escaped() 
				<< ":r" << fi->read() << ":w" << fi->written() << ":f" << fi->flags()
			<< std::endl;
		break;
	}
}
static inline void PROVLOG_F2F(const ProcInfo *pi, const FileInfo *fi1, const FileInfo *fi2, const char mode) {
	switch(mode) {
		case 'd':
			prov_out << "d:" << fi1->name_escaped() << ":" << fi2->name_escaped() << std::endl;
		break;

		default:
			prov_out << "# dcomment:" << fi1->name_escaped() << ":" << fi2->name_escaped() << std::endl;
		break;
	}
}
#endif

/* vim:set tabstop=4 softtabstop=4 noexpandtab */
