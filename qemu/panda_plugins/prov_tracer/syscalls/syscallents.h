#ifndef __SYSCALLENTS_H__
#define __SYSCALLENTS_H__

#define SYSCALL_MAXARGS 6
#define SYSCALL_STRSAMPLE_LEN 128

enum prov_tracer_syscall {
	SYSCALL_OTHER = -1,
	SYSCALL_READ = 0,
	SYSCALL_WRITE,
	SYSCALL_OPEN,
	SYSCALL_CLOSE,
	SYSCALL_CLONE,
	SYSCALL_EXECVE,
	SYSCALL_LINK,
	SYSCALL_UNLINK,

	SYSCALL_STAT,
	SYSCALL_FSTAT,
	SYSCALL_LSTAT,
	SYSCALL_POLL,
	SYSCALL_LSEEK,
	SYSCALL_MMAP
};

enum syscall_argtype {
	SYSCALL_ARG_INT,
	SYSCALL_ARG_PTR,
	SYSCALL_ARG_STR
};

struct syscall_entry {
	enum prov_tracer_syscall nr;
	const char *name;
	int nargs;
	enum syscall_argtype args[SYSCALL_MAXARGS];
};

#ifdef TARGET_PTR
union syscall_arg {
	int intval;
	TARGET_PTR pval;
	char *sval;
	uint8_t *buf;
};
#endif

#endif

/* vim:set tabstop=4 softtabstop=4 noexpandtab */
