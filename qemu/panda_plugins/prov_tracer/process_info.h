#ifndef PROCESSINFO_H
#define PROCESSINFO_H

class FileInfo {
	public:
		FileInfo(char *name);

		std::string name;
		bool written = false;
		bool read = false;
};
typedef std::unordered_map<int, FileInfo *> FDMap;


/**
 * @brief Wrapper class for ongoing system calls.
 */
class SyscallInfo {
	public:
		SyscallInfo(CPUState *env);
		//~SyscallInfo();
		std::ostream& dump(std::ostream& o) const;
		std::string str() const;
		const char *c_str() const;
		const char *get_name() const;

		int nr;
		union syscall_arg args[SYSCALL_MAXARGS];
};

/**
 * @brief Overload << operator for SyscallInfo.
 */
static inline std::ostream& operator<<(std::ostream &o, SyscallInfo const &s) { return s.dump(o); }
static inline std::ostream& operator<<(std::ostream &o, SyscallInfo const *s) { return s->dump(o); }


class ProcInfo {
	public:
		ProcInfo(OsiProc *p);
		~ProcInfo();

		OsiProc p;				/**< OsiProc struct. */
		bool is_fresh = true;	/**< Process is still "fresh". */
		FDMap fd;
		SyscallInfo *syscall = NULL;

	private:

};
typedef std::unordered_map<target_ulong, ProcInfo *> ProcInfoMap;

extern ProcInfoMap pimap;
#endif
