#ifndef PROCESSINFO_H
#define PROCESSINFO_H
/*
 * See Google's C++ style guide for style suggestions.
 * http://google-styleguide.googlecode.com/svn/trunk/cppguide.html#Variable_Names
 */

extern "C" {
#include "../osi/osi_types.h"			/**< Introspection data types. */
#include "syscalls/syscallents.h"
}
#include <glib.h>
#include <unordered_map>
#include <vector>

class FileInfo;
class SyscallInfo;
class ProcInfo;

class FileInfo {
	public:
		FileInfo(char *name, int flags);
		~FileInfo();

		char *name() const;
		char *name_escaped() const;
		int flags() const;
		bool test_flags(char c) const;
		uint64_t written() const;
		uint64_t read() const;
		uint64_t inc_written(uint64_t n);
		uint64_t inc_read(uint64_t n);
		uint64_t first_read_ts() const;
		uint64_t last_write_ts() const;

		std::string repr() const;

	private:
		char *name_;
		char *name_escaped_;
		int flags_;
		uint64_t written_;
		uint64_t read_;
		uint64_t first_read_ts_;
		uint64_t last_write_ts_;

		void update_name_escaped();
};
typedef std::unordered_map<int, FileInfo *> FDMap;
typedef std::vector<FileInfo *> FileInfoVector;


/**
 * @brief Wrapper class for ongoing system calls.
 */
class SyscallInfo {
	public:
		SyscallInfo(ProcInfo *pi, CPUState *env);		// XXX: Do we need ProcInfo???
		std::ostream& dump(std::ostream& o) const;		/*< Dumps a string representation of the syscall on stream `o`. */
		std::string str() const;						/*< Returns a string representation of the syscall, without showing a potential return value. */
		std::string str(bool include_rval) const;		/*< Returns a string representation of the syscall, which may also include the return value. */

		const char *get_name() const;
		union syscall_arg get_arg(int n, size_t sz) const;	/*< Returns the value of a syscall argument, depending on its type. Strings/buffers have to be freed. */
		int get_ret() const;

		int nr;

	private:
		union syscall_arg args[SYSCALL_MAXARGS];
		ProcInfo *pi = NULL;
		CPUState *env = NULL;	/**< Pointer to the CPUState, used for extracting string arguments from memory. */
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
		std::string label() const;
		void syscall_start(CPUState *env);
		void syscall_end(CPUState *env);
		uint64_t started_pts() const;
		uint64_t ended_pts() const;

		OsiProc p;				/**< OsiProc struct. */
		bool is_fresh;			/**< Process is still "fresh". */
		FDMap fmap;
		FileInfoVector fhist;

	private:
		bool logged;
		uint64_t started_pts_;
		uint64_t ended_pts_;
		SyscallInfo *syscall;
};
typedef std::unordered_map<target_ulong, ProcInfo *> ProcInfoMap;

extern ProcInfoMap pimap;
#endif

/* vim:set tabstop=4 softtabstop=4 noexpandtab */
