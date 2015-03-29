#ifndef PROCESSINFO_H
#define PROCESSINFO_H
extern "C" {
#include "../osi/osi_types.h"		/**< Introspection data types. */
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

		int flags;
		unsigned int written;
		unsigned int read;

		bool flag_set(char c) const;
		char *get_name() const;
		char *get_name_escaped() const;

	private:
		char *name;
		char *name_escaped;
		void update_escaped();
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

		OsiProc p;				/**< OsiProc struct. */
		bool is_fresh;			/**< Process is still "fresh". */
		FDMap fmap;
		FileInfoVector fhist;

	private:
		bool logged;
		SyscallInfo *syscall;

};
typedef std::unordered_map<target_ulong, ProcInfo *> ProcInfoMap;

extern ProcInfoMap pimap;
#endif
