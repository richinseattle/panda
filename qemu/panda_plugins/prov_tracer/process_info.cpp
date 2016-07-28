#include "platform.h"
#include "prov_tracer.h"
extern "C" {
#include "config.h"
#include "qemu-common.h"
#include "cpu.h"
#include "rr_log.h"			/**< Replay instruction count. */
}
#include <iostream>
#include <sstream>
#include <iomanip>

#include "accounting.h"
#include "prov_log.h"						/**< Macros for logging raw provenance. */

extern "C" {
extern struct syscall_entry *syscalls;	  /**< Syscalls info table. */
#include "../osi_linux/osi_linux_ext.h"	/**< Linux specific introspection API. */
}

// *******************************************************************
// Initialization of other plugin APIs called in this source file.
// *******************************************************************
void EXTERN_API_INIT_process_info() {
	if (!init_osi_linux_api()) {
		LOG_ERROR("OSI Linux API failed to initialize in " __FILE__ ".");
	}
	else{
		LOG_INFO("OSI Linux API initialized in " __FILE__ ".");
	}
}

// *******************************************************************
// ProcInfo definitions
// *******************************************************************
ProcInfo::ProcInfo(OsiProc *p) {
	copy_osiproc_g(p, &this->p);
	this->syscall = NULL;
	this->is_fresh = true;
	this->logged = false;
	this->started_pts_ = rr_get_guest_instr_count();
	this->ended_pts_ = 0;

	// Don't log exec here. Process is still fresh.
	//PROVLOG_EXEC(this);
}

ProcInfo::~ProcInfo(void) {
	this->ended_pts_ = rr_get_guest_instr_count();

	// Move currently open files to history.
	for (auto fdpair=this->fmap.begin(); fdpair!=this->fmap.end(); ++fdpair) {
		this->fhist.push_back( (*fdpair).second );
		// cannot .erase() here - iterator will be invalidated
	}
	this->fmap.clear();

	// Dump provenance for files.
	for (auto f_it=this->fhist.begin(); f_it!=this->fhist.end(); ++f_it) {
		// Dump process-file provenance relations.
		auto f = *f_it;
		bool fw = (f->test_flags('w') && (f->written() > 0));
		bool fr = (f->test_flags('r') && (f->read() > 0));

		if (f->test_flags('t')) {
			PROVLOG_P2F(this, f, 'g');
		}
		else if (fw) {
			PROVLOG_P2F(this, f, 'g');
		}
		else if (fr) {
			PROVLOG_P2F(this, f, 'u');
		}
		else {
			PROVLOG_P2F(this, f, '#');
		}

		for (auto g_it=this->fhist.begin(); g_it!=this->fhist.end(); ++g_it) {
			// Dump file-file provenance relations.
			auto g = *g_it;
			//bool gw = (g->test_flags('w') && (g->written() > 0));
			bool gr = (g->test_flags('r') && (g->read() > 0));

			// Comment the following line to produce a derivation edge
			// to itself for each file that was both read from and written to.
			if (*g_it == *f_it) { continue; }

			// Add derivation edges.
			// Emit a derivation edge only when the last write on a file is
			// after the first read from the other file.
			if (fw && gr && (f->last_write_ts() > g->first_read_ts())) {
				PROVLOG_F2F(this, f, g, 'd');
				LOG_INFO("%s(w@%" PRId64 ") wasDerivedFrom %s(r@%" PRId64 ")",
					f->name(), f->last_write_ts(),
					g->name(), g->first_read_ts()
				);
			}
		}
	}

	// Cleanup file history.

	PROVLOG_QUIT(this);
	g_free(this->p.name);
	if (this->syscall != NULL) delete this->syscall;
}

/*!
 * @brief Returns the process start pseudo-timestamp.
 */
uint64_t ProcInfo::started_pts() const { return this->started_pts_; }

/*!
 * @brief Returns the process finish pseudo-timestamp.
 */
uint64_t ProcInfo::ended_pts() const { return this->ended_pts_; }

std::string ProcInfo::label() const {
	std::ostringstream ss;
	ss << this->p.name << '~' << this->p.pid << (this->is_fresh ? "*" : "");
	return ss.str();
}

void ProcInfo::syscall_start(CPUState *env) {
#if defined(TARGET_I386)
	if (unlikely(this->syscall != NULL)) {
		LOG_WARN("%s: \"%s\" was pending when \"%s\" (" TARGET_FMT_ld ") started!",
			this->label().c_str(), this->syscall->get_name(),
			SyscallInfo(this, env).get_name(), env->regs[R_EAX]
		);
		delete this->syscall;
	}
	this->syscall = new SyscallInfo(this, env);
#endif
}

void ProcInfo::syscall_end(CPUState *env) {
#if defined(TARGET_I386)
	if (unlikely(this->syscall == NULL)) {
		// This may occur at the beginning of replay.
		LOG_INFO("%s: Unknown syscall completed.", this->label().c_str());
		return;
	}

	LOG_INFO("%s: syscall completed: %s", this->label().c_str(), this->syscall->str(true).c_str());

	int rval = this->syscall->get_ret();
	union syscall_arg arg;
	int nr = syscalls[this->syscall->nr].nr;

	// Emit provenance for program here.
	// This has two benefits:
	//	a. The program name has been updated (i.e. is_fresh is false).
	//	b. Programs that don't make any system calls will not be reported.
	if (!this->logged && !this->is_fresh) {
		PROVLOG_EXEC(this);
		this->logged = true;
	}

	// Handle cases based on the prov_tracer specific nr.
	// Using this custom nr is meant to simplify handling.
	// For open/close, only FileInfo entries are created.
	// Actual provenance is dumped when process exits.
	switch(nr) {
	case SYSCALL_OPEN:
	{
		// Check return status.
		if (unlikely(rval < 0)) break;

		// Retrieve filename by resolving fd. This will yield
		// the full path of files, vs the argument supplied
		// to open().
		char *filename = osi_linux_fd_to_filename(env, &(this->p), rval);
		if (filename == NULL) {
			filename = g_strdup_printf("(%d|fd%d)", (int)(&(this->p))->pid, rval);
		}

		// Retrieve arguments.
		//arg = this->syscall->get_arg(0, 128);
		//PERMIT_UNUSED char *filename = arg.sval;
		arg = this->syscall->get_arg(1, 0);
		PERMIT_UNUSED int flags = arg.intval;
		//arg = this->syscall->get_arg(2, 0);
		//PERMIT_UNUSED int mode = arg.intval;

		// Check for existing mapping for fd.
		// This may (?) happen if fd closed due to an error.
		auto fdpair = this->fmap.find(rval);
		if (unlikely(fdpair != this->fmap.end())) {
			LOG_WARN("%s: fd%d is already mapped to %s.", this->label().c_str(), rval, (*fdpair).second->name());
			this->fhist.push_back( (*fdpair).second );
			this->fmap.erase(fdpair);
		}

		// Add new fd mapping.
		this->fmap.insert(std::make_pair(rval, new FileInfo(filename, flags)));
	}
	break;

	case SYSCALL_CLOSE:
	{
		// Check return status.
		if (unlikely(rval < 0)) break;

		// Retrieve arguments.
		arg = this->syscall->get_arg(0, 0);
		PERMIT_UNUSED int fd = arg.intval;

		// Move file to history.
		auto fdpair = this->fmap.find(fd);
		if (unlikely(fdpair == this->fmap.end())) {
			LOG_WARN("%s: no mapping found for fd%d during %s. Ignoring fd%d.",
				this->label().c_str(), fd, this->syscall->get_name(), fd
			);
			break;
		}
		this->fhist.push_back( (*fdpair).second );
		this->fmap.erase(fdpair);
	}
	break;

	case SYSCALL_READ:
	case SYSCALL_WRITE:
	{
		// Check return status.
		if (unlikely(rval <= 0)) break;

		// Retrieve arguments.
		arg = this->syscall->get_arg(0, 0);
		PERMIT_UNUSED int fd = arg.intval;
		//arg = this->syscall->get_arg(1, 128);
		//PERMIT_UNUSED uint8_t *buf = arg.buf;
		//g_free(buf);
		arg = this->syscall->get_arg(2, 0);
		PERMIT_UNUSED int count = arg.intval;

		// Retrieve FileInfo.
		auto fdpair = this->fmap.find(fd);
		if (unlikely(fdpair == this->fmap.end())) {
			char *filename = osi_linux_fd_to_filename(env, &(this->p), fd);
			if (filename == NULL) {
				filename = g_strdup_printf("(%d|fd%d)", (int)(&(this->p))->pid, fd);
			}

			LOG_WARN("%s: no mapping for fd%d during %s - creating one to %s.",
				this->label().c_str(), fd, this->syscall->get_name(), filename
			);

			int flags;
			switch(fd) {
				case 0: flags = O_RDONLY; break;
				case 1: flags = O_WRONLY; break;
				case 2: flags = O_WRONLY; break;
				default: flags = (nr == SYSCALL_WRITE) ? O_RDWR : O_RDONLY; break;
			}
			auto fdpair_ins = this->fmap.insert(std::make_pair(fd, new FileInfo(filename, flags)));
			fdpair = fdpair_ins.first;
		}

		// Increase the proper counter for the file.
		if (nr == SYSCALL_READ)
			(*fdpair).second->inc_read(rval);
		else if (nr == SYSCALL_WRITE)
			(*fdpair).second->inc_written(rval);
		else
			EXIT_ON_ERROR(1 == 1, "Don't drink and code.");
	}
	break;

	case SYSCALL_LINK:
	case SYSCALL_RENAME:
	{
		// Check return status.
		if (unlikely(rval < 0)) break;

		// Make local FileInfo objects to emit provenance.
		arg = this->syscall->get_arg(0, GUEST_MAX_FILENAME);
		FileInfo *oldpath = new FileInfo(arg.sval, 0);
		arg = this->syscall->get_arg(1, GUEST_MAX_FILENAME);
		FileInfo *newpath = new FileInfo(arg.sval, 0);

		PROVLOG_F2F(this, newpath, oldpath, 'd');
		PROVLOG_P2F(this, newpath, 'g');
		LOG_INFO("%s: %s oldpath=%s newpath=%s", this->label().c_str(), this->syscall->get_name(), oldpath->name(), newpath->name());

		if (oldpath->name()[0] != '/' || newpath->name()[0] != '/') {
			// XXX: Use introspection to get cwd?
			LOG_WARN("%s: %s (!!!relative paths!!!) oldpath=%s newpath=%s", this->label().c_str(), this->syscall->get_name(), oldpath->name(), newpath->name());
		}
		else {
			LOG_INFO("%s: %s oldpath=%s newpath=%s", this->label().c_str(), this->syscall->get_name(), oldpath->name(), newpath->name());
		}

		delete oldpath;
		delete newpath;
	}
	break;

	case SYSCALL_OTHER:
		// ignore
		LOG_INFO("SYSCALL_OTHER complete for %s: %s", this->label().c_str(), this->syscall->get_name());
	break;

	default:
		LOG_WARN("UNHANDLED syscall complete for %s: %s", this->label().c_str(), this->syscall->get_name());
	break;
	}

	delete this->syscall;
	this->syscall = NULL;

	return;
#endif
}

/* vim:set tabstop=4 softtabstop=4 noexpandtab */
