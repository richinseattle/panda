#include "platform.h"
#include "prov_tracer.h"
extern "C" {
#include "config.h"
#include "qemu-common.h"
#include "cpu.h"
#include "rr_log.h"			/**< Replay instruction count. */
}
#include <sys/types.h>
#include <sys/stat.h>
#include <iomanip>
#include <sstream>

#include "accounting.h"
#include "prov_log.h"			/**< Macros for logging raw provenance. */

// *******************************************************************
// FileInfo definitions
// *******************************************************************
FileInfo::FileInfo(char *name, int flags) {
	this->flags_ = flags;

	this->written_ = 0;
	this->read_ = 0;
	this->first_read_ts_ = 0;
	this->last_write_ts_ = 0;

	this->name_ = name;
	this->name_escaped_ = NULL;
	this->update_name_escaped();
}

FileInfo::~FileInfo() {
	g_free(this->name_);
	g_free(this->name_escaped_);
}

/*!
 * @brief Debug representation of the file.
 */
std::string FileInfo::repr() const {
	std::stringstream ss;
	ss	<< this->name_
	<< "(r" << this->read_ << ":w" << this->written_
	<< ")";
	return ss.str();
}

/*!
 * @brief Returns the name of the file.
 */
char *FileInfo::name() const {
	return this->name_;
}

/*!
 * @brief Returns the name of the file, properly escaped for printing
 * in the raw provenance file.
 */
char *FileInfo::name_escaped() const {
	return this->name_escaped_;
}

/*!
 * @brief Returns the number of bytes written to the file.
 */
uint64_t FileInfo::written() const { return this->written_; }

/*!
 * @brief Returns the number of bytes read from the file.
 */
uint64_t FileInfo::read() const { return this->read_; }

/*!
 * @brief Returns the pseudo-timestamp for the first read on the file.
 */
uint64_t FileInfo::first_read_ts() const { return this->first_read_ts_; }

/*!
 * @brief Returns the pseudo-timestamp for the last write on the file.
 */
uint64_t FileInfo::last_write_ts() const { return this->last_write_ts_; }

/*!
 * @brief Increases the written bytes counter for the file.
 * Also adjusts the last written pseudo-timestamp.
 */
uint64_t FileInfo::inc_written(uint64_t n) {
	this->last_write_ts_ = rr_get_guest_instr_count();
	this->written_ += n;
	return this->written_;
}

/*!
 * @brief Increases the read bytes counter for the file.
 * Also initializes the first read pseudo-timestamp.
 */
uint64_t FileInfo::inc_read(uint64_t n) {
	if (unlikely(this->read_ == 0)) {
		this->first_read_ts_ = rr_get_guest_instr_count();
	}
	this->read_ += n;
	return this->read_;
}

/*!
 * @brief Updates the escaped representation of the file name.
 *
 * Escaping is used to avoid problems with the raw provenance format.
 * The characters that have to be escaped are :, line-control
 * characters, the rest of control characters.
 */
void FileInfo::update_name_escaped() {
	std::ostringstream escaped;
	escaped.fill('0');
	escaped << std::hex;

	for (char *cp = this->name_; *cp!='\0'; cp++) {
		// this would produce the equivalent to url encoding
		// if (!(isalnum(*cp) || *cp == '-' || *cp == '_' || *cp == '.' || *cp == '~')) {

		if (unlikely(iscntrl(*cp) || *cp == ':' || (isspace(*cp) && !isblank(*cp)))) {
			//			^^^				^^^						^^^
			//		non printable	raw separator			line control
			escaped << '%' << std::setw(2) << int((unsigned char) *cp);
			continue;
		}
		escaped << *cp;
	}
	g_free(this->name_escaped_);
	this->name_escaped_ = g_strdup(escaped.str().c_str());
}

/*!
 * @brief Returns the binary representation of the file flags.
 */
int FileInfo::flags() const { return this->flags_; }

/*!
 * @brief Tests if a specific flag is set for the file.
 * Supported flags are 'r', 'w', 't'.
 */
bool FileInfo::test_flags(char c) const {
	if (c == 'w')
		return ( (this->flags_ & O_WRONLY) || (this->flags_ & O_RDWR) );
	else if (c == 'r')
		return ( !(this->flags_ & O_WRONLY) );
	else if (c == 't')
		return ( ((this->flags_ & O_WRONLY) || (this->flags_ & O_RDWR)) && (this->flags_ & O_TRUNC) );
	else
		return false;
}

/* vim:set tabstop=4 softtabstop=4 noexpandtab */
