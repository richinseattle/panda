#include "platform.h"
#include "prov_tracer.h"
extern "C" {
#include "config.h"
#include "qemu-common.h"
#include "cpu.h"
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
	this->flags = flags;
	this->written = 0;
	this->read = 0;

	this->name = name;
	this->name_escaped = NULL;
	this->update_escaped();
}

FileInfo::~FileInfo() {
	g_free(this->name);
	g_free(this->name_escaped);
}

void FileInfo::update_escaped() {
    std::ostringstream escaped;
    escaped.fill('0');
    escaped << std::hex;

    for (char *cp = this->name; *cp!='\0'; cp++) {
	// this would produce the equivalent to url encoding
        // if (!(isalnum(*cp) || *cp == '-' || *cp == '_' || *cp == '.' || *cp == '~')) {

	//          non printable   raw separator            line control
	if (unlikely(iscntrl(*cp) || *cp == ':' || (isspace(*cp) && !isblank(*cp)))) {
	    escaped << '%' << std::setw(2) << int((unsigned char) *cp);
	    continue;
	}
	escaped << *cp;
    }
    g_free(this->name_escaped);
    this->name_escaped = g_strdup(escaped.str().c_str());
}

char *FileInfo::get_name() const {
    return this->name;
}

char *FileInfo::get_name_escaped() const {
    return this->name_escaped;
}

bool FileInfo::flag_set(char c) const {
	if (c == 'w')
		return ( (this->flags & O_WRONLY) || (this->flags & O_RDWR) );
	else if (c == 'r')
		return ( !(this->flags & O_WRONLY) );
	else if (c == 't')
		return ( ((this->flags & O_WRONLY) || (this->flags & O_RDWR)) && (this->flags & O_TRUNC) );
	else
		return false;
}

