#ifndef PROCESSINFO_H
#define PROCESSINFO_H

typedef std::unordered_map<int, std::string> FDMap;

class ProcInfo {
	public:
		ProcInfo(OsiProc *p);
		~ProcInfo();
		OsiProc p;			/**< OsiProc struct. */
		FDMap fd;			/**< Process is still "fresh". */
		bool fresh = true;

	private:

};

typedef std::unordered_map<target_ulong, ProcInfo *> ProcInfoMap;

extern ProcInfoMap pimap;

#endif
