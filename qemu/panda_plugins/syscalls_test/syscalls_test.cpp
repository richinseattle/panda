extern "C" {
#include "config.h"
}
#include <distorm.h>

// distorm extras
#if defined(TARGET_I386)
#include <mnemonics.h>
#if defined(TARGET_X86_64)
#define DISTORM_DT Decode64Bits
#else
#define DISTORM_DT Decode32Bits
#endif
#endif

extern "C" {
#include "qemu-common.h"
#include "cpu.h"

#include "panda_common.h"
#include "panda_plugin.h"
#include "osi_types.h"
#include "osi_ext.h"
#include "os_intro.h"
#include "osi_linux_ext.h"
}

#include <iostream>
#include <fstream>
#include <glib.h>

extern "C" {
	bool init_plugin(void *);
	void uninit_plugin(void *);
}

#define DEBUG_LOCATION __FILE__ << ":" << __FUNCTION__ << ":" << __LINE__ << ": "
#define TARGET_PTR target_ulong
#define TARGET_PTR_FMT TARGET_FMT_lx

// Disassembles up to ins_decoded_max instructions from `mloc` using distorm.
// Returns the number of decoded instructions.
// If nothing was decoded, FLAG_NOT_DECODABLE will be set in the returned buffer.
// A return value of zero indicates some other error.
static inline unsigned int distorm3_decode(CPUState *env, TARGET_PTR mloc, unsigned int len, _DInst *ins_decoded, unsigned int ins_decoded_max, unsigned int feats) {
#if defined(TARGET_I386)
	unsigned char *buf;
	unsigned int ndecoded;
	_CodeInfo ci;

	// read from memory
	buf = (unsigned char *)g_malloc0(len*sizeof(unsigned char));
	if (panda_virtual_memory_rw(env, mloc, buf, len, 0) < 0) {
		std::cerr << DEBUG_LOCATION << "qemu failed to read memory" << std::endl;
	}

	// decode read bytes
	ci.code = buf;
	ci.codeLen = len;
	ci.codeOffset = 0;
	ci.dt = DISTORM_DT;
	ci.features = feats;

	// distorm tips & tricks suggest not checking the return value of distorm_decompose()
	// https://code.google.com/p/distorm/wiki/TipsnTricks
	distorm_decompose(&ci, ins_decoded, ins_decoded_max, &ndecoded);

	g_free(buf);
	if (ndecoded > ins_decoded_max) {
		std::cerr << DEBUG_LOCATION << "unexpected number of decoded instructions" << std::endl;
	}
	return ndecoded;
#else
	return 0;
#endif
}

// distorm based implementation
bool ins_trans_cb_0(CPUState *env, TARGET_PTR pc) {
#if defined(TARGET_I386)
	const int nbytes = 32;			// number of bytes to attempt to decode. sysenter/sysexit are 2 bytes long.
	const int ndecode = 1;			// number of instructions to decode
	unsigned int ndecoded;			// number of instructions actually decoded
	_DInst ins_decoded[ndecode];	// the decoded instructions
	_DInst *ins;

	// with the DF_STOP_ON_SYS feature, decoding will stop on the first syscall related instruction
	// TODO: add a static buffer to decompose_from_mem() so that we don't need to read memory for every call
	ndecoded = distorm3_decode(env, pc, nbytes, ins_decoded, ndecode, DF_STOP_ON_SYS);
	if (ndecoded == 0) {
		std::cerr << DEBUG_LOCATION << "0 instructions decoded - this shouldn't happen" << std::endl;
	}

	// we requested decoding 1 instruction - no loop needed
	ins = &ins_decoded[0];
	if (ins->flags == FLAG_NOT_DECODABLE) {
		return false;
	}

	// check the decoded instruction class instead of the specific opcode
	switch(META_GET_FC(ins->meta)) {
	case FC_SYS:
		//std::cout << DEBUG_LOCATION << "SYS " << GET_MNEMONIC_NAME(ins->opcode) << std::endl;
		return true;

	case FC_INT:
		// we're only interested in int80 - the condition below is a bit pendantic:
		//	- 1st operand is immediate
		//	- no 2nd operand
		//	- 1st operand (immediate) size is 8bits
		//	- (1st operand) immediate value is 0x80
		if (ins->ops[0].type == O_IMM && ins->ops[1].type == O_NONE && ins->ops[0].size == 8 && ins->imm.byte == 0x80) {
			//std::cout << DEBUG_LOCATION << "INT " << GET_MNEMONIC_NAME(ins->opcode) << std::hex << (int)ins->imm.byte << std::endl;
			return true;
		}
		else {
			return false;
		}

	// XXX: check for IRET??? how to make sure this is from an int80 return???

	default:
		return false;
	}
#else
	return false;
#endif
}
int ins_exec_cb_0(CPUState *env, TARGET_PTR pc) {
#if defined(TARGET_I386)
	const int nbytes = 32;			// number of bytes to attempt to decode. sysenter/sysexit are 2 bytes long.
	const int ndecode = 1;			// number of instructions to decode
	unsigned int ndecoded;			// number of instructions actually decoded
	unsigned int nundecodable = 0;
	_DInst ins_decoded[ndecode];	// the decoded instructions
	_DInst *ins;
	bool in_kernel = panda_in_kernel(env);

	// with the DF_STOP_ON_SYS feature, decoding will stop on the first syscall related instruction
	ndecoded = distorm3_decode(env, pc, nbytes, ins_decoded, ndecode, DF_STOP_ON_SYS);
	if (ndecoded == 0) {
		std::cerr << DEBUG_LOCATION << "0 instructions decoded - this shouldn't happen" << std::endl;
	}

	// loop through decoded instructions
	for (unsigned int i=0; i<ndecoded; i++) {
		ins = &ins_decoded[i];
		if (ins->flags == FLAG_NOT_DECODABLE) {
			nundecodable++;
			continue;
		}

		std::cout << DEBUG_LOCATION <<
			"panda_in_kernel=" << in_kernel << " " <<
			"ins[" << i << "]=" << GET_MNEMONIC_NAME(ins->opcode);

		switch(ins->opcode) {
		case I_SYSENTER:
		case I_INT:
			std::cout << " " << "R_EAX=" << (int)env->regs[R_EAX] << std::endl;
			break;

		case I_SYSEXIT:
		default:
			std::cout << std::endl;
			break;
		}
	}

	return 0;
#else
	// have the function compiled, although initialization should fail earlier.
	// XXX: ARM
	return 0;
#endif
}

bool init_plugin(void *self) {
#if defined(TARGET_I386)
	panda_cb pcb;

	// initialize osi api
	assert(init_osi_api());
	assert(init_osi_linux_api());

	pcb.insn_translate = ins_trans_cb_0;
	panda_register_callback(self, PANDA_CB_INSN_TRANSLATE, pcb);
	pcb.insn_exec = ins_exec_cb_0;
	panda_register_callback(self, PANDA_CB_INSN_EXEC, pcb);
	return true;
#else
	std::cerr << "Target architecture not supported." << std::endl;
	return false;
#endif
}

void uninit_plugin(void *self) {
}


/* vim:set tabstop=4 softtabstop=4 noexpandtab */
