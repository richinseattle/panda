#ifndef PLATFORM_H
#define PLATFORM_H

extern "C" {
#include "config.h"         /**< TARGET_* macros */
}



/*!
 * @brief Macro for quashing unused variable warnings.
 */
#ifdef __GNUC__
#define PERMIT_UNUSED __attribute__ ((unused))
#else
#define PERMIT_UNUSED
#endif



/**
 * @brief Disassembly support.
 *
 * Currently ARM support is not implemented, but can be added by
 * interfacing with armstorm. Armstorm provides a simlar interface
 * with distorm.
 *
 * @see https://code.google.com/p/armstorm/
 */
#if defined(TARGET_I386)
#include <distorm.h>
namespace distorm {
#include <mnemonics.h>

/* redefine macros to use the distorm namespace */
#undef GET_REGISTER_NAME
#undef GET_MNEMONIC_NAME
#define GET_REGISTER_NAME(r) (unsigned char*)distorm::_REGISTERS[(r)].p
#define GET_MNEMONIC_NAME(m) ((distorm::_WMnemonic*)&distorm::_MNEMONICS[(m)])->p
}
#if defined(TARGET_X86_64)
#define DISTORM_DT Decode64Bits
#else
#define DISTORM_DT Decode32Bits
#endif
#elif defined(TARGET_ARM)
#include <distorm.h>        /**< XXX: only included to have the plugin compile. */
#warning "ARM disassembly support has not been implemented."
#else
#error "No disassembly backend for the target architecture."
#endif



/*!
 * @brief Pointer type of the guest VM.
 *
 * @note This definition implies that the guest VM pointer size matches the
 * size of unsigned long of the target processor. This is a reasonable 
 * assumption to make -- at least in the context of a research prototype.
 *
 * @todo Maybe target_phys_addr_t should be used as PTR. Check targphys.h of QEMU.
 */
#define TARGET_PTR target_ulong
#define TARGET_PTR_FMT TARGET_FMT_lx
#define TARGET_PID_FMT "%5d"

/*!
 * @brief Platform specific macro used to construct the name of the syscall table to load.
 */
#if defined(TARGET_I386)
#if defined(TARGET_X86_64)
#define SYSCALLS_LINUX "linux-x86_64"
#else
#define SYSCALLS_LINUX "linux-i686"
#endif
#elif defined(TARGET_ARM)
// XXX: ARM
#define SYSCALLS_LINUX "linux-arm"
#endif

/*!
 * @brief Platform specific macro for retrieving ESP.
 */
#if defined(TARGET_I386)
#define _ESP	(env->regs[R_ESP])
#elif defined(TARGET_ARM)
#define _ESP	(env->regs[13])
#else
#error	"_ESP macro not defined for target architecture."
#endif

/*!
 * @brief Platform specific macro for retrieving the page directory address.
 *
 * @note We use the PGD address as the asid of the process.
 * Maybe instead of this macro, it's better to use panda_current_asid().
 */
#if defined(TARGET_I386)
#define _PGD    (env->cr[3])
#elif defined(TARGET_ARM)
#define _PGD    (env->cp15.c2_base0 & env->cp15.c2_base_mask)
#else
#error	"_PGD macro not defined for target architecture."
#endif

/*!
 * @brief Platform specific macro for getting the current privillege level.
 */
#if defined(TARGET_I386)
/* check the Current Privillege Level in the flags register */
#define _IN_KERNEL ((env->hflags & HF_CPL_MASK) == 0)
#elif defined(TARGET_ARM)
/* check for supervisor mode in the Current Program Status register */
#define _IN_KERNEL ((env->uncached_cpsr & CPSR_M) == ARM_CPU_MODE_SVC)
#else
#error  "_IN_KERNEL macro not defined for target architecture."
#endif

/*!
 * @brief The privillege level as a printable string.
 */
#define _CPU_MODE (_IN_KERNEL ? "K" : "U")



extern "C" {
#include "panda_plugin.h"       /**< target virtual memory access */
}
#include "prov_tracer.h"        /**< logging macros */

/*!
 * @brief Disassembles up to `ins_decoded_max` instructions from `mloc`.
 * Returns the number of decoded instructions.
 *
 * @return Return value is typically non-zero.
 * If nothing was decoded, FLAG_NOT_DECODABLE will be set in
 * the returned instruction buffer.
 * A return value of zero indicates some other error.
 */
static inline unsigned int decompose_from_mem(CPUState *env, target_ulong mloc, unsigned int len, _DInst *ins_decoded, unsigned int ins_decoded_max, unsigned int feats) {
#if defined(TARGET_I386)
    unsigned char *buf;
    unsigned int ndecoded;
    _CodeInfo ci;

    // read from memory
    buf = (unsigned char *)g_malloc0(len*sizeof(unsigned char));
    CHECK_WARN((panda_virtual_memory_rw(env, mloc, buf, len, 0) < 0), "qemu failed to read memory");

    // decode read bytes
    ci.code = buf;
    ci.codeLen = len;
    ci.codeOffset = 0;
    ci.dt = DISTORM_DT;
    ci.features = feats;

    // distorm tips & tricks suggest not checking the return value of distorm_decompose()
    //  https://code.google.com/p/distorm/wiki/TipsnTricks
    distorm_decompose(&ci, ins_decoded, ins_decoded_max, &ndecoded);

    g_free(buf);
    CHECK_WARN((ndecoded > ins_decoded_max), "Unexpected number of decoded instructions.");
    return ndecoded;
#elif defined(TARGET_ARM)
    return 0;
#endif
}

#endif
