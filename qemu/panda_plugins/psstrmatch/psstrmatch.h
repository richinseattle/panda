#ifndef PSSTRMATCH_H
#define PSSTRMATCH_H
extern "C" {
#include "config.h"         /**< TARGET_* macros */
}
#include <iostream>
#include <fstream>

#define PLUGIN_NAME "psstrmatch"

/*!
 * @brief Branch prediction hint macros.
 */
#define likely(x)       __builtin_expect(!!(x), 1)
#define unlikely(x)     __builtin_expect(!!(x), 0)

/*!
 * @brief Logging macros.
 */
#define ERRNO_CLEAR errno = 0
#define LOG_ERROR(fmt, args...) fprintf(stderr, "ERROR(%s:%s): " fmt "\n", __FILE__, __func__, ## args)
#define LOG_WARN(fmt, args...) fprintf(stderr, "WARN(%s:%s): " fmt "\n", __FILE__, __func__, ## args)
#define LOG_INFO(fmt, args...) fprintf(stderr, "INFO(%s:%s): " fmt "\n", __FILE__, __func__, ## args)
#define CHECK_ERROR(cond, args...) do { if (unlikely(cond)) { LOG_ERROR(args); } } while(0)
#define CHECK_WARN(cond, args...) do { if (unlikely(cond)) { LOG_WARN(args); } } while(0)
#define EXIT_ON_ERROR(cond, args...) do { if (unlikely(cond)) { LOG_ERROR(args); exit(1); } } while(0)

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

#if 0
/*!
 * @brief Smart memory read function.
 *
 * The function will read up to n bytes from `addr`.
 * If a `\0` terminated string of at least `SMART_READ_MIN_STRLEN` characters
 * is found at the beggining of the buffer, this string will be returned.
 * Otherwise, `n` bytes will be returned formatted as a hex string.
 */
std::string panda_virtual_memory_smart_read(CPUState *env, target_ulong addr, size_t n);

/*!
 * @brief The number of printable characters at the beginning of a buffer
 * required to treat the buffer as a string.
 */
#define SMART_READ_MIN_STRLEN 3
#endif
#endif
