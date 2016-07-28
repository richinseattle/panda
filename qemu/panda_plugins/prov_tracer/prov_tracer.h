#ifndef PROV_TRACER_H
#define PROV_TRACER_H
#include <iostream>
#include <fstream>

#define PLUGIN_NAME "prov_tracer"

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
 * @brief Smart memory read function.
 *
 * The function will read up to n bytes from `addr`.
 * If a `\0` terminated string of at least `SMART_READ_MIN_STRLEN` characters
 * is found at the beggining of the buffer, this string will be returned.
 * Otherwise, `n` bytes will be returned formatted as a hex string.
 */
std::string panda_virtual_memory_smart_read(CPUState *env, target_ulong addr, size_t n);

/*!
 * @brief Simple string copy functions.
 */
uint32_t guest_strncpy(CPUState *env, char *buf, size_t maxlen, target_ulong guest_addr);
uint32_t guest_wstrncpy(CPUState *env, char *buf, size_t maxlen, target_ulong guest_addr);

/*!
 * @brief The number of printable characters at the beginning of a buffer
 * required to treat the buffer as a string.
 */
#define SMART_READ_MIN_STRLEN 3

#define GUEST_MAX_FILENAME 256

/*!
 * @brief Provenance output stream.
 */
extern std::ofstream prov_out;
#endif
