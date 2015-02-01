#ifndef PROV_TRACER_H
#define PROV_TRACER_H

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

#endif