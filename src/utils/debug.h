#ifndef __CICFLOWMETER_UTIL_DEBUG_H__
#define __CICFLOWMETER_UTIL_DEBUG_H__

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

#include "error.h"

// TODO: goto common.h and what is means?
#if defined __GNUC__
#define CHECK_PRINTF(m,n) __attribute__((format(printf,m,n)))
#else 
#define CHECK_PRINTF(m,n)
#endif


typedef enum {
    LOG_NOTSET = -1,	/* */
    LOG_NONE = 0,		/* */
	LOG_TRACE,			/* finer-grained information events than the DEBUG */
    LOG_DEBUG,			/* fine-grained information events that are most useful to debug an application */
    LOG_CONFIG,			/* */
    LOG_PERF,			/* */
    LOG_INFO,			/* information messages that highlight the progress of the application at coarse-grained level */
    LOG_NOTICE,			/* */
    LOG_WARNING,		/* potentially harmful situations */
    LOG_ERROR,			/* error events that migh still allow the application to continue running */
    LOG_CRITICAL,		/* */
    LOG_ALERT,			/* */
    LOG_EMERGENCY,		/* */
    LOG_LEVEL_MAX,		/* */
} LogLevel;

/* The default log_format, if it is not supplied by the user */
#define LOG_DEF_LOG_FORMAT_REL "%t - <%d> - "
#define LOG_DEF_LOG_FORMAT_DEV "[%i] %t - (%f:%l) <%d> (%n) -- "

#define MAX_LOG_MSG_LEN 2048	/* The maximum length of the log message */
#define MAX_LOG_FORMAT_LEN 128	/* The maximum length of the log format */

#define DEF_LOG_LEVEL LOG_INFO	/* The default log level, if it is not supplied by the user */


extern LogLevel g_log_level;

void LOG(const LogLevel log_level, const char *file, const char *func,
			const uint32_t line, const char *fmt, ...) CHECK_PRINTF(5,6);
void LOG_ERR(const LogLevel log_level, const char *file, const char *func,
		const uint32_t line, const Error error_code, const char *fmt, ...) CHECK_PRINTF(6, 7);


Error LogMessage(const LogLevel log_level, const char *file, const char *func,
					const uint32_t line, const Error error_code, const char *message);


#ifdef __cplusplus
}
#endif

#endif
