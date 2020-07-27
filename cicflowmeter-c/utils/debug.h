#ifndef __CICFLOWMETER_UTILS_DEBUG_H__
#define __CICFLOWMETER_UTILS_DEBUG_H__

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <time.h>

#include "error.h"

struct timeval {
  time_t      tv_sec;     /* seconds */
  long        tv_usec;    /* microseconds */
};

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

typedef enum {
	LOG_TYPE_STREAM	= 0,
	LOG_TYPE_FILE,
} LogType;

/* The default log_format, if it is not supplied by the user */
#define LOG_DEF_LOG_FORMAT_REL "%t - <%d> - "
#define LOG_DEF_LOG_FORMAT_DEV "[%i] %t - (%f:%l) <%d> (%n) -- "

#define MAX_LOG_MSG_LEN 2048	/* The maximum length of the log message */
#define MAX_LOG_FORMAT_LEN 128	/* The maximum length of the log format */

#define DEF_LOG_LEVEL LOG_INFO	/* The default log level, if it is not supplied by the user */

#define DEF_LOG_TYPE LOG_TYPE_STREAM

#define LOG_FMT_TIME             't' /* Timestamp in standard format */
#define LOG_FMT_PID              'p' /* PID */
#define LOG_FMT_TID              'i' /* Thread ID */
#define LOG_FMT_TM               'm' /* Thread module name */
#define LOG_FMT_LOG_LEVEL        'd' /* Log level */
#define LOG_FMT_FILE_NAME        'f' /* File name */
#define LOG_FMT_LINE             'l' /* Line number */
#define LOG_FMT_FUNCTION         'n' /* Function */

/* The log format prefix for the format specifiers */
#define LOG_FMT_PREFIX           '%'

extern LogLevel g_log_level;

void LOG(const LogLevel log_level, const char *file, const char *func,
			const uint32_t line, const char *fmt, ...) CHECK_PRINTF(5,6);
void LOG_ERR(const LogLevel log_level, const char *file, const char *func,
		const uint32_t line, const Error error_code, const char *fmt, ...) CHECK_PRINTF(6, 7);


static Error log_message_get_buffer(
                    struct timeval *tval, int color, LogType type,
                     char *buffer, size_t buffer_size,
                     const char *log_format,
                     const LogLevel log_level, const char *file,
                     const char *function, const uint32_t line,
                     const Error error_code, const char *message);
#ifdef __cplusplus
}
#endif

#endif
