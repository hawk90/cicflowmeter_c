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
	LOG_TYPE_STREAM_AND_FILE,
} LogType;	/* LogOPIface and LogOPType */


#define MAX_LOG_MSG_LEN 2048		/* The maximum length of the log message */
#define MAX_LOG_FORMAT_LEN 128		/* The maximum length of the log format */

/**
*	Default and format
*/
/* The default log_format, relase and devlop */
#define DEF_LOG_LEVEL LOG_INFO

#define DEF_LOG_TYPE LOG_TYPE_STREAM_AND_FILE

#define DEFLOG_FILE "cicflowmeter.log"

#define DEF_LOG_FORMAT_REL "%t - <%d> - "
//#define DEF_LOG_FORMAT_DEV "[%i] %t - (%f:%l) <%d> (%n) -- "
#define DEF_LOG_FORMAT_DEV "%t - (%f:%l) <%d> (%n) -- "

/* The log format prefix for the format specifiers */
#define LOG_FMT_PREFIX           '%'

#define LOG_FMT_TIME             't' /* Timestamp in standard format */
#define LOG_FMT_PID              'p' /* PID */
#define LOG_FMT_TID              'i' /* Thread ID */
#define LOG_FMT_TM               'm' /* Thread module name */
#define LOG_FMT_LOG_LEVEL        'd' /* Log level */
#define LOG_FMT_FILE_NAME        'f' /* File name */
#define LOG_FMT_LINE             'l' /* Line number */
#define LOG_FMT_FUNCTION         'n' /* Function */


void log(const LogLevel log_level, const char *file, const char *func,
		const uint32_t line, const ERROR_CODE error_code, const char *fmt, ...) CHECK_PRINTF(6, 7);

#define LOG_TRACE_MSG(...) log(LOG_TRACE, __FILE__, __func__, __LINE__, ERROR_NONE,  __VA_ARGS__)
#define LOG_DBG_MSG(...) log(LOG_DEBUG, __FILE__, __func__, __LINE__, ERROR_NONE, __VA_ARGS__)
#define LOG_INFO_MSG(...) log(LOG_INFO, __FILE__, __func__, __LINE__, ERROR_NONE, __VA_ARGS__)
#define LOG_NOTI_MSG(...) log(LOG_NOTICE, __FILE__, __func__, __LINE__, ERROR_NONE, __VA_ARGS__)
#define LOG_WARN_MSG(error_code, ...) log_err(LOG_WARNING, __FILE__, __func__, __LINE__, error_code,__VA_ARGS__)
#define LOG_ERR_MSG(error_code, ...) log_err(LOG_ERROR, __FILE__, __func__, __LINE__, error_code,__VA_ARGS__)
#define LOG_CRIT_MSG(error_code, ...) log_err(LOG_CRITICAL, __FILE__, __func__, __LINE__, error_code, __VA_ARGS__)
#define LOG_ALERT_MSG(error_code, ...) log(LOG_ALERT, __FILE__, __func__, __LINE__, error_code, __VA_ARGS__)
#define LOG_MERG_MSG(error_code, ...) log(LOG_EMERGENCY, __FILE__, __func__, __LINE__, error_code, __VA_ARGS__)



static ERROR_CODE get_log_message_buffer(
                    struct timeval *tval, int color, LogType type,
                     char *buffer, size_t buffer_size,
                     const char *log_format,
                     const LogLevel log_level, const char *file,
                     const char *function, const uint32_t line,
                     const ERROR_CODE error_code, const char *message);

ERROR_CODE log_message(const LogLevel log_level, const char *file, const char *func, const uint32_t line, ERROR_CODE error_code, const char *message)

extern LogLevel g_log_level;

#ifdef __cplusplus
}
#endif

#endif
