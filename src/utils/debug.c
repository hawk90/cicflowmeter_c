#include "debug.h"

#include <stdio.h>
#include <stdarg.h>

void LOG(const LogLevel log_level, const char *file, const char *func,
			const uint32_t line, const char *fmt, ...)
{
	char msg[MAX_LOG_MSG_LEN];
	va_list ap;

	va_start(ap, fmt);
	vsnprintf(msg, sizeof(msg), fmt, ap);
	va_end(ap);

	LogMessage(log_level, file, func, line, OK, msg);

}

Error LogMessage(const LogLevel log_level, const char *file, const char *func, const uint32_t line, Error error_code, const char *message)
{	
	printf("Log level: %d, [%s:%s:%d] <%d> %s", log_level, file, func, line, error_code, message);

	return OK;
}
