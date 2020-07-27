#include "debug.h"

#include <stdio.h>
#include <stdarg.h>

#if 0
ENUM_CHAR_MAP log_level_map[ ] = {
    { "Not set",        LOG_NOTSET},
    { "None",           LOG_NONE },
    { "Emergency",      LOG_EMERGENCY },
    { "Alert",          LOG_ALERT },
    { "Critical",       LOG_CRITICAL },
    { "Error",          LOG_ERROR },
    { "Warning",        LOG_WARNING },
    { "Notice",         LOG_NOTICE },
    { "Info",           LOG_INFO },
    { "Perf",           LOG_PERF },
    { "Config",         LOG_CONFIG },
    { "Debug",          LOG_DEBUG },
    { NULL,             -1 }
};
#endif

/**
 * \brief Adds the global log_format to the outgoing buffer
 *
 * \param log_level log_level of the message that has to be logged
 * \param msg       Buffer containing the outgoing message
 * \param file      File_name from where the message originated
 * \param function  Function_name from where the message originated
 * \param line      Line_no from where the messaged originated
 *
 * \retval OK on success; else an error code
 */
#if 0
static ERROR LogMessageGetBuffer(
        struct timeval *tval, int color, LogType type,
                     char *buffer, size_t buffer_size,
                     const char *log_format,

                     const LogLevel log_level, const char *file,
                     const unsigned int line, const char *function,
                     const Error error_code, const char *message)
{
    char *temp = buffer;
    const char *s = NULL;
    struct tm *tms = NULL;

    const char *redb = "";
    const char *red = "";
    const char *yellowb = "";
    const char *yellow = "";
    const char *green = "";
    const char *blue = "";
    const char *reset = "";
    if (color) {
        redb = "\x1b[1;31m";
        red = "\x1b[31m";
        yellowb = "\x1b[1;33m";
        yellow = "\x1b[33m";
        green = "\x1b[32m";
        blue = "\x1b[34m";
        reset = "\x1b[0m";
    }
    /* no of characters_written(cw) by snprintf */
    int cw = 0;

    /* make a copy of the format string as it will be modified below */
    char local_format[strlen(log_format) + 1];
    strlcpy(local_format, log_format, sizeof(local_format));
    char *temp_fmt = local_format;
    char *substr = temp_fmt;

	while ( (temp_fmt = strchr(temp_fmt, LOG_FMT_PREFIX)) ) {
        if ((temp - buffer) > LOG_MAX_LOG_MSG_LEN) {
            return OK;
        }
        switch(temp_fmt[1]) {
            case LOG_FMT_TIME:
                temp_fmt[0] = '\0';

                struct tm local_tm;
                tms = LocalTime(tval->tv_sec, &local_tm);

                cw = snprintf(temp, LOG_MAX_LOG_MSG_LEN - (temp - buffer),
                              "%s%s%d/%d/%04d -- %02d:%02d:%02d%s",
                              substr, green, tms->tm_mday, tms->tm_mon + 1,
                              tms->tm_year + 1900, tms->tm_hour, tms->tm_min,
                              tms->tm_sec, reset);
                if (cw < 0)
                    return ERR_SPRINTF;
                temp += cw;
                temp_fmt++;
                substr = temp_fmt;
                substr++;
                break;

            case LOG_FMT_PID:
                temp_fmt[0] = '\0';
                cw = snprintf(temp, LOG_MAX_LOG_MSG_LEN - (temp - buffer),
                              "%s%s%u%s", substr, yellow, getpid(), reset);
                if (cw < 0)
                    return ERR_SPRINTF;
                temp += cw;
                temp_fmt++;
                substr = temp_fmt;
                substr++;
                break;

            case LOG_FMT_TID:
                temp_fmt[0] = '\0';
                cw = snprintf(temp, LOG_MAX_LOG_MSG_LEN - (temp - buffer),
                              "%s%s%lu%s", substr, yellow, GetThreadIdLong(), reset);
                if (cw < 0)
                    return ERR_SPRINTF;
                temp += cw;
                temp_fmt++;
                substr = temp_fmt;
                substr++;
                break;

            case LOG_FMT_TM:
                temp_fmt[0] = '\0';
                cw = snprintf(temp, LOG_MAX_LOG_MSG_LEN - (temp - buffer),
                              "%s%s", substr, "N/A");
                if (cw < 0)
                    return ERR_SPRINTF;
                temp += cw;
                temp_fmt++;
                substr = temp_fmt;
                substr++;
                break;

            case LOG_FMT_LOG_LEVEL:
                temp_fmt[0] = '\0';
                s = MapEnumValueToName(log_level, sc_log_level_map);
                if (s != NULL) {
                    if (log_level <= LOG_ERROR)
                        cw = snprintf(temp, LOG_MAX_LOG_MSG_LEN - (temp - buffer),
                                  "%s%s%s%s", substr, redb, s, reset);
                    else if (log_level == LOG_WARNING)
                        cw = snprintf(temp, LOG_MAX_LOG_MSG_LEN - (temp - buffer),
                                  "%s%s%s%s", substr, red, s, reset);
                    else if (log_level == LOG_NOTICE)
                        cw = snprintf(temp, LOG_MAX_LOG_MSG_LEN - (temp - buffer),
                                  "%s%s%s%s", substr, yellowb, s, reset);
                    else
                        cw = snprintf(temp, LOG_MAX_LOG_MSG_LEN - (temp - buffer),
                                  "%s%s%s%s", substr, yellow, s, reset);
                } else {
                    cw = snprintf(temp, LOG_MAX_LOG_MSG_LEN - (temp - buffer),
                                  "%s%s", substr, "INVALID");
                }
                if (cw < 0)
                    return ERR_SPRINTF;
                temp += cw;
                temp_fmt++;
                substr = temp_fmt;
                substr++;
                break;

            case LOG_FMT_FILE_NAME:
                temp_fmt[0] = '\0';
                cw = snprintf(temp, LOG_MAX_LOG_MSG_LEN - (temp - buffer),
                              "%s%s%s%s", substr, blue, file, reset);
                if (cw < 0)
                    return ERR_SPRINTF;
                temp += cw;
                temp_fmt++;
                substr = temp_fmt;
                substr++;
                break;

            case LOG_FMT_LINE:
                temp_fmt[0] = '\0';
                cw = snprintf(temp, LOG_MAX_LOG_MSG_LEN - (temp - buffer),
                              "%s%s%u%s", substr, green, line, reset);
                if (cw < 0)
                    return ERR_SPRINTF;
                temp += cw;
                temp_fmt++;
                substr = temp_fmt;
                substr++;
                break;

            case LOG_FMT_FUNCTION:
                temp_fmt[0] = '\0';
                cw = snprintf(temp, LOG_MAX_LOG_MSG_LEN - (temp - buffer),
                              "%s%s%s%s", substr, green, function, reset);
                if (cw < 0)
                    return ERR_SPRINTF;
                temp += cw;
                temp_fmt++;
                substr = temp_fmt;
                substr++;
                break;

        }
        temp_fmt++;
	}
    if ((temp - buffer) > LOG_MAX_LOG_MSG_LEN) {
        return OK;
    }
    cw = snprintf(temp, LOG_MAX_LOG_MSG_LEN - (temp - buffer), "%s", substr);
    if (cw < 0) {
        return ERR_SPRINTF;
    }
    temp += cw;
    if ((temp - buffer) > LOG_MAX_LOG_MSG_LEN) {
        return OK;
    }

    if (error_code != OK) {
        cw = snprintf(temp, LOG_MAX_LOG_MSG_LEN - (temp - buffer),
                "[%sERRCODE%s: %s%s%s(%s%d%s)] - ", yellow, reset, red, ErrorToString(error_code), reset, yellow, error_code, reset);
        if (cw < 0) {
            return ERR_SPRINTF;
        }
        temp += cw;
        if ((temp - buffer) > LOG_MAX_LOG_MSG_LEN) {
            return OK;
        }
    }

    const char *hi = "";
    if (error_code > OK)
        hi = red;
    else if (log_level <= LOG_NOTICE)
        hi = yellow;
    cw = snprintf(temp, LOG_MAX_LOG_MSG_LEN - (temp - buffer), "%s%s%s", hi, message, reset);
    if (cw < 0) {
        return ERR_SPRINTF;
    }
    temp += cw;
    if ((temp - buffer) > LOG_MAX_LOG_MSG_LEN) {
        return OK;
    }

    if (sc_log_config->op_filter_regex != NULL) {
#define MAX_SUBSTRINGS 30
        int ov[MAX_SUBSTRINGS];

        if (pcre_exec(sc_log_config->op_filter_regex,
                      sc_log_config->op_filter_regex_study,
                      buffer, strlen(buffer), 0, 0, ov, MAX_SUBSTRINGS) < 0)
        {
            return ERR_LOG_FG_FILTER_MATCH; // bit hacky, but just return !0
        }
#undef MAX_SUBSTRINGS
    }

    return OK;
}
#endif

Error log_message(const LogLevel log_level, const char *file, const char *func, const uint32_t line, Error error_code, const char *message)
{	
	printf("Log level: %d, [%s:%s:%d] <%d> %s", log_level, file, func, line, error_code, message);

	return OK;
}

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
