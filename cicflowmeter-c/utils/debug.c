#include <stdio.h>
#include <stdarg.h>
#include <string.h>

#include "debug.h"
#include "enum.h"

MAP g_log_level_map[ ] = {
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

static inline int log_print(FILE *fd, const char *msg)
{
	int rt = 0;

	if (fd == NULL) goto error;
	
	rt = fprintf(fd, "%s\n", msg);
	if (rt < 0)	goto error;

	rt = fflush(fd);
	if (rt < 0) goto error;

	return 0;

error:
	return -1;
}

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
static ERROR_CODE get_fmt_log_message_buffer(struct timeval *tval, int color, LogType type, char *buffer, size_t buffer_size, const char *log_format,
		const LogLevel log_level, const char *file, const char *function, const uint32_t line,	const ERROR_CODE error_code, const char *message)
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

    /* no of characters_written(rt) by snprintf */
    int rt = 0;

    /* make a copy of the format string as it will be modified below */
    char local_format[strlen(log_format) + 1];
    strncpy(local_format, log_format, sizeof(local_format));
    char *temp_fmt = local_format;
    char *substr = temp_fmt;

	// "%t - (%f:%l) <%d> (%n) -- " 
	// t: timestamp
	// f: filename
	// l: line number
	// d: log level
	// n: funtion

#if DEBUG
	struct tm local_tm;
	// get time .ko

    rt = snprintf(temp, MAX_LOG_MSG_LEN - (temp - buffer),
                              "%s%s%d/%d/%04d -- %02d:%02d:%02d%s",
                              substr, green, tms->tm_mday, tms->tm_mon + 1,
                              tms->tm_year + 1900, tms->tm_hour, tms->tm_min,
                              tms->tm_sec, reset);
	if (rt < 0) return ERROR_SPRINTF;

	case LOG_FMT_LOG_LEVEL:
		temp_fmt[0] = '\0';
		s = get_map_key(log_level, g_log_level_map);
		/* function */
		if (s != NULL) {
			if (log_level <= LOG_ERROR)
				rt = snprintf(temp, MAX_LOG_MSG_LEN - (temp - buffer),
						  "%s%s%s%s", substr, redb, s, reset);
			else if (log_level == LOG_WARNING)
				rt = snprintf(temp, MAX_LOG_MSG_LEN - (temp - buffer),
						  "%s%s%s%s", substr, red, s, reset);
			else if (log_level == LOG_NOTICE)
				rt = snprintf(temp, MAX_LOG_MSG_LEN - (temp - buffer),
						  "%s%s%s%s", substr, yellowb, s, reset);
			else
				rt = snprintf(temp, MAX_LOG_MSG_LEN - (temp - buffer),
						  "%s%s%s%s", substr, yellow, s, reset);
		} else {
			rt = snprintf(temp, MAX_LOG_MSG_LEN - (temp - buffer),
						  "%s%s", substr, "INVALID");
		}
		/* function end */

		if (rt < 0)
			return ERROR_SPRINTF;
		if ((temp - buffer) > MAX_LOG_MSG_LEN) {
        	return OK;
   		 }

		/* MACRO? */
		temp += rt;
		temp_fmt++;
		substr = temp_fmt;
		substr++;
		/* MACRO? end */

		if ((temp - buffer) > MAX_LOG_MSG_LEN) {
        	return OK;
   		 }

	case LOG_FMT_FILE_NAME:
		temp_fmt[0] = '\0';
		rt = snprintf(temp, MAX_LOG_MSG_LEN - (temp - buffer),
					  "%s%s%s%s", substr, blue, file, reset);
		if (rt < 0)
			return ERROR_SPRINTF;

		/*
		temp += rt;
		temp_fmt++;
		substr = temp_fmt;
		substr++;
		*/
		if ((temp - buffer) > MAX_LOG_MSG_LEN) {
        	return OK;
   		 }

	case LOG_FMT_LINE:
		temp_fmt[0] = '\0';
		rt = snprintf(temp, MAX_LOG_MSG_LEN - (temp - buffer),
					  "%s%s%u%s", substr, green, line, reset);
		if (rt < 0)
			return ERROR_SPRINTF;

		/*
		temp += rt;
		temp_fmt++;
		substr = temp_fmt;
		substr++;
		*/
		if ((temp - buffer) > MAX_LOG_MSG_LEN) {
        	return OK;
   		 }

	case LOG_FMT_FUNCTION:
		temp_fmt[0] = '\0';
		rt = snprintf(temp, MAX_LOG_MSG_LEN - (temp - buffer),
					  "%s%s%s%s", substr, green, function, reset);
		if (rt < 0)
			return ERROR_SPRINTF;

		/*
		temp += rt;
		temp_fmt++;
		substr = temp_fmt;
		substr++;
		*/
		if ((temp - buffer) > MAX_LOG_MSG_LEN) {
        	return OK;
   		 }

#endif

    rt = snprintf(temp, MAX_LOG_MSG_LEN - (temp - buffer), "%s", substr);
    if (rt < 0) return ERROR_SPRINTF;
    temp += rt;
    if ((temp - buffer) > MAX_LOG_MSG_LEN) {
        return OK;
    }

    if (error_code != OK) {
        rt = snprintf(temp, MAX_LOG_MSG_LEN - (temp - buffer),
                "[%sERRCODE%s: %s%s%s(%s%d%s)] - ", yellow, reset, red, error_to_string(error_code), reset, yellow, error_code, reset);
        if (rt < 0) {
            return ERROR_SPRINTF;
        }
        temp += rt;
        if ((temp - buffer) > MAX_LOG_MSG_LEN) {
            return OK;
        }
    }

    const char *hi = "";
    if (error_code > OK)
        hi = red;
    else if (log_level >= LOG_NOTICE)
        hi = yellow;
    rt = snprintf(temp, MAX_LOG_MSG_LEN - (temp - buffer), "%s%s%s", hi, message, reset);
    if (rt < 0) return ERROR_SPRINTF;
    temp += rt;
    if ((temp - buffer) > MAX_LOG_MSG_LEN) {
        return OK;
    }


	return OK;
}

ERROR_CODE print_log(const LogLevel log_level, const char *file, const char *func, const uint32_t line, ERROR_CODE error_code, const char *message)
{	
	char buffer[MAX_LOG_MSG_LEN] = "";
	struct timeval tval;
	int rc = 0;

	switch (/*LogType*/) {
		case LOG_TYPE_STREAM:
			rt = get_fmt_message_get_buffer();
			if (rt != 0) goto error;

			rc = log_print();
			if (rt != 0) goto error;

			break;
		case LOG_TYPE_FILE:
			rt = get_ftm_log_message_buffer();
			if (rt != 0) goto error;

			mutex_lock();

			rc = log_print_file();
			if (rt != 0) goto error;

			mutex_unlock();
			
			break;
		case LOG_TYPE_STREAM_FILE:
			rt = get_fmt_log_message_buffer();
			if (rt != 0) goto error;

			mutex_lock();
			
			rc = log_print_fd();
			if (rt != 0) goto error;

			mutex_unlock();

			rc = log_print();
			if (rt != 0) goto error;

			break;
		default:
			// printf("ERROR_CODE not invalide log type: %d", log_type);
			goto error;
			break;
	}

	return OK;

error:
	return OK;
}

void log(const LogLevel log_level, const char *file, const char *func,
			const uint32_t line, ERROR_CODE error_code, const char *fmt, ...)
{
	char msg[MAX_LOG_MSG_LEN];
	va_list ap;

	va_start(ap, fmt);
	vsnprintf(msg, sizeof(msg), fmt, ap);
	va_end(ap);

	print_log(log_level, file, func, line, error_code, msg);

}
