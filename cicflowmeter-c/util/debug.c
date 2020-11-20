#include "cicflowmeter-c/common/cicflowmeter-common.h"

#include "debug.h"

MAP g_log_level_map[] = {{"Not set", LOG_NOTSET},
                         {"None", LOG_NONE},
                         {"Emergency", LOG_EMERGENCY},
                         {"Alert", LOG_ALERT},
                         {"Critical", LOG_CRITICAL},
                         {"Error", LOG_ERROR},
                         {"Warning", LOG_WARNING},
                         {"Notice", LOG_NOTICE},
                         {"Info", LOG_INFO},
                         {"Perf", LOG_PERF},
                         {"Config", LOG_CONFIG},
                         {"Debug", LOG_DEBUG},
                         {NULL, -1}};

struct LOG_CONFIG {
    LOG_TYPE_T log_type;
    FILE *fd;
    pthread_mutex_t mutex;
    uint32_t color;
} LOG_CONFIG_T;

static struct LOG_CONFIG_T g_log_config;

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
static ERROR_CODE get_fmt_log_message_buffer(
    struct timeval *tval, char *buffer, size_t buffer_size,
    const char *log_format, const LOG_LEVEL_T log_level, const char *file,
    const char *function, const uint32_t line, const ERROR_CODE error_code,
    const char *message) {
    char *temp = buffer;
    const char *s = NULL;
    struct tm *tms = NULL;

    /* no of characters_written(rt) by snprintf */
    int rt = 0;

    /* make a copy of the format string as it will be modified below */
    char local_format[strlen(log_format) + 1];
    strncpy(local_format, log_format, sizeof(local_format));
    char *temp_fmt = local_format;
    char *substr = temp_fmt;

    const char *redb = "\x1b[1;31m";
    const char *red = "\x1b[31m";
    const char *yellowb = "\x1b[1;33m";
    const char *yellow = "\x1b[33m";
    const char *green = "\x1b[32m";
    const char *blue = "\x1b[34m";
    const char *reset = "\x1b[0m";

    // REL "%d - <%d>"
    // DEV "%t - (%f:%l) <%d> (%n) -- "
    // t: timestamp
    // f: filename
    // l: line number
    // d: log level
    // n: funtion
    while ((temp_fmt = strchr(temp_fmt, LOG_FMT_PREFIX))) {
        if ((temp - buffer) > MAX_LOG_MSG_LEN) goto ok;

        switch (temp_fmt[1]) {
            case LOG_FMT_TIME:
                temp_fmt[0] = '\0';

                struct tm local_tm;
                tms = localtime_r(&tval->tv_sec, &local_tm);
                if (tms == NULL) goto error;

                rt = snprintf(temp, MAX_LOG_MSG_LEN - (temp - buffer),
                              "%s%s%d/%d/%04d -- %02d:%02d:%02d%s", substr,
                              green, tms->tm_mday, tms->tm_mon + 1,
                              tms->tm_year + 1900, tms->tm_hour, tms->tm_min,
                              tms->tm_sec, reset);
                if (rt < 0) goto error;
                temp += rt;
                temp_fmt++;
                substr = temp_fmt;
                substr++;
                break;

            case LOG_FMT_PID:
#if 0
                temp_fmt[0] = '\0';
                rt = snprintf(temp, LOG_MAX_LOG_MSG_LEN - (temp - buffer),
                        "%s%s%u%s", substr, yellow, getpid(), reset);
                if (rt < 0)
                    return ERROR_SPRINTF;
                temp += rt;
                temp_fmt++;
                substr = temp_fmt;
                substr++;
#endif
                break;

            case LOG_FMT_TID:
#if 0
                temp_fmt[0] = '\0';
                rt = snprintf(temp, LOG_MAX_LOG_MSG_LEN - (temp - buffer),
                        "%s%s%lu%s", substr, yellow, SCGetThreadIdLong(), reset);
                if (rt < 0)
                    return ERROR_SPRINTF;
                temp += rt;
                temp_fmt++;
                substr = temp_fmt;
                substr++;
#endif
                break;

            case LOG_FMT_TM:
#if 0
                temp_fmt[0] = '\0';
                rt = snprintf(temp, LOG_MAX_LOG_MSG_LEN - (temp - buffer),
                        "%s%s", substr, "N/A");
                if (rt < 0)
                    return ERROR_SPRINTF;
                temp += rt;
                temp_fmt++;
                substr = temp_fmt;
                substr++;
#endif
                break;

            case LOG_FMT_LOG_LEVEL_T:
                temp_fmt[0] = '\0';
                s = get_map_key(log_level, g_log_level_map);
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
                if (rt < 0) goto error;

                temp += rt;
                temp_fmt++;
                substr = temp_fmt;
                substr++;
                break;

            case LOG_FMT_FILE_NAME:
                temp_fmt[0] = '\0';
                rt = snprintf(temp, MAX_LOG_MSG_LEN - (temp - buffer),
                              "%s%s%s%s", substr, blue, file, reset);
                if (rt < 0) goto error;

                temp += rt;
                temp_fmt++;
                substr = temp_fmt;
                substr++;
                break;

            case LOG_FMT_LINE:
                temp_fmt[0] = '\0';
                rt = snprintf(temp, MAX_LOG_MSG_LEN - (temp - buffer),
                              "%s%s%u%s", substr, green, line, reset);
                if (rt < 0) goto error;

                temp += rt;
                temp_fmt++;
                substr = temp_fmt;
                substr++;
                break;

            case LOG_FMT_FUNCTION:
                temp_fmt[0] = '\0';
                rt = snprintf(temp, MAX_LOG_MSG_LEN - (temp - buffer),
                              "%s%s%s%s", substr, green, function, reset);
                if (rt < 0) goto error;

                temp += rt;
                temp_fmt++;
                substr = temp_fmt;
                substr++;
                break;
        }
        temp_fmt++;
    }
    if ((temp - buffer) > MAX_LOG_MSG_LEN) goto ok;

    rt = snprintf(temp, MAX_LOG_MSG_LEN - (temp - buffer), "%s", substr);
    if (rt < 0) goto error;
    ;

    temp += rt;
    if ((temp - buffer) > MAX_LOG_MSG_LEN) {
        return OK;
    }

    if (error_code != OK) {
        rt = snprintf(temp, MAX_LOG_MSG_LEN - (temp - buffer),
                      "[%sERRCODE%s: %s%s%s(%s%d%s)] - ", yellow, reset, red,
                      error_to_string(error_code), reset, yellow, error_code,
                      reset);
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
    rt = snprintf(temp, MAX_LOG_MSG_LEN - (temp - buffer), "%s%s%s", hi,
                  message, reset);
    if (rt < 0) return ERROR_SPRINTF;
    temp += rt;
    if ((temp - buffer) > MAX_LOG_MSG_LEN) {
        return OK;
    }

    return OK;

ok:
    return OK;
error:
    return ERROR_SPRINTF;
}

static inline int flush_log_buffer(FILE *fd, const char *msg) {
    int rt = 0;

    if (fd == NULL) goto error;

    rt = fprintf(fd, "%s\n", msg);
    if (rt < 0) goto error;

    rt = fflush(fd);
    if (rt < 0) goto error;

    return 0;

error:
    return -1;
}

ERROR_CODE print_log(const LOG_LEVEL_T log_level, const char *file,
                     const char *func, const uint32_t line,
                     ERROR_CODE error_code, const char *message) {
    char buffer[MAX_LOG_MSG_LEN] = "";
    struct timeval tval;
    int rt = 0;

    rt = gettimeofday(&tval, NULL);
    if (rt != 0) goto error;

    /* conf */
    rt = get_fmt_log_message_buffer(&tval, buffer, sizeof(buffer),
                                    DEF_LOG_FORMAT_DEV, log_level, file, func,
                                    line, error_code, message);
    if (rt != 0) goto error;

    switch (g_log_config.log_type) {
        case LOG_TYPE_T_STREAM:
            flush_log_buffer(stdout, buffer);
            break;
        case LOG_TYPE_T_FILE:
            pthread_mutex_lock(&(g_log_config.mutex));

            /* Ciritical Session */
            g_log_config.fd = fopen("cicflowmeter", "a");
            flush_log_buffer(g_log_config.fd, buffer);
            fclose(g_log_config.fd);

            pthread_mutex_unlock(&(g_log_config.mutex));
            break;
        case LOG_TYPE_T_STREAM_AND_FILE:
            break;
        default:
            goto error;
    }
error:
    return OK;
}

void logger(const LOG_LEVEL_T log_level, const char *file, const char *func,
            const uint32_t line, ERROR_CODE error_code, const char *fmt, ...) {
    if (log_level >= LOG_DEBUG) {
        char msg[MAX_LOG_MSG_LEN];
        va_list ap;

        va_start(ap, fmt);
        vsnprintf(msg, sizeof(msg), fmt, ap);
        va_end(ap);

        print_log(log_level, file, func, line, error_code, msg);
    }
}

int init_log_config() {
    g_log_config.log_type = LOG_TYPE_T_STREAM;
    g_log_config.fd = NULL;
    pthread_mutex_init(&(g_log_config.mutex), NULL);

    return 0;
}
