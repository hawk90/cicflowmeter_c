#ifndef __CICFLOWMETER_COMMON_H__
#define __CICFLOWMETER_COMMON_H__

#ifdef __cplusplus
extern "C" {
#endif

#define TRUE 1
#define FALSE 0

#define _GNU_SOURCE
#define __USE_GNU

#ifndef CLS
#define CLS 64
#endif

#include <dirent.h>
#include <errno.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#if HAVE_LIMITS_H
#include <limits.h>
#endif

#include <ctype.h>
#include <string.h>
#include <strings.h>

#if HAVE_FCNTL_H
#include <fcntl.h>
#endif

#include <time.h>

#if HAVE_SYS_SYSCALL_H
#include <sys/syscall.h>
#endif

#if HAVE_SYSCALL_H
#include <syscall.h>
#endif

#if HAVE_SYS_TYPES_H
#include <sys/types.h> /* for gettid(2) */
#endif

#if HAVE_SCHED_H
#include <sched.h> /* for sched_setaffinity(2) */
#endif

#ifdef HAVE_TYPE_U_LONG_NOT_DEFINED
typedef unsigned long int u_long
#endif
#ifdef HAVE_TYPE_U_INT_NOT_DEFINED
    typedef unsigned int u_int
#endif
#ifdef HAVE_TYPE_U_SHORT_NOT_DEFINED
    typedef unsigned short u_short
#endif
#ifdef HAVE_TYPE_U_CHAR_NOT_DEFINED
    typedef unsigned char u_char
#endif

#if HAVE_SYS_TIME_H
#include <sys/time.h>
#endif

#if HAVE_POLL_H
#include <poll.h>
#endif

#if HAVE_SYS_SIGNAL_H
#include <sys/signal.h>
#endif

#if HAVE_SIGNAL_H
#include <signal.h>
#endif

#if HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif

#if HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif

#if HAVE_SYS_MMAN_H
#include <sys/mman.h>
#endif

#if HAVE_SYS_RANDOM_H
#include <sys/random.h>
#endif

#include <netinet/in.h>

#include <arpa/inet.h>

#if HAVE_NETDB_H
#include <netdb.h>
#endif

#include <pcap/pcap.h>

#ifdef HAVE_UTIME_H
#include <utime.h>
#endif

#ifdef HAVE_LIBGEN_H
#include <libgen.h>
#endif

#ifdef HAVE_GRP_H
#include <grp.h>
#endif

#ifdef HAVE_PWD_H
#include <pwd.h>
#endif

#ifdef HAVE_MAGIC
#include <magic.h>
#endif

/* we need this to stringify the defines which are supplied at compiletime see:
   http://gcc.gnu.org/onlinedocs/gcc-3.4.1/cpp/Stringification.html#Stringification
 */
#define xstr(s) str(s)
#define str(s) #s

/** type for the internal signature id. Since it's used in the matching engine
 *  extensively keeping this as small as possible reduces the overall memory
 *  footprint of the engine. Set to uint32_t if the engine needs to support
 *  more than 64k sigs. */
//#define SigIntId uint16_t
// TODO
#define SigIntId uint32_t

/** same for pattern id's */
// TODO
#define PatIntId uint32_t

/** FreeBSD does not define __WORDSIZE, but it uses __LONG_BIT */
#ifndef __WORDSIZE
#ifdef __LONG_BIT
#define __WORDSIZE __LONG_BIT
#else
#ifdef LONG_BIT
#define __WORDSIZE LONG_BIT
#endif
#endif
#endif

/** Windows does not define __WORDSIZE, but it uses __X86__ */
#ifndef __WORDSIZE
#if defined(__X86__) || defined(_X86_) || defined(_M_IX86)
#define __WORDSIZE 32
#else
#if defined(__X86_64__) || defined(_X86_64_) || defined(__x86_64) || \
    defined(__x86_64__) || defined(__amd64) || defined(__amd64__)
#define __WORDSIZE 64
#endif
#endif
#endif

/** if not succesful yet try the data models */
#ifndef __WORDSIZE
#if defined(_ILP32) || defined(__ILP32__)
#define __WORDSIZE 32
#endif
#if defined(_LP64) || defined(__LP64__)
#define __WORDSIZE 64
#endif
#endif

#ifndef __WORDSIZE
#warning Defaulting to __WORDSIZE 32
#define __WORDSIZE 32
#endif

/** darwin doesn't defined __BYTE_ORDER and friends, but BYTE_ORDER */
#ifndef __BYTE_ORDER
#if defined(BYTE_ORDER)
#define __BYTE_ORDER BYTE_ORDER
#elif defined(__BYTE_ORDER__)
#define __BYTE_ORDER __BYTE_ORDER__
#else
#error "byte order not detected"
#endif
#endif

#ifndef __LITTLE_ENDIAN
#if defined(LITTLE_ENDIAN)
#define __LITTLE_ENDIAN LITTLE_ENDIAN
#elif defined(__ORDER_LITTLE_ENDIAN__)
#define __LITTLE_ENDIAN __ORDER_LITTLE_ENDIAN__
#endif
#endif

#ifndef __BIG_ENDIAN
#if defined(BIG_ENDIAN)
#define __BIG_ENDIAN BIG_ENDIAN
#elif defined(__ORDER_BIG_ENDIAN__)
#define __BIG_ENDIAN __ORDER_BIG_ENDIAN__
#endif
#endif

#if !defined(__LITTLE_ENDIAN) && !defined(__BIG_ENDIAN)
#error "byte order: can't figure out big or little"
#endif

#ifndef MIN
#define MIN(x, y) (((x) < (y)) ? (x) : (y))
#endif

#ifndef MAX
#define MAX(x, y) (((x) < (y)) ? (y) : (x))
#endif

#define BIT_U8(n) ((uint8_t)(1 << (n)))
#define BIT_U16(n) ((uint16_t)(1 << (n)))
#define BIT_U32(n) (1UL << (n))
#define BIT_U64(n) (1ULL << (n))

#define WARN_UNUSED __attribute__((warn_unused_result))

#define NTOHL(x) (uint32_t) ntohl((x))
#define NTOHS(x) (uint16_t) ntohs((x))

/* swap flags if one of them is set, otherwise do nothing. */
#define SWAP_FLAGS(flags, a, b)                      \
    do {                                             \
        if (((flags) & ((a) | (b))) == (a)) {        \
            (flags) &= ~(a);                         \
            (flags) |= (b);                          \
        } else if (((flags) & ((a) | (b))) == (b)) { \
            (flags) &= ~(b);                         \
            (flags) |= (a);                          \
        }                                            \
    } while (0)

#define SWAP_VARS(type, a, b) \
    do {                      \
        type t = (a);         \
        (a) = (b);            \
        (b) = t;              \
    } while (0)

    /** \note update PacketProfileLoggertIdToString if you change anything here
     */
    typedef enum {
        LOGGER_UNDEFINED,

        /* TX loggers first for low logger IDs */
        LOGGER_DNS_TS,
        LOGGER_DNS_TC,
        LOGGER_HTTP,
        LOGGER_TLS_STORE,
        LOGGER_TLS,
        LOGGER_JSON_DNS_TS,
        LOGGER_JSON_DNS_TC,
        LOGGER_JSON_HTTP,
        LOGGER_JSON_SMTP,
        LOGGER_JSON_TLS,
        LOGGER_JSON_NFS,
        LOGGER_JSON_TFTP,
        LOGGER_JSON_FTP,
        LOGGER_JSON_DNP3_TS,
        LOGGER_JSON_DNP3_TC,
        LOGGER_JSON_SSH,
        LOGGER_JSON_SMB,
        LOGGER_JSON_IKEV2,
        LOGGER_JSON_KRB5,
        LOGGER_JSON_DHCP,
        LOGGER_JSON_SNMP,
        LOGGER_JSON_SIP,
        LOGGER_JSON_TEMPLATE_RUST,
        LOGGER_JSON_RFB,
        LOGGER_JSON_TEMPLATE,
        LOGGER_JSON_RDP,
        LOGGER_JSON_DCERPC,

        LOGGER_ALERT_DEBUG,
        LOGGER_ALERT_FAST,
        LOGGER_UNIFIED2,
        LOGGER_ALERT_SYSLOG,
        LOGGER_DROP,
        LOGGER_JSON_ALERT,
        LOGGER_JSON_ANOMALY,
        LOGGER_JSON_DROP,
        LOGGER_FILE_STORE,
        LOGGER_JSON_FILE,
        LOGGER_TCP_DATA,
        LOGGER_JSON_FLOW,
        LOGGER_JSON_NETFLOW,
        LOGGER_STATS,
        LOGGER_JSON_STATS,
        LOGGER_PRELUDE,
        LOGGER_PCAP,
        LOGGER_JSON_METADATA,
        LOGGER_SIZE,
    } LoggerId;

/*
#include <htp/htp.h>
#include "detect-engine-alert.h"
#include "threads.h"
#include "tm-threads-common.h"
#include "util-conf.h"
#include "util-debug.h"
#include "util-error.h"
#include "util-mem.h"
#include "util-optimize.h"
#include "util-path.h"
*/

#ifndef HAVE_STRLCAT
size_t strlcat(char *, const char *src, size_t siz);
#endif
#ifndef HAVE_STRLCPY
size_t strlcpy(char *dst, const char *src, size_t siz);
#endif
#ifndef HAVE_STRPTIME
char *strptime(const char *__restrict, const char *__restrict,
               struct tm *__restrict);
#endif

#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof(arr[0]))

#include <pthread.h>

#ifndef NAME_MAX
#define NAME_MAX 255
#endif

#ifdef __cplusplus
}
#endif

#endif
