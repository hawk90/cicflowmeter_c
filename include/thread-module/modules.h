#ifndef __CICFLOWMETER_THREAD_MODULE_MODULES_H__
#define __CICFLOWMETER_THREAD_MODULE_MODULES_H__

#ifdef __cplusplus
extern "C" {
#endif

#include "../thread/thread_t.h"
#include "threads-common.h"

/* thread flags */
#define TM_FLAG_RECEIVE_TM 0x01
#define TM_FLAG_DECODE_TM 0x02
#define TM_FLAG_STREAM_TM 0x04
#define TM_FLAG_DETECT_TM 0x08
#define TM_FLAG_LOGAPI_TM 0x10 /**< TM is run by Log API */
#define TM_FLAG_MANAGEMENT_TM 0x20
#define TM_FLAG_COMMAND_TM 0x40

typedef TM_ERROR (*ThreadInitFunc)(THREAD_T *, const void *, void **);
typedef TM_ERROR (*ThreadDeinitFunc)(THREAD_T *, void *);
typedef void (*ThreadExitPrintStatsFunc)(THREAD_T *, void *);

typedef struct _TM_MODULES_T {
    const char *name;

    /** thread handling */
    TM_ERROR (*ThreadInit)(THREAD_T *, const void *, void **);
    void (*ThreadExitPrintStats)(THREAD_T *, void *);
    TM_ERROR (*ThreadDeinit)(THREAD_T *, void *);

    /** the packet processing function */
    TM_ERROR (*Func)(THREAD_T *, Packet *, void *);

    TM_ERROR (*PktAcqLoop)(THREAD_T *, void *, void *);

    /** terminates the capture loop in PktAcqLoop */
    TM_ERROR (*PktAcqBreakLoop)(THREAD_T *, void *);

    TM_ERROR (*Management)(THREAD_T *, void *);

    /** global Init/DeInit */
    TM_ERROR (*Init)(void);
    TM_ERROR (*DeInit)(void);
#ifdef UNITTESTS
    void (*RegisterTests)(void);
#endif
    uint8_t cap_flags; /**< Flags to indicate the capability requierment of
                           the given TmModule */
    /* Other flags used by the module */
    uint8_t flags;
} TM_MODULES_T;

extern TM_MODULES_T tmm_modules[TMM_SIZE];

/**
 * Structure that output modules use to maintain private data.
 */
typedef struct OutputCtx_ {
    /** Pointer to data private to the output. */
    void *data;

    /** Pointer to a cleanup function. */
    void (*DeInit)(struct OutputCtx_ *);

    TAILQ_HEAD(, OutputModule_) submodules;
} OutputCtx;

TM_MODULES_T *TmModuleGetByName(const char *name);
TM_MODULES_T *TmModuleGetById(int id);
int TmModuleGetIdByName(const char *name);
int TmModuleGetIDForTM(TmModule *tm);
TM_ERROR TmModuleRegister(char *name,
                          int (*module_func)(THREAD_T *, Packet *, void *));
void TmModuleDebugList(void);
void TmModuleRegisterTests(void);
const char *TmModuleTmmIdToString(TmmId id);

void TmModuleRunInit(void);
void TmModuleRunDeInit(void);

#ifdef __cplusplus
}
#endif

#endif
