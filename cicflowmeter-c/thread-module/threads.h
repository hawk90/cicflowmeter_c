#ifndef __CICFLOWMETER_THREAD_MODULE_THREADS_H__
#define __CICFLOWMETER_THREAD_MODULE_THREADS_H__

#ifdef __cplusplus
extern "C" {
#endif

#include "../queue-handler/packetpool.h"
#include "modules.h"
#include "threads_common.h"

#ifdef OS_WIN32
static inline void SleepUsec(uint64_t usec) {
    uint64_t msec = 1;
    if (usec > 1000) {
        msec = usec / 1000;
    }
    Sleep(msec);
}
#define SleepMsec(msec) Sleep((msec))
#else
#define SleepUsec(usec) usleep((usec))
#define SleepMsec(msec) usleep((msec)*1000)
#endif

#define TM_QUEUE_NAME_MAX 16
#define TM_THREAD_NAME_MAX 16

typedef TM_ERROR_T (*TmSlotFunc)(THREAD_T *, PACKET_T *, void *);

typedef struct _TM_SLOT_T {
    /* function pointers */
    union {
        TmSlotFunc SlotFunc;
        TM_ERROR_T (*PktAcqLoop)(THREAD_T *, void *, void *);
        TM_ERROR_T (*Management)(THREAD_T *, void *);
    };
    /** linked list of slots, used when a pipeline has multiple slots
     *  in a single thread. */
    struct _TM_SLOT_T *slot_next;

    ATOMIC_DECLARE(void *, slot_data);

    TM_ERROR_T (*SlotThreadInit)(THREAD_T *, const void *, void **);
    void (*SlotThreadExitPrintStats)(THREAD_T *, void *);
    TM_ERROR_T (*SlotThreadDeinit)(THREAD_T *, void *);

    /* data storage */
    const void *slot_initdata;
    /* store the thread module id */
    int tm_id;

} TM_SLOT_T;

extern THREAD_T *thread_root[TVT_MAX];

extern pthread_mutex_t thread_root_lock;

void TmSlotSetFuncAppend(THREAD_T *, TmModule *, const void *);
TmSlot *TmSlotGetSlotForTM(int);

ThreadVars *TmThreadCreate(const char *, const char *, const char *,
                           const char *, const char *, const char *,
                           void *(fn_p)(void *), int);
ThreadVars *TmThreadCreatePacketHandler(const char *, const char *,
                                        const char *, const char *,
                                        const char *, const char *);
ThreadVars *TmThreadCreateMgmtThread(const char *name, void *(fn_p)(void *),
                                     int);
ThreadVars *TmThreadCreateMgmtThreadByName(const char *name, const char *module,
                                           int mucond);
ThreadVars *TmThreadCreateCmdThreadByName(const char *name, const char *module,
                                          int mucond);
TM_ERROR_T TmThreadSpawn(THREAD_T *);
void TmThreadSetFlags(THREAD_T *, uint8_t);
void TmThreadKillThreadsFamily(int family);
void TmThreadKillThreads(void);
void TmThreadClearThreadsFamily(int family);
void TmThreadAppend(ThreadVars *, int);
void TmThreadSetGroupName(THREAD_T *thread, const char *name);
void TmThreadDumpThreads(void);

TM_ERROR_T TmThreadSetCPUAffinity(THREAD_T *, uint16_t);
TM_ERROR_T TmThreadSetThreadPriority(THREAD_T *, int);
TM_ERROR_T TmThreadSetCPU(THREAD_T *, uint8_t);
TM_ERROR_T TmThreadSetupOptions(THREAD_T *);
void TmThreadSetPrio(ThreadVars *);
int TmThreadGetNbThreads(uint8_t type);

void TmThreadInitMC(THREAD_T *);
void TmThreadTestThreadUnPaused(THREAD_T *);
void TmThreadContinue(THREAD_T *);
void TmThreadContinueThreads(void);
void TmThreadPause(THREAD_T *);
void TmThreadPauseThreads(void);
void TmThreadCheckThreadState(void);
TM_ERROR_T TmThreadWaitOnThreadInit(void);
THREAD_T *TmThreadsGetCallingThread(void);

int TmThreadsCheckFlag(THREAD_T *, uint32_t);
void TmThreadsSetFlag(THREAD_T *, uint32_t);
void TmThreadsUnsetFlag(THREAD_T *, uint32_t);
void TmThreadWaitForFlag(THREAD_T *, uint32_t);

TM_ERROR_T TmThreadsSlotVarRun(THREAD_T *tv, Packet *p, TmSlot *slot);

THREAD_T *TmThreadsGetTVContainingSlot(TmSlot *);
void TmThreadDisablePacketThreads(void);
void TmThreadDisableReceiveThreads(void);
TmSlot *TmThreadGetFirstTmSlotForPartialPattern(const char *);

uint32_t TmThreadCountThreadsByTmmFlags(uint8_t flags);

static inline void TmThreadsCleanDecodePQ(PacketQueueNoLock *pq) {
    while (1) {
        Packet *p = PacketDequeueNoLock(pq);
        if (unlikely(p == NULL)) break;
        TmqhOutputPacketpool(NULL, p);
    }
}

static inline void TmThreadsSlotProcessPktFail(THREAD_T *tv, TmSlot *s,
                                               Packet *p) {
    if (p != NULL) {
        TmqhOutputPacketpool(tv, p);
    }
    TmThreadsCleanDecodePQ(&tv->decode_pq);
    if (tv->stream_pq_local) {
        SCMutexLock(&tv->stream_pq_local->mutex_q);
        TmqhReleasePacketsToPacketPool(tv->stream_pq_local);
        SCMutexUnlock(&tv->stream_pq_local->mutex_q);
    }
    TmThreadsSetFlag(tv, THV_FAILED);
}

/**
 *  \brief Handle timeout from the capture layer. Checks
 *         stream_pq which may have been filled by the flow
 *         manager.
 *  \param s pipeline to run on these packets.
 */
static inline void TmThreadsHandleInjectedPackets(THREAD_T *tv) {
    PacketQueue *pq = tv->stream_pq_local;
    if (pq && pq->len > 0) {
        while (1) {
            SCMutexLock(&pq->mutex_q);
            Packet *extra_p = PacketDequeue(pq);
            SCMutexUnlock(&pq->mutex_q);
            if (extra_p == NULL) break;
            TM_ERROR_T r = TmThreadsSlotVarRun(tv, extra_p, tv->tm_flowworker);
            if (r == TM_ECODE_FAILED) {
                TmThreadsSlotProcessPktFail(tv, tv->tm_flowworker, extra_p);
                break;
            }
            tv->tmqh_out(tv, extra_p);
        }
    }
}

/**
 *  \brief Process the rest of the functions (if any) and queue.
 */
static inline TM_ERROR_T TmThreadsSlotProcessPkt(THREAD_T *tv, TmSlot *s,
                                                 Packet *p) {
    if (s == NULL) {
        tv->tmqh_out(tv, p);
        return TM_ECODE_OK;
    }

    TM_ERROR_T r = TmThreadsSlotVarRun(tv, p, s);
    if (unlikely(r == TM_ECODE_FAILED)) {
        TmThreadsSlotProcessPktFail(tv, s, p);
        return TM_ECODE_FAILED;
    }

    tv->tmqh_out(tv, p);

    TmThreadsHandleInjectedPackets(tv);

    return TM_ECODE_OK;
}

/** \brief inject packet if THV_CAPTURE_INJECT_PKT is set
 *  Allow caller to supply their own packet
 *
 *  Meant for detect reload process that interupts an sleeping capture thread
 *  to force a packet through the engine to complete a reload */
static inline void TmThreadsCaptureInjectPacket(THREAD_T *tv, Packet *p) {
    TmThreadsUnsetFlag(tv, THV_CAPTURE_INJECT_PKT);
    if (p == NULL) p = PacketGetFromQueueOrAlloc();
    if (p != NULL) {
        p->flags |= PKT_PSEUDO_STREAM_END;
        PKT_SET_SRC(p, PKT_SRC_CAPTURE_TIMEOUT);
        if (TmThreadsSlotProcessPkt(tv, tv->tm_flowworker, p) != TM_ECODE_OK) {
            TmqhOutputPacketpool(tv, p);
        }
    }
}

static inline void TmThreadsCaptureHandleTimeout(THREAD_T *tv, Packet *p) {
    if (TmThreadsCheckFlag(tv, THV_CAPTURE_INJECT_PKT)) {
        TmThreadsCaptureInjectPacket(tv, p);
    } else {
        TmThreadsHandleInjectedPackets(tv);

        /* packet could have been passed to us that we won't use
         * return it to the pool. */
        if (p != NULL) tv->tmqh_out(tv, p);
    }
}

void TmThreadsListThreads(void);
int TmThreadsRegisterThread(THREAD_T *tv, const int type);
void TmThreadsUnregisterThread(const int id);
int TmThreadsInjectPacketsById(Packet **, int id);
void TmThreadsInjectFlowById(Flow *f, const int id);

void TmThreadsInitThreadsTimestamp(const struct timeval *ts);
void TmThreadsSetThreadTimestamp(const int id, const struct timeval *ts);
void TmThreadsGetMinimalTimestamp(struct timeval *ts);
uint16_t TmThreadsGetWorkerThreadMax(void);
bool TmThreadsTimeSubsysIsReady(void);

#ifdef __cplusplus
}
#endif

#endif
