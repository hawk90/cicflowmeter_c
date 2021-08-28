#ifndef __CICFLOWMETER_THREAD_THREAD_H__
#define __CICFLOWMETER_THREAD_THREAD_H__

#ifdef __cplusplus
extern "C" {
#endif

#include "../packet/queue.h"
#include "../thread-module/queues.h"
#include "../utils/affinity.h"
#include "../utils/atomic.h"
#include "counters.h"

struct _TM_SLOT_T;

/** Thread flags set and read by threads to control the threads */
#define THREAD_USE BIT_U32(0)       /** thread is in use */
#define THREAD_INIT_DONE BIT_U32(1) /** thread initialization done */
#define THREAD_PAUSE BIT_U32(2)     /** signal thread to pause itself */
#define THREAD_PAUSED BIT_U32(3)    /** the thread is paused atm */
#define THREAD_KILL                                          \
    BIT_U32(4) /** thread has been asked to cleanup and exit \
                */
#define THREAD_FAILED \
    BIT_U32(5) /** thread has encountered an error and failed */
#define THREAD_CLOSED BIT_U32(6) /** thread done, should be joinable */
/* used to indicate the thread is going through de-init.  Introduced as more
 * of a hack for solving stream-timeout-shutdown.  Is set by the main thread. */
#define THREAD_DEINIT BIT_U32(7)
#define THREAD_RUNNING_DONE                                     \
    BIT_U32(8) /** thread has completed running and is entering \
                * the de-init phase */
#define THREAD_KILL_PKTACQ BIT_U32(9) /**< flag thread to stop packet acq */
#define THREAD_FLOW_LOOP BIT_U32(10)  /**< thread is in flow shutdown loop */

/** signal thread's capture method to create a fake packet to force through
 *  the engine. This is to force timely handling of maintenance taks like
 *  rule reloads even if no packets are read by the capture method. */
#define THREAD_CAPTURE_INJECT_PKT BIT_U32(11)
#define THREAD_DEAD \
    BIT_U32(12) /**< thread has been joined with pthread_join() */

/** \brief Per thread variable structure */
typedef struct _TRHEAD_T {
    pthread_t t;
    /** function pointer to the function that runs the packet pipeline for
     *  this thread. It is passed directly to pthread_create(), hence the
     *  void pointers in and out. */
    void *(*tm_func)(void *);

    char name[16];
    char *printable_name;
    char *thread_group_name;

    uint8_t thread_setup_flags;

    /** the type of thread as defined in tm-threads.h (TVT_PPT, TVT_MGMT) */
    uint8_t type;

    uint16_t cpu_affinity; /** cpu or core number to set affinity to */
    int thread_priority;   /** priority (real time) for this thread. Look at
                              threads.h */

    /** TmModule::flags for each module part of this thread */
    uint8_t tmm_flags;

    uint8_t cap_flags; /**< Flags to indicate the capabilities of all the
                            TmModules resgitered under this thread */
    uint8_t inq_id;
    uint8_t outq_id;

    /** local id */
    int id;

    /** incoming queue and handler */
    TM_QUEUE_T *inq;
    PACKET_T *(*tmqh_in)(struct _THREAD_VAR_T *);

    ATOMIC_DECLARE(uint32_t, flags);

    /** list of of TmSlot objects together forming the packet pipeline. */
    struct _TM_SLOT_T *tm_slots;

    /** pointer to the flowworker in the pipeline. Used as starting point
     *  for injected packets. Can be NULL if the flowworker is not part
     *  of this thread. */
    struct _TM_SLOT_T *tm_flow_worker;

    /** outgoing queue and handler */
    TM_QUEUE_T *outq;
    void *outctx;
    void (*tmqh_out)(struct _THREAD_T *, PACKET_T *);

    /** queue for decoders to temporarily store extra packets they
     *  generate. */
    PACKET_QUEUE_NO_LOCK_T decode_pq;

    /** Stream packet queue for flow time out injection. Either a pointer to the
     *  workers input queue or to stream_pq_local */
    PACKET_QUEUE_T *stream_pq;
    PACKET_QUEUE_T *stream_pq_local;

    /* counters */

    /** private counter store: counter updates modify this */
    StatsPrivateThreadContext perf_private_ctx;

    /** pointer to the next thread */
    struct _THREAD_T *next;

    /** public counter store: counter syncs update this */
    StatsPublicThreadContext perf_public_ctx;

    /* mutex and condition used by management threads */

    pthread_mutext_t *ctrl_mutex;
    pthread_cond_t *ctrl_cond;

    FLOW_QUEUE_T *flow_queue;

} THREAD_T;

/** Thread setup flags: */
#define THREAD_SET_AFFINITY 0x01 /** CPU/Core affinity */
#define THREAD_SET_PRIORITY 0x02 /** Real time priority */
#define THREAD_SET_AFFTYPE 0x04  /** Priority and affinity */

#ifdef __cplusplus
}
#endif

#endif
