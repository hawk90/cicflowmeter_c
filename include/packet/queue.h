#ifndef __CICFLOWMETER_PACKET_QUEUE_H__
#define __CICFLOWMETER_PACKET_QUEUE_H__

#ifdef __cplusplus
extern "C" {
#endif

#include "decode.h"

typedef struct _PACKET_QUEUE_NO_LOCK_T {
    PACKET_T *top;
    PACKET_T *bot;
    uint32_t len;
} PACKET_QUEUE_NO_LOCK_T;

typedef struct _PACKET_QUEUE_T {
    PACKET_T *top;
    PACKET_T *bot;
    uint32_t len;
    pthread_mutex_t mutex_q;
    pthread_condition_t cond_q;
} PACKET_QUEUE_T;

void PacketEnqueueNoLock(PACKET_QUEUE_NO_LOCK_T *qnl, PACKET_T *p);
void PacketEnqueue(PACKET_QUEUE_T *, PACKET_T *);

PACKET_T *PacketDequeueNoLock(PACKET_QUEUE_NO_LOCK_T *qnl);
PACKET_T *PacketDequeue(PACKET_QUEUE_T *);

PACKET_QUEUE_T *alloc_packet_queue(void);
void free_packet_queue(PACKET_QUEUE_T *);

#ifdef __cplusplus
}
#endif

#endif
