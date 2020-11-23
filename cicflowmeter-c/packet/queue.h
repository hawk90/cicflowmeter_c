#ifndef __CICFLOWMETER_PACKET_QUEUE_H__
#define __CICFLOWMETER_PACKET_QUEUE_H__

#ifdef __cplusplus
extern "C" {
#endif

#include "decode.h"

typedef struct _PACKET_QUEUE_NO_LOCK_T {
    struct Packet_ *top;
    struct Packet_ *bot;
    uint32_t len;
} PACKET_QUEUE_NO_LOCK_T;

typedef struct _PACKET_QUEUE_T {
    struct Packet_ *top;
    struct Packet_ *bot;
    uint32_t len;
    pthread_mutex_t mutex_q;
    pthread_condition_t cond_q;
} PACKET_QUEUE_T;

void PacketEnqueueNoLock(PACKET_QUEUE_NO_LOCK_T *qnl, struct Packet_ *p);
void PacketEnqueue(PACKET_QUEUE_T *, struct Packet_ *);

struct Packet_ *PacketDequeueNoLock(PACKET_QUEUE_NO_LOCK_T *qnl);
struct Packet_ *PacketDequeue(PACKET_QUEUE_T *);

PACKET_QUEUE_T *PacketQueueAlloc(void);
void PacketQueueFree(PACKET_QUEUE_T *);

#ifdef __cplusplus
}
#endif

#endif
