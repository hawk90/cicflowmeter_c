#ifndef __CICFLOWMETER_THREAD_MODULE_QUEUES_H__
#define __CICFLOWMETER_THREAD_MODULE_QUEUES_H__

#ifdef __cplusplus
extern "C" {
#endif

#include "packet-queue.h"

typedef struct Tmq_ {
    char *name;
    bool is_packet_pool;
    uint16_t id;
    uint16_t reader_cnt;
    uint16_t writer_cnt;
    PacketQueue *pq;
    TAILQ_ENTRY(Tmq_) next;
} TM_QUEUE_T;

Tmq *TmqCreateQueue(const char *name);
Tmq *TmqGetQueueByName(const char *name);

void TmqDebugList(void);
void TmqResetQueues(void);
void TmValidateQueueState(void);

#ifdef __cplusplus
}
#endif

#endif
