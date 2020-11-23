#ifndef __CICFLOWMETER_THREAD_MODULE_QUEUES_H__
#define __CICFLOWMETER_THREAD_MODULE_QUEUES_H__

#ifdef __cplusplus
extern "C" {
#endif

#include "../packet/queue.h"

typedef struct _TM_QUEUE_T {
    char *name;
    bool is_packet_pool;
    uint16_t id;
    uint16_t reader_cnt;
    uint16_t writer_cnt;
    PacketQueue *pq;
    TAILQ_ENTRY(Tmq_) next;
} TM_QUEUE_T;

TM_QUEUE_T *create_tm_queue(const char *name);
TM_QUEUE_T *get_tm_queue_by_name(const char *name);

void TmqDebugList(void);
void TmqResetQueues(void);
void TmValidateQueueState(void);

#ifdef __cplusplus
}
#endif

#endif
