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
    PACKET_QUEUE_T *pkt_queue;
    TAILQ_ENTRY(_TM_QUEUE_T) next;
} TM_QUEUE_T;

TM_QUEUE_T *create_tm_queue(const char *name);
TM_QUEUE_T *get_tm_queue_by_name(const char *name);

void tmq_debug_list(void);
void tmq_reset_queues(void);
void tm_validate_queue_state(void);

#ifdef __cplusplus
}
#endif

#endif
