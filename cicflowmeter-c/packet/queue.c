#include "suricata-common.h"

#include "decode.h"

#include "../packet/queue.h"
#include "pkt-var.h"
#include "suricata.h"
#include "threads.h"
#include "util-var.h"

static inline void PacketEnqueueDo(PacketQueue *q, Packet *p) {
    // PacketQueueValidateDebug(q);

    if (p == NULL) return;

    /* more packets in queue */
    if (q->top != NULL) {
        p->prev = NULL;
        p->next = q->top;
        q->top->prev = p;
        q->top = p;
        /* only packet */
    } else {
        p->prev = NULL;
        p->next = NULL;
        q->top = p;
        q->bot = p;
    }
    q->len++;
}

void PacketEnqueueNoLock(PacketQueueNoLock *qnl, Packet *p) {
    PacketQueue *q = (PacketQueue *)qnl;
    PacketEnqueueDo(q, p);
}

void PacketEnqueue(PacketQueue *q, Packet *p) { PacketEnqueueDo(q, p); }

static inline Packet *PacketDequeueDo(PacketQueue *q) {
    // PacketQueueValidateDebug(q);
    /* if the queue is empty there are no packets left. */
    if (q->len == 0) {
        return NULL;
    }
    q->len--;

    /* pull the bottom packet from the queue */
    Packet *p = q->bot;

    /* more packets in queue */
    if (q->bot->prev != NULL) {
        q->bot = q->bot->prev;
        q->bot->next = NULL;
        /* just the one we remove, so now empty */
    } else {
        q->top = NULL;
        q->bot = NULL;
    }

    p->next = NULL;
    p->prev = NULL;
    return p;
}

Packet *PacketDequeueNoLock(PacketQueueNoLock *qnl) {
    PacketQueue *q = (PacketQueue *)qnl;
    return PacketDequeueDo(q);
}

Packet *PacketDequeue(PacketQueue *q) { return PacketDequeueDo(q); }

PACKET_QUEUE_T *alloc_packet_queue(void) {
    PACKET_QUEUE_T *pq = SCCalloc(1, sizeof(*pq));
    if (pq == NULL) return NULL;
    SCMutexInit(&pq->mutex_q, NULL);
    SCCondInit(&pq->cond_q, NULL);
    return pq;
}

void free_packet_queue(PACKET_QUEUE_T *pq) {
    SCCondDestroy(&pq->cond_q);
    SCMutexDestroy(&pq->mutex_q);
    SCFree(pq);
}
