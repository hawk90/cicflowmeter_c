/* Copyright (C) 2007-2019 Open Information Security Foundation
 *
 * You can copy, redistribute or modify this Program under the terms of
 * the GNU General Public License version 2 as published by the Free
 * Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

/**
 * \file
 *
 * \author Victor Julien <victor@inliniac.net>
 *
 * Thread module management functions
 */

//#include "suricata.h"
#include "queues.h"
#include "../utils/debug.h"
#include "threads.h"

static TAILQ_HEAD(TM_QUEUE_LIST_T_,
                  TM_QUEUE_T_) tmq_list = TAILQ_HEAD_INITIALIZER(tmq_list);

static uint16_t tmq_id = 0;

TM_QUEUE_T *create_tm_queue(const char *name) {
    TM_QUEUE_T *q = SCCalloc(1, sizeof(*q));
    if (q == NULL) FatalError(ERR_MEM_ALLOC, "SCCalloc failed");

    q->name = SCStrdup(name);
    if (q->name == NULL) FatalError(ERR_MEM_ALLOC, "SCStrdup failed");

    q->id = tmq_id++;
    q->is_packet_pool = (strcmp(q->name, "packetpool") == 0);
    if (!q->is_packet_pool) {
        q->pq = PacketQueueAlloc();
        if (q->pq == NULL) FatalError(ERR_MEM_ALLOC, "PacketQueueAlloc failed");
    }

    TAILQ_INSERT_HEAD(&tmq_list, q, next);

    LOG_DBG_MSG("created queue \'%s\', %p", name, q);
    return q;
}

TM_QUEUE_T *get_tm_queue_by_name(const char *name) {
    TM_QUEUE_T *tmq = NULL;
    TAILQ_FOREACH(tmq, &tmq_list, next) {
        if (strcmp(tmq->name, name) == 0) return tmq;
    }
    return NULL;
}

void TmqDebugList(void) {
    TM_QUEUE_T *tmq = NULL;
    TAILQ_FOREACH(tmq, &tmq_list, next) {
        /* get a lock accessing the len */
        pthread_mutex_lock(&tmq->pq->mutex_q);
        printf("TM_QUEUE_TDebugList: id %" PRIu32 ", name \'%s\', len %" PRIu32
               "\n",
               tmq->id, tmq->name, tmq->pq->len);
        pthread_mutex_unlock(&tmq->pq->mutex_q);
    }
}

void TmqResetQueues(void) {
    TM_QUEUE_T *tmq;

    while ((tmq = TAILQ_FIRST(&tmq_list))) {
        TAILQ_REMOVE(&tmq_list, tmq, next);
        if (tmq->name) {
            SCFree(tmq->name);
        }
        if (tmq->pq) {
            PacketQueueFree(tmq->pq);
        }
        SCFree(tmq);
    }
    tmq_id = 0;
}

/**
 * \brief Checks if all the queues allocated so far have at least one reader
 *        and writer.
 */
void TmValidateQueueState(void) {
    bool err = false;

    TM_QUEUE_T *tmq = NULL;
    TAILQ_FOREACH(tmq, &tmq_list, next) {
        pthread_mutex_lock(&tmq->pq->mutex_q);
        if (tmq->reader_cnt == 0) {
            LOG_ERR_MSG(ERR_THREAD_QUEUE,
                        "queue \"%s\" doesn't have a reader (id %d max %u)",
                        tmq->name, tmq->id, tmq_id);
            err = true;
        } else if (tmq->writer_cnt == 0) {
            LOG_ERR_MSG(ERR_THREAD_QUEUE,
                        "queue \"%s\" doesn't have a writer (id %d, max %u)",
                        tmq->name, tmq->id, tmq_id);
            err = true;
        }
        pthread_mutex_unlock(&tmq->pq->mutex_q);

        if (err == true) goto error;
    }

    return;

error:
    FatalError(ERR_FATAL, "fatal error during threading setup");
}
