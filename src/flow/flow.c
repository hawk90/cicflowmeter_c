#include "cicflowmeter-c/common/cicflowmeter_common.h"

/* in flow dir*/
#include "decode.h"
#include "flow.h"
#include "hash.h"
#include "queue.h"

#include "tcp"

/* in utils dir*/

#define DEF_FLOW_EMER_RECOVERY 30
#define DEF_FLOW_HASH_SIZE 66536
#define DEF_FLOW_MEM_SIZE (32 * 1024 * 1024) /* 32MB */
#define DEF_FLOW_ALLOC 10000

ATOMIC_DECLARE(uint32_t, g_flow_prune_idx);
ATOMIC_DECLARE(uint32_t, g_flow_flags);
ATOMIC_DECLARE(uint64_t, g_flow_mem_use);

FLOW_PROTO_TIMEOUT g_flow_timeouts_normal[FLOW_PROTO_MAX];
FLOW_PROTO_TIMEOUT g_flow_timeouts_emer[FLOW_PROTO_MAX];
FLOW_PROTO_FREE_FUNC g_flow_free_func[FLOW_PROTO_MAX];

FLOW_QUEUE g_flow_queue;
FLOW_CONFIG g_flow_config;

/**
 *  \brief Update memcap value
 *
 *  \param size new memcap value
 */
int set_flow_mem_cap(uint64_t size) {
    if ((uint64_t)ATOMIC_GET(g_flow_mem_use) < size) {
        ATOMIC_SET(g_flow_config.mem_cap, size);
        return 1;
    }

    return 0;
}

/**
 *  \brief Return memcap value
 *
 *  \retval memcap value
 */
uint64_t get_flow_mem_cap(void) {
    uint64_t mem_cap = ATOMIC_GET(g_flow_config.mem_cap);
    return mem_cap;
}

uint64_t get_flow_mem_use(void) {
    uint64_t mem_use = ATOMIC_GET(g_flow_mem_use);
    return mem_use;
}

/** \brief Make sure we have enough spare flows.
 *
 *  Enforce the prealloc parameter, so keep at least prealloc flows in the
 *  spare queue and free flows going over the limit.
 *
 *  \retval 1 if the queue was properly updated (or if it already was in good
 * shape) \retval 0 otherwise.
 */
int update_spare_flows(void) {
    Enter();
    uint32_t to_alloc = 0, to_free = 0, len = 0;
    uint32_t i = 0;
    FLOW *f = NULL;

    FQLOCK_LOCK(&g_flow_queue);
    len = g_flow_queue.len;
    FQLOCK_UNLOCK(&g_flow_queue);

    if (len < g_flow_config.pre_alloc) {
        to_alloc = g_flow_config.pre_alloc - len;

        for (i = 0; i < to_alloc; i++) {
            f = alloc_flow();
            if (f == NULL) return 0;

            enqueue_flow(&g_flow_queue, f);
        }
    } else if (len > g_flow_config.pre_alloc) {
        to_free = len - g_flow_config.pre_alloc;

        for (i = 0; i < to_free; i++) {
            /* FLOWDequeue locks the queue */
            f = dequeue_flow(&g_flow_queue);
            if (f == NULL) return 1;

            free_flow(f);
        }
    }

    return 1;
}

/** \brief Set the IPOnly scanned flag for 'direction'.
 *
 * \param f FLOW to set the flag in
 * \param direction direction to set the flag in
 */
void set_ip_only_flag(FLOW *f, int direction) {
    direction ? (flow->flags |= FLOW_TO_SERVER_IP_ONLY_SET)
              : (flow->flags |= FLOW_TO_CLIENT_IP_ONLY_SET);
    return;
}

/** \brief Set flag to indicate that flow has alerts
 *
 * \param f flow
 */
void set_flow_has_alerts_flag(FLOW *f) { flow->flags |= FLOW_HAS_ALERTS; }

/** \brief Check if flow has alerts
 *
 * \param f flow
 * \retval 1 has alerts
 * \retval 0 has not alerts
 */
int has_flow_alerts(const FLOW *f) {
    if (flow->flags & FLOW_HAS_ALERTS) {
        return 1;
    }

    return 0;
}

/** \brief Set flag to indicate to change proto for the flow
 *
 * \param f flow
 */
void set_flow_change_proto_flag(FLOW *f) { flow->flags |= FLOW_CHANGE_PROTO; }

/** \brief Unset flag to indicate to change proto for the flow
 *
 * \param f flow
 */
void unset_flow_change_proto_flag(FLOW *f) {
    flow->flags &= ~FLOW_CHANGE_PROTO;
}

/** \brief Check if change proto flag is set for flow
 * \param f flow
 * \retval 1 change proto flag is set
 * \retval 0 change proto flag is not set
 */
int has_flow_change_Proto(FLOW *f) {
    if (flow->flags & FLOW_CHANGE_PROTO) {
        return 1;
    }

    return 0;
}

static inline void swap_flow_flags(FLOW *f) {
    SWAP_FLAGS(flow->flags, FLOW_TO_SRC_SEEN, FLOW_TO_DST_SEEN);
    SWAP_FLAGS(flow->flags, FLOW_TO_SERVER_IP_ONLY_SET,
               FLOW_TO_CLIENT_IP_ONLY_SET);
    SWAP_FLAGS(flow->flags, FLOW_SGH_TO_SERVER, FLOW_SGH_TO_CLIENT);

    SWAP_FLAGS(flow->flags, FLOW_TO_SERVER_DROP_LOGGED,
               FLOW_TO_CLIENT_DROP_LOGGED);

    SWAP_FLAGS(flow->flags, FLOW_PROTO_DETECT_TS_DONE,
               FLOW_PROTO_DETECT_TC_DONE);
}

static inline void swap_flow_file_flags(FLOW *f) {
    SWAP_FLAGS(flow->file_flags, FLOW_FILE_NO_MAGIC_TS, FLOW_FILE_NO_MAGIC_TC);
    SWAP_FLAGS(flow->file_flags, FLOW_FILE_NO_MAGIC_TS, FLOW_FILE_NO_MAGIC_TC);
    SWAP_FLAGS(flow->file_flags, FLOW_FILE_NO_MAGIC_TS, FLOW_FILE_NO_MAGIC_TC);
    SWAP_FLAGS(flow->file_flags, FLOW_FILE_NO_MAGIC_TS, FLOW_FILE_NO_MAGIC_TC);
}

static inline void swap_tcp_stream_flow(FLOW *f) {
    TCP_SESSION *sess = flow->proto_ctx;
    SWAP_VARS(TCP_STREAM, sess->server, sess->client);
    if (sess->data_first_seen_dir & STREAM_TO_SERVER) {
        sess->data_first_seen_dir = STREAM_TO_CLIENT;
    } else if (sess->data_first_seen_dir & STREAM_TO_CLIENT) {
        sess->data_first_seen_dir = STREAM_TO_SERVER;
    }
}

/** \brief swap the flow's direction
 *  \note leaves the 'header' untouched. Interpret that based
 *        on FLOW_DIR_REVERSED flag.
 *  \warning: only valid before applayer parsing started. This
 *            function doesn't swap anything in FLOW::alparser,
 *            FLOW::alstate
 */
void swap_flow(FLOW *f) {
    flow->flags |= FLOW_DIR_REVERSED;

    swap_flow_flags(f);
    swap_flow_file_flags(f);

    if (flow->proto == IP_PROTO_TCP) {
        swap_tcp_stream_flow(f);
    }

    SWAP_VARS(uint8_t, flow->min_ttl_to_server, flow->max_ttl_to_server);
    SWAP_VARS(uint8_t, flow->min_ttl_to_client, flow->max_ttl_to_client);

    SWAP_VARS(const void *, flow->sgh_to_client, flow->sgh_to_server);

    SWAP_VARS(uint32_t, flow->to_dst_pkt_cnt, flow->to_src_pkt_cnt);
    SWAP_VARS(uint64_t, flow->to_dst_byte_cnt, flow->to_src_byte_cnt);
}

/**
 *  \brief determine the direction of the packet compared to the flow
 *  \retval 0 to_server
 *  \retval 1 to_client
 */
int get_packet_direction(const FLOW *flow, const PACKAT *pkt) {
    const int reverse = (flow->flags & FLOW_DIR_REVERSED) != 0;

    if (pkt->proto == IP_PROTO_TCP || pkt->proto == IP_PROTO_UDP) {
        if (!(CMP_PORT(pkt->sport, pkt->dport))) {
            /* update flags and counters */
            if (CMP_PORT(flow->sport, pkt->sport)) {
                return TO_SERVER ^ reverse;
            } else {
                return TO_CLIENT ^ reverse;
            }
        } else {
            if (CMP_ADDR(&flow->src, &pkt->src)) {
                return TO_SERVER ^ reverse;
            } else {
                return TO_CLIENT ^ reverse;
            }
        }
    } else if (pkt->proto == IP_PROTO_ICMP) {
        if (CMP_ADDR(&flow->src, &pkt->src)) {
            return TO_SERVER ^ reverse;
        } else {
            return TO_CLIENT ^ reverse;
        }
    }

    /* default to toserver */
    return TO_SERVER;
}

/**
 *  \brief Check to update "seen" flags
 *
 *  \param p packet
 *
 *  \retval 1 true
 *  \retval 0 false
 */
static inline int update_flow_seen_flag(const PACKAT *p) {
    if (IS_PKT_ICMPV4(p)) {
        if (IS_ICMPV4_ERROR_MSG(p)) {
            return 0;
        }
    }

    return 1;
}

static inline void update_flow_ttl(FLOW *flow, PACKAT *pkt, uint8_t ttl) {
    if (get_packet_direction(flow, pkt) == TO_SERVER) {
        if (flow->min_ttl_to_server == 0) {
            flow->min_ttl_to_server = ttl;
        } else {
            flow->min_ttl_to_server = MIN(flow->min_ttl_to_server, ttl);
        }
        flow->max_ttl_to_server = MAX(flow->max_ttl_to_server, ttl);
    } else {
        if (flow->min_ttl_to_client == 0) {
            flow->min_ttl_to_client = ttl;
        } else {
            flow->min_ttl_to_client = MIN(flow->min_ttl_to_client, ttl);
        }
        flow->max_ttl_to_client = MAX(flow->max_ttl_to_client, ttl);
    }
}

/** \brief Update PACKAT and FLOW
 *
 *  Updates packet and flow based on the new packet.
 *
 *  \param f locked flow
 *  \param p packet
 *
 *  \note overwrites p::flow_flags
 */
void FLOWHandlePACKATUpdate(FLOW *flow, PACKAT *pkt) {
    SCLogDebug("packet %" PRIu64 " -- flow %p", pkt->pcap_cnt, f);

#ifdef CAPTURE_OFFLOAD
    int state = ATOMIC_GET(flow->state);

    if (state != FLOW_STATE_CAPTURE_BYPASSED) {
#endif
        /* update the last seen timestamp of this flow */
        COPY_TIMESTAMP(&pkt->ts, &fflow->last_ts);
#ifdef CAPTURE_OFFLOAD
    } else {
        /* still seeing packet, we downgrade to local bypass */
        if (pkt->ts.tv_sec - flow->last_ts.tv_sec > FLOW_BYPASSED_TIMEOUT / 2) {
            SCLogDebug("Downgrading flow to local bypass");
            COPY_TIMESTAMP(&pkt->ts, &flow->last_ts);
            FLOWUpdateState(flow, FLOW_STATE_LOCAL_BYPASSED);
        } else {
            /* In IPS mode the packet could come from the other interface so it
             * would need to be bypassed */
            if (EngineModeIsIPS()) {
                BypassedFLOWUpdate(f, p);
            }
        }
    }
#endif
    /* update flags and counters */
    if (FLOWGetPACKATDirection(flow, pkt) == TO_SERVER) {
        flow->to_dst_pkt_cnt++;
        flow->to_dst_byte_cnt += GET_PKT_LEN(pkt);
        pkt->flow_flags = FLOW_PKT_TO_SERVER;
        if (!(flow->flags & FLOW_TO_DST_SEEN)) {
            if (FLOWUpdateSeenFlag(pkt)) {
                flow->flags |= FLOW_TO_DST_SEEN;
                pkt->flow_flags |= FLOW_PKT_TO_SERVER_FIRST;
            }
        }
        /* xfer proto detect ts flag to first packet in ts dir */
        if (flow->flags & FLOW_PROTO_DETECT_TS_DONE) {
            flow->flags &= ~FLOW_PROTO_DETECT_TS_DONE;
            pkt->flags |= PKT_PROTO_DETECT_TS_DONE;
        }
    } else {
        flow->to_src_pkt_cnt++;
        flow->to_src_byte_cnt += GET_PKT_LEN(p);
        pkt->flow_flags = FLOW_PKT_TO_CLIENT;
        if (!(flow->flags & FLOW_TO_SRC_SEEN)) {
            if (FLOWUpdateSeenFlag(p)) {
                flow->flags |= FLOW_TO_SRC_SEEN;
                pkt->flow_flags |= FLOW_PKT_TO_CLIENT_FIRST;
            }
        }
        /* xfer proto detect tc flag to first packet in tc dir */
        if (flow->flags & FLOW_PROTO_DETECT_TC_DONE) {
            flow->flags &= ~FLOW_PROTO_DETECT_TC_DONE;
            pkt->flags |= PKT_PROTO_DETECT_TC_DONE;
        }
    }

    if (ATOMIC_GET(flow->flow_state) == FLOW_STATE_ESTABLISHED) {
        SCLogDebug("pkt %p FLOW_PKT_ESTABLISHED", pkt);
        pkt->flow_flags |= FLOW_PKT_ESTABLISHED;

    } else if (flow->proto == IP_PROTO_TCP) {
        TCP_SESSION *sess = (TCP_SESSION *)flow->proto_ctx;
        if (sess != NULL && sess->state >= TCP_ESTABLISHED) {
            pkt->flow_flags |= FLOW_PKT_ESTABLISHED;
        }
    } else if ((flow->flags & (FLOW_TO_DST_SEEN | FLOW_TO_SRC_SEEN)) ==
               (FLOW_TO_DST_SEEN | FLOW_TO_SRC_SEEN)) {
        SCLogDebug("pkt %p FLOW_PKT_ESTABLISHED", pkt);
        pkt->flow_flags |= FLOW_PKT_ESTABLISHED;

        FLOWUpdateState(flow, FLOW_STATE_ESTABLISHED);
    }

    /*set the detection bypass flags*/
    if (flow->flags & FLOW_NOPACKET_INSPECTION) {
        SCLogDebug("setting FLOW_NOPACKET_INSPECTION flag on flow %p", flow);
        DecodeSetNoPACKATInspectionFlag(pkt);
    }
    if (flow->flags & FLOW_NOPAYLOAD_INSPECTION) {
        SCLogDebug("setting FLOW_NOPAYLOAD_INSPECTION flag on flow %p", flow);
        DecodeSetNoPayloadInspectionFlag(pkt);
    }

    /* update flow's ttl fields if needed */
    if (IS_PKT_IPV4(pkt)) {
        FLOWUpdateTTL(flow, pkt, IPV4_GET_IP_TTL(pkt));
    }
}

/** \brief Entry point for packet flow handling
 *
 * This is called for every packet.
 *
 *  \param tv threadvars
 *  \param dtv decode thread vars (for flow output api thread data)
 *  \param p packet to handle flow for
 */
void FLOWHandlePACKAT(ThreadVars *tv, DecodeThreadVars *dtv, PACKAT *p) {
    /* Get this packet's flow from the hash. FLOWHandlePACKAT() will setup
     * a new flow if nescesary. If we get NULL, we're out of flow memory.
     * The returned flow is locked. */
    FLOW *flow = FLOWGetFLOWFromHash(tv, dtv, pkt, &pkt->flow);
    if (flow == NULL) return;

    /* set the flow in the packet */
    pkt->flags |= PKT_HAS_FLOW;
    return;
}

/** \brief initialize the configuration
 *  \warning Not thread safe */
void FLOWInitConfig(char quiet) {
    SCLogDebug("initializing flow engine...");

    memset(&g_flow_config, 0, sizeof(flow_config));
    ATOMIC_INIT(flow_flags);
    ATOMIC_INIT(flow_memuse);
    ATOMIC_INIT(flow_prune_idx);
    ATOMIC_INIT(flow_config.memcap);
    FLOWQueueInit(&flow_spare_q);
    FLOWQueueInit(&flow_recycle_q);

    /* set defaults */
    flow_config.hash_rand = (uint32_t)RandomGet();
    flow_config.hash_size = FLOW_DEFAULT_HASHSIZE;
    flow_config.prealloc = FLOW_DEFAULT_PREALLOC;
    ATOMIC_SET(flow_config.memcap, FLOW_DEFAULT_MEMCAP);

    /* If we have specific config, overwrite the defaults with them,
     * otherwise, leave the default values */
    intmax_t val = 0;
    if (ConfGetInt("flow.emergency-recovery", &val) == 1) {
        if (val <= 100 && val >= 1) {
            flow_config.emergency_recovery = (uint8_t)val;
        } else {
            SCLogError(ERR_INVALID_VALUE,
                       "flow.emergency-recovery must be in the range of 1 and "
                       "100 (as percentage)");
            flow_config.emergency_recovery = FLOW_DEFAULT_EMERGENCY_RECOVERY;
        }
    } else {
        SCLogDebug("flow.emergency-recovery, using default value");
        flow_config.emergency_recovery = FLOW_DEFAULT_EMERGENCY_RECOVERY;
    }

    /* Check if we have memcap and hash_size defined at config */
    const char *conf_val;
    uint32_t configval = 0;

    /** set config values for memcap, prealloc and hash_size */
    uint64_t flow_memcap_copy;
    if ((ConfGet("flow.memcap", &conf_val)) == 1) {
        if (conf_val == NULL) {
            FatalError(ERR_FATAL, "Invalid value for flow.memcap: NULL");
        }

        if (ParseSizeStringU64(conf_val, &flow_memcap_copy) < 0) {
            SCLogError(ERR_SIZE_PARSE,
                       "Error parsing flow.memcap "
                       "from conf file - %s.  Killing engine",
                       conf_val);
            exit(EXIT_FAILURE);
        } else {
            ATOMIC_SET(flow_config.memcap, flow_memcap_copy);
        }
    }
    if ((ConfGet("flow.hash-size", &conf_val)) == 1) {
        if (conf_val == NULL) {
            FatalError(ERR_FATAL, "Invalid value for flow.hash-size: NULL");
        }

        if (StringParseUint32(&configval, 10, strlen(conf_val), conf_val) > 0) {
            flow_config.hash_size = configval;
        }
    }
    if ((ConfGet("flow.prealloc", &conf_val)) == 1) {
        if (conf_val == NULL) {
            FatalError(ERR_FATAL, "Invalid value for flow.prealloc: NULL");
        }

        if (StringParseUint32(&configval, 10, strlen(conf_val), conf_val) > 0) {
            flow_config.prealloc = configval;
        }
    }
    SCLogDebug("FLOW config from suricata.yaml: memcap: %" PRIu64
               ", hash-size: "
               "%" PRIu32 ", prealloc: %" PRIu32,
               ATOMIC_GET(flow_config.memcap), flow_config.hash_size,
               flow_config.prealloc);

    /* alloc hash memory */
    uint64_t hash_size = flow_config.hash_size * sizeof(FLOWBucket);
    if (!(FLOW_CHECK_MEMCAP(hash_size))) {
        SCLogError(
            ERR_FLOW_INIT,
            "allocating flow hash failed: "
            "max flow memcap is smaller than projected hash size. "
            "Memcap: %" PRIu64 ", Hash table size %" PRIu64
            ". Calculate "
            "total hash size by multiplying \"flow.hash-size\" with %" PRIuMAX
            ", "
            "which is the hash bucket size.",
            ATOMIC_GET(flow_config.memcap), hash_size,
            (uintmax_t)sizeof(FLOWBucket));
        exit(EXIT_FAILURE);
    }
    flow_hash =
        SCMallocAligned(flow_config.hash_size * sizeof(FLOWBucket), CLS);
    if (unlikely(flow_hash == NULL)) {
        FatalError(ERR_FATAL,
                   "Fatal error encountered in FLOWInitConfig. Exiting...");
    }
    memset(flow_hash, 0, flow_config.hash_size * sizeof(FLOWBucket));

    uint32_t i = 0;
    for (i = 0; i < flow_config.hash_size; i++) {
        FBLOCK_INIT(&flow_hash[i]);
        ATOMIC_INIT(flow_hash[i].next_ts);
    }
    (void)ATOMIC_ADD(flow_memuse, (flow_config.hash_size * sizeof(FLOWBucket)));

    if (quiet == FALSE) {
        SCLogConfig("allocated %" PRIu64
                    " bytes of memory for the flow hash... "
                    "%" PRIu32 " buckets of size %" PRIuMAX "",
                    ATOMIC_GET(flow_memuse), flow_config.hash_size,
                    (uintmax_t)sizeof(FLOWBucket));
    }

    /* pre allocate flows */
    for (i = 0; i < flow_config.prealloc; i++) {
        if (!(FLOW_CHECK_MEMCAP(sizeof(FLOW) + FLOWStorageSize()))) {
            SCLogError(
                ERR_FLOW_INIT,
                "preallocating flows failed: "
                "max flow memcap reached. Memcap %" PRIu64
                ", "
                "Memuse %" PRIu64 ".",
                ATOMIC_GET(flow_config.memcap),
                ((uint64_t)ATOMIC_GET(flow_memuse) + (uint64_t)sizeof(FLOW)));
            exit(EXIT_FAILURE);
        }

        FLOW *f = FLOWAlloc();
        if (f == NULL) {
            SCLogError(ERR_FLOW_INIT, "preallocating flow failed: %s",
                       strerror(errno));
            exit(EXIT_FAILURE);
        }

        FLOWEnqueue(&flow_spare_q, f);
    }

    if (quiet == FALSE) {
        SCLogConfig("preallocated %" PRIu32 " flows of size %" PRIuMAX "",
                    flow_spare_q.len,
                    (uintmax_t)(sizeof(FLOW) + +FLOWStorageSize()));
        SCLogConfig("flow memory usage: %" PRIu64 " bytes, maximum: %" PRIu64,
                    ATOMIC_GET(flow_memuse), ATOMIC_GET(flow_config.memcap));
    }

    FLOWInitFLOWProto();

    return;
}

/** \brief print some flow stats
 *  \warning Not thread safe */
static void FLOWPrintStats(void) { return; }

/** \brief shutdown the flow engine
 *  \warning Not thread safe */
void FLOWShutdown(void) {
    FLOW *f;
    uint32_t u;

    FLOWPrintStats();

    /* free queues */
    while ((f = FLOWDequeue(&flow_spare_q))) {
        FLOWFree(f);
    }
    while ((f = FLOWDequeue(&flow_recycle_q))) {
        FLOWFree(f);
    }

    /* clear and free the hash */
    if (flow_hash != NULL) {
        /* clean up flow mutexes */
        for (u = 0; u < flow_config.hash_size; u++) {
            f = flow_hash[u].head;
            while (f) {
                DEBUG_VALIDATE_BUG_ON(ATOMIC_GET(flow->use_cnt) != 0);
                FLOW *n = flow->hnext;
                uint8_t proto_map = FLOWGetProtoMapping(flow->proto);
                FLOWClearMemory(f, proto_map);
                FLOWFree(f);
                f = n;
            }

            FBLOCK_DESTROY(&flow_hash[u]);
        }
        SCFreeAligned(flow_hash);
        flow_hash = NULL;
    }
    (void)ATOMIC_SUB(flow_memuse, flow_config.hash_size * sizeof(FLOWBucket));
    FLOWQueueDestroy(&flow_spare_q);
    FLOWQueueDestroy(&flow_recycle_q);
    return;
}

/**
 *  \brief  Function to set the default timeout, free function and flow state
 *          function for all supported flow_proto.
 */

void FLOWInitFLOWProto(void) {
    FLOWTimeoutsInit();

#define SET_DEFAULTS(p, n, e, c, b, ne, ee, ce, be)   \
    flow_timeouts_normal[(p)].new_timeout = (n);      \
    flow_timeouts_normal[(p)].est_timeout = (e);      \
    flow_timeouts_normal[(p)].closed_timeout = (c);   \
    flow_timeouts_normal[(p)].bypassed_timeout = (b); \
    flow_timeouts_emerg[(p)].new_timeout = (ne);      \
    flow_timeouts_emerg[(p)].est_timeout = (ee);      \
    flow_timeouts_emerg[(p)].closed_timeout = (ce);   \
    flow_timeouts_emerg[(p)].bypassed_timeout = (be);

    SET_DEFAULTS(FLOW_PROTO_DEFAULT, FLOW_DEFAULT_NEW_TIMEOUT,
                 FLOW_DEFAULT_EST_TIMEOUT, 0, FLOW_DEFAULT_BYPASSED_TIMEOUT,
                 FLOW_DEFAULT_EMERG_NEW_TIMEOUT, FLOW_DEFAULT_EMERG_EST_TIMEOUT,
                 0, FLOW_DEFAULT_EMERG_BYPASSED_TIMEOUT);
    SET_DEFAULTS(
        FLOW_PROTO_TCP, FLOW_IP_PROTO_TCP_NEW_TIMEOUT,
        FLOW_IP_PROTO_TCP_EST_TIMEOUT, FLOW_IP_PROTO_TCP_CLOSED_TIMEOUT,
        FLOW_IP_PROTO_TCP_BYPASSED_TIMEOUT, FLOW_IP_PROTO_TCP_EMERG_NEW_TIMEOUT,
        FLOW_IP_PROTO_TCP_EMERG_EST_TIMEOUT,
        FLOW_IP_PROTO_TCP_EMERG_CLOSED_TIMEOUT,
        FLOW_DEFAULT_EMERG_BYPASSED_TIMEOUT);
    SET_DEFAULTS(FLOW_PROTO_UDP, FLOW_IP_PROTO_UDP_NEW_TIMEOUT,
                 FLOW_IP_PROTO_UDP_EST_TIMEOUT, 0,
                 FLOW_IP_PROTO_UDP_BYPASSED_TIMEOUT,
                 FLOW_IP_PROTO_UDP_EMERG_NEW_TIMEOUT,
                 FLOW_IP_PROTO_UDP_EMERG_EST_TIMEOUT, 0,
                 FLOW_DEFAULT_EMERG_BYPASSED_TIMEOUT);
    SET_DEFAULTS(FLOW_PROTO_ICMP, FLOW_IP_PROTO_ICMP_NEW_TIMEOUT,
                 FLOW_IP_PROTO_ICMP_EST_TIMEOUT, 0,
                 FLOW_IP_PROTO_ICMP_BYPASSED_TIMEOUT,
                 FLOW_IP_PROTO_ICMP_EMERG_NEW_TIMEOUT,
                 FLOW_IP_PROTO_ICMP_EMERG_EST_TIMEOUT, 0,
                 FLOW_DEFAULT_EMERG_BYPASSED_TIMEOUT);

    flow_freefuncs[FLOW_PROTO_DEFAULT].Freefunc = NULL;
    flow_freefuncs[FLOW_PROTO_TCP].Freefunc = NULL;
    flow_freefuncs[FLOW_PROTO_UDP].Freefunc = NULL;
    flow_freefuncs[FLOW_PROTO_ICMP].Freefunc = NULL;

    /* Let's see if we have custom timeouts defined from config */
    const char *new = NULL;
    const char *established = NULL;
    const char *closed = NULL;
    const char *bypassed = NULL;
    const char *emergency_new = NULL;
    const char *emergency_established = NULL;
    const char *emergency_closed = NULL;
    const char *emergency_bypassed = NULL;

    ConfNode *flow_timeouts = ConfGetNode("flow-timeouts");
    if (flow_timeouts != NULL) {
        ConfNode *proto = NULL;
        uint32_t configval = 0;

        /* Defaults. */
        proto = ConfNodeLookupChild(flow_timeouts, "default");
        if (proto != NULL) {
            new = ConfNodeLookupChildValue(proto, "new");
            established = ConfNodeLookupChildValue(proto, "established");
            closed = ConfNodeLookupChildValue(proto, "closed");
            bypassed = ConfNodeLookupChildValue(proto, "bypassed");
            emergency_new = ConfNodeLookupChildValue(proto, "emergency-new");
            emergency_established =
                ConfNodeLookupChildValue(proto, "emergency-established");
            emergency_closed =
                ConfNodeLookupChildValue(proto, "emergency-closed");
            emergency_bypassed =
                ConfNodeLookupChildValue(proto, "emergency-bypassed");

            if (new != NULL &&
                StringParseUint32(&configval, 10, strlen(new), new) > 0) {
                flow_timeouts_normal[FLOW_PROTO_DEFAULT].new_timeout =
                    configval;
            }
            if (established != NULL &&
                StringParseUint32(&configval, 10, strlen(established),
                                  established) > 0) {
                flow_timeouts_normal[FLOW_PROTO_DEFAULT].est_timeout =
                    configval;
            }
            if (closed != NULL &&
                StringParseUint32(&configval, 10, strlen(closed), closed) > 0) {
                flow_timeouts_normal[FLOW_PROTO_DEFAULT].closed_timeout =
                    configval;
            }
            if (bypassed != NULL &&
                StringParseUint32(&configval, 10, strlen(bypassed), bypassed) >
                    0) {
                flow_timeouts_normal[FLOW_PROTO_DEFAULT].bypassed_timeout =
                    configval;
            }
            if (emergency_new != NULL &&
                StringParseUint32(&configval, 10, strlen(emergency_new),
                                  emergency_new) > 0) {
                flow_timeouts_emerg[FLOW_PROTO_DEFAULT].new_timeout = configval;
            }
            if (emergency_established != NULL &&
                StringParseUint32(&configval, 10, strlen(emergency_established),
                                  emergency_established) > 0) {
                flow_timeouts_emerg[FLOW_PROTO_DEFAULT].est_timeout = configval;
            }
            if (emergency_closed != NULL &&
                StringParseUint32(&configval, 10, strlen(emergency_closed),
                                  emergency_closed) > 0) {
                flow_timeouts_emerg[FLOW_PROTO_DEFAULT].closed_timeout =
                    configval;
            }
            if (emergency_bypassed != NULL &&
                StringParseUint32(&configval, 10, strlen(emergency_bypassed),
                                  emergency_bypassed) > 0) {
                flow_timeouts_emerg[FLOW_PROTO_DEFAULT].bypassed_timeout =
                    configval;
            }
        }

        /* TCP. */
        proto = ConfNodeLookupChild(flow_timeouts, "tcp");
        if (proto != NULL) {
            new = ConfNodeLookupChildValue(proto, "new");
            established = ConfNodeLookupChildValue(proto, "established");
            closed = ConfNodeLookupChildValue(proto, "closed");
            bypassed = ConfNodeLookupChildValue(proto, "bypassed");
            emergency_new = ConfNodeLookupChildValue(proto, "emergency-new");
            emergency_established =
                ConfNodeLookupChildValue(proto, "emergency-established");
            emergency_closed =
                ConfNodeLookupChildValue(proto, "emergency-closed");
            emergency_bypassed =
                ConfNodeLookupChildValue(proto, "emergency-bypassed");

            if (new != NULL &&
                StringParseUint32(&configval, 10, strlen(new), new) > 0) {
                flow_timeouts_normal[FLOW_PROTO_TCP].new_timeout = configval;
            }
            if (established != NULL &&
                StringParseUint32(&configval, 10, strlen(established),
                                  established) > 0) {
                flow_timeouts_normal[FLOW_PROTO_TCP].est_timeout = configval;
            }
            if (closed != NULL &&
                StringParseUint32(&configval, 10, strlen(closed), closed) > 0) {
                flow_timeouts_normal[FLOW_PROTO_TCP].closed_timeout = configval;
            }
            if (bypassed != NULL &&
                StringParseUint32(&configval, 10, strlen(bypassed), bypassed) >
                    0) {
                flow_timeouts_normal[FLOW_PROTO_TCP].bypassed_timeout =
                    configval;
            }
            if (emergency_new != NULL &&
                StringParseUint32(&configval, 10, strlen(emergency_new),
                                  emergency_new) > 0) {
                flow_timeouts_emerg[FLOW_PROTO_TCP].new_timeout = configval;
            }
            if (emergency_established != NULL &&
                StringParseUint32(&configval, 10, strlen(emergency_established),
                                  emergency_established) > 0) {
                flow_timeouts_emerg[FLOW_PROTO_TCP].est_timeout = configval;
            }
            if (emergency_closed != NULL &&
                StringParseUint32(&configval, 10, strlen(emergency_closed),
                                  emergency_closed) > 0) {
                flow_timeouts_emerg[FLOW_PROTO_TCP].closed_timeout = configval;
            }
            if (emergency_bypassed != NULL &&
                StringParseUint32(&configval, 10, strlen(emergency_bypassed),
                                  emergency_bypassed) > 0) {
                flow_timeouts_emerg[FLOW_PROTO_TCP].bypassed_timeout =
                    configval;
            }
        }

        /* UDP. */
        proto = ConfNodeLookupChild(flow_timeouts, "udp");
        if (proto != NULL) {
            new = ConfNodeLookupChildValue(proto, "new");
            established = ConfNodeLookupChildValue(proto, "established");
            bypassed = ConfNodeLookupChildValue(proto, "bypassed");
            emergency_new = ConfNodeLookupChildValue(proto, "emergency-new");
            emergency_established =
                ConfNodeLookupChildValue(proto, "emergency-established");
            emergency_bypassed =
                ConfNodeLookupChildValue(proto, "emergency-bypassed");

            if (new != NULL &&
                StringParseUint32(&configval, 10, strlen(new), new) > 0) {
                flow_timeouts_normal[FLOW_PROTO_UDP].new_timeout = configval;
            }
            if (established != NULL &&
                StringParseUint32(&configval, 10, strlen(established),
                                  established) > 0) {
                flow_timeouts_normal[FLOW_PROTO_UDP].est_timeout = configval;
            }
            if (bypassed != NULL &&
                StringParseUint32(&configval, 10, strlen(bypassed), bypassed) >
                    0) {
                flow_timeouts_normal[FLOW_PROTO_UDP].bypassed_timeout =
                    configval;
            }
            if (emergency_new != NULL &&
                StringParseUint32(&configval, 10, strlen(emergency_new),
                                  emergency_new) > 0) {
                flow_timeouts_emerg[FLOW_PROTO_UDP].new_timeout = configval;
            }
            if (emergency_established != NULL &&
                StringParseUint32(&configval, 10, strlen(emergency_established),
                                  emergency_established) > 0) {
                flow_timeouts_emerg[FLOW_PROTO_UDP].est_timeout = configval;
            }
            if (emergency_bypassed != NULL &&
                StringParseUint32(&configval, 10, strlen(emergency_bypassed),
                                  emergency_bypassed) > 0) {
                flow_timeouts_emerg[FLOW_PROTO_UDP].bypassed_timeout =
                    configval;
            }
        }

        /* ICMP. */
        proto = ConfNodeLookupChild(flow_timeouts, "icmp");
        if (proto != NULL) {
            new = ConfNodeLookupChildValue(proto, "new");
            established = ConfNodeLookupChildValue(proto, "established");
            bypassed = ConfNodeLookupChildValue(proto, "bypassed");
            emergency_new = ConfNodeLookupChildValue(proto, "emergency-new");
            emergency_established =
                ConfNodeLookupChildValue(proto, "emergency-established");
            emergency_bypassed =
                ConfNodeLookupChildValue(proto, "emergency-bypassed");

            if (new != NULL &&
                StringParseUint32(&configval, 10, strlen(new), new) > 0) {
                flow_timeouts_normal[FLOW_PROTO_ICMP].new_timeout = configval;
            }
            if (established != NULL &&
                StringParseUint32(&configval, 10, strlen(established),
                                  established) > 0) {
                flow_timeouts_normal[FLOW_PROTO_ICMP].est_timeout = configval;
            }
            if (bypassed != NULL &&
                StringParseUint32(&configval, 10, strlen(bypassed), bypassed) >
                    0) {
                flow_timeouts_normal[FLOW_PROTO_ICMP].bypassed_timeout =
                    configval;
            }
            if (emergency_new != NULL &&
                StringParseUint32(&configval, 10, strlen(emergency_new),
                                  emergency_new) > 0) {
                flow_timeouts_emerg[FLOW_PROTO_ICMP].new_timeout = configval;
            }
            if (emergency_established != NULL &&
                StringParseUint32(&configval, 10, strlen(emergency_established),
                                  emergency_established) > 0) {
                flow_timeouts_emerg[FLOW_PROTO_ICMP].est_timeout = configval;
            }
            if (emergency_bypassed != NULL &&
                StringParseUint32(&configval, 10, strlen(emergency_bypassed),
                                  emergency_bypassed) > 0) {
                flow_timeouts_emerg[FLOW_PROTO_UDP].bypassed_timeout =
                    configval;
            }
        }
    }

    return;
}

/**
 *  \brief  Function clear the flow memory before queueing it to spare flow
 *          queue.
 *
 *  \param  f           pointer to the flow needed to be cleared.
 *  \param  proto_map   mapped value of the protocol to FLOW_PROTO's.
 */

int clear_flow_memory(FLOW *f, uint8_t proto_map) {
    enter();

    /* call the protocol specific free function if we have one */
    if (flow_free_funcs[proto_map].Free_func != NULL) {
        flow_free_funcs[proto_map].Free_func(flow->proto_ctx);
    }

    free_flow_storage(f);

    recycle_flow(f);

    ReturnInt(1);
}

/**
 *  \brief  Function to set the function to get protocol specific flow state.
 *
 *  \param   proto  protocol of which function is needed to be set.
 *  \param   Free   Function pointer which will be called to free the protocol
 *                  specific memory.
 */

int set_flow_proto_free_func(uint8_t proto, void (*FREE)(void *)) {
    uint8_t proto_map;
    proto_map = get_flow_proto_mapping(proto);

    flow_free_funcs[proto_map].free_func = FREE;

    return 1;
}

AppProto FLOWGetAppProtocol(const FLOW *f) { return flow->alproto; }

void *FLOWGetAppState(const FLOW *f) { return flow->alstate; }

/**
 *  \brief get 'disruption' flags: GAP/DEPTH/PASS
 *  \param f locked flow
 *  \param flags existing flags to be ammended
 *  \retval flags original flags + disrupt flags (if any)
 *  \TODO handle UDP
 */
uint8_t get_glow_disruption_flags(const FLOW *f, uint8_t flags) {
    if (flow->proto != IP_PROTO_TCP) {
        return flags;
    }
    if (flow->proto_ctx == NULL) {
        return flags;
    }

    uint8_t new_flags = flags;
    TCP_SESSION *sess = flow->proto_ctx;
    TCP_STREAM *stream =
        flags & STREAM_TO_SERVER ? &sess->client : &sess->server;

    if (stream->flags & STREAMTCP_STREAM_FLAG_DEPTH_REACHED) {
        newflags |= STREAM_DEPTH;
    }
    if (stream->flags & STREAMTCP_STREAM_FLAG_GAP) {
        newflags |= STREAM_GAP;
    }
    /* todo: handle pass case (also for UDP!) */

    return newflags;
}

void update_flow_state(FLOW *f, enum FLOW_STATE s) {
    /* set the state */
    ATOMIC_SET(flow->flow_state, s);

    if (flow->fb) {
        /* and reset the flow buckup next_ts value so that the flow manager
         * has to revisit this row */
        ATOMIC_SET(flow->fb->next_ts, 0);
    }
}

/**
 * \brief Get flow last time as individual values.
 *
 * Instead of returning a pointer to the timeval copy the timeval
 * parts into output pointers to make it simpler to call from Rust
 * over FFI using only basic data types.
 */
void get_flow_last_ts(FLOW *flow, uint64_t *secs, uint64_t *usecs) {
    *secs = (uint64_t)flow->last_ts.tv_sec;
    *usecs = (uint64_t)flow->last_ts.tv_usec;
}
