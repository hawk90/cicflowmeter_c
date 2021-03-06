#include "../common/cicflowmeter_common.h"

#include "decode.h"

#include "../util/debug.h"
#include "../util/error.h"
#include "../util/print.h"
#include "conf.h"
#include "flow-storage.h"
#include "output-flow.h"
#include "output.h"
#include "pkt-var.h"
#include "tm-threads.h"
#include "tmqh-packetpool.h"
#include "util-hash-string.h"
#include "util-mem.h"
#include "util-mpm-ac.h"
#include "util-profiling.h"

uint32_t default_packet_size = 0;
extern bool stats_decoder_events;
extern const char *stats_decoder_events_prefix;
extern bool stats_stream_events;

int decode_tunnel(THREAD_T *thread, THREAD_VARS_T *thread_vars, PACKET_T *pkt,
                  const uint8_t *raw, uint32_t len,
                  enum DecodeTunnelProto proto) {
    switch (proto) {
        case DECODE_TUNNEL_IPV4:
            return decode_ipv4(thread, thread_vars, pkt, raw, len);
        case DECODE_TUNNEL_ETHERNET:
            return decode_ethernet(thread, thread_vars, pkt, raw, len);
        default:
            LOG_DBG_MSG("FIXME: DecodeTunnel: protocol %" PRIu32
                        " not supported.",
                        proto);
            break;
    }
    return TM_ECODE_OK;
}

/**
 * \brief Return a malloced packet.
 */
void free_packet(PACKET_T *pkt) {
    PACKET_DESTRUCTOR(pkt);
    free(pkt);
}

/**
 * \brief Finalize decoding of a packet
 *
 * This function needs to be call at the end of decode
 * functions when decoding has been successful.
 *
 */
void finalize_decode(TRHEAD_T *thread, THREAD_VARS_T *thread_vars,
                     PACKET_T *pkt) {
    if (pkt->flags & PKT_IS_INVALID) {
        StatsIncr(thread, thread_vars->counter_invalid);
    }
}

void PacketUpdateEngineEventCounters(ThreadVars *tv, DecodeThreadVars *dtv,
                                     Packet *p) {
    for (uint8_t i = 0; i < p->events.cnt; i++) {
        const uint8_t e = p->events.events[i];

        if (e <= DECODE_EVENT_PACKET_MAX && !stats_decoder_events)
            continue;
        else if (e > DECODE_EVENT_PACKET_MAX && !stats_stream_events)
            continue;
        StatsIncr(tv, dtv->counter_engine_events[e]);
    }
}

/**
 * \brief Get a malloced packet.
 *
 * \retval p packet, NULL on error
 */
PACKET_T *get_from_alloc(void) {
    PACKET *p = malloc(SIZE_OF_PACKET);
    if (unlikely(pkt == NULL)) {
        return NULL;
    }

    memset(pkt, 0, SIZE_OF_PACKET);
    PACKET_INITIALIZE(pkt);
    pkt->ReleasePacket = PacketFree;
    pkt->flags |= PKT_ALLOC;

    LOG_DBG_MSG("allocated a new packet only using alloc...");

    PACKET_PROFILING_START(pkt);
    return pkt;
}

/**
 * \brief Return a packet to where it was allocated.
 */
void free_or_release(PACKET_T *pkt) {
    if (pkt->flags & PKT_ALLOC)
        PacketFree(pkt);
    else
        PacketPoolReturnPacket(pkt);
}

/**
 *  \brief Get a packet. We try to get a packet from the packetpool first, but
 *         if that is empty we alloc a packet that is free'd again after
 *         processing.
 *
 *  \retval p packet, NULL on error
 */
PACKET_T *get_from_queue_or_alloc(void) {
    /* try the pool first */
    PACKET_T *pkt = PacketPoolGetPacket();

    if (p == NULL) {
        /* non fatal, we're just not processing a packet then */
        p = get_from_alloc();
    } else {
        PACKET_PROFILING_START(p);
    }

    return p;
}

inline int calloc_ext_pkt(PACKET_T *pkt, int len) {
    if (!pkt->ext_pkt) {
        pkt->ext_pkt = calloc(1, datalen);
        if (unlikely(pkt->ext_pkt == NULL)) {
            SET_PKT_LEN(pkt, 0);
            return -1;
        }
    }
    return 0;
}

/**
 *  \brief Copy data to Packet payload at given offset
 *
 * This function copies data/payload to a Packet. It uses the
 * space allocated at Packet creation (pointed by Packet::pkt)
 * or allocate some memory (pointed by Packet::ext_pkt) if the
 * data size is to big to fit in initial space (of size
 * default_packet_size).
 *
 *  \param Pointer to the Packet to modify
 *  \param Offset of the copy relatively to payload of Packet
 *  \param Pointer to the data to copy
 *  \param Length of the data to copy
 */
inline int copy_data_offset(PACKET_T *pkt, uint32_t offset, const uint8_t *raw,
                            uint32_t len) {
    if (unlikely(offset + len > MAX_PAYLOAD_SIZE)) {
        /* too big */
        return -1;
    }

    /* Do we have already an packet with allocated data */
    if (!pkt->ext_pkt) {
        uint32_t newsize = offset + len;
        // check overflow
        if (newsize < offset) return -1;
        if (newsize <= default_packet_size) {
            /* data will fit in memory allocated with packet */
            memcpy(GET_PKT_DIRECT_DATA(pkt) + offset, raw, len);
        } else {
            /* here we need a dynamic allocation */
            pkt->ext_pkt = malloc(MAX_PAYLOAD_SIZE);
            if (unlikely(pkt->ext_pkt == NULL)) {
                SET_PKT_LEN(pkt, 0);
                return -1;
            }
            /* copy initial data */
            memcpy(pkt->ext_pkt, GET_PKT_DIRECT_DATA(pkt),
                   GET_PKT_DIRECT_MAX_SIZE(pkt));
            /* copy data as asked */
            memcpy(pkt->ext_pkt + offset, raw, len);
        }
    } else {
        memcpy(pkt->ext_pkt + offset, data, len);
    }
    return 0;
}

/**
 *  \brief Copy data to Packet payload and set packet length
 *
 *  \param Pointer to the Packet to modify
 *  \param Pointer to the data to copy
 *  \param Length of the data to copy
 */
inline int copy_data(PACKET_T *pkt, const uint8_t *raw, uint32_t len) {
    SET_PKT_LEN(pkt, (size_t)len);
    return copy_data_offset(pkt, 0, raw, len);
}

/**
 *  \brief Setup a pseudo packet (tunnel)
 *
 *  \param parent parent packet for this pseudo pkt
 *  \param pkt raw packet data
 *  \param len packet data length
 *  \param proto protocol of the tunneled packet
 *
 *  \retval p the pseudo packet or NULL if out of memory
 */
Packet *PacketTunnelPktSetup(ThreadVars *tv, DecodeThreadVars *dtv,
                             Packet *parent, const uint8_t *pkt, uint32_t len,
                             enum DecodeTunnelProto proto) {
    int ret;

    SCEnter();

    /* get us a packet */
    Packet *p = PacketGetFromQueueOrAlloc();
    if (unlikely(p == NULL)) {
        SCReturnPtr(NULL, "Packet");
    }

    /* copy packet and set length, proto */
    PacketCopyData(p, pkt, len);
    p->recursion_level = parent->recursion_level + 1;
    p->ts.tv_sec = parent->ts.tv_sec;
    p->ts.tv_usec = parent->ts.tv_usec;
    p->datalink = DLT_RAW;
    p->tenant_id = parent->tenant_id;
    p->livedev = parent->livedev;

    /* set the root ptr to the lowest layer */
    if (parent->root != NULL)
        p->root = parent->root;
    else
        p->root = parent;

    /* tell new packet it's part of a tunnel */
    SET_TUNNEL_PKT(p);

    ret = DecodeTunnel(tv, dtv, p, GET_PKT_DATA(p), GET_PKT_LEN(p), proto);

    if (unlikely(ret != TM_ECODE_OK) ||
        (proto == DECODE_TUNNEL_IPV6_TEREDO && (p->flags & PKT_IS_INVALID))) {
        /* Not a (valid) tunnel packet */
        SCLogDebug("tunnel packet is invalid");

        p->root = NULL;
        UNSET_TUNNEL_PKT(p);
        TmqhOutputPacketpool(tv, p);
        SCReturnPtr(NULL, "Packet");
    }

    /* tell parent packet it's part of a tunnel */
    SET_TUNNEL_PKT(parent);

    /* increment tunnel packet refcnt in the root packet */
    TUNNEL_INCR_PKT_TPR(p);

    /* disable payload (not packet) inspection on the parent, as the payload
     * is the packet we will now run through the system separately. We do
     * check it against the ip/port/other header checks though */
    DecodeSetNoPayloadInspectionFlag(parent);
    SCReturnPtr(p, "Packet");
}

/**
 *  \brief Setup a pseudo packet (reassembled frags)
 *
 *  Difference with PacketPseudoPktSetup is that this func doesn't increment
 *  the recursion level. It needs to be on the same level as the frags because
 *  we run the flow engine against this and we need to get the same flow.
 *
 *  \param parent parent packet for this pseudo pkt
 *  \param pkt raw packet data
 *  \param len packet data length
 *  \param proto protocol of the tunneled packet
 *
 *  \retval p the pseudo packet or NULL if out of memory
 */
Packet *PacketDefragPktSetup(Packet *parent, const uint8_t *pkt, uint32_t len,
                             uint8_t proto) {
    SCEnter();

    /* get us a packet */
    Packet *p = PacketGetFromQueueOrAlloc();
    if (unlikely(p == NULL)) {
        SCReturnPtr(NULL, "Packet");
    }

    /* set the root ptr to the lowest layer */
    if (parent->root != NULL)
        p->root = parent->root;
    else
        p->root = parent;

    /* copy packet and set lenght, proto */
    if (pkt && len) {
        PacketCopyData(p, pkt, len);
    }
    p->recursion_level = parent->recursion_level; /* NOT incremented */
    p->ts.tv_sec = parent->ts.tv_sec;
    p->ts.tv_usec = parent->ts.tv_usec;
    p->datalink = DLT_RAW;
    p->tenant_id = parent->tenant_id;
    /* tell new packet it's part of a tunnel */
    SET_TUNNEL_PKT(p);
    p->vlan_id[0] = parent->vlan_id[0];
    p->vlan_id[1] = parent->vlan_id[1];
    p->vlan_idx = parent->vlan_idx;
    p->livedev = parent->livedev;

    SCReturnPtr(p, "Packet");
}

/**
 *  \brief inform defrag "parent" that a pseudo packet is
 *         now associated to it.
 */
void PacketDefragPktSetupParent(Packet *parent) {
    /* tell parent packet it's part of a tunnel */
    SET_TUNNEL_PKT(parent);

    /* increment tunnel packet refcnt in the root packet */
    TUNNEL_INCR_PKT_TPR(parent);

    /* disable payload (not packet) inspection on the parent, as the payload
     * is the packet we will now run through the system separately. We do
     * check it against the ip/port/other header checks though */
    DecodeSetNoPayloadInspectionFlag(parent);
}

/**
 *  \note if p->flow is set, the flow is locked
 */
void PacketBypassCallback(Packet *p) {
    if (PKT_IS_PSEUDOPKT(p)) return;

#ifdef CAPTURE_OFFLOAD
    /* Don't try to bypass if flow is already out or
     * if we have failed to do it once */
    if (p->flow) {
        int state = p->flow->flow_state;
        if ((state == FLOW_STATE_LOCAL_BYPASSED) ||
            (state == FLOW_STATE_CAPTURE_BYPASSED)) {
            return;
        }
        FlowBypassInfo *fc = SCCalloc(sizeof(FlowBypassInfo), 1);
        if (fc) {
            FlowSetStorageById(p->flow, GetFlowBypassInfoID(), fc);
        } else {
            return;
        }
    }
    if (p->BypassPacketsFlow && p->BypassPacketsFlow(p)) {
        if (p->flow) {
            FlowUpdateState(p->flow, FLOW_STATE_CAPTURE_BYPASSED);
        }
    } else {
        if (p->flow) {
            FlowUpdateState(p->flow, FLOW_STATE_LOCAL_BYPASSED);
        }
    }
#else /* CAPTURE_OFFLOAD */
    if (p->flow) {
        int state = p->flow->flow_state;
        if (state == FLOW_STATE_LOCAL_BYPASSED) return;
        FlowUpdateState(p->flow, FLOW_STATE_LOCAL_BYPASSED);
    }
#endif
}

/** \brief switch direction of a packet */
void swap_packet(PACKET_T *pkt) {
    if (IS_TOSERVER(pkt)) {
        pkt->flow_flags &= ~FLOW_PKT_TOSERVER;
        pkt->flow_flags |= FLOW_PKT_TOCLIENT;

        if (pkt->flow_flags & FLOW_PKT_TOSERVER_FIRST) {
            pkt->flow_flags &= ~FLOW_PKT_TOSERVER_FIRST;
            pkt->flow_flags |= FLOW_PKT_TOCLIENT_FIRST;
        }
    } else {
        pkt->flow_flags &= ~FLOW_PKT_TOCLIENT;
        pkt->flow_flags |= FLOW_PKT_TOSERVER;

        if (pkt->flow_flags & FLOW_PKT_TOCLIENT_FIRST) {
            pkt->flow_flags &= ~FLOW_PKT_TOCLIENT_FIRST;
            pkt->flow_flags |= FLOW_PKT_TOSERVER_FIRST;
        }
    }
}

/* counter name store */
static HASH_TABLE_T *g_counter_table = NULL;
static pthread_mutex_t g_counter_table_mutex = SCMUTEX_INITIALIZER;

void DecodeUnregisterCounters(void) {
    SCMutexLock(&g_counter_table_mutex);
    if (g_counter_table) {
        HashTableFree(g_counter_table);
        g_counter_table = NULL;
    }
    SCMutexUnlock(&g_counter_table_mutex);
}

void DecodeRegisterPerfCounters(DecodeThreadVars *dtv, ThreadVars *tv) {
    /* register counters */
    dtv->counter_pkts = StatsRegisterCounter("decoder.pkts", tv);
    dtv->counter_bytes = StatsRegisterCounter("decoder.bytes", tv);
    dtv->counter_invalid = StatsRegisterCounter("decoder.invalid", tv);
    dtv->counter_ipv4 = StatsRegisterCounter("decoder.ipv4", tv);
    dtv->counter_ipv6 = StatsRegisterCounter("decoder.ipv6", tv);
    dtv->counter_eth = StatsRegisterCounter("decoder.ethernet", tv);
    dtv->counter_chdlc = StatsRegisterCounter("decoder.chdlc", tv);
    dtv->counter_raw = StatsRegisterCounter("decoder.raw", tv);
    dtv->counter_null = StatsRegisterCounter("decoder.null", tv);
    dtv->counter_sll = StatsRegisterCounter("decoder.sll", tv);
    dtv->counter_tcp = StatsRegisterCounter("decoder.tcp", tv);
    dtv->counter_udp = StatsRegisterCounter("decoder.udp", tv);
    dtv->counter_sctp = StatsRegisterCounter("decoder.sctp", tv);
    dtv->counter_icmpv4 = StatsRegisterCounter("decoder.icmpv4", tv);
    dtv->counter_icmpv6 = StatsRegisterCounter("decoder.icmpv6", tv);
    dtv->counter_ppp = StatsRegisterCounter("decoder.ppp", tv);
    dtv->counter_pppoe = StatsRegisterCounter("decoder.pppoe", tv);
    dtv->counter_geneve = StatsRegisterCounter("decoder.geneve", tv);
    dtv->counter_gre = StatsRegisterCounter("decoder.gre", tv);
    dtv->counter_vlan = StatsRegisterCounter("decoder.vlan", tv);
    dtv->counter_vlan_qinq = StatsRegisterCounter("decoder.vlan_qinq", tv);
    dtv->counter_vxlan = StatsRegisterCounter("decoder.vxlan", tv);
    dtv->counter_ieee8021ah = StatsRegisterCounter("decoder.ieee8021ah", tv);
    dtv->counter_teredo = StatsRegisterCounter("decoder.teredo", tv);
    dtv->counter_ipv4inipv6 = StatsRegisterCounter("decoder.ipv4_in_ipv6", tv);
    dtv->counter_ipv6inipv6 = StatsRegisterCounter("decoder.ipv6_in_ipv6", tv);
    dtv->counter_mpls = StatsRegisterCounter("decoder.mpls", tv);
    dtv->counter_avg_pkt_size =
        StatsRegisterAvgCounter("decoder.avg_pkt_size", tv);
    dtv->counter_max_pkt_size =
        StatsRegisterMaxCounter("decoder.max_pkt_size", tv);
    dtv->counter_max_mac_addrs_src =
        StatsRegisterMaxCounter("decoder.max_mac_addrs_src", tv);
    dtv->counter_max_mac_addrs_dst =
        StatsRegisterMaxCounter("decoder.max_mac_addrs_dst", tv);
    dtv->counter_erspan = StatsRegisterMaxCounter("decoder.erspan", tv);
    dtv->counter_flow_memcap = StatsRegisterCounter("flow.memcap", tv);

    dtv->counter_flow_tcp = StatsRegisterCounter("flow.tcp", tv);
    dtv->counter_flow_udp = StatsRegisterCounter("flow.udp", tv);
    dtv->counter_flow_icmp4 = StatsRegisterCounter("flow.icmpv4", tv);
    dtv->counter_flow_icmp6 = StatsRegisterCounter("flow.icmpv6", tv);
    dtv->counter_flow_tcp_reuse = StatsRegisterCounter("flow.tcp_reuse", tv);
    dtv->counter_flow_get_used = StatsRegisterCounter("flow.get_used", tv);
    dtv->counter_flow_get_used_eval =
        StatsRegisterCounter("flow.get_used_eval", tv);
    dtv->counter_flow_get_used_eval_reject =
        StatsRegisterCounter("flow.get_used_eval_reject", tv);
    dtv->counter_flow_get_used_eval_busy =
        StatsRegisterCounter("flow.get_used_eval_busy", tv);
    dtv->counter_flow_get_used_failed =
        StatsRegisterCounter("flow.get_used_failed", tv);

    dtv->counter_flow_spare_sync_avg =
        StatsRegisterAvgCounter("flow.wrk.spare_sync_avg", tv);
    dtv->counter_flow_spare_sync =
        StatsRegisterCounter("flow.wrk.spare_sync", tv);
    dtv->counter_flow_spare_sync_incomplete =
        StatsRegisterCounter("flow.wrk.spare_sync_incomplete", tv);
    dtv->counter_flow_spare_sync_empty =
        StatsRegisterCounter("flow.wrk.spare_sync_empty", tv);

    dtv->counter_defrag_ipv4_fragments =
        StatsRegisterCounter("defrag.ipv4.fragments", tv);
    dtv->counter_defrag_ipv4_reassembled =
        StatsRegisterCounter("defrag.ipv4.reassembled", tv);
    dtv->counter_defrag_ipv4_timeouts =
        StatsRegisterCounter("defrag.ipv4.timeouts", tv);
    dtv->counter_defrag_ipv6_fragments =
        StatsRegisterCounter("defrag.ipv6.fragments", tv);
    dtv->counter_defrag_ipv6_reassembled =
        StatsRegisterCounter("defrag.ipv6.reassembled", tv);
    dtv->counter_defrag_ipv6_timeouts =
        StatsRegisterCounter("defrag.ipv6.timeouts", tv);
    dtv->counter_defrag_max_hit =
        StatsRegisterCounter("defrag.max_frag_hits", tv);

    for (int i = 0; i < DECODE_EVENT_MAX; i++) {
        BUG_ON(i != (int)DEvents[i].code);

        if (i <= DECODE_EVENT_PACKET_MAX && !stats_decoder_events)
            continue;
        else if (i > DECODE_EVENT_PACKET_MAX && !stats_stream_events)
            continue;

        if (i < DECODE_EVENT_PACKET_MAX &&
            strncmp(DEvents[i].event_name, "decoder.", 8) == 0) {
            SCMutexLock(&g_counter_table_mutex);
            if (g_counter_table == NULL) {
                g_counter_table =
                    HashTableInit(256, StringHashFunc, StringHashCompareFunc,
                                  StringHashFreeFunc);
                if (g_counter_table == NULL) {
                    FatalError(SC_ERR_INITIALIZATION,
                               "decoder counter hash "
                               "table init failed");
                }
            }

            char name[256];
            char *dot = strchr(DEvents[i].event_name, '.');
            BUG_ON(!dot);
            snprintf(name, sizeof(name), "%s.%s", stats_decoder_events_prefix,
                     dot + 1);

            const char *found = HashTableLookup(g_counter_table, name, 0);
            if (!found) {
                char *add = SCStrdup(name);
                if (add == NULL)
                    FatalError(SC_ERR_INITIALIZATION,
                               "decoder counter hash "
                               "table name init failed");
                int r = HashTableAdd(g_counter_table, add, 0);
                if (r != 0)
                    FatalError(SC_ERR_INITIALIZATION,
                               "decoder counter hash "
                               "table name add failed");
                found = add;
            }
            dtv->counter_engine_events[i] = StatsRegisterCounter(found, tv);

            SCMutexUnlock(&g_counter_table_mutex);
        } else {
            dtv->counter_engine_events[i] =
                StatsRegisterCounter(DEvents[i].event_name, tv);
        }
    }

    return;
}

void DecodeUpdatePacketCounters(ThreadVars *tv, const DecodeThreadVars *dtv,
                                const Packet *p) {
    StatsIncr(tv, dtv->counter_pkts);
    // StatsIncr(tv, dtv->counter_pkts_per_sec);
    StatsAddUI64(tv, dtv->counter_bytes, GET_PKT_LEN(p));
    StatsAddUI64(tv, dtv->counter_avg_pkt_size, GET_PKT_LEN(p));
    StatsSetUI64(tv, dtv->counter_max_pkt_size, GET_PKT_LEN(p));
}

/**
 *  \brief Debug print function for printing addresses
 *
 *  \param Address object
 *
 *  \todo IPv6
 */
void AddressDebugPrint(Address *a) {
    if (a == NULL) return;

    switch (a->family) {
        case AF_INET: {
            char s[16];
            PrintInet(AF_INET, (const void *)&a->addr_data32[0], s, sizeof(s));
            SCLogDebug("%s", s);
            break;
        }
    }
}

/** \brief Alloc and setup DecodeThreadVars */
THREAD_VARS_T *thread_vars_alloc(THREAD_T *thread) {
    THREAD_VARS_T *thread_vars = NULL;

    if ((thread_vars = malloc(sizeof(THREAD_VARS_T))) == NULL) return NULL;
    memset(thread_vars, 0, sizeof(THREAD_VARS_T));

    dtv->app_tctx = AppLayerGetCtxThread(tv);

    if (OutputFlowLogThreadInit(tv, NULL, &dtv->output_flow_thread_data) !=
        TM_ECODE_OK) {
        LOG_ERR_MSG(SC_ERR_THREAD_INIT,
                    "initializing flow log API for thread failed");
        free_thread_vars(thread, thread_vars);
        return NULL;
    }

    return thread_vars;
}

void free_thread_vars(THREAD_T *thread, THREAD_VARS_T *thread_vars) {
    if (thread_vars != NULL) {
        if (thread_vars->app_tctx != NULL)
            AppLayerDestroyCtxThread(thread_vars->app_tctx);

        if (thread_vars->output_flow_thread_data != NULL)
            OutputFlowLogThreadDeinit(thread,
                                      thread_vars->output_flow_thread_data);

        free(thread_vars);
    }
}

/**
 * \brief Set data for Packet and set length when zero copy is used
 *
 *  \param Pointer to the Packet to modify
 *  \param Pointer to the data
 *  \param Length of the data
 */
inline int set_data(PACKET_T *pkt, const uint8_t *raw, uint32_t len) {
    SET_PKT_LEN(pkt, (size_t)len);
    if (unlikely(!raw)) {
        return -1;
    }
    // ext_pkt cannot be const (because we sometimes copy)
    pkt->ext_pkt = (uint8_t *)raw;
    pkt->flags |= PKT_ZERO_COPY;

    return 0;
}

const char *src_to_string(enum PKT_SRC_ENUM pkt_src) {
    const char *pkt_src_str = "<unknown>";
    switch (pkt_src) {
        case PKT_SRC_WIRE:
            pkt_src_str = "wire/pcap";
            break;
        case PKT_SRC_DECODER_GRE:
            pkt_src_str = "gre tunnel";
            break;
        case PKT_SRC_DECODER_IPV4:
            pkt_src_str = "ipv4 tunnel";
            break;
        case PKT_SRC_DECODER_IPV6:
            pkt_src_str = "ipv6 tunnel";
            break;
        case PKT_SRC_DECODER_TEREDO:
            pkt_src_str = "teredo tunnel";
            break;
        case PKT_SRC_DEFRAG:
            pkt_src_str = "defrag";
            break;
        case PKT_SRC_STREAM_TCP_DETECTLOG_FLUSH:
            pkt_src_str = "stream (detect/log)";
            break;
        case PKT_SRC_FFR:
            pkt_src_str = "stream (flow timeout)";
            break;
        case PKT_SRC_DECODER_GENEVE:
            pkt_src_str = "geneve encapsulation";
            break;
        case PKT_SRC_DECODER_VXLAN:
            pkt_src_str = "vxlan encapsulation";
            break;
        case PKT_SRC_DETECT_RELOAD_FLUSH:
            pkt_src_str = "detect reload flush";
            break;
        case PKT_SRC_CAPTURE_TIMEOUT:
            pkt_src_str = "capture timeout flush";
            break;
    }
    return pkt_src_str;
}

void update_capture_stats(THREAD_T *thread, CAPTURE_STATST *stats,
                          const PACKET_T *pkt) {
    if (unlikely(PACKET_TEST_ACTION(
            pkt, (ACTION_REJECT | ACTION_REJECT_DST | ACTION_REJECT_BOTH)))) {
        StatsIncr(thread, stats->counter_ips_rejected);
    } else if (unlikely(PACKET_TEST_ACTION(pkt, ACTION_DROP))) {
        StatsIncr(thread, stats->counter_ips_blocked);
    } else if (unlikely(pkt->flags & PKT_STREAM_MODIFIED)) {
        StatsIncr(thread, stats->counter_ips_replaced);
    } else {
        StatsIncr(thread, stats->counter_ips_accepted);
    }
}

void setup_capture_stats(THREAD_T *thread, CAPTURE_STATS_T *stats) {
    stats->counter_ips_accepted = StatsRegisterCounter("ips.accepted", thread);
    stats->counter_ips_blocked = StatsRegisterCounter("ips.blocked", thread);
    stats->counter_ips_rejected = StatsRegisterCounter("ips.rejected", thread);
    stats->counter_ips_replaced = StatsRegisterCounter("ips.replaced", thread);
}
