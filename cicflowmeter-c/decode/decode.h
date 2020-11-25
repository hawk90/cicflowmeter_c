#ifndef __CICFLOWMETER_DECODE_DECODE_H__
#define __CICFLOWMETER_DECODE_DECODE_H__

#ifdef __cplusplus
extern "C" {
#endif

//#define DBG_THREADS
#define COUNTERS

#include "../common/cicflowmeter_common.h"

#include "ethernet.h"
#include "events.h"
#include "icmpv4.h"
#include "ipv4.h"
#include "null.h"
#include "raw.h"
#include "tcp.h"
#include "udp.h"

/*
#include "../flow/worker.h"
#include "../source/pcap.h"
#include "../thread/thread_t.h"
#include "../utils/debug.h"

#include "action-globals.h"
#include "app-layer-protos.h"
#include "detect-reference.h"
*/

typedef enum {
    CHECKSUM_VALIDATION_DISABLE,
    CHECKSUM_VALIDATION_ENABLE,
    CHECKSUM_VALIDATION_AUTO,
    CHECKSUM_VALIDATION_RXONLY,
    CHECKSUM_VALIDATION_KERNEL,
} CHECK_SUM_VALIDATION_MODE;

enum PKT_SRC_ENUM {
    PKT_SRC_WIRE = 1,
    PKT_SRC_DECODER_IPV4,
    PKT_SRC_DEFRAG,
    PKT_SRC_FFR,
    PKT_SRC_STREAM_TCP_DETECTLOG_FLUSH,
    PKT_SRC_DETECT_RELOAD_FLUSH,
    PKT_SRC_CAPTURE_TIMEOUT,
};

/* forward declarations */
struct DetectionEngineThreadCtx_;
typedef struct AppLayerThreadCtx_ AppLayerThreadCtx;

struct PktPool_;

/* declare these here as they are called from the
 * PACKET_RECYCLE and PACKET_CLEANUP macro's. */
typedef struct AppLayerDecoderEvents_ AppLayerDecoderEvents;
void AppLayerDecoderEventsResetEvents(AppLayerDecoderEvents *events);
void AppLayerDecoderEventsFreeEvents(AppLayerDecoderEvents **events);

/* Address */
typedef struct ADDR_T_ {
    char family;
    union {
        uint32_t address_un_data32[4]; /* type-specific field */
        uint16_t address_un_data16[8]; /* type-specific field */
        uint8_t address_un_data8[16];  /* type-specific field */
        struct in6_addr address_un_in6;
    } address;
} ADDR_T;

#define addr_data32 address.address_un_data32
#define addr_data16 address.address_un_data16
#define addr_data8 address.address_un_data8
#define addr_in6addr address.address_un_in6

#define COPY_ADDRESS(a, b)                         \
    do {                                           \
        (b)->family = (a)->family;                 \
        (b)->addr_data32[0] = (a)->addr_data32[0]; \
        (b)->addr_data32[1] = (a)->addr_data32[1]; \
        (b)->addr_data32[2] = (a)->addr_data32[2]; \
        (b)->addr_data32[3] = (a)->addr_data32[3]; \
    } while (0)

/* Set the IPv4 addresses into the Addrs of the Packet.
 * Make sure p->ip4h is initialized and validated.
 *
 * We set the rest of the struct to 0 so we can
 * prevent using memset. */
#define SET_IPV4_SRC_ADDR(p, a)                                     \
    do {                                                            \
        (a)->family = AF_INET;                                      \
        (a)->addr_data32[0] = (uint32_t)(p)->ip4h->s_ip_src.s_addr; \
        (a)->addr_data32[1] = 0;                                    \
        (a)->addr_data32[2] = 0;                                    \
        (a)->addr_data32[3] = 0;                                    \
    } while (0)

#define SET_IPV4_DST_ADDR(p, a)                                     \
    do {                                                            \
        (a)->family = AF_INET;                                      \
        (a)->addr_data32[0] = (uint32_t)(p)->ip4h->s_ip_dst.s_addr; \
        (a)->addr_data32[1] = 0;                                    \
        (a)->addr_data32[2] = 0;                                    \
        (a)->addr_data32[3] = 0;                                    \
    } while (0)

/* clear the address structure by setting all fields to 0 */
#define CLEAR_ADDR(a)            \
    do {                         \
        (a)->family = 0;         \
        (a)->addr_data32[0] = 0; \
        (a)->addr_data32[1] = 0; \
        (a)->addr_data32[2] = 0; \
        (a)->addr_data32[3] = 0; \
    } while (0)

/* Set the TCP ports into the Ports of the Packet.
 * Make sure p->tcph is initialized and validated. */
#define SET_TCP_SRC_PORT(pkt, prt)                 \
    do {                                           \
        SET_PORT(TCP_GET_SRC_PORT((pkt)), *(prt)); \
    } while (0)

#define SET_TCP_DST_PORT(pkt, prt)                 \
    do {                                           \
        SET_PORT(TCP_GET_DST_PORT((pkt)), *(prt)); \
    } while (0)

/* Set the UDP ports into the Ports of the Packet.
 * Make sure p->udph is initialized and validated. */
#define SET_UDP_SRC_PORT(pkt, prt)                 \
    do {                                           \
        SET_PORT(UDP_GET_SRC_PORT((pkt)), *(prt)); \
    } while (0)
#define SET_UDP_DST_PORT(pkt, prt)                 \
    do {                                           \
        SET_PORT(UDP_GET_DST_PORT((pkt)), *(prt)); \
    } while (0)

#define GET_IPV4_SRC_ADDR_U32(p) ((p)->src.addr_data32[0])
#define GET_IPV4_DST_ADDR_U32(p) ((p)->dst.addr_data32[0])
#define GET_IPV4_SRC_ADDR_PTR(p) ((p)->src.addr_data32)
#define GET_IPV4_DST_ADDR_PTR(p) ((p)->dst.addr_data32)

#define GET_TCP_SRC_PORT(p) ((p)->sp)
#define GET_TCP_DST_PORT(p) ((p)->dp)

#define GET_PKT_LEN(p) ((p)->pktlen)
#define GET_PKT_DATA(p) \
    ((((p)->ext_pkt) == NULL) ? (uint8_t *)((p) + 1) : (p)->ext_pkt)
#define GET_PKT_DIRECT_DATA(p) (uint8_t *)((p) + 1)
#define GET_PKT_DIRECT_MAX_SIZE(p) (default_packet_size)

#define SET_PKT_LEN(p, len)  \
    do {                     \
        (p)->pktlen = (len); \
    } while (0)

/* Port is just a uint16_t */
typedef uint16_t Port;
#define SET_PORT(v, p) ((p) = (v))
#define COPY_PORT(a, b) ((b) = (a))

#define CMP_ADDR(a1, a2)                              \
    (((a1)->addr_data32[3] == (a2)->addr_data32[3] && \
      (a1)->addr_data32[2] == (a2)->addr_data32[2] && \
      (a1)->addr_data32[1] == (a2)->addr_data32[1] && \
      (a1)->addr_data32[0] == (a2)->addr_data32[0]))
#define CMP_PORT(p1, p2) ((p1) == (p2))

/*Given a packet pkt offset to the start of the ip header in a packet
 *We determine the ip version. */
#define GET_IP_RAW_VER(pkt) ((((pkt)[0] & 0xf0) >> 4))

#define IS_IPV4(p) (((p)->ip4h != NULL))
#define IS_IPV6(p) (((p)->ip6h != NULL))
#define IS_TCP(p) (((p)->tcph != NULL))
#define IS_UDP(p) (((p)->udph != NULL))
#define IS_ICMPV4(p) (((p)->icmpv4h != NULL))
#define IS_ICMPV6(p) (((p)->icmpv6h != NULL))
#define IS_TOSERVER(p) (((p)->flowflags & FLOW_PKT_TOSERVER))
#define IS_TOCLIENT(p) (((p)->flowflags & FLOW_PKT_TOCLIENT))

#define IS_VALID_IPH(p) (IS_IPV4((p)) || IS_IPV6((p)))

/* Retrieve proto regardless of IP version */
#define GET_IP_IPPROTO(p)                              \
    (p->proto ? p->proto                               \
              : (IS_IPV4((p)) ? GET_IPV4_IP_PROTO((p)) \
                              : (IS_IPV6((p)) ? GET_IPV6_L4_PROTO((p)) : 0)))

/* structure to store the sids/gids/etc the detection engine
 * found in this packet */
typedef struct _PACKET_ALERT_T {
    SigIntId num;   /* Internal num, used for sorting */
    uint8_t action; /* Internal num, used for sorting */
    uint8_t flags;
    const struct Signature_ *s;
    uint64_t tx_id;
} PACKET_ALERT_T;

/** After processing an alert by the thresholding module, if at
 *  last it gets triggered, we might want to stick the drop action to
 *  the flow on IPS mode */
#define PACKET_ALERT_FLAG_DROP_FLOW 0x01
/** alert was generated based on state */
#define PACKET_ALERT_FLAG_STATE_MATCH 0x02
/** alert was generated based on stream */
#define PACKET_ALERT_FLAG_STREAM_MATCH 0x04
/** alert is in a tx, tx_id set */
#define PACKET_ALERT_FLAG_TX 0x08
/** action was changed by rate_filter */
#define PACKET_ALERT_RATE_FILTER_MODIFIED 0x10

#define PACKET_ALERT_MAX 15

typedef struct _PACKET_ALERTS_T {
    uint16_t cnt;
    PACKET_ALERT_T alerts[PACKET_ALERT_MAX];
    /* single pa used when we're dropping,
     * so we can log it out in the drop log. */
    PACKET_ALERT_T drop;
} PACKET_ALERTS_T;

/** number of decoder events we support per packet. Power of 2 minus 1
 *  for memory layout */
#define PACKET_EVENT_MAX 15

/** data structure to store decoder, defrag and stream events */
typedef struct _PACKET_EVENTS_T {
    uint8_t cnt;                      /**< number of events */
    uint8_t events[PACKET_EVENT_MAX]; /**< array of events */
} PACKET_EVENTS_T;

typedef struct _PACKET_VARS_T {
    uint32_t id;
    struct _PACKET_VAR_T *next; /* right now just implement this as a list,
                                 * in the long run we have thing of something
                                 * faster. */
    uint16_t key_len;
    uint16_t value_len;
    uint8_t *key;
    uint8_t *value;
} PACKET_VARS_T;

#ifdef PROFILING

/** \brief Per TMM stats storage */
typedef struct PktProfilingTmmData_ {
    uint64_t ticks_start;
    uint64_t ticks_end;
#ifdef PROFILE_LOCKING
    uint64_t mutex_lock_cnt;
    uint64_t mutex_lock_wait_ticks;
    uint64_t mutex_lock_contention;
    uint64_t spin_lock_cnt;
    uint64_t spin_lock_wait_ticks;
    uint64_t spin_lock_contention;
    uint64_t rww_lock_cnt;
    uint64_t rww_lock_wait_ticks;
    uint64_t rww_lock_contention;
    uint64_t rwr_lock_cnt;
    uint64_t rwr_lock_wait_ticks;
    uint64_t rwr_lock_contention;
#endif
} PktProfilingTmmData;

typedef struct PktProfilingData_ {
    uint64_t ticks_start;
    uint64_t ticks_end;
} PktProfilingData;

typedef struct PktProfilingDetectData_ {
    uint64_t ticks_start;
    uint64_t ticks_end;
    uint64_t ticks_spent;
} PktProfilingDetectData;

typedef struct PktProfilingAppData_ {
    uint64_t ticks_spent;
} PktProfilingAppData;

typedef struct PktProfilingLoggerData_ {
    uint64_t ticks_start;
    uint64_t ticks_end;
    uint64_t ticks_spent;
} PktProfilingLoggerData;

typedef struct PktProfilingPrefilterEngine_ {
    uint64_t ticks_spent;
} PktProfilingPrefilterEngine;

typedef struct PktProfilingPrefilterData_ {
    PktProfilingPrefilterEngine *engines;
    uint32_t size; /**< array size */
} PktProfilingPrefilterData;

/** \brief Per pkt stats storage */
typedef struct PktProfiling_ {
    uint64_t ticks_start;
    uint64_t ticks_end;

    PktProfilingTmmData tmm[TMM_SIZE];
    PktProfilingData flowworker[PROFILE_FLOWWORKER_SIZE];
    PktProfilingAppData app[ALPROTO_MAX];
    PktProfilingDetectData detect[PROF_DETECT_SIZE];
    PktProfilingLoggerData logger[LOGGER_SIZE];
    uint64_t proto_detect;
} PktProfiling;

#endif /* PROFILING */

/* forward declaration since Packet struct definition requires this */
struct PACKET_QUEUE_T;

/* sizes of the members:
 * src: 17 bytes
 * dst: 17 bytes
 * sp/type: 1 byte
 * dp/code: 1 byte
 * proto: 1 byte
 * recurs: 1 byte
 *
 * sum of above: 38 bytes
 *
 * flow ptr: 4/8 bytes
 * flags: 1 byte
 * flowflags: 1 byte
 *
 * sum of above 44/48 bytes
 */
typedef struct _PACKET_T {
    /* Addresses, Ports and protocol
     * these are on top so we can use
     * the Packet as a hash key */
    ADDR_T src;
    ADDR_T dst;
    union {
        PORT sport;
        // icmp type and code of this packet
        struct {
            uint8_t type;
            uint8_t code;
        } icmp_s;
    };
    union {
        PORT dport;
        // icmp type and code of the expected counterpart (for flows)
        struct {
            uint8_t type;
            uint8_t code;
        } icmp_d;
    };
    uint8_t proto;
    /* make sure we can't be attacked on when the tunneled packet
     * has the exact same tuple as the lower levels */
    uint8_t recursion_level;

    /* flow */
    uint8_t flow_flags;
    /* coccinelle: Packet:flowflags:FLOW_PKT_ */

    /* Pkt Flags */
    uint32_t flags;

    struct FLOW_ *flow;

    /* raw hash value for looking up the flow, will need to modulated to the
     * hash size still */
    uint32_t flow_hash;

    struct timeval ts;

    union {
        /** libpcap vars: shared by Pcap Live mode and Pcap File mode */
        PcapPacketVars pcap_v;
    };

    /** The release function for packet structure and data */
    void (*ReleasePacket)(struct PACKT_T *);
    /** The function triggering bypass the flow in the capture method.
     * Return 1 for success and 0 on error */
    int (*BypassPacketsFlow)(struct PACKT_T *);

    /* pkt vars */
    PACKET_VAR_T *pkt_var;

    /* header pointers */
    EthernetHdr *eth_hdr;

    /* Checksum for IP packets. */
    int32_t level3_comp_csum;
    /* Check sum for TCP, UDP or ICMP packets */
    int32_t level4_comp_csum;

    IPV4Hdr *ip4h;

    /* IPv4 and IPv6 are mutually exclusive */
    union {
        IPV4Vars ip4vars;
    };
    /* Can only be one of TCP, UDP, ICMP at any given time */
    union {
        TCPVars tcp_vars;
        ICMPV4Vars icmpv4vars;
    } l4vars;

#define tcpvars l4vars.tcpvars
#define icmpv4vars l4vars.icmpv4vars
#define icmpv6vars l4vars.icmpv6vars

    TCP_HDR_T *tcp_hdr;

    UDPHdr *udph;

    ICMPV4Hdr *icmpv4h;

    /* ptr to the payload of the packet
     * with it's length. */
    uint8_t *payload;
    uint16_t payload_len;

    /* IPS action to take */
    uint8_t action;

    uint8_t pkt_src;

    /* storage: set to pointer to heap and extended via allocation if necessary
     */
    uint32_t pkt_len;
    uint8_t *ext_pkt;

    /* Incoming interface */
    struct LiveDevice_ *livedev;

    PACKET_ALERTS_T alerts;

    struct Host_ *host_src;
    struct Host_ *host_dst;

    /** packet number in the pcap file, matches wireshark */
    uint64_t pcap_cnt;

    /* engine events */
    PacketEngineEvents events;

    AppLayerDecoderEvents *app_layer_events;

    /* double linked list ptrs */
    struct _PACKET_T *next;
    struct _PACKET_T *prev;

    /** data linktype in host order */
    int datalink;

    /* tunnel/encapsulation handling */
    struct _PACKET_T *root; /* in case of tunnel this is a ptr
                             * to the 'real' packet, the one we
                             * need to set the verdict on --
                             * It should always point to the lowest
                             * packet in a encapsulated packet */

    /** mutex to protect access to:
     *  - tunnel_rtv_cnt
     *  - tunnel_tpr_cnt
     */
    pthread_mutex_t tunnel_mutex;
    /* ready to set verdict counter, only set in root */
    uint16_t tunnel_rtv_cnt;
    /* tunnel packet ref count */
    uint16_t tunnel_tpr_cnt;

    /** tenant id for this packet, if any. If 0 then no tenant was assigned. */
    uint32_t tenant_id;

    /* The Packet pool from which this packet was allocated. Used when returning
     * the packet to its owner's stack. If NULL, then allocated with malloc.
     */
    struct PktPool_ *pool;

} PACKET_T;

/** highest mtu of the interfaces we monitor */
extern int g_default_mtu;
#define DEFAULT_MTU 1500
#define MINIMUM_MTU 68 /**< ipv4 minimum: rfc791 */

#define DEFAULT_PACKET_SIZE (DEFAULT_MTU + ETHERNET_HEADER_LEN)
/* storage: maximum ip packet size + link header */
#define MAX_PAYLOAD_SIZE (IPV6_HEADER_LEN + 65536 + 28)
extern uint32_t default_packet_size;
#define SIZE_OF_PACKET (default_packet_size + sizeof(PACKET_T))

/** \brief Structure to hold thread specific data for all decode modules */
typedef struct _THREAD_VARS_T {
    /** Specific context for udp protocol detection (here atm) */
    AppLayerThreadCtx *app_tctx;

    /** stats/counters */
    uint16_t counter_pkts;
    uint16_t counter_bytes;
    uint16_t counter_avg_pkt_size;
    uint16_t counter_max_pkt_size;
    uint16_t counter_max_mac_addrs_src;
    uint16_t counter_max_mac_addrs_dst;

    uint16_t counter_invalid;

    uint16_t counter_eth;
    uint16_t counter_chdlc;
    uint16_t counter_ipv4;
    uint16_t counter_ipv6;
    uint16_t counter_tcp;
    uint16_t counter_udp;
    uint16_t counter_icmpv4;
    uint16_t counter_icmpv6;

    uint16_t counter_sll;
    uint16_t counter_raw;
    uint16_t counter_null;
    uint16_t counter_sctp;
    uint16_t counter_ppp;
    uint16_t counter_gre;
    uint16_t counter_vlan;
    uint16_t counter_vlan_qinq;
    uint16_t counter_vxlan;
    uint16_t counter_ieee8021ah;
    uint16_t counter_pppoe;
    uint16_t counter_teredo;
    uint16_t counter_mpls;
    uint16_t counter_ipv4inipv6;
    uint16_t counter_ipv6inipv6;
    uint16_t counter_erspan;

    /** frag stats - defrag runs in the context of the decoder. */
    uint16_t counter_defrag_ipv4_fragments;
    uint16_t counter_defrag_ipv4_reassembled;
    uint16_t counter_defrag_ipv4_timeouts;
    uint16_t counter_defrag_ipv6_fragments;
    uint16_t counter_defrag_ipv6_reassembled;
    uint16_t counter_defrag_ipv6_timeouts;
    uint16_t counter_defrag_max_hit;

    uint16_t counter_flow_memcap;

    uint16_t counter_flow_tcp;
    uint16_t counter_flow_udp;
    uint16_t counter_flow_icmp4;
    uint16_t counter_flow_icmp6;

    uint16_t counter_engine_events[DECODE_EVENT_MAX];

    /* thread data for flow logging api: only used at forced
     * flow recycle during lookups */
    void *output_flow_thread_data;

} THREAD_VARS_T;

typedef struct CaptureStats_ {
    uint16_t counter_ips_accepted;
    uint16_t counter_ips_blocked;
    uint16_t counter_ips_rejected;
    uint16_t counter_ips_replaced;

} CaptureStats;

void CaptureStatsUpdate(THREAD_T *thread, CaptureStats *s, const PACKET_T *pkt);
void CaptureStatsSetup(THREAD_T *thread, CaptureStats *s);

#define PACKET_CLEAR_L4VARS(p)                           \
    do {                                                 \
        memset(&(p)->l4vars, 0x00, sizeof((p)->l4vars)); \
    } while (0)

/**
 *  \brief reset these to -1(indicates that the packet is fresh from the queue)
 */
#define PACKET_RESET_CHECKSUMS(p)   \
    do {                            \
        (p)->level3_comp_csum = -1; \
        (p)->level4_comp_csum = -1; \
    } while (0)

/* if p uses extended data, free them */
#define PACKET_FREE_EXTDATA(p)                   \
    do {                                         \
        if ((p)->ext_pkt) {                      \
            if (!((p)->flags & PKT_ZERO_COPY)) { \
                SCFree((p)->ext_pkt);            \
            }                                    \
            (p)->ext_pkt = NULL;                 \
        }                                        \
    } while (0)

/**
 *  \brief Initialize a packet structure for use.
 */
#define PACKET_INITIALIZE(p)                   \
    {                                          \
        SCMutexInit(&(p)->tunnel_mutex, NULL); \
        PACKET_RESET_CHECKSUMS((p));           \
        (p)->livedev = NULL;                   \
    }

#define PACKET_RELEASE_REFS(p)             \
    do {                                   \
        FlowDeReference(&((p)->flow));     \
        HostDeReference(&((p)->host_src)); \
        HostDeReference(&((p)->host_dst)); \
    } while (0)

/**
 *  \brief Recycle a packet structure for reuse.
 */
#define PACKET_REINIT(p)                                         \
    do {                                                         \
        CLEAR_ADDR(&(p)->src);                                   \
        CLEAR_ADDR(&(p)->dst);                                   \
        (p)->sp = 0;                                             \
        (p)->dp = 0;                                             \
        (p)->proto = 0;                                          \
        (p)->recursion_level = 0;                                \
        PACKET_FREE_EXTDATA((p));                                \
        (p)->flags = (p)->flags & PKT_ALLOC;                     \
        (p)->flowflags = 0;                                      \
        (p)->pkt_src = 0;                                        \
        (p)->vlan_id[0] = 0;                                     \
        (p)->vlan_id[1] = 0;                                     \
        (p)->vlan_idx = 0;                                       \
        (p)->ts.tv_sec = 0;                                      \
        (p)->ts.tv_usec = 0;                                     \
        (p)->datalink = 0;                                       \
        (p)->action = 0;                                         \
        if ((p)->pktvar != NULL) {                               \
            PktVarFree((p)->pktvar);                             \
            (p)->pktvar = NULL;                                  \
        }                                                        \
        (p)->ethh = NULL;                                        \
        if ((p)->ip4h != NULL) {                                 \
            CLEAR_IPV4_PACKET((p));                              \
        }                                                        \
        if ((p)->ip6h != NULL) {                                 \
            CLEAR_IPV6_PACKET((p));                              \
        }                                                        \
        if ((p)->tcph != NULL) {                                 \
            CLEAR_TCP_PACKET((p));                               \
        }                                                        \
        if ((p)->udph != NULL) {                                 \
            CLEAR_UDP_PACKET((p));                               \
        }                                                        \
        if ((p)->sctph != NULL) {                                \
            CLEAR_SCTP_PACKET((p));                              \
        }                                                        \
        if ((p)->icmpv4h != NULL) {                              \
            CLEAR_ICMPV4_PACKET((p));                            \
        }                                                        \
        if ((p)->icmpv6h != NULL) {                              \
            CLEAR_ICMPV6_PACKET((p));                            \
        }                                                        \
        (p)->ppph = NULL;                                        \
        (p)->pppoesh = NULL;                                     \
        (p)->pppoedh = NULL;                                     \
        (p)->greh = NULL;                                        \
        (p)->payload = NULL;                                     \
        (p)->payload_len = 0;                                    \
        (p)->BypassPacketsFlow = NULL;                           \
        (p)->pktlen = 0;                                         \
        (p)->alerts.cnt = 0;                                     \
        (p)->alerts.drop.action = 0;                             \
        (p)->pcap_cnt = 0;                                       \
        (p)->tunnel_rtv_cnt = 0;                                 \
        (p)->tunnel_tpr_cnt = 0;                                 \
        (p)->events.cnt = 0;                                     \
        AppLayerDecoderEventsResetEvents((p)->app_layer_events); \
        (p)->next = NULL;                                        \
        (p)->prev = NULL;                                        \
        (p)->root = NULL;                                        \
        (p)->livedev = NULL;                                     \
        PACKET_RESET_CHECKSUMS((p));                             \
        PACKET_PROFILING_RESET((p));                             \
        p->tenant_id = 0;                                        \
    } while (0)

#define PACKET_RECYCLE(p)         \
    do {                          \
        PACKET_RELEASE_REFS((p)); \
        PACKET_REINIT((p));       \
    } while (0)

/**
 *  \brief Cleanup a packet so that we can free it. No memset needed..
 */
#define PACKET_DESTRUCTOR(p)                                     \
    do {                                                         \
        if ((p)->pktvar != NULL) {                               \
            PktVarFree((p)->pktvar);                             \
        }                                                        \
        PACKET_FREE_EXTDATA((p));                                \
        SCMutexDestroy(&(p)->tunnel_mutex);                      \
        AppLayerDecoderEventsFreeEvents(&(p)->app_layer_events); \
        PACKET_PROFILING_RESET((p));                             \
    } while (0)

/* macro's for setting the action
 * handle the case of a root packet
 * for tunnels */

#define PACKET_SET_ACTION(p, a)                                    \
    do {                                                           \
        ((p)->root ? ((p)->root->action = a) : ((p)->action = a)); \
    } while (0)

#define PACKET_ALERT(p) PACKET_SET_ACTION(p, ACTION_ALERT)

#define PACKET_ACCEPT(p) PACKET_SET_ACTION(p, ACTION_ACCEPT)

#define PACKET_DROP(p) PACKET_SET_ACTION(p, ACTION_DROP)

#define PACKET_REJECT(p) PACKET_SET_ACTION(p, (ACTION_REJECT | ACTION_DROP))

#define PACKET_REJECT_DST(p) \
    PACKET_SET_ACTION(p, (ACTION_REJECT_DST | ACTION_DROP))

#define PACKET_REJECT_BOTH(p) \
    PACKET_SET_ACTION(p, (ACTION_REJECT_BOTH | ACTION_DROP))

#define PACKET_PASS(p) PACKET_SET_ACTION(p, ACTION_PASS)

#define PACKET_TEST_ACTION(p, a) \
    ((p)->root ? ((p)->root->action & a) : ((p)->action & a))

#define PACKET_UPDATE_ACTION(p, a)                                   \
    do {                                                             \
        ((p)->root ? ((p)->root->action |= a) : ((p)->action |= a)); \
    } while (0)

#define TUNNEL_INCR_PKT_RTV_NOLOCK(p)                                      \
    do {                                                                   \
        ((p)->root ? (p)->root->tunnel_rtv_cnt++ : (p)->tunnel_rtv_cnt++); \
    } while (0)

#define TUNNEL_INCR_PKT_TPR(p)                                             \
    do {                                                                   \
        SCMutexLock((p)->root ? &(p)->root->tunnel_mutex                   \
                              : &(p)->tunnel_mutex);                       \
        ((p)->root ? (p)->root->tunnel_tpr_cnt++ : (p)->tunnel_tpr_cnt++); \
        SCMutexUnlock((p)->root ? &(p)->root->tunnel_mutex                 \
                                : &(p)->tunnel_mutex);                     \
    } while (0)

#define TUNNEL_PKT_RTV(p) \
    ((p)->root ? (p)->root->tunnel_rtv_cnt : (p)->tunnel_rtv_cnt)
#define TUNNEL_PKT_TPR(p) \
    ((p)->root ? (p)->root->tunnel_tpr_cnt : (p)->tunnel_tpr_cnt)

#define IS_TUNNEL_PKT(p) (((p)->flags & PKT_TUNNEL))
#define SET_TUNNEL_PKT(p) ((p)->flags |= PKT_TUNNEL)
#define UNSET_TUNNEL_PKT(p) ((p)->flags &= ~PKT_TUNNEL)
#define IS_TUNNEL_ROOT_PKT(p) (IS_TUNNEL_PKT(p) && (p)->root == NULL)

#define IS_TUNNEL_PKT_VERDICTED(p) (((p)->flags & PKT_TUNNEL_VERDICTED))
#define SET_TUNNEL_PKT_VERDICTED(p) ((p)->flags |= PKT_TUNNEL_VERDICTED)

PACKET_T *PacketTunnelPktSetup(THREAD_T *thread, THREAD_VARS_T *thread_vars,
                               PACKET_T *parent, const uint8_t *raw,
                               uint32_t len, enum DecodeTunnelProto proto);
PACKET_T *PacketDefragPktSetup(PACKET_T *parent, const uint8_t *raw,
                               uint32_t len, uint8_t proto);
void PacketDefragPktSetupParent(PACKET_T *parent);
void DecodeRegisterPerfCounters(THREAD_VARS_T *, THREAD_T *);
PACKET_T *PacketGetFromQueueOrAlloc(void);
PACKET_T *PacketGetFromAlloc(void);
void PacketDecodeFinalize(THREAD_T *thread, THREAD_VARS_T *thread_vars,
                          PACKET_T *pkt);
void PacketUpdateEngineEventCounters(THREAD_T *thread,
                                     THREAD_VARS_T *thread_vars, PACKET_T *pkt);
void free_packet(PACKET_T *pkt);
void PacketFreeOrRelease(PACKET_T *pkt);
int PacketCallocExtPkt(PACKET_T *pkt, int datalen);
int PacketCopyData(PACKET_T *pkt, const uint8_t *raw, uint32_t pktlen);
int PacketSetData(PACKET_T *pkt, const uint8_t *raw, uint32_t pktlen);
int PacketCopyDataOffset(PACKET_T *pkt, uint32_t offset, const uint8_t *raw,
                         uint32_t datalen);
const char *PktSrcToString(enum PktSrcEnum pkt_src);
void PacketBypassCallback(PACKET_T *pkt);
void PacketSwap(PACKET_T *pkt);

THREAD_VARS_T *alloc_thread_vars(THREAD_T *);
void DecodeThreadVarsFree(THREAD_T *, THREAD_VARS_T *);
void DecodeUpdatePacketCounters(THREAD_T *thread,
                                const THREAD_VARS_T *thread_vars,
                                const PACKET_T *pkt);

/* decoder functions */
int decode_ethernet(THREAD_T *, THREAD_VARS_T *, PACKET_T *, const uint8_t *,
                    uint32_t);
int decode_raw(THREAD_T *, THREAD_VARS_T *, PACKET_T *, const uint8_t *,
               uint32_t);
int decode_ipv4(THREAD_T *, THREAD_VARS_T *, PACKET_T *, const uint8_t *,
                uint16_t);
int decode_icmpv4(THREAD_T *, THREAD_VARS_T *, PACKET_T *, const uint8_t *,
                  uint32_t);
int decode_tcp(THREAD_T *, THREAD_VARS_T *, PACKET_T *, const uint8_t *,
               uint16_t);
int decode_udp(THREAD_T *, THREAD_VARS_T *, PACKET_T *, const uint8_t *,
               uint16_t);
int decode_template(THREAD_T *, THREAD_VARS_T *, PACKET_T *, const uint8_t *,
                    uint32_t);
void AddressDebugPrint(ADDR_T *);

typedef int (*decode_func)(THREAD_T *thread, THREAD_VARS_T *thread_var,
                           PACKET_T *pkt, const uint8_t *raw, uint32_t len);
void DecodeGlobalConfig(void);
void DecodeUnregisterCounters(void);

/** \brief Set the No payload inspection Flag for the packet.
 *
 * \param p Packet to set the flag in
 */
#define DecodeSetNoPayloadInspectionFlag(p)     \
    do {                                        \
        (p)->flags |= PKT_NOPAYLOAD_INSPECTION; \
    } while (0)

#define DecodeUnsetNoPayloadInspectionFlag(p)    \
    do {                                         \
        (p)->flags &= ~PKT_NOPAYLOAD_INSPECTION; \
    } while (0)

/** \brief Set the No packet inspection Flag for the packet.
 *
 * \param p Packet to set the flag in
 */
#define DecodeSetNoPacketInspectionFlag(p)     \
    do {                                       \
        (p)->flags |= PKT_NOPACKET_INSPECTION; \
    } while (0)
#define DecodeUnsetNoPacketInspectionFlag(p)    \
    do {                                        \
        (p)->flags &= ~PKT_NOPACKET_INSPECTION; \
    } while (0)

#define SET_EVENT(p, e)                                  \
    do {                                                 \
        SCLogDebug("p %p event %d", (p), e);             \
        if ((p)->events.cnt < PACKET_ENGINE_EVENT_MAX) { \
            (p)->events.events[(p)->events.cnt] = e;     \
            (p)->events.cnt++;                           \
        }                                                \
    } while (0)

#define SET_INVALID_EVENT(p, e)     \
    do {                            \
        p->flags |= PKT_IS_INVALID; \
        ENGINE_SET_EVENT(p, e);     \
    } while (0)

#define IS_SET_EVENT(p, e)                      \
    ({                                          \
        int r = 0;                              \
        uint8_t u;                              \
        for (u = 0; u < (p)->events.cnt; u++) { \
            if ((p)->events.events[u] == (e)) { \
                r = 1;                          \
                break;                          \
            }                                   \
        }                                       \
        r;                                      \
    })

#ifndef IPPROTO_IPIP
#define IPPROTO_IPIP 4
#endif

/* older libcs don't contain a def for IPPROTO_DCCP
 * inside of <netinet/in.h>
 * if it isn't defined let's define it here.
 */
#ifndef IPPROTO_DCCP
#define IPPROTO_DCCP 33
#endif

/* older libcs don't contain a def for IPPROTO_SCTP
 * inside of <netinet/in.h>
 * if it isn't defined let's define it here.
 */
#ifndef IPPROTO_SCTP
#define IPPROTO_SCTP 132
#endif

#ifndef IPPROTO_MH
#define IPPROTO_MH 135
#endif

/* Host Identity Protocol (rfc 5201) */
#ifndef IPPROTO_HIP
#define IPPROTO_HIP 139
#endif

#ifndef IPPROTO_SHIM6
#define IPPROTO_SHIM6 140
#endif

/* pcap provides this, but we don't want to depend on libpcap */
#ifndef DLT_EN10MB
#define DLT_EN10MB 1
#endif

#ifndef DLT_C_HDLC
#define DLT_C_HDLC 104
#endif

/* taken from pcap's bpf.h */
#ifndef DLT_RAW
#ifdef __OpenBSD__
#define DLT_RAW 14 /* raw IP */
#else
#define DLT_RAW 12 /* raw IP */
#endif
#endif

#ifndef DLT_NULL
#define DLT_NULL 0
#endif

/** libpcap shows us the way to linktype codes
 * \todo we need more & maybe put them in a separate file? */
#define LINKTYPE_NULL DLT_NULL
#define LINKTYPE_ETHERNET DLT_EN10MB
#define LINKTYPE_LINUX_SLL 113
#define LINKTYPE_PPP 9
#define LINKTYPE_RAW DLT_RAW
/* http://www.tcpdump.org/linktypes.html defines DLT_RAW as 101, yet others
 * don't.
 * Libpcap on at least OpenBSD returns 101 as datalink type for RAW pcaps
 * though. */
#define LINKTYPE_RAW2 101
#define LINKTYPE_IPV4 228
#define LINKTYPE_GRE_OVER_IP 778
#define LINKTYPE_CISCO_HDLC DLT_C_HDLC
#define PPP_OVER_GRE 11
#define VLAN_OVER_GRE 13

/*Packet Flags*/
#define PKT_NOPACKET_INSPECTION                                            \
    (1) /**< Flag to indicate that packet header or contents should not be \
           inspected*/
#define PKT_NOPAYLOAD_INSPECTION                                      \
    (1 << 2) /**< Flag to indicate that packet contents should not be \
                inspected*/
#define PKT_ALLOC \
    (1 << 3) /**< Packet was alloc'd this run, needs to be freed */
#define PKT_HAS_TAG (1 << 4) /**< Packet has matched a tag */
#define PKT_STREAM_ADD \
    (1 << 5) /**< Packet payload was added to reassembled stream */
#define PKT_STREAM_EST (1 << 6) /**< Packet is part of established stream */
#define PKT_STREAM_EOF (1 << 7) /**< Stream is in eof state */
#define PKT_HAS_FLOW (1 << 8)
#define PKT_PSEUDO_STREAM_END (1 << 9) /**< Pseudo packet to end the stream */
#define PKT_STREAM_MODIFIED                                                   \
    (1 << 10) /**< Packet is modified by the stream engine, we need to recalc \
                 the csum and reinject/replace */
#define PKT_MARK_MODIFIED (1 << 11) /**< Packet mark is modified */
#define PKT_STREAM_NOPCAPLOG                                                 \
    (1 << 12) /**< Exclude packet from pcap logging as it's part of a stream \
                 that has reassembly depth reached. */

#define PKT_TUNNEL (1 << 13)
#define PKT_TUNNEL_VERDICTED (1 << 14)

#define PKT_IGNORE_CHECKSUM \
    (1 << 15) /**< Packet checksum is not computed (TX packet for example) */
#define PKT_ZERO_COPY \
    (1 << 16) /**< Packet comes from zero copy (ext_pkt must not be freed) */

#define PKT_HOST_SRC_LOOKED_UP (1 << 17)
#define PKT_HOST_DST_LOOKED_UP (1 << 18)

#define PKT_IS_FRAGMENT (1 << 19) /**< Packet is a fragment */
#define PKT_IS_INVALID (1 << 20)
#define PKT_PROFILE (1 << 21)

/** indication by decoder that it feels the packet should be handled by
 *  flow engine: Packet::flow_hash will be set */
#define PKT_WANTS_FLOW (1 << 22)

/** protocol detection done */
#define PKT_PROTO_DETECT_TS_DONE (1 << 23)
#define PKT_PROTO_DETECT_TC_DONE (1 << 24)

#define PKT_REBUILT_FRAGMENT              \
    (1 << 25) /**< Packet is rebuilt from \
               * fragments. */
#define PKT_DETECT_HAS_STREAMDATA \
    (1 << 26) /**< Set by Detect() if raw stream data is available. */

#define PKT_PSEUDO_DETECTLOG_FLUSH \
    (1 << 27) /**< Detect/log flush for protocol upgrade */

/** Packet is part of stream in known bad condition (loss, wrong thread),
 *  so flag it for not setting stream events */
#define PKT_STREAM_NO_EVENTS (1 << 28)

/** \brief return 1 if the packet is a pseudo packet */
#define PKT_IS_PSEUDOPKT(p) \
    ((p)->flags & (PKT_PSEUDO_STREAM_END | PKT_PSEUDO_DETECTLOG_FLUSH))

#define PKT_SET_SRC(p, src_val) ((p)->pkt_src = src_val)

/** \brief return true if *this* packet needs to trigger a verdict.
 *
 *  If we have the root packet, and we have none outstanding,
 *  we can verdict now.
 *
 *  If we have a upper layer packet, it's the only one and root
 *  is already processed, we can verdict now.
 *
 *  Otherwise, a future packet will issue the verdict.
 */
static inline void decode_linklayer(THREAD_T *thread,
                                    THREAD_VARS_T *thread_vars,
                                    const int datalink, PACKET_T *pkt,
                                    const uint8_t *raw, const uint32_t len) {
    /* call the decoder */
    switch (datalink) {
        case LINKTYPE_ETHERNET:
            decode_ethernet(thread, thread_vars, pkt, raw, len);
            break;
        default:
            LOG_ERR_MSG(SC_ERR_DATALINK_UNIMPLEMENTED,
                        "datalink type "
                        "%" PRId32 " not yet supported",
                        datalink);
            break;
    }
}

/** \brief decode network layer
 *  \retval bool true if successful, false if unknown */
static inline bool decode_networklayer(THREAD_T *thread,
                                       THREAD_VARS_T *thread_vars,
                                       const uint16_t proto, PACKET_T *pkt,
                                       const uint8_t *raw, const uint32_t len) {
    switch (proto) {
        case ETHERNET_TYPE_IP: {
            uint16_t ip_len =
                (len < USHRT_MAX) ? (uint16_t)len : (uint16_t)USHRT_MAX;
            decode_ipv4(thread, thread_vars, pkt, raw, ip_len);
            break;
        }
        default:
            LOG_DBG_MSG("unknown ether type: %" PRIx16 "", proto);
            return false;
    }
    return true;
}

#ifdef __cplusplus
}
#endif

#endif
