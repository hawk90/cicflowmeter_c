#include "../common/cicflowmeter_common.h"

#include "decode.h"
#include "events.h"
#include "icmpv4.h"
#include "ipv4.h"

#include "../flow/flow.h"

/**
 * Note, this is the IP header, plus a bit of the original packet, not the whole
 * thing!
 */
static int DecodePartialIPV4(Packet *p, uint8_t *partial_packet, uint16_t len) {
    /** Check the sizes, the header must fit at least */
    if (len < IPV4_HEADER_LEN) {
        SCLogDebug("DecodePartialIPV4: ICMPV4_IPV4_TRUNC_PKT");
        ENGINE_SET_INVALID_EVENT(p, ICMPV4_IPV4_TRUNC_PKT);
        return -1;
    }

    IPV4Hdr *icmp4_ip4h = (IPV4Hdr *)partial_packet;

    /** Check the embedded version */
    if (IPV4_GET_RAW_VER(icmp4_ip4h) != 4) {
        /** Check the embedded version */
        SCLogDebug(
            "DecodePartialIPV4: ICMPv4 contains Unknown IPV4 version "
            "ICMPV4_IPV4_UNKNOWN_VER");
        ENGINE_SET_INVALID_EVENT(p, ICMPV4_IPV4_UNKNOWN_VER);
        return -1;
    }

    /** We need to fill icmpv4vars */
    p->icmpv4vars.emb_ipv4h = icmp4_ip4h;

    /** Get the IP address from the contained packet */
    p->icmpv4vars.emb_ip4_src = IPV4_GET_RAW_IPSRC(icmp4_ip4h);
    p->icmpv4vars.emb_ip4_dst = IPV4_GET_RAW_IPDST(icmp4_ip4h);

    p->icmpv4vars.emb_ip4_hlen = IPV4_GET_RAW_HLEN(icmp4_ip4h) << 2;

    switch (IPV4_GET_RAW_IPPROTO(icmp4_ip4h)) {
        case IPPROTO_TCP:
            if (len >= IPV4_HEADER_LEN + TCP_HEADER_LEN) {
                p->icmpv4vars.emb_tcph =
                    (TCPHdr *)(partial_packet + IPV4_HEADER_LEN);
                p->icmpv4vars.emb_sport =
                    SCNtohs(p->icmpv4vars.emb_tcph->th_sport);
                p->icmpv4vars.emb_dport =
                    SCNtohs(p->icmpv4vars.emb_tcph->th_dport);
                p->icmpv4vars.emb_ip4_proto = IPPROTO_TCP;

                SCLogDebug(
                    "DecodePartialIPV4: ICMPV4->IPV4->TCP header sport: "
                    "%" PRIu16 " dport %" PRIu16 "",
                    p->icmpv4vars.emb_sport, p->icmpv4vars.emb_dport);
            } else if (len >= IPV4_HEADER_LEN + 4) {
                /* only access th_sport and th_dport */
                TCPHdr *emb_tcph = (TCPHdr *)(partial_packet + IPV4_HEADER_LEN);

                p->icmpv4vars.emb_tcph = NULL;
                p->icmpv4vars.emb_sport = SCNtohs(emb_tcph->th_sport);
                p->icmpv4vars.emb_dport = SCNtohs(emb_tcph->th_dport);
                p->icmpv4vars.emb_ip4_proto = IPPROTO_TCP;
                SCLogDebug(
                    "DecodePartialIPV4: ICMPV4->IPV4->TCP partial header "
                    "sport: "
                    "%" PRIu16 " dport %" PRIu16 "",
                    p->icmpv4vars.emb_sport, p->icmpv4vars.emb_dport);
            } else {
                SCLogDebug(
                    "DecodePartialIPV4: Warning, ICMPV4->IPV4->TCP "
                    "header Didn't fit in the packet!");
                p->icmpv4vars.emb_sport = 0;
                p->icmpv4vars.emb_dport = 0;
            }

            break;
        case IPPROTO_UDP:
            if (len >= IPV4_HEADER_LEN + UDP_HEADER_LEN) {
                p->icmpv4vars.emb_udph =
                    (UDPHdr *)(partial_packet + IPV4_HEADER_LEN);
                p->icmpv4vars.emb_sport =
                    SCNtohs(p->icmpv4vars.emb_udph->uh_sport);
                p->icmpv4vars.emb_dport =
                    SCNtohs(p->icmpv4vars.emb_udph->uh_dport);
                p->icmpv4vars.emb_ip4_proto = IPPROTO_UDP;

                SCLogDebug(
                    "DecodePartialIPV4: ICMPV4->IPV4->UDP header sport: "
                    "%" PRIu16 " dport %" PRIu16 "",
                    p->icmpv4vars.emb_sport, p->icmpv4vars.emb_dport);
            } else {
                SCLogDebug(
                    "DecodePartialIPV4: Warning, ICMPV4->IPV4->UDP "
                    "header Didn't fit in the packet!");
                p->icmpv4vars.emb_sport = 0;
                p->icmpv4vars.emb_dport = 0;
            }

            break;
        case IPPROTO_ICMP:
            if (len >= IPV4_HEADER_LEN + ICMPV4_HEADER_LEN) {
                p->icmpv4vars.emb_icmpv4h =
                    (ICMPV4Hdr *)(partial_packet + IPV4_HEADER_LEN);
                p->icmpv4vars.emb_sport = 0;
                p->icmpv4vars.emb_dport = 0;
                p->icmpv4vars.emb_ip4_proto = IPPROTO_ICMP;

                SCLogDebug("DecodePartialIPV4: ICMPV4->IPV4->ICMP header");
            }

            break;
    }

        /* debug print */
#ifdef DEBUG
    char s[16], d[16];
    PrintInet(AF_INET, &(p->icmpv4vars.emb_ip4_src), s, sizeof(s));
    PrintInet(AF_INET, &(p->icmpv4vars.emb_ip4_dst), d, sizeof(d));
    SCLogDebug(
        "ICMPv4 embedding IPV4 %s->%s - PROTO: %" PRIu32 " ID: %" PRIu32 "", s,
        d, IPV4_GET_RAW_IPPROTO(icmp4_ip4h), IPV4_GET_RAW_IPID(icmp4_ip4h));
#endif

    return 0;
}

/** DecodeICMPV4
 *  \brief Main ICMPv4 decoding function
 */
int DecodeICMPV4(ThreadVars *tv, DecodeThreadVars *dtv, Packet *p,
                 const uint8_t *pkt, uint32_t len) {
    StatsIncr(tv, dtv->counter_icmpv4);

    if (len < ICMPV4_HEADER_LEN) {
        ENGINE_SET_INVALID_EVENT(p, ICMPV4_PKT_TOO_SMALL);
        return TM_ECODE_FAILED;
    }

    p->icmpv4h = (ICMPV4Hdr *)pkt;

    SCLogDebug("ICMPV4 TYPE %" PRIu32 " CODE %" PRIu32 "", p->icmpv4h->type,
               p->icmpv4h->code);

    p->proto = IPPROTO_ICMP;
    p->icmp_s.type = p->icmpv4h->type;
    p->icmp_s.code = p->icmpv4h->code;

    int ctype = ICMPv4GetCounterpart(p->icmp_s.type);
    if (ctype != -1) {
        p->icmp_d.type = (uint8_t)ctype;
    }

    ICMPV4ExtHdr *icmp4eh = (ICMPV4ExtHdr *)p->icmpv4h;
    p->icmpv4vars.hlen = ICMPV4_HEADER_LEN;

    switch (p->icmpv4h->type) {
        case ICMP_ECHOREPLY:
            p->icmpv4vars.id = icmp4eh->id;
            p->icmpv4vars.seq = icmp4eh->seq;
            if (p->icmpv4h->code != 0) {
                ENGINE_SET_EVENT(p, ICMPV4_UNKNOWN_CODE);
            }
            break;

        case ICMP_DEST_UNREACH:
            if (p->icmpv4h->code > NR_ICMP_UNREACH) {
                ENGINE_SET_EVENT(p, ICMPV4_UNKNOWN_CODE);
            } else {
                /* parse IP header plus 64 bytes */
                if (len > ICMPV4_HEADER_PKT_OFFSET) {
                    (void)DecodePartialIPV4(
                        p, (uint8_t *)(pkt + ICMPV4_HEADER_PKT_OFFSET),
                        len - ICMPV4_HEADER_PKT_OFFSET);
                }
            }
            break;

        case ICMP_SOURCE_QUENCH:
            if (p->icmpv4h->code != 0) {
                ENGINE_SET_EVENT(p, ICMPV4_UNKNOWN_CODE);
            } else {
                // parse IP header plus 64 bytes
                if (len >= ICMPV4_HEADER_PKT_OFFSET) {
                    if (unlikely(len > ICMPV4_HEADER_PKT_OFFSET + USHRT_MAX)) {
                        return TM_ECODE_FAILED;
                    }
                    DecodePartialIPV4(
                        p, (uint8_t *)(pkt + ICMPV4_HEADER_PKT_OFFSET),
                        len - ICMPV4_HEADER_PKT_OFFSET);
                }
            }
            break;

        case ICMP_REDIRECT:
            if (p->icmpv4h->code > ICMP_REDIR_HOSTTOS) {
                ENGINE_SET_EVENT(p, ICMPV4_UNKNOWN_CODE);
            } else {
                // parse IP header plus 64 bytes
                if (len > ICMPV4_HEADER_PKT_OFFSET) {
                    if (unlikely(len > ICMPV4_HEADER_PKT_OFFSET + USHRT_MAX)) {
                        return TM_ECODE_FAILED;
                    }
                    DecodePartialIPV4(
                        p, (uint8_t *)(pkt + ICMPV4_HEADER_PKT_OFFSET),
                        len - ICMPV4_HEADER_PKT_OFFSET);
                }
            }
            break;

        case ICMP_ECHO:
            p->icmpv4vars.id = icmp4eh->id;
            p->icmpv4vars.seq = icmp4eh->seq;
            if (p->icmpv4h->code != 0) {
                ENGINE_SET_EVENT(p, ICMPV4_UNKNOWN_CODE);
            }
            break;

        case ICMP_TIME_EXCEEDED:
            if (p->icmpv4h->code > ICMP_EXC_FRAGTIME) {
                ENGINE_SET_EVENT(p, ICMPV4_UNKNOWN_CODE);
            } else {
                // parse IP header plus 64 bytes
                if (len > ICMPV4_HEADER_PKT_OFFSET) {
                    if (unlikely(len > ICMPV4_HEADER_PKT_OFFSET + USHRT_MAX)) {
                        return TM_ECODE_FAILED;
                    }
                    DecodePartialIPV4(
                        p, (uint8_t *)(pkt + ICMPV4_HEADER_PKT_OFFSET),
                        len - ICMPV4_HEADER_PKT_OFFSET);
                }
            }
            break;

        case ICMP_PARAMETERPROB:
            if (p->icmpv4h->code != 0) {
                ENGINE_SET_EVENT(p, ICMPV4_UNKNOWN_CODE);
            } else {
                // parse IP header plus 64 bytes
                if (len > ICMPV4_HEADER_PKT_OFFSET) {
                    if (unlikely(len > ICMPV4_HEADER_PKT_OFFSET + USHRT_MAX)) {
                        return TM_ECODE_FAILED;
                    }
                    DecodePartialIPV4(
                        p, (uint8_t *)(pkt + ICMPV4_HEADER_PKT_OFFSET),
                        len - ICMPV4_HEADER_PKT_OFFSET);
                }
            }
            break;

        case ICMP_TIMESTAMP:
            p->icmpv4vars.id = icmp4eh->id;
            p->icmpv4vars.seq = icmp4eh->seq;
            if (p->icmpv4h->code != 0) {
                ENGINE_SET_EVENT(p, ICMPV4_UNKNOWN_CODE);
            }

            if (len < (sizeof(ICMPV4Timestamp) + ICMPV4_HEADER_LEN)) {
                ENGINE_SET_EVENT(p, ICMPV4_IPV4_TRUNC_PKT);
            } else {
                p->icmpv4vars.hlen += sizeof(ICMPV4Timestamp);
            }
            break;

        case ICMP_TIMESTAMPREPLY:
            p->icmpv4vars.id = icmp4eh->id;
            p->icmpv4vars.seq = icmp4eh->seq;
            if (p->icmpv4h->code != 0) {
                ENGINE_SET_EVENT(p, ICMPV4_UNKNOWN_CODE);
            }

            if (len < (sizeof(ICMPV4Timestamp) + ICMPV4_HEADER_LEN)) {
                ENGINE_SET_EVENT(p, ICMPV4_IPV4_TRUNC_PKT);
            } else {
                p->icmpv4vars.hlen += sizeof(ICMPV4Timestamp);
            }
            break;

        case ICMP_INFO_REQUEST:
            p->icmpv4vars.id = icmp4eh->id;
            p->icmpv4vars.seq = icmp4eh->seq;
            if (p->icmpv4h->code != 0) {
                ENGINE_SET_EVENT(p, ICMPV4_UNKNOWN_CODE);
            }
            break;

        case ICMP_INFO_REPLY:
            p->icmpv4vars.id = icmp4eh->id;
            p->icmpv4vars.seq = icmp4eh->seq;
            if (p->icmpv4h->code != 0) {
                ENGINE_SET_EVENT(p, ICMPV4_UNKNOWN_CODE);
            }
            break;

        case ICMP_ROUTERADVERT: {
            /* pkt points to beginning of icmp message */
            ICMPV4RtrAdvert *icmpv4_router_advert =
                (ICMPV4RtrAdvert *)(pkt + sizeof(ICMPV4Hdr));
            uint32_t advert_len =
                icmpv4_router_advert->naddr *
                (icmpv4_router_advert->addr_sz * sizeof(uint32_t));
            if (len < (advert_len + ICMPV4_HEADER_LEN)) {
                ENGINE_SET_EVENT(p, ICMPV4_IPV4_TRUNC_PKT);
            } else {
                p->icmpv4vars.hlen += advert_len;
            }
        } break;

        case ICMP_ADDRESS:
            p->icmpv4vars.id = icmp4eh->id;
            p->icmpv4vars.seq = icmp4eh->seq;
            if (p->icmpv4h->code != 0) {
                ENGINE_SET_EVENT(p, ICMPV4_UNKNOWN_CODE);
            }
            break;

        case ICMP_ADDRESSREPLY:
            p->icmpv4vars.id = icmp4eh->id;
            p->icmpv4vars.seq = icmp4eh->seq;
            if (p->icmpv4h->code != 0) {
                ENGINE_SET_EVENT(p, ICMPV4_UNKNOWN_CODE);
            }
            break;

        default:
            ENGINE_SET_EVENT(p, ICMPV4_UNKNOWN_TYPE);
    }

    p->payload = (uint8_t *)pkt + p->icmpv4vars.hlen;
    p->payload_len = len - p->icmpv4vars.hlen;

    FlowSetupPacket(p);
    return TM_ECODE_OK;
}
