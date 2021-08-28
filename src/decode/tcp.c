#include "../common/cicflowmeter_common.h"

#include "decode.h"
#include "events.h"
#include "flow/flow.h"
#include "host.h"
#include "pkt-var.h"
#include "tcp.h"
#include "util/profiling.h"
#include "utils/debug.h"
#include "utils/optimize.h"

#define SET_OPTS(dst, src)   \
    (dst).type = (src).type; \
    (dst).len = (src).len;   \
    (dst).data = (src).data

static void decode_tcp_options(PACKET_T *pkt, const uint8_t *raw,
                               uint16_t len) {
    uint8_t opt_cnt = 0;
    OPTION_T tcp_opts[TCP_OPTMAX];

    uint16_t plen = len;
    while (plen) {
        const uint8_t type = *raw;

        /* single byte options */
        if (type == TCP_OPT_EOL) {
            break;
        } else if (type == TCP_OPT_NOP) {
            raw++;
            plen--;

            /* multibyte options */
        } else {
            if (plen < 2) {
                break;
            }

            const uint8_t olen = *(raw + 1);

            /* we already know that the total options len is valid,
             * so here the len of the specific option must be bad.
             * Also check for invalid lengths 0 and 1. */
            if (unlikely(olen > plen || olen < 2)) {
                ENGINE_SET_INVALID_EVENT(p, TCP_OPT_INVALID_LEN);
                return;
            }

            tcp_opts[opt_cnt].type = type;
            tcp_opts[opt_cnt].len = olen;
            tcp_opts[opt_cnt].data = (olen > 2) ? (pkt + 2) : NULL;

            /* we are parsing the most commonly used opts to prevent
             * us from having to walk the opts list for these all the
             * time. */
            switch (type) {
                case TCP_OPT_WS:
                    if (olen != TCP_OPT_WS_LEN) {
                        ENGINE_SET_EVENT(pkt, TCP_OPT_INVALID_LEN);
                    } else {
                        if (pkt->tcpvars.ws.type != 0) {
                            ENGINE_SET_EVENT(p, TCP_OPT_DUPLICATE);
                        } else {
                            SET_OPTS(pkt->tcpvars.ws, tcp_opts[opt_cnt]);
                        }
                    }
                    break;
                case TCP_OPT_MSS:
                    if (olen != TCP_OPT_MSS_LEN) {
                        ENGINE_SET_EVENT(pkt, TCP_OPT_INVALID_LEN);
                    } else {
                        if (pkt->tcpvars.mss.type != 0) {
                            ENGINE_SET_EVENT(pkt, TCP_OPT_DUPLICATE);
                        } else {
                            SET_OPTS(pkt->tcpvars.mss, tcp_opts[opt_cnt]);
                        }
                    }
                    break;
                case TCP_OPT_SACKOK:
                    if (olen != TCP_OPT_SACKOK_LEN) {
                        ENGINE_SET_EVENT(pkt, TCP_OPT_INVALID_LEN);
                    } else {
                        if (p->tcpvars.sackok.type != 0) {
                            ENGINE_SET_EVENT(pkt, TCP_OPT_DUPLICATE);
                        } else {
                            SET_OPTS(pkt->tcpvars.sackok, tcp_opts[opt_cnt]);
                        }
                    }
                    break;
                case TCP_OPT_TS:
                    if (olen != TCP_OPT_TS_LEN) {
                        ENGINE_SET_EVENT(pkt, TCP_OPT_INVALID_LEN);
                    } else {
                        if (p->tcpvars.ts_set) {
                            ENGINE_SET_EVENT(pkt, TCP_OPT_DUPLICATE);
                        } else {
                            uint32_t values[2];
                            memcpy(&values, tcp_opts[opt_cnt].data,
                                   sizeof(values));
                            pkt->tcpvars.ts_val = SCNtohl(values[0]);
                            pkt->tcpvars.ts_ecr = SCNtohl(values[1]);
                            pkt->tcpvars.ts_set = TRUE;
                        }
                    }
                    break;
                case TCP_OPT_SACK:
                    SCLogDebug("SACK option, len %u", olen);
                    if ((olen != 2) && (olen < TCP_OPT_SACK_MIN_LEN ||
                                        olen > TCP_OPT_SACK_MAX_LEN ||
                                        !((olen - 2) % 8 == 0))) {
                        ENGINE_SET_EVENT(pkt, TCP_OPT_INVALID_LEN);
                    } else {
                        if (pkt->tcpvars.sack.type != 0) {
                            ENGINE_SET_EVENT(pkt, TCP_OPT_DUPLICATE);
                        } else {
                            SET_OPTS(pkt->tcpvars.sack, tcp_opts[opt_cnt]);
                        }
                    }
                    break;
                case TCP_OPT_TFO:
                    SCLogDebug("TFO option, len %u", olen);
                    if ((olen != 2) && (olen < TCP_OPT_TFO_MIN_LEN ||
                                        olen > TCP_OPT_TFO_MAX_LEN ||
                                        !((olen - 2) % 8 == 0))) {
                        ENGINE_SET_EVENT(pkt, TCP_OPT_INVALID_LEN);
                    } else {
                        if (pkt->tcpvars.tfo.type != 0) {
                            ENGINE_SET_EVENT(pkt, TCP_OPT_DUPLICATE);
                        } else {
                            SET_OPTS(pkt->tcpvars.tfo, tcp_opts[opt_cnt]);
                        }
                    }
                    break;
                /* experimental options, could be TFO */
                case TCP_OPT_EXP1:
                case TCP_OPT_EXP2:
                    SCLogDebug("TCP EXP option, len %u", olen);
                    if (olen == 4 || olen == 12) {
                        uint16_t magic =
                            SCNtohs(*(uint16_t *)tcp_opts[tcp_opt_cnt].data);
                        if (magic == 0xf989) {
                            if (pkt->tcpvars.tfo.type != 0) {
                                ENGINE_SET_EVENT(pkt, TCP_OPT_DUPLICATE);
                            } else {
                                SET_OPTS(pkt->tcpvars.tfo, tcp_opts[opt_cnt]);
                                pkt->tcpvars.tfo.type =
                                    TCP_OPT_TFO;  // treat as regular TFO
                            }
                        }
                    } else {
                        ENGINE_SET_EVENT(pkt, TCP_OPT_INVALID_LEN);
                    }
                    break;
            }

            raw += olen;
            plen -= olen;
            opt_cnt++;
        }
    }
}

static int decode_tcp_packet(THREAD_T *thread, Packet *pkt, const uint8_t *raw,
                             uint16_t len) {
    if (unlikely(len < TCP_HEADER_LEN)) {
        ENGINE_SET_INVALID_EVENT(pkt, TCP_PKT_TOO_SMALL);
        return -1;
    }

    pkt->tcph = (TCP_HDR_T *)raw;

    uint8_t hlen = TCP_GET_HLEN(pkt);
    if (unlikely(len < hlen)) {
        ENGINE_SET_INVALID_EVENT(pkt, TCP_HLEN_TOO_SMALL);
        return -1;
    }

    uint8_t _opt_len = hlen - TCP_HEADER_LEN;
    if (unlikely(tcp_opt_len > TCP_OPTLENMAX)) {
        ENGINE_SET_INVALID_EVENT(p, TCP_INVALID_OPTLEN);
        return -1;
    }

    if (likely(opt_len > 0)) {
        decode_tcp_options(pkt, raw + TCP_HEADER_LEN, opt_len);
    }

    SET_TCP_SRC_PORT(pkt, &pkt->sport);
    SET_TCP_DST_PORT(pkt, &pkt->dport);

    pkt->proto = IPPROTO_TCP;

    pkt->payload = (uint8_t *)raw + hlen;
    pkt->payload_len = len - hlen;

    return 0;
}

int decode_tcp(THREAD_T *thread, THREAD_VARS_T *thread_vars, PACKET_T *pkt,
               const uint8_t *p, uint16_t len) {
    StatsIncr(thread, thread_vars->counter_tcp);

    if (unlikely(decode_tcp_packet(thread, pkt, raw, len) < 0)) {
        LOG_DBG_MSG("invalid TCP packet");
        CLEAR_TCP_PACKET(pkt);
        return TM_ECODE_FAILED;
    }

    FlowSetupPacket(pkt);

    return TM_ECODE_OK;
}
