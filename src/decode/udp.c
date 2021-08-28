#include "app-layer.h"
#include "decode-events.h"
#include "decode-geneve.h"
#include "decode-teredo.h"
#include "decode-udp.h"
#include "decode-vxlan.h"
#include "decode.h"
#include "flow.h"
#include "suricata-common.h"
#include "util-debug.h"
#include "util-unittest.h"

static int decode_udp_packet(THREAD_T *thread, PACKET_T *pkt,
                             const uint8_t *raw, uint16_t len) {
    if (unlikely(len < UDP_HEADER_LEN)) {
        ENGINE_SET_INVALID_EVENT(pkt, UDP_HLEN_TOO_SMALL);
        return -1;
    }

    pkt->udph = (UDP_HDR_T *)raw;

    if (unlikely(len < UDP_GET_LEN(pkt))) {
        ENGINE_SET_INVALID_EVENT(pkt, UDP_PKT_TOO_SMALL);
        return -1;
    }

    if (unlikely(len != UDP_GET_LEN(pkt))) {
        ENGINE_SET_INVALID_EVENT(pkt, UDP_HLEN_INVALID);
        return -1;
    }

    SET_UDP_SRC_PORT(pkt, &p->sport);
    SET_UDP_DST_PORT(pkt, &p->dport);

    pkt->payload = (uint8_t *)raw + UDP_HEADER_LEN;
    pkt->payload_len = len - UDP_HEADER_LEN;

    pkt->proto = IPPROTO_UDP;

    return 0;
}

int decode_udp(THREAD_T *thread, TRHEAD_VARS_T *thread_vars, PACKET_T *pkt,
               const uint8_t *raw, uint16_t len) {
    StatsIncr(thread, thread_vars->counter_udp);

    if (unlikely(decode_udp_packet(thread, pkt, raw, len) < 0)) {
        CLEAR_UDP_PACKET(pket);
        return TM_ECODE_FAILED;
    }

    LOG_DBG_MSG("UDP sp: %" PRIu32 " -> dp: %" PRIu32 " - HLEN: %" PRIu32
                " LEN: %" PRIu32 "",
                UDP_GET_SRC_PORT(pkt), UDP_GET_DST_PORT(pkt), UDP_HEADER_LEN,
                pkt->payload_len);

    if (DecodeTeredoEnabledForPort(p->sp, p->dp) &&
        likely(DecodeTeredo(tv, dtv, p, p->payload, p->payload_len) ==
               TM_ECODE_OK)) {
        /* Here we have a Teredo packet and don't need to handle app
         * layer */
        FlowSetupPacket(p);
        return TM_ECODE_OK;
    }

    /* Handle Geneve if configured */
    if (DecodeGeneveEnabledForPort(p->sp, p->dp) &&
        unlikely(DecodeGeneve(tv, dtv, p, p->payload, p->payload_len) ==
                 TM_ECODE_OK)) {
        /* Here we have a Geneve packet and don't need to handle app
         * layer */
        FlowSetupPacket(p);
        return TM_ECODE_OK;
    }

    /* Handle VXLAN if configured */
    if (DecodeVXLANEnabledForPort(p->sp, p->dp) &&
        unlikely(DecodeVXLAN(tv, dtv, p, p->payload, p->payload_len) ==
                 TM_ECODE_OK)) {
        /* Here we have a VXLAN packet and don't need to handle app
         * layer */
        FlowSetupPacket(p);
        return TM_ECODE_OK;
    }

    FlowSetupPacket(pkt);

    return TM_ECODE_OK;
}
