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

static int DecodeUDPPacket(ThreadVars *t, Packet *p, const uint8_t *pkt,
                           uint16_t len) {
    if (unlikely(len < UDP_HEADER_LEN)) {
        ENGINE_SET_INVALID_EVENT(p, UDP_HLEN_TOO_SMALL);
        return -1;
    }

    p->udph = (UDPHdr *)pkt;

    if (unlikely(len < UDP_GET_LEN(p))) {
        ENGINE_SET_INVALID_EVENT(p, UDP_PKT_TOO_SMALL);
        return -1;
    }

    if (unlikely(len != UDP_GET_LEN(p))) {
        ENGINE_SET_INVALID_EVENT(p, UDP_HLEN_INVALID);
        return -1;
    }

    SET_UDP_SRC_PORT(p, &p->sp);
    SET_UDP_DST_PORT(p, &p->dp);

    p->payload = (uint8_t *)pkt + UDP_HEADER_LEN;
    p->payload_len = len - UDP_HEADER_LEN;

    p->proto = IPPROTO_UDP;

    return 0;
}

int DecodeUDP(ThreadVars *tv, DecodeThreadVars *dtv, Packet *p,
              const uint8_t *pkt, uint16_t len) {
    StatsIncr(tv, dtv->counter_udp);

    if (unlikely(DecodeUDPPacket(tv, p, pkt, len) < 0)) {
        CLEAR_UDP_PACKET(p);
        return TM_ECODE_FAILED;
    }

    SCLogDebug("UDP sp: %" PRIu32 " -> dp: %" PRIu32 " - HLEN: %" PRIu32
               " LEN: %" PRIu32 "",
               UDP_GET_SRC_PORT(p), UDP_GET_DST_PORT(p), UDP_HEADER_LEN,
               p->payload_len);

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

    FlowSetupPacket(p);

    return TM_ECODE_OK;
}
