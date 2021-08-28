#include "decode-ethernet.h"
#include "decode-events.h"
#include "decode.h"
#include "suricata-common.h"

#include "util-debug.h"
#include "util-unittest.h"

int decode_ethernet(THREAD_T *thread, THREAD_VARS_T *thread_vars, PACKET_T *pkt,
                    const uint8_t *raw, uint32_t len) {
    StatsIncr(thread, thread_vars->counter_eth);

    if (unlikely(len < ETHERNET_HEADER_LEN)) {
        ENGINE_SET_INVALID_EVENT(pkt, ETHERNET_PKT_TOO_SMALL);
        return TM_ECODE_FAILED;
    }

    pkt->eth_hdr = (EthernetHdr *)raw;
    if (unlikely(p->ethh == NULL)) return TM_ECODE_FAILED;

    LOG_DBG_MSG("p %p pkt %p ether type %04x", pkt, raw,
                SCNtohs(pkt->eth_hdr->eth_type));

    decode_networklayer(thread, thread_vars, SCNtohs(pkt->eth_hdr->eth_type),
                        pkt, raw + ETHERNET_HEADER_LEN,
                        len - ETHERNET_HEADER_LEN);

    return TM_ECODE_OK;
}
