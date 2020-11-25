#include "decode-ethernet.h"
#include "decode-events.h"
#include "decode.h"
#include "suricata-common.h"

#include "util-debug.h"
#include "util-unittest.h"

int DecodeEthernet(ThreadVars *tv, DecodeThreadVars *dtv, Packet *p,
                   const uint8_t *pkt, uint32_t len) {
    StatsIncr(tv, dtv->counter_eth);

    if (unlikely(len < ETHERNET_HEADER_LEN)) {
        ENGINE_SET_INVALID_EVENT(p, ETHERNET_PKT_TOO_SMALL);
        return TM_ECODE_FAILED;
    }

    p->ethh = (EthernetHdr *)pkt;
    if (unlikely(p->ethh == NULL)) return TM_ECODE_FAILED;

    SCLogDebug("p %p pkt %p ether type %04x", p, pkt,
               SCNtohs(p->ethh->eth_type));

    DecodeNetworkLayer(tv, dtv, SCNtohs(p->ethh->eth_type), p,
                       pkt + ETHERNET_HEADER_LEN, len - ETHERNET_HEADER_LEN);

    return TM_ECODE_OK;
}
