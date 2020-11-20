#include "decode.h"

int decode_raw(THREAD_T *thread, DECODE_THREAD_T, decode, Packet *p,
               const uint8_t *pkt, uint32_t len) {
    StatsIncr(tv, dtv->counter_raw);

    /* If it is ipv4 or ipv6 it should at least be the size of ipv4 */
    /*
if (unlikely(len < IPV4_HEADER_LEN)) {
    ENGINE_SET_INVALID_EVENT(p, IPV4_PKT_TOO_SMALL);
    return TM_ECODE_FAILED;
}
    */

    if (GET_IP_RAW_VER(pkt) == 4) {
        if (unlikely(GET_PKT_LEN(p) > USHRT_MAX)) {
            return TM_ECODE_FAILED;
        }
        decode_ipv4(tv, dtv, p, GET_PKT_DATA(p), GET_PKT_LEN(p));
    } else if (IP_GET_RAW_VER(pkt) == 6) {
        if (unlikely(GET_PKT_LEN(p) > USHRT_MAX)) {
            return TM_ECODE_FAILED;
        }
        decode_ipv6(tv, dtv, p, GET_PKT_DATA(p), GET_PKT_LEN(p));
    } else {
        ENGINE_SET_EVENT(p, IPRAW_INVALID_IPV);
    }
    return TM_ECODE_OK;
}
