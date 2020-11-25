#include "decode.h"

int decode_raw(THREAD_T *thread, THREAD_VARS_T, thread_vars, PACKET_T *pkt,
               const uint8_t *raw, uint32_t len) {
    //    StatsIncr(thread, thread_vars->counter_raw);

    /* If it is ipv4 or ipv6 it should at least be the size of ipv4 */

    if (unlikely(len < IPV4_HEADER_LEN)) {
        //        ENGINE_SET_INVALID_EVENT(p, IPV4_PKT_TOO_SMALL);
        return TM_ECODE_FAILED;
    }

    if (GET_IP_VER_RAW(raw) == 4) {
        if (unlikely(GET_PKT_LEN(p) > USHRT_MAX)) {
            return TM_ECODE_FAILED;
        }
        decode_ipv4(thread, thread_vars, pkt, GET_PKT_DATA(pkt),
                    GET_PKT_LEN(pkt));
    } else {
        //        ENGINE_SET_EVENT(pkt, IPRAW_INVALID_IPV);
    }

    return TM_ECODE_OK;
}
