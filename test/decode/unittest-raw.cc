#include "../flow/flow.h"
#include "../flow/util.h"

/** DecodeRawtest01
 *  \brief Valid Raw packet
 *  \retval 0 Expected test value
 */
static int DecodeRawTest01(void) {
    /* IPV6/TCP/no eth header */
    uint8_t raw_ip[] = {
        0x60, 0x00, 0x00, 0x00, 0x00, 0x28, 0x06, 0x40, 0x20, 0x01, 0x06, 0x18,
        0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x51, 0x99, 0xcc, 0x70,
        0x20, 0x01, 0x06, 0x18, 0x00, 0x01, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x05, 0x8c, 0x9b, 0x00, 0x50, 0x6a, 0xe7, 0x07, 0x36,
        0x00, 0x00, 0x00, 0x00, 0xa0, 0x02, 0x16, 0x30, 0x29, 0x9c, 0x00, 0x00,
        0x02, 0x04, 0x05, 0x8c, 0x04, 0x02, 0x08, 0x0a, 0x00, 0xdd, 0x1a, 0x39,
        0x00, 0x00, 0x00, 0x00, 0x01, 0x03, 0x03, 0x02};
    Packet *p = PacketGetFromAlloc();
    if (unlikely(p == NULL)) return 0;
    ThreadVars tv;
    DecodeThreadVars dtv;

    memset(&dtv, 0, sizeof(DecodeThreadVars));
    memset(&tv, 0, sizeof(ThreadVars));

    if (PacketCopyData(p, raw_ip, sizeof(raw_ip)) == -1) {
        SCFree(p);
        return 0;
    }

    FlowInitConfig(FLOW_QUIET);

    DecodeRaw(&tv, &dtv, p, raw_ip, GET_PKT_LEN(p));
    if (p->ip6h == NULL) {
        printf("expected a valid ipv6 header but it was NULL: ");
        FlowShutdown();
        SCFree(p);
        return 0;
    }

    PACKET_RECYCLE(p);
    FlowShutdown();
    SCFree(p);
    return 1;
}
/** DecodeRawtest02
 *  \brief Valid Raw packet
 *  \retval 0 Expected test value
 */
static int DecodeRawTest02(void) {
    /* IPV4/TCP/no eth header */
    uint8_t raw_ip[] = {
        0x45, 0x00, 0x00, 0x30, 0x00, 0xad, 0x40, 0x00, 0x7f, 0x06, 0xac, 0xc5,
        0xc0, 0xa8, 0x67, 0x02, 0xc0, 0xa8, 0x66, 0x02, 0x0b, 0xc7, 0x00, 0x50,
        0x1d, 0xb3, 0x12, 0x37, 0x00, 0x00, 0x00, 0x00, 0x70, 0x02, 0x40, 0x00,
        0xb8, 0xc8, 0x00, 0x00, 0x02, 0x04, 0x05, 0xb4, 0x01, 0x01, 0x04, 0x02};

    Packet *p = PacketGetFromAlloc();
    if (unlikely(p == NULL)) return 0;
    ThreadVars tv;
    DecodeThreadVars dtv;

    memset(&dtv, 0, sizeof(DecodeThreadVars));
    memset(&tv, 0, sizeof(ThreadVars));

    if (PacketCopyData(p, raw_ip, sizeof(raw_ip)) == -1) {
        SCFree(p);
        return 0;
    }

    FlowInitConfig(FLOW_QUIET);

    DecodeRaw(&tv, &dtv, p, raw_ip, GET_PKT_LEN(p));
    if (p->ip4h == NULL) {
        printf("expected a valid ipv4 header but it was NULL: ");
        PACKET_RECYCLE(p);
        FlowShutdown();
        SCFree(p);
        return 0;
    }

    PACKET_RECYCLE(p);
    FlowShutdown();
    SCFree(p);
    return 1;
}
/** DecodeRawtest03
 *  \brief Valid Raw packet
 *  \retval 0 Expected test value
 */
static int DecodeRawTest03(void) {
    /* IPV13 */
    uint8_t raw_ip[] = {0xdf, 0x00, 0x00, 0x3d, 0x49, 0x42, 0x40, 0x00, 0x40,
                        0x06, 0xcf, 0x8a, 0x0a, 0x1f, 0x03, 0xaf, 0x0a, 0x1f,
                        0x0a, 0x02, 0xa5, 0xe7, 0xde, 0xad, 0x00, 0x0c, 0xe2,
                        0x0e, 0x8b, 0xfe, 0x0c, 0xe7, 0x80, 0x18, 0x00, 0xb7,
                        0xaf, 0xeb, 0x00, 0x00, 0x01, 0x01, 0x08, 0x0a, 0x00,
                        0x08, 0xab, 0x4f, 0x34, 0x40, 0x67, 0x31, 0x3b, 0x63,
                        0x61, 0x74, 0x20, 0x6b, 0x65, 0x79, 0x3b};

    Packet *p = PacketGetFromAlloc();
    if (unlikely(p == NULL)) return 0;
    ThreadVars tv;
    DecodeThreadVars dtv;

    memset(&dtv, 0, sizeof(DecodeThreadVars));
    memset(&tv, 0, sizeof(ThreadVars));

    if (PacketCopyData(p, raw_ip, sizeof(raw_ip)) == -1) {
        SCFree(p);
        return 0;
    }

    FlowInitConfig(FLOW_QUIET);

    DecodeRaw(&tv, &dtv, p, raw_ip, GET_PKT_LEN(p));
    if (!ENGINE_ISSET_EVENT(p, IPRAW_INVALID_IPV)) {
        printf("expected IPRAW_INVALID_IPV to be set but it wasn't: ");
        FlowShutdown();
        SCFree(p);
        return 0;
    }
    PACKET_RECYCLE(p);
    FlowShutdown();
    SCFree(p);
    return 1;
}
