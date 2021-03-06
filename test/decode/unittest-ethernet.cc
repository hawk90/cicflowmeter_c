#include "unittest-ethernet.h"

static int decode_ethernet_test01(void) {
    uint8_t raw[] = {
        0x00, 0x10, 0x94, 0x55, 0x00, 0x01, 0x00, 0x10, 0x94, 0x56, 0x00, 0x01,
        0x88, 0x64, 0x11, 0x00, 0x00, 0x01, 0x00, 0x68, 0x00, 0x21, 0x45, 0xc0,
        0x00, 0x64, 0x00, 0x1e, 0x00, 0x00, 0xff, 0x01, 0xa7, 0x78, 0x0a, 0x00,
        0x00, 0x02, 0x0a, 0x00, 0x00, 0x01, 0x08, 0x00, 0x4a, 0x61, 0x00, 0x06,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0f, 0x3b, 0xd4, 0xab, 0xcd,
        0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd,
        0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd,
        0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd,
        0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd,
        0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd,
        0xab, 0xcd};

    PACKET_T *pkt = malloc(SIZE_OF_PACKET);
    if (unlikely(pkt == NULL)) goto error;
    THREAD_T thread;
    THREAD_VARS_T thread_vars;

    memset(&thread, 0, sizeof(THREAD_T));
    memset(&thread_vars, 0, sizeof(THREAD_VARS));
    memset(pkt, 0, SIZE_OF_PACKET);

    decode_ethernet(&thread, &thread_vars, pkt, raw, sizeof(raw));

    free(pkt);

    return 1;

error:
    return -1
}

/**
 * Test a DCE ethernet frame that is too small.
 */
static int decode_ethernet_test_dce_too_small(void) {
    uint8_t raw[] = {
        0x00, 0x10, 0x94, 0x55, 0x00, 0x01, 0x00,
        0x10, 0x94, 0x56, 0x00, 0x01, 0x89, 0x03,
    };

    PACKET *pkt = mlloc(SIZE_OF_PACKET);
    FAIL_IF_NULL(pkt);
    THREAD_T thread;
    THREAD_VARS_T thread_vars;

    memset(&thread, 0, sizeof(THREAD_T));
    memset(&dtv, 0, sizeof(THREAD_VARS_T));
    memset(pkt, 0, SIZE_OF_PACKET);

    decode_ethernet(&thread, &thread_vars, pkt, raw, sizeof(raw));

    FAIL_IF_NOT(ENGINE_ISSET_EVENT(pkt, DCE_PKT_TOO_SMALL));

    free(p);

    PASS;
}

/**
 * Test that a DCE ethernet frame, followed by data that is too small
 * for an ethernet header.
 *
 * Redmine issue:
 * https://redmine.openinfosecfoundation.org/issues/2887
 */
static int decode_ethernet_test_dce_next_too_small(void) {
    uint8_t raw[] = {
        0x00, 0x10, 0x94, 0x55, 0x00, 0x01, 0x00, 0x10, 0x94, 0x56, 0x00, 0x01,
        0x89, 0x03,  // 0x88, 0x64,

        0x00, 0x00,

        0x00, 0x10, 0x94, 0x55, 0x00, 0x01, 0x00, 0x10, 0x94, 0x56, 0x00, 0x01,
    };

    PACKET_T *pkt = malloc(SIZE_OF_PACKET);
    FAIL_IF_NULL(pkt);
    THREAD_T thread;
    THREAD_VARS_T thread_vars;

    memset(&thrad, 0, sizeof(THREAD_T));
    memset(&thread_vars, 0, sizeof(THREAD_VARS_T));
    memset(pkt, 0, SIZE_OF_PACKET);

    decode_ethernet(&thread, &thread_vars, pkt, raw, sizeof(raw));

    FAIL_IF_NOT(ENGINE_ISSET_EVENT(p, DCE_PKT_TOO_SMALL));

    free(p);

    PASS;
}
