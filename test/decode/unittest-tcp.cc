

static int TCPCalculateValidChecksumtest01(void) {
    uint16_t csum = 0;

    uint8_t raw_ipshdr[] = {0x40, 0x8e, 0x7e, 0xb2, 0xc0, 0xa8, 0x01, 0x03};

    uint8_t raw_tcp[] = {0x00, 0x50, 0x8e, 0x16, 0x0d, 0x59, 0xcd, 0x3c,
                         0xcf, 0x0d, 0x21, 0x80, 0xa0, 0x12, 0x16, 0xa0,
                         0xfa, 0x03, 0x00, 0x00, 0x02, 0x04, 0x05, 0xb4,
                         0x04, 0x02, 0x08, 0x0a, 0x6e, 0x18, 0x78, 0x73,
                         0x01, 0x71, 0x74, 0xde, 0x01, 0x03, 0x03, 02};

    csum = *(((uint16_t *)raw_tcp) + 8);

    FAIL_IF(TCPChecksum((uint16_t *)raw_ipshdr, (uint16_t *)raw_tcp,
                        sizeof(raw_tcp), csum) != 0);
    PASS;
}

static int TCPCalculateInvalidChecksumtest02(void) {
    uint16_t csum = 0;

    uint8_t raw_ipshdr[] = {0x40, 0x8e, 0x7e, 0xb2, 0xc0, 0xa8, 0x01, 0x03};

    uint8_t raw_tcp[] = {0x00, 0x50, 0x8e, 0x16, 0x0d, 0x59, 0xcd, 0x3c,
                         0xcf, 0x0d, 0x21, 0x80, 0xa0, 0x12, 0x16, 0xa0,
                         0xfa, 0x03, 0x00, 0x00, 0x02, 0x04, 0x05, 0xb4,
                         0x04, 0x02, 0x08, 0x0a, 0x6e, 0x18, 0x78, 0x73,
                         0x01, 0x71, 0x74, 0xde, 0x01, 0x03, 0x03, 03};

    csum = *(((uint16_t *)raw_tcp) + 8);

    FAIL_IF(TCPChecksum((uint16_t *)raw_ipshdr, (uint16_t *)raw_tcp,
                        sizeof(raw_tcp), csum) == 0);
    PASS;
}

static int TCPV6CalculateValidChecksumtest03(void) {
    uint16_t csum = 0;

    static uint8_t raw_ipv6[] = {
        0x00, 0x60, 0x97, 0x07, 0x69, 0xea, 0x00, 0x00, 0x86, 0x05, 0x80,
        0xda, 0x86, 0xdd, 0x60, 0x00, 0x00, 0x00, 0x00, 0x20, 0x06, 0x40,
        0x3f, 0xfe, 0x05, 0x07, 0x00, 0x00, 0x00, 0x01, 0x02, 0x00, 0x86,
        0xff, 0xfe, 0x05, 0x80, 0xda, 0x3f, 0xfe, 0x05, 0x01, 0x04, 0x10,
        0x00, 0x00, 0x02, 0xc0, 0xdf, 0xff, 0xfe, 0x47, 0x03, 0x3e, 0x03,
        0xfe, 0x00, 0x16, 0xd6, 0x76, 0xf5, 0x2d, 0x0c, 0x7a, 0x08, 0x77,
        0x80, 0x10, 0x21, 0x5c, 0xc2, 0xf1, 0x00, 0x00, 0x01, 0x01, 0x08,
        0x0a, 0x00, 0x08, 0xca, 0x5a, 0x00, 0x01, 0x69, 0x27};

    csum = *(((uint16_t *)(raw_ipv6 + 70)));

    FAIL_IF(TCPV6Checksum((uint16_t *)(raw_ipv6 + 14 + 8),
                          (uint16_t *)(raw_ipv6 + 54), 32, csum) != 0);
    PASS;
}

static int TCPV6CalculateInvalidChecksumtest04(void) {
    uint16_t csum = 0;

    static uint8_t raw_ipv6[] = {
        0x00, 0x60, 0x97, 0x07, 0x69, 0xea, 0x00, 0x00, 0x86, 0x05, 0x80,
        0xda, 0x86, 0xdd, 0x60, 0x00, 0x00, 0x00, 0x00, 0x20, 0x06, 0x40,
        0x3f, 0xfe, 0x05, 0x07, 0x00, 0x00, 0x00, 0x01, 0x02, 0x00, 0x86,
        0xff, 0xfe, 0x05, 0x80, 0xda, 0x3f, 0xfe, 0x05, 0x01, 0x04, 0x10,
        0x00, 0x00, 0x02, 0xc0, 0xdf, 0xff, 0xfe, 0x47, 0x03, 0x3e, 0x03,
        0xfe, 0x00, 0x16, 0xd6, 0x76, 0xf5, 0x2d, 0x0c, 0x7a, 0x08, 0x77,
        0x80, 0x10, 0x21, 0x5c, 0xc2, 0xf1, 0x00, 0x00, 0x01, 0x01, 0x08,
        0x0a, 0x00, 0x08, 0xca, 0x5a, 0x00, 0x01, 0x69, 0x28};

    csum = *(((uint16_t *)(raw_ipv6 + 70)));

    FAIL_IF(TCPV6Checksum((uint16_t *)(raw_ipv6 + 14 + 8),
                          (uint16_t *)(raw_ipv6 + 54), 32, csum) == 0);
    PASS;
}

/** \test Get the wscale of 2 */
static int TCPGetWscaleTest01(void) {
    int retval = 0;
    static uint8_t raw_tcp[] = {0xda, 0xc1, 0x00, 0x50, 0xb6, 0x21, 0x7f, 0x58,
                                0x00, 0x00, 0x00, 0x00, 0xa0, 0x02, 0x16, 0xd0,
                                0x8a, 0xaf, 0x00, 0x00, 0x02, 0x04, 0x05, 0xb4,
                                0x04, 0x02, 0x08, 0x0a, 0x00, 0x62, 0x88, 0x28,
                                0x00, 0x00, 0x00, 0x00, 0x01, 0x03, 0x03, 0x02};
    Packet *p = PacketGetFromAlloc();
    if (unlikely(p == NULL)) return 0;
    IPV4Hdr ip4h;
    ThreadVars tv;
    DecodeThreadVars dtv;

    memset(&tv, 0, sizeof(ThreadVars));
    memset(&dtv, 0, sizeof(DecodeThreadVars));
    memset(&ip4h, 0, sizeof(IPV4Hdr));

    p->src.family = AF_INET;
    p->dst.family = AF_INET;
    p->ip4h = &ip4h;

    FlowInitConfig(FLOW_QUIET);
    DecodeTCP(&tv, &dtv, p, raw_tcp, sizeof(raw_tcp));

    if (p->tcph == NULL) {
        printf("tcp packet decode failed: ");
        goto end;
    }

    uint8_t wscale = TCP_GET_WSCALE(p);
    if (wscale != 2) {
        printf("wscale %" PRIu8 ", expected 2: ", wscale);
        goto end;
    }

    retval = 1;
end:
    PACKET_RECYCLE(p);
    FlowShutdown();
    SCFree(p);
    return retval;
}

/** \test Get the wscale of 15, so see if return 0 properly */
static int TCPGetWscaleTest02(void) {
    int retval = 0;
    static uint8_t raw_tcp[] = {0xda, 0xc1, 0x00, 0x50, 0xb6, 0x21, 0x7f, 0x58,
                                0x00, 0x00, 0x00, 0x00, 0xa0, 0x02, 0x16, 0xd0,
                                0x8a, 0xaf, 0x00, 0x00, 0x02, 0x04, 0x05, 0xb4,
                                0x04, 0x02, 0x08, 0x0a, 0x00, 0x62, 0x88, 0x28,
                                0x00, 0x00, 0x00, 0x00, 0x01, 0x03, 0x03, 0x0f};
    Packet *p = PacketGetFromAlloc();
    if (unlikely(p == NULL)) return 0;
    IPV4Hdr ip4h;
    ThreadVars tv;
    DecodeThreadVars dtv;

    memset(&tv, 0, sizeof(ThreadVars));
    memset(&dtv, 0, sizeof(DecodeThreadVars));
    memset(&ip4h, 0, sizeof(IPV4Hdr));

    p->src.family = AF_INET;
    p->dst.family = AF_INET;
    p->ip4h = &ip4h;

    FlowInitConfig(FLOW_QUIET);
    DecodeTCP(&tv, &dtv, p, raw_tcp, sizeof(raw_tcp));

    if (p->tcph == NULL) {
        printf("tcp packet decode failed: ");
        goto end;
    }

    uint8_t wscale = TCP_GET_WSCALE(p);
    if (wscale != 0) {
        printf("wscale %" PRIu8 ", expected 0: ", wscale);
        goto end;
    }

    retval = 1;
end:
    PACKET_RECYCLE(p);
    FlowShutdown();
    SCFree(p);
    return retval;
}

/** \test Get the wscale, but it's missing, so see if return 0 properly */
static int TCPGetWscaleTest03(void) {
    int retval = 0;
    static uint8_t raw_tcp[] = {0xda, 0xc1, 0x00, 0x50, 0xb6, 0x21, 0x7f, 0x59,
                                0xdd, 0xa3, 0x6f, 0xf8, 0x80, 0x10, 0x05, 0xb4,
                                0x7c, 0x70, 0x00, 0x00, 0x01, 0x01, 0x08, 0x0a,
                                0x00, 0x62, 0x88, 0x9e, 0x00, 0x00, 0x00, 0x00};
    Packet *p = PacketGetFromAlloc();
    if (unlikely(p == NULL)) return 0;
    IPV4Hdr ip4h;
    ThreadVars tv;
    DecodeThreadVars dtv;

    memset(&tv, 0, sizeof(ThreadVars));
    memset(&dtv, 0, sizeof(DecodeThreadVars));
    memset(&ip4h, 0, sizeof(IPV4Hdr));

    p->src.family = AF_INET;
    p->dst.family = AF_INET;
    p->ip4h = &ip4h;

    FlowInitConfig(FLOW_QUIET);
    DecodeTCP(&tv, &dtv, p, raw_tcp, sizeof(raw_tcp));

    if (p->tcph == NULL) {
        printf("tcp packet decode failed: ");
        goto end;
    }

    uint8_t wscale = TCP_GET_WSCALE(p);
    if (wscale != 0) {
        printf("wscale %" PRIu8 ", expected 0: ", wscale);
        goto end;
    }

    retval = 1;
end:
    PACKET_RECYCLE(p);
    FlowShutdown();
    SCFree(p);
    return retval;
}

static int TCPGetSackTest01(void) {
    int retval = 0;
    static uint8_t raw_tcp[] = {0x00, 0x50, 0x06, 0xa6, 0xfa, 0x87, 0x0b, 0xf5,
                                0xf1, 0x59, 0x02, 0xe0, 0xa0, 0x10, 0x3e, 0xbc,
                                0x1d, 0xe7, 0x00, 0x00, 0x01, 0x01, 0x05, 0x12,
                                0xf1, 0x59, 0x13, 0xfc, 0xf1, 0x59, 0x1f, 0x64,
                                0xf1, 0x59, 0x08, 0x94, 0xf1, 0x59, 0x0e, 0x48};
    static uint8_t raw_tcp_sack[] = {0xf1, 0x59, 0x13, 0xfc, 0xf1, 0x59,
                                     0x1f, 0x64, 0xf1, 0x59, 0x08, 0x94,
                                     0xf1, 0x59, 0x0e, 0x48};
    Packet *p = PacketGetFromAlloc();
    if (unlikely(p == NULL)) return 0;
    IPV4Hdr ip4h;
    ThreadVars tv;
    DecodeThreadVars dtv;

    memset(&tv, 0, sizeof(ThreadVars));
    memset(&dtv, 0, sizeof(DecodeThreadVars));
    memset(&ip4h, 0, sizeof(IPV4Hdr));

    p->src.family = AF_INET;
    p->dst.family = AF_INET;
    p->ip4h = &ip4h;

    FlowInitConfig(FLOW_QUIET);
    DecodeTCP(&tv, &dtv, p, raw_tcp, sizeof(raw_tcp));

    if (p->tcph == NULL) {
        printf("tcp packet decode failed: ");
        goto end;
    }

    if (!TCP_HAS_SACK(p)) {
        printf("tcp packet sack not decoded: ");
        goto end;
    }

    int sack = TCP_GET_SACK_CNT(p);
    if (sack != 2) {
        printf("expected 2 sack records, got %u: ", TCP_GET_SACK_CNT(p));
        goto end;
    }

    const uint8_t *sackptr = TCP_GET_SACK_PTR(p);
    if (sackptr == NULL) {
        printf("no sack data: ");
        goto end;
    }

    if (memcmp(sackptr, raw_tcp_sack, 16) != 0) {
        printf("malformed sack data: ");
        goto end;
    }

    retval = 1;
end:
    PACKET_RECYCLE(p);
    FlowShutdown();
    SCFree(p);
    return retval;
}
