#ifndef __CICFLOWMETER_DECODE_UDP_H__
#define __CICFLOWMETER_DECODE_UDP_H__

#ifdef __cplusplus
extern "C" {
#endif

#define UDP_GET_RAW_LEN(udph) SCNtohs((udph)->uh_len)
#define UDP_GET_RAW_SRC_PORT(udph) SCNtohs((udph)->uh_sport)
#define UDP_GET_RAW_DST_PORT(udph) SCNtohs((udph)->uh_dport)
#define UDP_GET_RAW_SUM(udph) SCNtohs((udph)->uh_sum)

#define UDP_GET_LEN(p) UDP_GET_RAW_LEN(p->udph)
#define UDP_GET_SRC_PORT(p) UDP_GET_RAW_SRC_PORT(p->udph)
#define UDP_GET_DST_PORT(p) UDP_GET_RAW_DST_PORT(p->udph)
#define UDP_GET_SUM(p) UDP_GET_RAW_SUM(p->udph)

/* UDP header structure */
typedef struct _UDP_HDR_T {
    uint16_t sport; /* source port */
    uint16_t dport; /* destination port */
    uint16_t len;   /* length */
    uint16_t sum;   /* checksum */
} __attribute__((__packed__)) UDP_HDR_T;

#define CLEAR_UDP_PACKET(p)         \
    do {                            \
        (p)->level4_comp_csum = -1; \
        (p)->udph = NULL;           \
    } while (0)

void DecodeUDPV4RegisterTests(void);

/** ------ Inline function ------ */
static inline uint16_t UDPV4Checksum(uint16_t *, uint16_t *, uint16_t,
                                     uint16_t);
static inline uint16_t UDPV6Checksum(uint16_t *, uint16_t *, uint16_t,
                                     uint16_t);

/**
 * \brief Calculate or valid the checksum for the UDP packet
 *
 * \param shdr Pointer to source address field from the IP packet.  Used as a
 *             part of the psuedoheader for computing the checksum
 * \param pkt  Pointer to the start of the UDP packet
 * \param hlen Total length of the UDP packet(header + payload)
 * \param init For validation this is the UDP checksum, for calculation this
 *    value should be set to 0.
 *
 * \retval csum For validation 0 will be returned for success, for calculation
 *    this will be the checksum.
 */
static inline uint16_t UDPV4Checksum(uint16_t *shdr, uint16_t *pkt,
                                     uint16_t tlen, uint16_t init) {
    uint16_t pad = 0;
    uint32_t csum = init;

    csum += shdr[0] + shdr[1] + shdr[2] + shdr[3] + htons(17) + htons(tlen);

    csum += pkt[0] + pkt[1] + pkt[2];

    tlen -= 8;
    pkt += 4;

    while (tlen >= 32) {
        csum += pkt[0] + pkt[1] + pkt[2] + pkt[3] + pkt[4] + pkt[5] + pkt[6] +
                pkt[7] + pkt[8] + pkt[9] + pkt[10] + pkt[11] + pkt[12] +
                pkt[13] + pkt[14] + pkt[15];
        tlen -= 32;
        pkt += 16;
    }

    while (tlen >= 8) {
        csum += pkt[0] + pkt[1] + pkt[2] + pkt[3];
        tlen -= 8;
        pkt += 4;
    }

    while (tlen >= 4) {
        csum += pkt[0] + pkt[1];
        tlen -= 4;
        pkt += 2;
    }

    while (tlen > 1) {
        csum += pkt[0];
        pkt += 1;
        tlen -= 2;
    }

    if (tlen == 1) {
        *(uint8_t *)(&pad) = (*(uint8_t *)pkt);
        csum += pad;
    }

    csum = (csum >> 16) + (csum & 0x0000FFFF);
    csum += (csum >> 16);

    uint16_t csum_u16 = (uint16_t)~csum;
    if (init == 0 && csum_u16 == 0)
        return 0xFFFF;
    else
        return csum_u16;
}

#ifdef __cplusplus
}
#endif

#endif
