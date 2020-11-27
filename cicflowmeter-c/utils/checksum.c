/* Copyright (C) 2011-2012 Open Information Security Foundation
 *
 * You can copy, redistribute or modify this Program under the terms of
 * the GNU General Public License version 2 as published by the Free
 * Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

#include "checksum.h"

#include "../common/cicflowmeter_common.h"
#include "../decode/decode.h"
#include "debug.h"

int recalculate_checksum(PACKET_T *pkt) {
    if (IS_IPV4(pkt)) {
        if (IS_TCP(pkt)) {
            // TCP
            pkt->tcp_hdr->th_sum = 0;
            pkt->tcp_hdr->th_sum =
                tcp_checksum(pkt->ip4_hdr->s_ip_addrs, (uint16_t *)pkt->tcp_hdr,
                             (pkt->payload_len + GET_TCP_HLEN(pkt)), 0);
        } else if (IS_UDP(pkt)) {
            pkt->udp_hdr->uh_sum = 0;
            pkt->udp_hdr->uh_sum =
                udpv4_checksum(p->ip4h->s_ip_addrs, (uint16_t *)pkt->udp_hdr,
                               (pkt->payload_len + UDP_HEADER_LEN), 0);
        }
        pkt->ip4_hdr->ip_csum = 0;
        pkt->ip4_hdr->ip_csum = ipv4_checksum((uint16_t *)pkt->ip4_hdr,
                                              IPV4_GET_RAW_HLEN(pkt->ip4h), 0);
    }

    return 0;
}

/**
 *  \brief Check if the number of invalid checksums indicate checksum
 *         offloading in place.
 *
 *  \retval 1 yes, offloading in place
 *  \retval 0 no, no offloading used
 */
int check_checksum_automode(uint64_t thread_count, uint64_t iface_count,
                            uint64_t iface_fail) {
    if (thread_count == CHECKSUM_SAMPLE_COUNT) {
        if (iface_fail != 0) {
            if ((iface_count / iface_fail) < CHECKSUM_INVALID_RATIO) {
                LOG_INFO_MSG(
                    "More than 1/%dth of packets have an invalid "
                    "checksum, assuming checksum offloading is used "
                    "(%" PRIu64 "/%" PRIu64 ")",
                    CHECKSUM_INVALID_RATIO, iface_fail, iface_count);
                return 1;
            } else {
                LOG_INFO_MSG(
                    "Less than 1/%dth of packets have an invalid "
                    "checksum, assuming checksum offloading is NOT used "
                    "(%" PRIu64 "/%" PRIu64 ")",
                    CHECKSUM_INVALID_RATIO, iface_fail, iface_count);
            }
        } else {
            LOG_INFO_MSG(
                "No packets with invalid checksum, assuming "
                "checksum offloading is NOT used");
        }
    }
    return 0;
}
