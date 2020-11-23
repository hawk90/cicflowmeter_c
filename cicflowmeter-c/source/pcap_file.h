/* Copyright (C) 2007-2010 Open Information Security Foundation
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

#ifndef __CICFLOWMETER_SOURCE_PCAP_FILE_H__
#define __CICFLOWMETER_SOURCE_PCAP_FILE_H__

void tm_receive_pcap_file_register(void);
void tm_decode_pcap_file_register(void);

void pcap_increase_invalid_checksum(void);

void init_global_pcap_file(void);
const char *get_pcap_filename(void);

#endif
