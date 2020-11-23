#ifndef __CICFLOWMETER_SOURCE_PCAP_H__
#define __CICFLOWMETER_SOURCE_PCAP_H__

#ifdef __cplusplus
extern "C" {
#endif

#if 0
void TmModuleReceivePcapRegister(void);
void TmModuleDecodePcapRegister(void);
#endif

void pcap_ip_to_device(char *pcap_dev, size_t len);

#define LIBPCAP_COPYWAIT 500
#define LIBPCAP_PROMISC 1

#define PCAP_IFACE_NAME_LENGTH 128

/* per packet Pcap vars */
typedef struct PCAP_PACKET_T_ {
    uint32_t tenant_id;
} PCAP_PACKET_T;

typedef struct PCAP_IFACE_CONFIG_ {
    char iface[PCAP_IFACE_NAME_LENGTH];
    int threads_num;
    int buffer_size;
    int snap_len;
    int promisc;
    CHECKSUM_VALIDATION_MODE checksum_mode;
    ATOMIC_DECLARE(unsigned int, ref);
    void (*deref_func)(void *);
} PCAP_IFACE_CONFIG_T;

#ifdef __cplusplus
}
#endif

#endif
