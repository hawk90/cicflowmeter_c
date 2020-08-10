#ifndef __SOURCE_PCAP_H__
#define __SOURCE_PCAP_H__

void TmModuleReceivePcapRegister (void);
void TmModuleDecodePcapRegister (void);
void PcapTranslateIPToDevice(char *pcap_dev, size_t len);

#define LIBPCAP_COPYWAIT    500
#define LIBPCAP_PROMISC     1

#define PCAP_IFACE_NAME_LENGTH 128

// TODO what is means?
/* per packet Pcap vars */
typedef struct PCAP_PACKET_VARS_
{
    uint32_t tenant_id;
} PCAP_PACKET_VARS;

typedef struct PCAP_IFACE_CONFIG_
{
    char iface[PCAP_IFACE_NAME_LENGTH];
    int threads_num;
    int buffer_size;
    int snap_len;
    int promisc;
    CHECKSUM_VALIDATION_MODE checksum_mode;
    ATOMIC_DECLARE(unsigned int, ref);
    void (*deref_func)(void *);
} PCAP_IFACE_CONFIG_T;

#endif /* __SOURCE_PCAP_H__ */
