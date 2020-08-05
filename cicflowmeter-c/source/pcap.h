#ifndef __CICFLOWMETER_SOURCE_PCAP_H__
#define __CICFLOWMETER_SOURCE_PCAP_H__

#define LIBPCAP_COPYWAIT    500
#define LIBPCAP_PROMISC     1
#define PCAP_IFACE_NAME_LENGTH 128

/* per packet Pcap vars */
typedef struct PcapPacketVars_
{
    uint32_t tenant_id;
} PcapPacketVars;
typedef struct PCAP_IFACE_CONFIG_
{
    char iface[PCAP_IFACE_NAME_LENGTH];
    /* number of threads */
    int threads;
    /* socket buffer size */
    int buffer_size;
    /* snapshot length */
    int snap_len;
    /* promiscuous value */
    int promiscuous;
    /* BPF filter */
    ChecksumValidationMode checksum_mode;
    ATOMIC_DECLARE(unsigned int, ref);
    void (*deref_func)(void *);
} PCAP_IFACE_CONFIG;

void TmModuleReceivePcapRegister (void);
void TmModuleDecodePcapRegister (void);
void PcapTranslateIPToDevice(char *pcap_dev, size_t len);

#endif /* __SOURCE_PCAP_H__ */
