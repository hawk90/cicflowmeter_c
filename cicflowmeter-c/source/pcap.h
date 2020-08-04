#ifndef __CICFLOWMETER_SOURCE_PCAP_H__
#define __CICFLOWMETER_SOURCE_PCAP_H__

#define LIBPCAP_COPYWAIT	    500
#define LIBPCAP_PROMISC			1
#define PCAP_IFACE_NAME_LENGTH	128


/* per packet Pcap vars */
typedef struct PCAP_PACKET_VARS_
{
    uint32_t tenant_id;
} PCAP_PACKET_VARS;

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
    int promisc;
    /* BPF filter */
    const char *bpf_filter;
    CHECKSUM_VALIDATION_MODE checksum_mode;
    ATOMIC_DECLARE(unsigned int, ref);
    void (*DerefFunc)(void *);
} PCAP_IFACE_CONFIG:

#endif
