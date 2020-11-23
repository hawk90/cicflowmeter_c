#ifndef __CICFLOWMETER_RUNMODE_PCAP_H__
#define __CICFLOWMETER_RUNMODE_PCAP_H__

#ifdef __cplusplus
extern "C" {
#endif

int runmode_ids_pcap_single(void);
int runmode_ids_pcap_auto_fp(void);
void runmode_ids_pcap_register(void);
const char *get_default_ids_pcap_runmode(void);

#ifdef __cplusplus
}
#endif

#endif /* __RUNMODE_PCAP_H__ */
