#ifndef __CICFLOWMETER_RUNMODE_PCAP_FILE_H__
#define __CICFLOWMETER_RUNMODE_PCAP_FILE_H__

#ifdef __cplusplus
extern "C" {
#endif

int runmode_pcap_file_single(void);
int runmode_pcap_file_auto_fp(void);
void runmode_pcap_file_register(void);
const char *get_default_pcap_file_runmode(void);

#ifdef __cplusplus
}
#endif

#endif
