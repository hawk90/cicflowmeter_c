#include "common/cicflowmeter-common.h"

#include "util/debug.h"

#define next_ex_ok 1

void hello_print() {
    printf("\n\n");
    printf("==============================================================\n");
    printf("=====================     cicflowmete     ====================\n");
    printf("==============================================================\n");
    printf("\n\n");
}

int main(int argc, char *argv[]) {
    hello_print();

    LOG_DBG_MSG("test");
#if 0
	int rc = 0;
	const char *dev = "enp0s3";
	pcap_t *handle;
	char error_buffer[PCAP_ERRBUF_SIZE];
	struct pcap_pkthdr *header = NULL;
	const u_char *pkt = NULL;

	//handle = pcap_open_offline();
	handle = pcap_open_live(dev, BUFSIZ, 10, 10000, error_buffer);
	if(handle == NULL) {
		printf("pcap open failed: %s\n", error_buffer);
		goto error;
	}	

	rc = pcap_next_ex(handle, &header, &pkt);
	if(rc == NEXT_EX_OK) {
		printf("pkt read success\n");
	}


    return 0;

error:
#endif

    return -1;
}
