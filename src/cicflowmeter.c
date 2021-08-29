#include "common/cicflowmeter_common.h"
#include "utils/debug.h"

#include <pcap.h>
#include <pcap/pcap.h>

#define NEXT_EX_OK 1

void hello_print() {
    printf("\n\n");
    printf("==============================================================\n");
    printf("=====================     CICFLOWMETE     ====================\n");
    printf("==============================================================\n");
    printf("\n\n");
}

void goodbye_error_print() {
    printf("\n\n");
    printf("==============================================================\n");
    printf("=====================         DOWN        ====================\n");
    printf("==============================================================\n");
    printf("\n\n");
}

void goodbye_print() {
    printf("\n\n");
    printf("==============================================================\n");
    printf("=====================       GOODBYE       ====================\n");
    printf("==============================================================\n");
    printf("\n\n");
}


int main(int argc, char *argv[]) {
    hello_print();

	int rc = 0;
	const char *dev = "enp0s3";
	pcap_t *handle;
	char error_buffer[PCAP_ERRBUF_SIZE];
	struct pcap_pkthdr *header = NULL;
	const u_char *pkt = NULL;

	handle = pcap_open_live(dev, BUFSIZ, 10, 10000, error_buffer);
	if(handle == NULL) {
		goto error;
	}	

    /*
	rc = pcap_next_ex(handle, &header, &pkt);
	if(rc == NEXT_EX_OK) {
	}
    */
    goodbye_print();
    return 0;

error:
    goodbye_error_print();
    return -1;
}
