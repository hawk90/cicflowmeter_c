#include <stdio.h>
#include <time.h>
#include <pcap/pcap.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include "common/cicflowmeter-common.h"

#define NEXT_EX_OK 1

void hello_print()
{
	printf("\n\n");
	printf("=========================================================================\n");
	printf("========================       CICFLOWMETER       =======================\n");
	printf("=========================================================================\n");
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
	return -1;
}
