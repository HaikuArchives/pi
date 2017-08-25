#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <string.h>

#include <pi_utilities.h>
#include <pi_test.h>

#define close_on_error(msg) \
	do { fprintf(stderr, "%s\n", msg); goto close; } while(0)


int
main(int argc, char *argv[])
{
	if (argc < 3) {
		fprintf(stderr, "usuage: %s <interface_name> <test number>\n", argv[0]);
		exit(EXIT_FAILURE);
	}

	int rt, test;
	char* interface;

	interface = argv[1];
	test = strtol(argv[2], NULL, 10);

	pcap_t* handle = pcap_create(interface, NULL);
	if (handle == NULL) { 
		fprintf(stderr, "Error in pcap_create. Exiting.\n"); 
		exit(EXIT_FAILURE); 
	}

	readConfig(handle);

	rt = pcap_set_snaplen(handle, 96);
	if (rt != 0)
		close_on_error("There was a problem with setting pcap_set_snaplen");
	rt = pcap_activate(handle);
	if (rt != 0)
		close_on_error("error occured activating device");
	rt = compileFilter(handle);
	if (rt != 0)
		close_on_error(pcap_geterr(handle));

	printf("Link layer header type: %s\n\n", pcap_datalink_val_to_name(pcap_datalink(handle)));
	
	switch (test) {
		case TEST_SAMPLE: 			rt = test_sample(handle);
						  			break;
		case TEST_FASTRETRANSMIT: 	rt = test_fastretransmit(handle);
								  	break;
		case TEST_LIMITEDTRANSMIT:	rt = test_limitedtransmit(handle);
									break;
		case TEST_OUTOFBAND:		rt = test_outofband(handle);
									break;
		case TEST_RTOSAMPLES:		rt = test_rtosamples(handle);
									break;
		case TEST_NEWRENO:			rt = test_newreno(handle);
									break;
		case TEST_SACK:				rt = test_sack(handle);
									break;
		default:
			fprintf(stderr, "Invalid test number\n");
	}

	
	if (rt < 0) 
		close_on_error(pcap_geterr(handle));

	printStats(handle);

	close:
	pcap_close(handle);

	return rt;
}