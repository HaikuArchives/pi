#ifndef TEST_H
#define TEST_H

#include <pcap.h>

#define TEST_SAMPLE 0
#define TEST_FASTRETRANSMIT 1
#define TEST_LIMITEDTRANSMIT 2
#define TEST_OUTOFBAND 3
#define TEST_RTOSAMPLES 4
#define TEST_NEWRENO 5
#define TEST_SACK 6

int test_sample(pcap_t* handle);
int test_fastretransmit(pcap_t* handle);
int test_limitedtransmit(pcap_t* handle);
int test_outofband(pcap_t* handle);
int test_rtosamples(pcap_t* handle);
int test_newreno(pcap_t* handle);
int test_sack(pcap_t* handle);

#endif