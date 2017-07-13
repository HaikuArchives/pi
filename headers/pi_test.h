#ifndef TEST_H
#define TEST_H

#include <pcap.h>

#define TEST_SAMPLE 0
#define TEST_FASTRETRANSMIT 1
#define TEST_LIMITEDTRANSMIT 2

int test_sample(pcap_t* handle);
int test_fastretransmit(pcap_t* handle);
int test_limitedtransmit(pcap_t* handle);

#endif