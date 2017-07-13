#ifndef UTILITIES_H
#define UTILITIES_H

#include <stdint.h>
#include <netinet/in.h>
#include <pcap.h>

extern uint8_t SOURCE_MAC[6];
extern uint8_t DEST_MAC[6];
extern struct in_addr SOURCE_IP;
extern struct in_addr DEST_IP;
extern uint16_t SOURCE_PORT;
extern uint16_t DEST_PORT;

void readConfig(pcap_t* handle);
void printStats(pcap_t* handle);
int compileFilter(pcap_t* handle);

#endif