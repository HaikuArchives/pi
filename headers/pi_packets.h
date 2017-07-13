#ifndef PACKETS_H
#define PACKETS_H

#include <stdint.h>
#include <pcap.h>

extern uint64_t r_time;
extern uint64_t s_time;

extern uint32_t r_seq;
extern uint32_t r_ack; 
extern uint32_t r_len;

int readTillFlag(pcap_t* handle, uint8_t flag);
int establishConnection(pcap_t* handle);
int closeConnection(pcap_t* handle);
int sendAck(pcap_t* handle, char* payload, size_t payload_len, uint8_t extra_flags);


#endif