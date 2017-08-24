#ifndef PACKETS_H
#define PACKETS_H

#include <stdint.h>
#include <pcap.h>

extern uint64_t r_time;
extern uint64_t s_time;
extern uint64_t u_delay;

extern uint32_t r_seq;
extern uint32_t r_ack; 
extern uint32_t r_len;
extern uint32_t r_wnd;

#define _IS_GREATER 0
#define _IS_SMALLER 1
#define _IS_EQUAL 2
#define _IS_SMALLER_EQUAL 3
#define _IS_GREATER_EQUAL 4

#define NEGOTIATE_SACK 0x01
#define NEGOTIATE_MSS 0x02
#define NEGOTIATE_WINDOW_SCALE 0x04

int readTillFlags(pcap_t* handle, uint8_t flags);
int readTillSeq(pcap_t* handle, uint8_t relation, uint32_t value);
int readTillAck(pcap_t* handle, uint8_t relation, uint32_t value);
int establishConnection(pcap_t* handle, int flags);
int closeConnection(pcap_t* handle);
int sendAck(pcap_t* handle, char* options, uint8_t oplen, char* payload, uint16_t payload_len, uint8_t extra_flags);

#endif