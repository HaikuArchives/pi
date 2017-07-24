#ifndef SET_HEADERS_H
#define SET_HEADERS_H

#include <stdint.h>

extern uint32_t s_seq;
extern uint32_t s_ack;
extern uint16_t s_wnd;

void set_en10mb(void* _header);
void set_ipv4_tcp(void* _header, uint16_t total_length);
void set_tcp(void* _header, uint8_t flags, void* options, uint8_t oplen, void* payload, uint16_t paylen);

#endif