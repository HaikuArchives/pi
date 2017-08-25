#include <arpa/inet.h>
#include <string.h>

#include <pi_set_headers.h>
#include <pi_protocol_headers.h>
#include <pi_utilities.h>

// Sequence and Acknowledgment of the latest injected segment
uint32_t s_seq, s_ack;
uint16_t s_wnd;


static uint16_t
ip_checksum(const void *buf, size_t len)
{
    unsigned long sum = 0;
    const uint16_t *ptr;

    ptr = buf;
    while (len > 1) {
        sum += *ptr++;
        len -= 2;
    }

    if (len & 1)
        sum += *(uint8_t*)(buf);

    while (sum > 0xffff)
        sum -= 0xffff;

    return (uint16_t)~sum;
}


static uint16_t
tcp_checksum(const void *buff, size_t len, in_addr_t src_addr, in_addr_t dest_addr)
{
        const uint16_t *buf=buff;

        uint16_t *source = (void *)&src_addr, *dest = (void *)&dest_addr;
        uint32_t sum;
        size_t length = len;

        sum = 0;
        while (len > 1) {
            sum += *buf++;
            len -= 2;
        }

        if(len & 1)
            sum += *(uint8_t*)(buf);
 
        sum += *(source++);
        sum += *source;
        sum += *(dest++);
   		sum += *dest;
        sum += htons(IPPROTO_TCP);
        sum += htons(length);
		
        while(sum > 0xffff)
            sum -= 0xffff;

        return (uint16_t)(~sum);
}


void 
set_en10mb(void* _header)
{
	struct en10mb_header* header = (struct en10mb_header*)_header;
	memcpy(header->dhost, DEST_MAC, ETHER_ADDR_LEN);
	memcpy(header->shost, SOURCE_MAC, ETHER_ADDR_LEN);
	header->type = htons(0x0800);
}


void
set_ipv4_tcp(void* _header, uint16_t total_length)
{

	struct ipv4_header* header = (struct ipv4_header*)_header;
	header->version = 0x04;
	header->ihl = 0x05;
	header->total_length = htons(total_length);
	header->dscp = 0x0;
	header->ecn = 0x0;
	header->id = htons(54321);
	header->flags_n_offset = htons(0x4000);
	header->ttl = 255;
	header->protocol = 0x06;
	header->checksum = 0x0;
	header->source_ip = SOURCE_IP;
	header->dest_ip = DEST_IP;
	header->checksum = ip_checksum(header, header->ihl*4);
}


void
set_tcp(void* _header, uint8_t flags, void* options, uint8_t oplen, void* payload, uint16_t paylen)
{

	struct tcp_header* header = (struct tcp_header*)(_header);
	header->source_port = htons(SOURCE_PORT);
	header->dest_port = htons(DEST_PORT);
	header->sequence = htonl(s_seq);
	header->acknowledge = htonl(s_ack);
	header->offset = 0x05 + (oplen>>2);
	header->reserved = 0x0;
	header->flags = flags;
	header->window = htons(s_wnd);
	header->checksum = 0x0;
	header->urgent_pointer = 0x0;

	if(options != NULL)
		memcpy(_header + sizeof(struct tcp_header), options, oplen);
	if(payload != NULL)
		memcpy(_header + sizeof(struct tcp_header) + oplen, payload, paylen);

	header->checksum = tcp_checksum(header, sizeof(struct tcp_header) + oplen + paylen, 
										SOURCE_IP.s_addr, DEST_IP.s_addr);
}

