#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pcap.h>

#include <pi_packets.h>
#include <pi_protocol_headers.h>
#include <pi_set_headers.h>
#include <pi_utilities.h>

// Sequence, Acknowledgment, Length of data, Window of the latest captured segment
uint32_t r_seq, r_ack, r_len, r_wnd;
uint64_t r_time, s_time, u_delay;

static size_t ll_header_sz, ip_header_sz, tcp_header_sz;

#if DUMP_TO_FILE==1
	static u_char* outFile;
#endif

// stores the condition to break the pcap_loop
struct userData {
	pcap_t* handle;
	union {
		uint32_t seq;
		uint32_t ack;
		uint8_t flags;
	};
	uint8_t type, relation;
};

#define READ_TILL_FLAG 0
#define READ_TILL_SEQ 1
#define READ_TILL_ACK 2

/* Returns true if num1 and num2 adhere to the specified relation */
static uint8_t _handleSubtypes(uint32_t num1, uint32_t num2, uint8_t relation) {
	
	switch(relation) {
		case _IS_GREATER		:	return num1 > num2;
		case _IS_SMALLER		:	return num1 < num2;
		case _IS_EQUAL			:	return num1 == num2;
		case _IS_SMALLER_EQUAL 	: 	return num1 <= num2;
		case _IS_GREATER_EQUAL	:	return num1 >= num2;
	}

	return 0;
}

static void _read(u_char* _userData, const struct pcap_pkthdr* header, const u_char* data) {

	const struct ipv4_header* ip_header = (const struct ipv4_header*)((u8*)data + sizeof(struct en10mb_header));
	if(ip_header->version != 4)
		puts("not an ipv4 packet.");
	else {
		
		#if DUMP_TO_FILE==1
			pcap_dump(outFile, header, data);
		#endif

		const struct tcp_header* tcp_header = (const struct tcp_header*)((u8*)ip_header + (ip_header->ihl * 4));
		r_seq = ntohl(tcp_header->sequence);
		r_ack = ntohl(tcp_header->acknowledge);
		r_len = ntohs(ip_header->total_length) - ip_header_sz - tcp_header->offset*4;
		r_wnd = ntohs(tcp_header->window);
		r_time = header->ts.tv_sec*1000000 + header->ts.tv_usec;
		
		printf(">>");
		if(tcp_header->flags & FIN) printf(" FIN");
		if(tcp_header->flags & SYN) printf(" SYN");
		if(tcp_header->flags & RST) printf(" RST");
		if(tcp_header->flags & PSH) printf(" PSH");
		if(tcp_header->flags & ACK) printf(" ACK");
		printf(" [ %u , %u ] data_len: %u", r_seq, r_ack, r_len);
		puts("");
		
		struct userData* u = (struct userData*)_userData;
		switch(u->type) {
			case READ_TILL_FLAG : 	if(tcp_header->flags & u->flags) 
										pcap_breakloop(u->handle);
								  	break;
			case READ_TILL_SEQ 	:	if(_handleSubtypes(tcp_header->sequence, u->seq, u->relation))
										pcap_breakloop(u->handle);
									break;
			case READ_TILL_ACK 	:	if(_handleSubtypes(tcp_header->acknowledge, u->ack, u->relation))
										pcap_breakloop(u->handle);
									break;
		}
	}
}

/* Read until any of the specified flag is encountered */
int readTillFlags(pcap_t* handle, uint8_t flags){ 
	struct userData u;
	u.handle = handle;
	u.type = READ_TILL_FLAG;
	u.flags = flags;
	int rt = pcap_loop(handle, -1, _read, (void*)&u);
	if(rt == -1) return -1; // No < 0 check since pcap_loop returns -2 on pcap_breakloop
	else return 0;	
}

/* Read until a segment with desired relation with its sequence is encountered */
int readTillSeq(pcap_t* handle, uint8_t relation, uint32_t value) {
	struct userData u;
	u.handle = handle;
	u.type = READ_TILL_SEQ;
	u.relation = relation;
	u.seq = value;
	int rt = pcap_loop(handle, -1, _read, (void*)&u);
	if(rt == -1) return -1;
	else return 0;	
}

/* Read until a segment with desired relation with its acknowledge is encountered */
int readTillAck(pcap_t* handle, uint8_t relation, uint32_t value) {
	struct userData u;
	u.handle = handle;
	u.type = READ_TILL_ACK;
	u.relation = relation;
	u.seq = value;
	int rt = pcap_loop(handle, -1, _read, (void*)&u);
	if(rt == -1) return -1;
	else return 0;	
}

static uint8_t* _generateOptions(int flags, uint8_t* oplen){
	static uint8_t options[40];

	if(flags == 0) {
		*oplen = 0;
		return NULL;
	}

	int len = 0;
	if((flags & NEGOTIATE_SACK) != 0) {
		options[len] = 0x04;
		options[len + 1] = 0x02;
		options[len + 2] = 0x01;
		options[len + 3] = 0x01;
		len += 4;
	}

	*oplen = len;
	return options;
}

int establishConnection(pcap_t* handle, int flags) {
	
	ll_header_sz = sizeof(struct en10mb_header);
	ip_header_sz = sizeof(struct ipv4_header);
	tcp_header_sz = sizeof(struct tcp_header);
	
	// u_delay = 700000;

	#if DUMP_TO_FILE==1
		pcap_dumper_t* _outFile = pcap_dump_open(handle, "sample.capture");
    	if(_outFile == NULL)
        	return -1;
    	outFile = (u_char*)(_outFile);
    #endif

    uint8_t oplen;
	uint8_t* options = _generateOptions(flags, &oplen);
	size_t total_length = ll_header_sz + ip_header_sz + tcp_header_sz + oplen;
	char packet[total_length];
	
	// Send SYN
	set_en10mb(packet);
	set_ipv4_tcp(packet + ll_header_sz, total_length - ll_header_sz);
	set_tcp(packet + ll_header_sz + ip_header_sz, SYN, options, oplen, NULL, 0);

	int rt= pcap_inject(handle, packet, total_length);
	if(rt == -1) return -1;
	else printf("<< SYN [ %u , %u ] data_len: 0\n", s_seq, s_ack);

	// Read SYN + ACK
	rt = readTillFlags(handle, ACK);
	if(rt == -1) return -1;
	
	// Send ACK
	s_seq = r_ack;
	s_ack = r_seq + 1;
	rt= sendAck(handle, NULL, 0, NULL, 0, 0);
	if(rt < 0) return -1;

	return 0;		
}

int closeConnection(pcap_t* handle) {
	size_t total_length = ll_header_sz + ip_header_sz + tcp_header_sz;
	char packet[total_length];

	// Send FIN/ACK
	int rt= sendAck(handle, NULL, 0, NULL, 0, FIN);
	if(rt == -1) return -1;

	// Read FIN
	rt = readTillFlags(handle, FIN);
	if(rt == -1) return -1;

	// Send ACK
	s_seq = r_ack;
	s_ack = r_seq + 1;
	rt= sendAck(handle, NULL, 0, NULL, 0, 0);
	if(rt < 0) return -1;
	return 0;
}

int sendAck(pcap_t* handle, char* options, uint8_t oplen, char* payload, uint16_t payload_len, uint8_t extra_flags){

	uint8_t toFree = 0;
	// If the pointer is NULL but the length isn't 0, push random values into payload
	if(payload == NULL && payload_len != 0) {
		toFree = 1;
		payload = malloc(payload_len);
		srand(time(NULL));
		int i;
		int* arr = (int*)payload;
		for(i=0; i<payload_len/sizeof(int); ++i){
			arr[i] = rand();
		}
	}

	size_t total_length = ll_header_sz + ip_header_sz + tcp_header_sz + payload_len + oplen;
	char packet[total_length];

	set_en10mb(packet);
	set_ipv4_tcp(packet + ll_header_sz, total_length - ll_header_sz);
	set_tcp(packet + ll_header_sz + ip_header_sz, ACK | extra_flags, options, oplen, payload, payload_len);

	// usleep(u_delay);

	int rt= pcap_inject(handle, packet, total_length);

	struct timeval tv;
	gettimeofday(&tv, NULL);
	
	s_time = tv.tv_sec*1000000 + tv.tv_usec; 
	
	if(toFree)
		free(payload);

	printf("<<");
	if(extra_flags & FIN) printf(" FIN");
	if(extra_flags & SYN) printf(" SYN");
	if(extra_flags & RST) printf(" RST");
	if(extra_flags & PSH) printf(" PSH");		
	printf(" ACK [ %u , %u ] data_len: %d\n", s_seq, s_ack, payload_len);

	return rt;
}