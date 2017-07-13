#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>
#include <pcap.h>

#include <pi_packets.h>
#include <pi_protocol_headers.h>
#include <pi_set_headers.h>
#include <pi_utilities.h>

// Sequence, Acknowledgment, Length of data of the latest captured segment
uint32_t r_seq, r_ack, r_len;
uint64_t r_time, s_time;

static size_t ll_header_sz, ip_header_sz, tcp_header_sz;

#if DUMP_TO_FILE==1
	static u_char* outFile;
#endif

struct userData {
	pcap_t* handle;
	uint8_t flag;
};

void _readTillFlag(u_char* _userData, const struct pcap_pkthdr* header, const u_char* data) {

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
		r_time = header->ts.tv_sec*1000000 + header->ts.tv_usec;
		
		printf(">>");
		if(tcp_header->flags & 0x01) printf(" FIN");
		if(tcp_header->flags & 0x02) printf(" SYN");
		if(tcp_header->flags & 0x04) printf(" RST");
		if(tcp_header->flags & 0x08) printf(" PSH");
		if(tcp_header->flags & 0x10) printf(" ACK");
		printf(" [ %u , %u ] data_len: %u", r_seq, r_ack, r_len);
		puts("");
		
		struct userData* u = (struct userData*)_userData;
		if(tcp_header->flags & u->flag) pcap_breakloop(u->handle);
	}
}

int readTillFlag(pcap_t* handle, uint8_t flag){ 
	struct userData u;
	u.handle = handle;
	u.flag = flag;
	int rt = pcap_loop(handle, -1, _readTillFlag, (void*)&u);
	if(rt == -1) return -1; // No < 0 check since pcap_loop returns -2 on pcap_breakloop
	else return 0;	
}

int establishConnection(pcap_t* handle) {
	
	ll_header_sz = sizeof(struct en10mb_header);
	ip_header_sz = sizeof(struct ipv4_header);
	tcp_header_sz = sizeof(struct tcp_header);
	
	#if DUMP_TO_FILE==1
		pcap_dumper_t* _outFile = pcap_dump_open(handle, "sample.capture");
    	if(_outFile == NULL)
        	return -1;
    	outFile = (u_char*)(_outFile);
    #endif

	size_t total_length = ll_header_sz + ip_header_sz + tcp_header_sz;
	char packet[total_length];
	
	// Send SYN
	set_en10mb(packet);
	set_ipv4_tcp(packet + ll_header_sz, total_length - ll_header_sz);
	set_tcp(packet + ll_header_sz + ip_header_sz, SYN, NULL, 0, NULL, 0);
	int rt= pcap_inject(handle, packet, total_length);
	if(rt == -1) return -1;
	else printf("<< SYN [ %u , %u ] data_len: 0\n", s_seq, s_ack);

	// Read SYN + ACK
	rt = readTillFlag(handle, ACK);
	if(rt == -1) return -1;
	
	// Send ACK
	s_seq = r_ack;
	s_ack = r_seq + 1;
	rt= sendAck(handle, NULL, 0, 0);
	if(rt < 0) return -1;
	else printf("<< ACK [ %u , %u ] data_len: 0\n", s_seq, s_ack);

	return 0;		
}

int closeConnection(pcap_t* handle) {
	size_t total_length = ll_header_sz + ip_header_sz + tcp_header_sz;
	char packet[total_length];

	// Send FIN/ACK
	int rt= sendAck(handle, NULL, 0, FIN);
	if(rt == -1) return -1;
	else printf("<< FIN ACK [ %u , %u ] data_len: 0\n", s_seq, s_ack);

	// Read FIN
	rt = readTillFlag(handle, FIN);
	if(rt == -1) return -1;

	// Send ACK
	s_seq = r_ack;
	s_ack = r_seq + 1;
	rt= sendAck(handle, NULL, 0, 0);
	if(rt < 0) return -1;
	else printf("<< ACK [ %u , %u ] data_len:0\n", s_seq, s_ack);

	return 0;
}

int sendAck(pcap_t* handle, char* payload, size_t payload_len, uint8_t extra_flags){

	int toFree = 0;
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

	size_t total_length = ll_header_sz + ip_header_sz + tcp_header_sz + payload_len;
	char packet[total_length];

	set_en10mb(packet);
	set_ipv4_tcp(packet + ll_header_sz, total_length - ll_header_sz);
	set_tcp(packet + ll_header_sz + ip_header_sz, ACK | extra_flags, NULL, 0, payload, payload_len);

	int rt= pcap_inject(handle, packet, total_length);

	struct timeval tv;
	gettimeofday(&tv, NULL);
	
	s_time = tv.tv_sec*1000000 + tv.tv_usec; 
	
	if(toFree)
		free(payload);

	return rt;
}