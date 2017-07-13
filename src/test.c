#include <stdio.h>
#include <string.h>

#include <pi_test.h>
#include <pi_packets.h>
#include <pi_protocol_headers.h>
#include <pi_set_headers.h>

int test_sample(pcap_t* handle){

	s_seq = 10000;
	s_ack = 0;
	int rt = establishConnection(handle);
	if(rt < 0) return -1;

	char* data = "Hi. My name is Ayush.\n";
	int len = strlen(data);
	rt = sendAck(handle, data, len, PSH);
	if(rt < 0) return -1;
	else printf("<< PSH ACK [ %u , %u ] data_len: %d\n", s_seq, s_ack, len);

	rt = readTillFlag(handle, ACK);
	if(rt < 0) return -1;

	s_seq = r_ack;
	s_ack = r_seq;
	rt = closeConnection(handle);
	return rt;	
}

int test_fastretransmit(pcap_t* handle){
	
	s_seq = 10000;
	s_ack = 0;
	int rt = establishConnection(handle);
	if(rt < 0) return -1;

	char* request = "p[200]p[200]p[200]p[200]p[200]p[200]p[200]p[200].";
	int len = strlen(request);
	rt = sendAck(handle, request, len, PSH);  // set PSH flag to get an immediate acknowledge
	if(rt < 0) return -1;
	else printf("<< PSH ACK [ %u , %u ] data_len: %d\n", s_seq, s_ack, len);

	rt = readTillFlag(handle, ACK);
	if(rt < 0) return -1;

	int i;
	for(i=0;i<7;++i){
		rt = readTillFlag(handle, ACK);
		if(rt < 0) return -1;
		s_seq = r_ack;
		s_ack = r_seq + r_len;
		rt = sendAck(handle, NULL, 0, 0);
		if(rt < 0) return -1;
		else printf("<< ACK [ %u , %u ] data_len: 0\n", s_seq, s_ack);
	}

	rt = readTillFlag(handle, ACK);
	if(rt < 0) return -1;
	// don't ackowledge the 8th packet so that it can be used to check for retransmit
	uint32_t check_seq = r_seq;
	uint32_t check_len = r_len;
	uint64_t check_time = s_time;

	// send 3 dup acks to trigger fast retransmit
	for(i=0;i<3;++i){
		s_seq = r_ack;
		s_ack = r_seq ;
		rt = sendAck(handle, NULL, 0, 0);
		if(rt < 0) return -1;
		else printf("<< ACK [ %u , %u ] data_len: 0\n", s_seq, s_ack);	
	}

	rt = readTillFlag(handle, ACK);
	if(rt < 0) return -1;

	puts("");
    puts("////////////////////////////////////////////////////////");
	if(r_seq == check_seq) {
		printf("Packet %s was retransmitted\n", r_len == check_len ? "of same length" : "of different length");
		printf("Time difference: %lld microseconds\n", (long long int)r_time - check_time);
	}

	else 
		printf("Rightful retransmission didn't occur\n");
	puts("///////////////////////////////////////////////////////");
    puts("");

	// now acknowledge the retranmitted packet
	s_seq = r_ack;
	s_ack = r_seq + r_len;
	rt = sendAck(handle, NULL, 0, 0);
	if(rt < 0) return -1;
	else printf("<< ACK [ %u , %u ] data_len: 0\n", s_seq, s_ack);

	rt = closeConnection(handle);
	return rt;	
}

int test_limitedtransmit(pcap_t* handle){
	s_seq = 10000;
	s_ack = 0;
	int rt = establishConnection(handle);
	if(rt < 0) return -1;

	char* request = "p500p500p500p500p[500]p[500].";
	int len = strlen(request);
	rt = sendAck(handle, request, len, PSH);
	if(rt < 0) return -1;
	else printf("<< PSH ACK [ %u , %u ] data_len: %d\n", s_seq, s_ack, len);

	rt = readTillFlag(handle, ACK);
	if(rt < 0) return -1;

	// no mss option specified during 3-way handshake for MSS, so 536 will be used by default
	// accoring to rules specified in rfc 5681 cwnd will equal 4 * 536 = 2144 bytes
	// sending 5 packets of about 500 bytes will overwhelm the cwnd and no more packets will be sent
	
	int i;
	for(i=0;i<5;++i){
		rt = readTillFlag(handle, ACK);
		if(rt < 0) return -1;
	}

	// since the sender still has 2 more segments (partial or full) that could be sent,
	// they should be sent in response to the first 2 duplicate acknowledgements

	for(i=0;i<2;++i){
		rt = sendAck(handle, NULL, 0, 0);
		if(rt < 0) return -1;
		else printf("<< ACK [ %u , %u ] data_len: 0\n", s_seq, s_ack);	
		
		rt = readTillFlag(handle, ACK);
		if(rt < 0) return -1;
	}

	// now acknowledge all the packets all together
	s_seq = r_ack;
	s_ack = r_seq + r_len;
	rt = sendAck(handle, NULL, 0, 0);
	if(rt < 0) return -1;
	else printf("<< ACK [ %u , %u ] data_len: 0\n", s_seq, s_ack);

	rt = closeConnection(handle);
	return rt;
}