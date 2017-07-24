#include <stdio.h>
#include <unistd.h>
#include <string.h>

#include <pi_test.h>
#include <pi_packets.h>
#include <pi_protocol_headers.h>
#include <pi_set_headers.h>

int test_sample(pcap_t* handle) {

	s_seq = 10000;
	s_ack = 0;
	s_wnd = 65000;
	int rt = establishConnection(handle);
	if(rt < 0) return -1;
	
	char* data = "Hi. My name is Ayush.\n";
	int len = strlen(data);
	rt = sendAck(handle, NULL, 0, data, len, PSH); // set PSH flag to get an immediate acknowledge
	if(rt < 0) return -1;

	rt = readTillFlags(handle, ACK);
	if(rt < 0) return -1;

	s_seq = r_ack;
	s_ack = r_seq;
	rt = closeConnection(handle);
	return rt;	
}

int test_fastretransmit(pcap_t* handle) {
	
	s_seq = 10000;
	s_ack = 0;
	s_wnd = 65000;
	int rt = establishConnection(handle);
	if(rt < 0) return -1;

	char* request = "p[200]p[200]p[200]p[200]p[200]p[200]p[200]p[200].";
	int len = strlen(request);
	rt = sendAck(handle, NULL, 0, request, len, PSH);
	if(rt < 0) return -1;
	rt = readTillFlags(handle, ACK);
	if(rt < 0) return -1;

	int i;
	for(i=0;i<7;++i) {
		rt = readTillFlags(handle, ACK);
		if(rt < 0) return -1;
		s_seq = r_ack;
		s_ack = r_seq + r_len;
		rt = sendAck(handle, NULL, 0, NULL, 0, 0);
		if(rt < 0) return -1;	
	}

	rt = readTillFlags(handle, ACK);
	if(rt < 0) return -1;
	// don't ackowledge the 8th packet so that it can be used to check for retransmit
	uint32_t check_seq = r_seq;
	uint32_t check_len = r_len;
	uint64_t check_time = r_time;

	// send 3 dup acks to trigger fast retransmit
	for(i=0;i<3;++i) {
		s_seq = r_ack;
		s_ack = r_seq ;
		rt = sendAck(handle, NULL, 0, NULL, 0, 0);
		if(rt < 0) return -1;	
	}

	rt = readTillFlags(handle, ACK);
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
	rt = sendAck(handle, NULL, 0, NULL, 0, 0);
	if(rt < 0) return -1;
	rt = closeConnection(handle);
	return rt;	
}

int test_limitedtransmit(pcap_t* handle) {
	s_seq = 10000;
	s_ack = 0;
	s_wnd = 65000;
	int rt = establishConnection(handle);
	if(rt < 0) return -1;

	char* request = "p500p500p500p500p500p500.";
	int len = strlen(request);
	rt = sendAck(handle, NULL, 0, request, len, PSH);
	if(rt < 0) return -1;
	rt = readTillFlags(handle, ACK);
	if(rt < 0) return -1;

	// no mss option specified during 3-way handshake for MSS, so 536 will be used by default
	// accoring to rules specified in rfc 5681 cwnd will equal 4 * 536 = 2144 bytes
	// sending 4 packets of 500 bytes will leave only 144 bytes from the congestion window and due to
	// rules specified in "ShouldSendSegment", no further segments will be sent since no TCP_NODELAY
	// option was used by the server nor are we at the ending of the sending list due to the 6th packet
	
	int i;
	for(i=0;i<4;++i){
		rt = readTillFlags(handle, ACK);
		if(rt < 0) return -1;
	}

	// since the sender still has 2 more segments (partial or full) that could be sent,
	// they should be sent in response to the first 2 duplicate acknowledgements

	s_seq = r_ack;
	for(i=0;i<2;++i){
		rt = sendAck(handle, NULL, 0, NULL, 0, 0);
		if(rt < 0) return -1;		
		rt = readTillFlags(handle, ACK);
		if(rt < 0) return -1;
	}

	// now acknowledge all the packets all together
	s_seq = r_ack;
	s_ack = r_seq + r_len;
	rt = sendAck(handle, NULL, 0, NULL, 0, 0);
	if(rt < 0) return -1;
	rt = closeConnection(handle);
	return rt;
}

int test_outofband(pcap_t* handle) {

	s_seq = 10000;
	s_ack = 0;
	s_wnd = 65000;
	int rt = establishConnection(handle);
	if(rt < 0) return -1;

	char* request = "p[200]p[200]p[200]p[200].";
	int len = strlen(request);
	rt = sendAck(handle, NULL, 0, request, len, PSH);
	if(rt < 0) return -1;	
	rt = readTillFlags(handle, ACK);
	if(rt < 0) return -1;
	
	// create some sample to and fro communication to clear timers and increase congestion window
	int i;
	for(i=0;i<4;++i) {
		rt = readTillFlags(handle, ACK);
		if(rt < 0) return -1;
		s_seq = r_ack;
		s_ack = r_seq + r_len;
		rt = sendAck(handle, NULL, 0, NULL, 0, 0);
		if(rt < 0) return -1;	
	}

	// send a sequence lesser than ISS
	s_seq = r_ack - 100;
	rt = sendAck(handle, NULL, 0, NULL, 100, PSH);  // push 100 bytes of random data
	if(rt < 0) return -1;	
	rt = readTillFlags(handle, ACK);
	if(rt < 0) return -1;

	// send a sequence greater than the receive window
	s_seq = r_ack + r_wnd + 100;
	rt = sendAck(handle, NULL, 0, NULL, 100, PSH);
	if(rt < 0) return -1;	
	rt = readTillFlags(handle, ACK);
	if(rt < 0) return -1;

	// send a sequence in window but not the one next expected
	s_seq = r_ack + (r_wnd < 537) ? r_wnd -1 : 536;
	rt = sendAck(handle, NULL, 0, NULL, 100, PSH);
	if(rt < 0) return -1;	
	rt = readTillFlags(handle, ACK);
	if(rt < 0) return -1;

	rt = closeConnection(handle);
	return rt;
}

int test_rtosamples(pcap_t* handle) {
	
	s_seq = 10000;
	s_ack = 0;
	s_wnd = 65000;
	int rt = establishConnection(handle);
	if(rt < 0) return -1;

	char* request = "p[100]p[100]s500p[100]p[100].";
	int len = strlen(request);
	rt = sendAck(handle, NULL, 0, request, len, PSH);
	if(rt < 0) return -1;
	rt = readTillFlags(handle, ACK);
	if(rt < 0) return -1;

	rt = readTillFlags(handle, ACK);
	if(rt < 0) return -1;
	s_seq = r_ack;
	s_ack = r_seq + r_len;

	rt = readTillFlags(handle, ACK);
	if(rt < 0) return -1;
	
	// should trigger a RTO update
	rt = sendAck(handle, NULL, 0, NULL, 0, 0);
	if(rt < 0) return -1;

	s_seq = r_ack;
	s_ack = r_seq + r_len;
	// should not trigger a RTO update
	rt = sendAck(handle, NULL, 0, NULL, 0, 0);
	if(rt < 0) return -1;
	
	rt = readTillFlags(handle, ACK);
	if(rt < 0) return -1;
	rt = readTillFlags(handle, ACK);
	if(rt < 0) return -1;

	// now acknowledge both together
	// should trigger a RTO update
	s_seq = r_ack;
	s_ack = r_seq + r_len;
	rt = sendAck(handle, NULL, 0, NULL, 0, 0);
	if(rt < 0) return -1;
	
	rt = closeConnection(handle);
	return rt;	
}