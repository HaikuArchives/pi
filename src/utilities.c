#include <pcap.h>
#include <fcntl.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include <pi_utilities.h>

#define err_exit(err) \
    do { perror(err); exit(EXIT_FAILURE);} while(0)
#define msg_exit(msg) \
    do { fprintf(stderr, "%s\n", msg); exit(EXIT_FAILURE); } while(0)

uint8_t SOURCE_MAC[6], DEST_MAC[6];
struct in_addr SOURCE_IP, DEST_IP;
uint16_t SOURCE_PORT, DEST_PORT;

void readConfig(pcap_t* handle) {
	
	int config = open("run.config", O_RDONLY);
	if(config < 0) err_exit("open");

	char buff[BUFSIZ], source_ip[16], dest_ip[16];
	int rt = read(config, buff, BUFSIZ);
	if(rt < 0) err_exit("read");

	int i;
	char* buf = buff;
	buf = buf - 1;
	for(i=0;i<6;++i)
		SOURCE_MAC[i] = strtol(buf + 1, &buf, 16);
	for(i=0;i<6;++i)
		DEST_MAC[i] = strtol(buf + 1, &buf, 16);

	char* end = strchr(buf + 1, '\n');
	strncpy(source_ip, buf + 1, end - buf);
	source_ip[end - buf - 1] = '\0';
	buf = end + 1;
	end = strchr(buf, '\n');
	strncpy(dest_ip, buf, end - buf);
	dest_ip[end - buf] = '\0';

	SOURCE_PORT = strtol(end + 1, &end, 0);
	DEST_PORT = strtol(end + 1, &end, 0);

	close(config);

    rt = inet_aton(source_ip, &SOURCE_IP);
    if(rt < 0)
        msg_exit("invalid source ipv4 addresses");
    rt = inet_aton(dest_ip, &DEST_IP);
    if(rt < 0)
        msg_exit("invalid destination ipv4 addresses");
}

int compileFilter(pcap_t* handle) {
	
	char FILTER_EXP[20];
	snprintf(FILTER_EXP, 20, "src port %d", DEST_PORT);

	struct bpf_program program;
	int rt = pcap_compile(handle, &program, FILTER_EXP, 1, PCAP_NETMASK_UNKNOWN);
	if(rt == -1) 
		return -1;
	rt = pcap_setfilter(handle, &program);
	if(rt == -1) 
		return -1;
	pcap_freecode(&program);
	return 0;
}

void printStats(pcap_t* handle) {
    struct pcap_stat ps;
    pcap_stats(handle, &ps);
    
    puts("");
    puts("////////////////////////////////////////////////////////");
    printf("Number of packets received: %u\n", ps.ps_recv);
    printf("Number of packets dropped due to no room: %u\n", ps.ps_drop);
    printf("Number of packets dropped by the interface or dirver: %u\n", ps.ps_ifdrop);
    puts("///////////////////////////////////////////////////////");
    puts("");
}