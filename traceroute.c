#include <arpa/inet.h>
#include <stdbool.h>
#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>
#include <sys/epoll.h>
#include "net_utils.h"


// rx thread writes true when packet from server is received
// indicating to tx thread to stop hops
bool done_flag = false;
// The last sequence number that was received
int done_offset = 0;
struct in_addr dest_ip;
struct in_addr local_ip;

// Trace Route Constants
#define REPEAT_HOP 3
#define MAX_TTL 30 
#define START_IP_ID 1000
#define MAX_EVENTS 100
#define INTER_HOP_DELAY 100000 //100ms

// Store the Tx and Rx times and the Hop's IP
struct timespec txtime[REPEAT_HOP*MAX_TTL];
struct timespec rxtime[REPEAT_HOP*MAX_TTL];
struct sockaddr_in iphop_addr[REPEAT_HOP*MAX_TTL];

void Usage(void) {
    printf ("Usage : traceroute <ip address>|<hostname> [--tcp]");
    return;
}

/*
 * Print trace route output
 * hopnumber hopIP rtt1 rtt2 rtt3
 * Ex: 
 * 1 1.2.3.4 10ms 21.2ms 33.4ms
 * 2 3.3.3.3 34.67ms 67.89ms 23.34ms
 */
void print_output(void) {
    int offset=0;
    int ttl, hop;
    double rtt[REPEAT_HOP];
    char iphop[INET_ADDRSTRLEN];
    struct sockaddr_in hop_addr;

    for (ttl=1; ttl<MAX_TTL && (done_offset >= ttl*REPEAT_HOP);ttl++) {
        hop_addr.sin_addr.s_addr = 0;
        for (hop=0; hop<REPEAT_HOP; hop++) {
            offset=(ttl*REPEAT_HOP+hop);
            if (iphop_addr[offset].sin_addr.s_addr != 0 ) {
                hop_addr = iphop_addr[offset];
            }
            if (rxtime[offset].tv_sec != -1) {
                double timeElapsed = ((double)(rxtime[offset].tv_nsec - 
                                 txtime[offset].tv_nsec))/1000000.0;
                rtt[hop] = (rxtime[offset].tv_sec- txtime[offset].tv_sec) * 1000.0 + timeElapsed;
            } else {
                rtt[hop] = 0;
            }
        }
        inet_ntop(AF_INET, &(hop_addr.sin_addr), iphop, INET_ADDRSTRLEN);
        printf (" %2d  %s  %3.3fms %3.3fms  %3.3fms \n", ttl, iphop, rtt[0], rtt[1], rtt[2]);
    }
}

/*
 * Transmit SYN packets for traceroute
 */
int traceroute_tcp(struct sockaddr_in *addr) {
    int sock_fd;
    int ttl = 1;
    int offset = 0;
    int i = 0;
    traceroute_tcp_pkt_t trc_pkt;
    int sock_raw;

    sock_fd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (sock_fd < 0) {
        printf ("Failed creating socket \n");
        return -1;
    }

    sock_raw = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);

    memset(&trc_pkt, 0, sizeof(trc_pkt));

    traceroute_iphdr_init(&trc_pkt.iphdr, &local_ip, &addr->sin_addr, IPPROTO_TCP);
    traceroute_tcphdr_init(&trc_pkt.tcp_hdr);

    // Tell the IPv4 layer we are providing the IP header
    int IP_HDRINCL_ON = 1;
    if (setsockopt (sock_fd, IPPROTO_IP, IP_HDRINCL, &IP_HDRINCL_ON, sizeof (IP_HDRINCL_ON)) < 0)
	{
		printf ("Error setting IP_HDRINCL. Error number : %d . Error message : %s \n" , errno , strerror(errno));
		exit(0);
	}

    struct pseudo_header psh;
    traceroute_pseudo_header_init(&psh, local_ip.s_addr, addr->sin_addr.s_addr);
		
    for (ttl=1; ttl<MAX_TTL && done_flag==false; ttl++) {
        for (i=0; i<REPEAT_HOP; i++) {
            offset = (ttl*3) + i;

            // Update the ttl for every set of 3 hops
            trc_pkt.iphdr.ip_ttl = ttl;

            // the TCP Source port is used to carry the Sequence number
            trc_pkt.tcp_hdr.source = htons( (START_IP_ID + offset));

            // Recalculate TCP header checksum
            trc_pkt.tcp_hdr.check = 0;
	        memcpy(&psh.tcp , &trc_pkt.tcp_hdr , sizeof (struct tcphdr));
            trc_pkt.tcp_hdr.check = calculate_checksum((void *)&psh, sizeof(struct pseudo_header));


            printf (".");
            fflush(stdout);
            usleep(INTER_HOP_DELAY);

            // Record transmit time
            rxtime[offset].tv_sec = -1;
            clock_gettime(CLOCK_MONOTONIC, &txtime[(offset)]);

            if (sendto(sock_fd, &trc_pkt, sizeof(trc_pkt), 0, (struct sockaddr *)addr,
                sizeof(*addr)) <= 0) {
                    printf("\nPacket Sending Failed!\n");
            }
        
        }
        sleep(1);
    }
    printf ("\n");
    return 0;
}

/*
 * Transmit ICMP traceroute packets
 */
int traceroute_icmp(struct sockaddr_in *addr) {
    int sock_fd;
    int ttl = 1;
    traceroute_icmp_pkt trc_pkt;
    struct sockaddr_in iphop_addr;
    int i = 0;

    sock_fd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sock_fd < 0) {
        printf ("Failed creating socket \n");
        return -1;
    }

    traceroute_icmphdr_init (&trc_pkt.icmp_hdr);

    for (ttl=1; ttl<MAX_TTL && done_flag==false; ttl++) {
        for (i=0; i<REPEAT_HOP; i++) {
            int offset = (ttl*3) + i;

            // Set ttl
            if (setsockopt(sock_fd, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl))!=0) {
                printf ("Setting socket option for TTLfailed \n");
                return -1;
            }

            // Use the icmp sequence nubmer to carry the traceroute sequence number
            trc_pkt.icmp_hdr.un.echo.sequence = htons(START_IP_ID+offset);
            trc_pkt.icmp_hdr.checksum = 0;
            trc_pkt.icmp_hdr.checksum = calculate_checksum(&trc_pkt, sizeof(trc_pkt));

            printf (".");
            fflush(stdout);
            usleep(INTER_HOP_DELAY);

            // Record transmit time
            rxtime[offset].tv_sec = -1;
            clock_gettime(CLOCK_MONOTONIC, &txtime[(offset)]);
            if (sendto(sock_fd, &trc_pkt, sizeof(trc_pkt), 0, (struct sockaddr *)addr,
                sizeof(*addr)) <= 0) {
                printf("\nPacket Sending Failed!\n");
                return 1;
            }
        
        }
        sleep(1);
    }
    printf ("\n");
    return 0;
}

/*
 * Process the received packet
 * Expecting following packets
 * SYN tracroute :
 *      TCP SYNACK packet
 *      ICMP Time exceeded packet. Inner packet is IP + TCP
 * ICMP traceroute :
 *      ICMP time exceedded packet . Inner packet is icmp
 *      ICMP echo reply packet
 */
void process_packet(unsigned char* buffer, int size, struct sockaddr_in *recv_addr)
{
	//Get the IP Header part of this packet
	struct ip *iph = (struct ip*)buffer;
    struct icmphdr icmp_hdr;

	struct sockaddr_in source,dest;
	unsigned short iphdrlen;
	iphdrlen = iph->ip_hl*4;
    int ip_id = ntohs(iph->ip_id) - START_IP_ID;

    // Handle TCP SYNACK
	if (iph->ip_p == IPPROTO_TCP) {
		struct tcphdr *tcph=(struct tcphdr*)(buffer + iphdrlen);
		//if(tcph->syn == 1 && tcph->ack == 1 && source.sin_addr.s_addr == dest_ip.s_addr) {
		if(tcph->syn == 1 && tcph->ack == 1) {
		    source.sin_addr.s_addr = iph->ip_src.s_addr;
            if (source.sin_addr.s_addr == dest_ip.s_addr) {
                ip_id = ntohs(tcph->th_dport) - START_IP_ID;
                clock_gettime(CLOCK_MONOTONIC, &rxtime[ip_id]);
                iphop_addr[ip_id] = *recv_addr;
                done_offset=ip_id;
                if ((done_offset % REPEAT_HOP) == (REPEAT_HOP-1)) {
                    done_flag = true;
                }
            }
		}
	} else { //Handle ICMP packet
		struct icmphdr *icmp_hdr=(struct icmphdr*)(buffer + iphdrlen);
        struct ip *inner_ip = (struct ip*)((uint8_t *)icmp_hdr + sizeof(struct icmphdr));
        int proto = inner_ip->ip_p;
        uint16_t inner_ip_len = inner_ip->ip_hl*4;; 
        // ICMP Echo Reply from Server
        if((icmp_hdr->type == ICMP_ECHOREPLY && icmp_hdr->code == 0))  {
                ip_id = ntohs(icmp_hdr->un.echo.sequence) - START_IP_ID;
                clock_gettime(CLOCK_MONOTONIC, &rxtime[ip_id]);
                iphop_addr[ip_id] = *recv_addr;
                done_offset=ip_id;
                if ((done_offset % REPEAT_HOP) == (REPEAT_HOP-1)) {
                    done_flag = true;
                }
        } else if (proto == IPPROTO_TCP) { // ICMP Time Exceeded Response for TCP Packet
            struct tcphdr *inner_tcp = (struct tcphdr*)((uint8_t *)inner_ip + inner_ip_len);
            uint16_t sport = ntohs(inner_tcp->th_sport);
            ip_id = sport - START_IP_ID;
            clock_gettime(CLOCK_MONOTONIC, &rxtime[ip_id]);
            iphop_addr[ip_id] = *recv_addr;
        } else if (proto == IPPROTO_ICMP) { //ICMP Time Exceeded Response for ICMP Packet
            if((icmp_hdr->type == ICMP_TIME_EXCEEDED && icmp_hdr->code == ICMP_EXC_TTL))  {
                struct icmphdr *inner_icmp = (struct icmphdr*)((uint8_t *)inner_ip + inner_ip_len);
                ip_id = ntohs(inner_icmp->un.echo.sequence) - START_IP_ID;
                clock_gettime(CLOCK_MONOTONIC, &rxtime[ip_id]);
                iphop_addr[ip_id] = *recv_addr;
            }
        }
    }
    return;
}

static struct epoll_event *events;
/*
 * Sniff for the following packets 
 * SYN traceroute ;
 *     - TCP SYNACK (Final hop from the server)
 *     - ICMP time exceeded packet
 * ICMP traceroute :
 *     - ICMP time exceeded packet
 */
int start_sniffer()
{
	int sock_tcp;
	int sock_icmp;
	
	int saddr_size , data_size;
    struct sockaddr_in saddr;

	unsigned char *buffer = (unsigned char *)malloc(MAX_PKT_SIZE); //Its Big!
	
    int epollfd = -1;
    struct epoll_event ev;
    if ( (epollfd = epoll_create(16)) < 0) {
        perror("epoll_create error");
        exit(EXIT_FAILURE);
    }
    events = calloc(50, sizeof(struct epoll_event));

	//Create a raw socket to sniff TCP packets
	sock_tcp = socket(AF_INET , SOCK_RAW , IPPROTO_TCP);
	if(sock_tcp < 0)
	{
		printf("TCP Socket Error\n");
        exit(EXIT_FAILURE);
	}

    ev.events = EPOLLIN | EPOLLET;
    ev.data.fd = sock_tcp;
    if (epoll_ctl(epollfd, EPOLL_CTL_ADD, sock_tcp, &ev) == -1) {
        perror("epoll_ctl: sock_tcp");
        exit(EXIT_FAILURE);
    }

	sock_icmp = socket(AF_INET , SOCK_RAW , IPPROTO_ICMP);
	if(sock_icmp < 0)
	{
		printf("ICMP Socket Error\n");
        exit(EXIT_FAILURE);
	}
    ev.events = EPOLLIN | EPOLLET;
    ev.data.fd = sock_icmp;
    if (epoll_ctl(epollfd, EPOLL_CTL_ADD, sock_icmp, &ev) == -1) {
        perror("epoll_ctl: sock_tcp");
        exit(EXIT_FAILURE);
    }
	
	saddr_size = sizeof saddr;
    int client_fd = -1;
    int count = -1;
    int pkt = 0;

    // Repeat till final response from server is reached, which is indicated in the packet processing function
    while (done_flag == false) {
        count = epoll_wait(epollfd, events, MAX_EVENTS, -1);
        for (pkt = 0; pkt < count; pkt ++) {
            client_fd = events[pkt].data.fd;
            if (client_fd == sock_tcp) {
		        data_size = recvfrom(sock_tcp , buffer , MAX_PKT_SIZE , 0 , (struct sockaddr *)&saddr , &saddr_size);
            }
            if (client_fd == sock_icmp) {
		        data_size = recvfrom(sock_icmp , buffer , MAX_PKT_SIZE , 0 , (struct sockaddr *)&saddr , &saddr_size);
            }    
		    process_packet(buffer , data_size, &saddr);
        }
    }
	
	close(sock_tcp);
	return 0;
}

/*
	Sniff incoming packets.
*/
void * receive_pkts( void *ptr )
{
	start_sniffer();
}

int main(int argc, char *argv[])
{
    struct sockaddr_in sa;
    int rc, ip_arg = 1;
    bool tcp_traceroute = false;
    char dest_addr_str[INET_ADDRSTRLEN];
    //char src_addr_str[INET_ADDRSTRLEN];
    if (argc < 2) {
        Usage();
        return 1;
    }
    // First parameter sanity
    if (strstr(argv[0], "traceroute") == NULL) {
        printf("%s", argv[0]);
        Usage();
        return 1;
    }

    if (argc == 3) {
        if (!strncmp(argv[1], "--tcp", strlen("--tcp"))) {
            ip_arg = 2;
        } else if (!strncmp(argv[2], "--tcp", strlen("--tcp"))) {
            ip_arg = 1;
        } else {
            Usage();
            return 1;
        }
        tcp_traceroute = true;
    }

    // Convert Destination IP string or hostname to IP
    if (resolve_host(argv[ip_arg], &sa) == -1) {
        Usage();
        return 1;
    }
    dest_ip.s_addr = sa.sin_addr.s_addr;
    inet_ntop(AF_INET, &(sa.sin_addr), dest_addr_str, INET_ADDRSTRLEN);

    struct sockaddr_in src_addr;
	rc = get_local_ip( &src_addr);
    if (rc == -1) {
        return 1;
    }
    local_ip = src_addr.sin_addr;

    /* Start thread to sniff received packets */
	char *name = "Receiver Thread";
	pthread_t receiver_thread;
	if( pthread_create( &receiver_thread , NULL ,  receive_pkts , (void*) name) < 0)
	{
		printf ("Could not create sniffer thread. Error number : %d . Error message : %s \n" , errno , strerror(errno));
		exit(0);
	}

    /* Start traceroute */
    if (tcp_traceroute == true) {
        printf ("SYN traceroute to %s (%s), %d hops max \n", argv[1], dest_addr_str, MAX_TTL);
        rc = traceroute_tcp(&sa);
    } else {
        printf ("ICMP traceroute to %s (%s), %d hops max \n", argv[1], dest_addr_str, MAX_TTL);
        rc = traceroute_icmp(&sa);
    }

    // Print the Traceroute output
    if (rc == 0) {
        sleep(1);
        print_output();
    }

    return 0;
}