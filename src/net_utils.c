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
#include "net_utils.h"

/*
 * Resolve a domain name and return the IP address in sockaddr_in structure
 * return -1 if not successful
 */
int resolve_host (char *host, struct sockaddr_in *addr) {
    struct hostent *host_entity;

    if ((host_entity = gethostbyname(host)) == NULL) {
        return -1;
    }

    addr->sin_family = host_entity->h_addrtype;
    addr->sin_port = htons(SRC_PORT);
    addr->sin_addr.s_addr  = *(long*)host_entity->h_addr;
  
    return 0;
}

/*
 * Returns packet checksum
 * Inputs pointer to packet and length of packet
 */
uint16_t calculate_checksum(void *pkt, int len)
{    
    uint16_t *buf = pkt;
    uint32_t sum=0;
    uint16_t result = 0;
 
    for (sum = 0; len > 1; len -= 2) { 
        sum += *buf++;
    }
    if ( len == 1 ) {
        sum += *(unsigned char*)buf;
    }

    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    result = ~sum;
    return result;
}

/*
 * Get the local IP..  Do this by "connect" to a known address and 
 * find the local interface used for that connection
 * return -1 on failure.
 */
int get_local_ip ( struct sockaddr_in *local_ip)
{
	int sock = socket ( AF_INET, SOCK_DGRAM, 0);

    /* Well know IP/Port to connect to */
	const char* kGoogleDnsIp = "8.8.8.8";
	int dns_port = 53;

	struct sockaddr_in serv;

	memset( &serv, 0, sizeof(serv) );
	serv.sin_family = AF_INET;
	serv.sin_addr.s_addr = inet_addr(kGoogleDnsIp);
	serv.sin_port = htons( dns_port );

	int err = connect( sock , (const struct sockaddr*) &serv , sizeof(serv) );
    if (err < 0) {
        perror("Connect to test server failed. Check Network interfaces");
        return -1;
    }

	socklen_t namelen = sizeof(struct sockaddr_in);
	err = getsockname(sock, (struct sockaddr*) local_ip, &namelen);
    if (err < 0) {
        perror("Failed to retrieve Local IP from connection");
	    close(sock);
        return -1;
    }

	close(sock);
    return 0;
}

/*
 * Initialize IP header 
 */
void traceroute_iphdr_init(struct ip *iphdr, struct in_addr *src, struct in_addr *dst, int protocol)
{
    iphdr->ip_hl = 5;
	iphdr->ip_v = IPVERSION;
	iphdr->ip_tos = 0;
	iphdr->ip_len = sizeof (struct ip) + sizeof (struct tcphdr);
	iphdr->ip_id = htons(TRACEROUTE_IP_ID);
	iphdr->ip_off = htons(16384);
	iphdr->ip_ttl = 1;
	iphdr->ip_p = protocol;
	iphdr->ip_sum = 0;
	iphdr->ip_src = *src;
	iphdr->ip_dst = *dst;
}

/*
 * Initialize TCP header
 * Source port will be modified later to use to carry the sequence ID of the packet
 * Destination port is the Port to which the SYN traceroute is executed against
 * SYN Flag is enabled
 */
void traceroute_tcphdr_init(struct tcphdr *tcp_hdr)
{
    tcp_hdr->source = htons( SRC_PORT);
    tcp_hdr->dest = htons( SYN_TCP_DST_PORT);
    tcp_hdr->ack_seq = 0;
    tcp_hdr->seq = htonl(2000);
    tcp_hdr->doff = sizeof(struct tcphdr)/4;
    tcp_hdr->fin = 0;
    tcp_hdr->syn = 1;
    tcp_hdr->rst = 0;
    tcp_hdr->psh = 0;
    tcp_hdr->ack = 0;
    tcp_hdr->urg = 0;
    tcp_hdr->window = htons(8192);
    tcp_hdr->check = 0;
    tcp_hdr->urg_ptr = 0;
}

/*
 * Initialize the icmp hdr for traceroute
 */
void traceroute_icmphdr_init (struct icmphdr *icmp_hdr)
{
    memset(icmp_hdr, 0, sizeof(struct icmphdr));
    icmp_hdr->type = ICMP_ECHO;
    icmp_hdr->un.echo.id = htons(1);
    icmp_hdr->un.echo.sequence = htons(1000);
    icmp_hdr->checksum = calculate_checksum(icmp_hdr, sizeof(struct icmphdr));
}

/*
 * Initialize the pseudo header required for TCP header checksum
 */
void traceroute_pseudo_header_init(struct pseudo_header *psh, uint32_t src_ip, uint32_t dst_ip)
{
    psh->source_address = src_ip;
	psh->dest_address = dst_ip;
	psh->placeholder = 0;
	psh->protocol = IPPROTO_TCP;
	psh->tcp_length = htons( sizeof(struct tcphdr) );
}