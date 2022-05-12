#ifndef __NET_UTILS_H
#define __NET_UTILS_H

// Packet constants
#define SRC_PORT 1234
#define SYN_TCP_DST_PORT 80 
#define MAX_PKT_SIZE 1500
#define TRACEROUTE_IP_ID 1000

/*
 * Custom packet used for SYN traceroute
 */
typedef struct traceroute_tcp_pkt_t_ {
    struct ip iphdr;
    struct tcphdr tcp_hdr;
} traceroute_tcp_pkt_t;

/*
 * Custom packet used for ICMP traceroute
 */
typedef struct traceroute_icmp_pkt_ {
    struct icmphdr icmp_hdr;
} traceroute_icmp_pkt;

/*
 * Pseudo header for checksum calculation
 */
struct pseudo_header
{
	uint32_t source_address;
	uint32_t dest_address;
	uint8_t placeholder;
	uint8_t protocol;
	uint16_t tcp_length;
	struct tcphdr tcp;
};

/* Resolve domain name to IP */
int resolve_host (char *, struct sockaddr_in*);

/* Calculate packet checksum */
uint16_t calculate_checksum(void *, int );

/* Get Local interface IP */
int get_local_ip ( struct sockaddr_in *);

/* Initialize IP header for traceroute*/
void traceroute_iphdr_init(struct ip *iphdr, struct in_addr *src, struct in_addr *dst, int protocol);

/* Initialize TCP header for traceroute*/
void traceroute_tcphdr_init(struct tcphdr *tcp_hdr);

/* Initialize ICMP header for traceroute*/
void traceroute_icmphdr_init (struct icmphdr *icmp_hdr);

/* Initialize Pseudo header for TCP checksum*/
void traceroute_pseudo_header_init(struct pseudo_header *psh, uint32_t src_ip, uint32_t dst_ip);

#endif //__NET_UTILS_H