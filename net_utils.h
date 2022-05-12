#define SRC_PORT 1234
#define SYN_TCP_PORT 80 
#define MAX_PKT_SIZE 1500

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
    struct icmphdr hdr;
} traceroute_icmp_pkt;

int resolve_host (char *, struct sockaddr_in*);
uint16_t calculate_checksum(void *, int );
int get_local_ip ( struct sockaddr_in *);

