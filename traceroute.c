#include <arpa/inet.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <inttypes.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#define SRC_PORT 1234

void Usage(void) {
    printf ("Usage : traceroute <ip address>|<hostname> [--tcp]");
    return;
}

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

#define RECV_TIMEOUT 5
#define TRACEROUTE_DATA 10 
typedef struct traceroute_pkt_ {
    struct icmphdr hdr;
    char msg[TRACEROUTE_DATA];
} traceroute_pkt;

typedef struct traceroute_rcv_pkt_ {
    struct ip iphdr;
    traceroute_pkt tr;
} traceroute_rcv_pkt;

uint16_t calculate_checksum(void *pkt, int len)
{    
    uint16_t *buf = pkt;
    uint16_t sum=0;
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

#define REPEAT_HOP 3
#define MAX_TTL 64

int
traceroute_icmp(struct sockaddr_in *addr) {
    int sock_fd;
    int ttl = 1;
    struct timeval trc_timeout;
    struct timespec time_start, time_end;
    trc_timeout.tv_sec = RECV_TIMEOUT;
    trc_timeout.tv_usec = 0;
    traceroute_pkt trc_pkt;
    traceroute_rcv_pkt trc_recv_pkt;
    char iphop[INET_ADDRSTRLEN];
    struct sockaddr_in iphop_addr;
    int i = 0;
    double rtt[REPEAT_HOP];
    struct sockaddr_in recv_addr;
    int addr_len=sizeof(recv_addr);
    bool tr_fail = false;
    bool done=false;

    sock_fd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sock_fd < 0) {
        printf ("Failed creating socket \n");
        return -1;
    }

    if (setsockopt(sock_fd, SOL_SOCKET, SO_RCVTIMEO, (const char *)&trc_timeout, sizeof(trc_timeout)) != 0) {
        printf ("Setting socket option for timeout failed \n");
        return -1;
    }

    memset(&trc_pkt, 0, sizeof(trc_pkt));
    memset(&trc_recv_pkt, 0, sizeof(trc_recv_pkt));
    trc_pkt.hdr.type = ICMP_ECHO;
    trc_pkt.hdr.un.echo.id = 1;
    for (i=0; i<TRACEROUTE_DATA; i++) {
        trc_pkt.msg[i]=i;
    }
    trc_pkt.hdr.un.echo.sequence = 1;
    trc_pkt.hdr.checksum = calculate_checksum(&trc_pkt, sizeof(trc_pkt));

    for (ttl=1; ttl<MAX_TTL && done==false; ttl++) {
        for (i=0; i<REPEAT_HOP; i++) {
            if (setsockopt(sock_fd, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl))!=0) {
                printf ("Setting socket option for TTLfailed \n");
                return -1;
            }
            usleep(10);
            clock_gettime(CLOCK_MONOTONIC, &time_start);
            if (sendto(sock_fd, &trc_pkt, sizeof(trc_pkt), 0, (struct sockaddr *)addr,
                sizeof(*addr)) <= 0) {
                    printf("\nPacket Sending Failed!\n");
            }
        
            if (recvfrom(sock_fd, &trc_recv_pkt, sizeof(trc_recv_pkt), 0, (struct sockaddr *)&recv_addr,
                &addr_len) <= 0) {
                    printf("\nPacket receive failed!\n");
            }
            iphop_addr = recv_addr;
            clock_gettime(CLOCK_MONOTONIC, &time_end);
            double timeElapsed = ((double)(time_end.tv_nsec - 
                                     time_start.tv_nsec))/1000000.0;
            rtt[i] = (time_end.tv_sec- time_start.tv_sec) * 1000.0 + timeElapsed;
    
            if((trc_recv_pkt.tr.hdr.type == ICMP_TIME_EXCEEDED && trc_recv_pkt.tr.hdr.code == ICMP_EXC_TTL))  {
                continue;
            } else if((trc_recv_pkt.tr.hdr.type == ICMP_ECHOREPLY && trc_recv_pkt.tr.hdr.code == 0))  {
                done=true;
                break;
            } else {
                printf("Error.. Packet received with ICMP type %d code %d \n",
                    trc_recv_pkt.tr.hdr.type, trc_recv_pkt.tr.hdr.code);
                tr_fail = true;
                break;
            }
        }
    
        if (tr_fail == false) {
            inet_ntop(AF_INET, &(iphop_addr.sin_addr), iphop, INET_ADDRSTRLEN);
            printf (" %2d  %s  %3.3fms %3.3fms  %3.3fms \n", ttl, iphop, rtt[0], rtt[1], rtt[2]);
        }
    }
    return 0;
}

int main(int argc, char *argv[])
{
    struct sockaddr_in sa;
    int rc, ip_arg = 1;
    bool tcp_traceroute = false;
    char dest_addr[INET_ADDRSTRLEN];
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

    // Convert IP string or hostname to IP
    if (resolve_host(argv[ip_arg], &sa) == -1) {
        Usage();
        return 1;
    }

    
    inet_ntop(AF_INET, &(sa.sin_addr), dest_addr, INET_ADDRSTRLEN);
    printf ("traceroute to %s (%s), %d hops max \n", argv[1], dest_addr, MAX_TTL);
    traceroute_icmp(&sa);

    //printf ("traceroute to %s 0x%x tcp = %s \n", argv[ip_arg], ntohl(sa.sin_addr.s_addr), (tcp_traceroute == true)?"true":"false");
    return 0;
}