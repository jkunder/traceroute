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