#include <arpa/inet.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <netinet/in.h>
#include <netdb.h>

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

int main(int argc, char *argv[])
{
    struct sockaddr_in sa;
    int rc, ip_arg = 1;
    bool tcp_traceroute = false;
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

    printf ("traceroute to %s 0x%x tcp = %s \n", argv[ip_arg], ntohl(sa.sin_addr.s_addr), (tcp_traceroute == true)?"true":"false");
    return 0;
}