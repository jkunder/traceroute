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

#define SRC_PORT 1234

void * receive_ack( void *ptr );
void process_packet(unsigned char* , int , struct sockaddr_in*);
int start_sniffer(void);
bool done_flag = false;

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
struct in_addr dest_ip;
struct in_addr src_ip;

int get_local_ip ( char * buffer)
{
	int sock = socket ( AF_INET, SOCK_DGRAM, 0);

	const char* kGoogleDnsIp = "8.8.8.8";
	int dns_port = 53;

	struct sockaddr_in serv;

	memset( &serv, 0, sizeof(serv) );
	serv.sin_family = AF_INET;
	serv.sin_addr.s_addr = inet_addr(kGoogleDnsIp);
	serv.sin_port = htons( dns_port );

	int err = connect( sock , (const struct sockaddr*) &serv , sizeof(serv) );

	struct sockaddr_in name;
	socklen_t namelen = sizeof(name);
	err = getsockname(sock, (struct sockaddr*) &name, &namelen);

	const char *p = inet_ntop(AF_INET, &name.sin_addr, buffer, 100);
    src_ip = name.sin_addr;

	close(sock);
}

typedef struct traceroute_tcp_pkt_t_ {
    struct ip iphdr;
    struct tcphdr hdr;
    //char msg[TRACEROUTE_DATA];
} traceroute_tcp_pkt_t;

typedef struct traceroute_pkt_ {
    struct icmphdr hdr;
    char msg[TRACEROUTE_DATA];
} traceroute_pkt;

typedef struct traceroute_rcv_pkt_ {
    struct ip iphdr;
    traceroute_pkt tr;
    char msg[100];
} traceroute_rcv_pkt;

unsigned short csum(unsigned short *ptr,int nbytes) {
    register long sum;
    unsigned short oddbyte;
    register short answer;
 
    sum=0;
    while(nbytes>1) {
        sum+=*ptr++;
        nbytes-=2;
    }
    if(nbytes==1) {
        oddbyte=0;
        *((u_char*)&oddbyte)=*(u_char*)ptr;
        sum+=oddbyte;
    }
 
    sum = (sum>>16)+(sum & 0xffff);
    sum = sum + (sum>>16);
    answer=(short)~sum;
     
    return(answer);
}


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
#define MAX_TTL 10
#define START_IP_ID 1000

struct pseudo_header    //needed for checksum calculation
{
	unsigned int source_address;
	unsigned int dest_address;
	unsigned char placeholder;
	unsigned char protocol;
	unsigned short tcp_length;
	struct tcphdr tcp;
};

struct timespec txtime[REPEAT_HOP*MAX_TTL];
struct timespec rxtime[REPEAT_HOP*MAX_TTL];
struct sockaddr_in iphop_addr[REPEAT_HOP*MAX_TTL];

int
traceroute_tcp(struct sockaddr_in *addr) {
    int sock_fd;
    int ttl = 1;
    struct timeval trc_timeout;
    struct timespec time_start, time_end;
    trc_timeout.tv_sec = RECV_TIMEOUT;
    trc_timeout.tv_usec = 0;

    traceroute_tcp_pkt_t trc_pkt;
    traceroute_rcv_pkt trc_recv_pkt;
    char iphop[INET_ADDRSTRLEN];
    int i = 0;
    double rtt[REPEAT_HOP];
    struct sockaddr_in recv_addr;
    int addr_len=sizeof(recv_addr);
    bool tr_fail = false;
    bool done=false;

    sock_fd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (sock_fd < 0) {
        printf ("Failed creating socket \n");
        return -1;
    }

    if (setsockopt(sock_fd, SOL_SOCKET, SO_RCVTIMEO, (const char *)&trc_timeout, sizeof(trc_timeout)) != 0) {
        printf ("Setting socket option for timeout failed \n");
        return -1;
    }

    int sock_raw = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);

    memset(&trc_pkt, 0, sizeof(trc_pkt));
    memset(&trc_recv_pkt, 0, sizeof(trc_recv_pkt));

    
    char source_ip[20];
	get_local_ip( source_ip );
    printf ("SOURCE IP = %s \n", source_ip);

    trc_pkt.iphdr.ip_hl = 5;
	trc_pkt.iphdr.ip_v = 4;
	trc_pkt.iphdr.ip_tos = 0;
	trc_pkt.iphdr.ip_len = sizeof (struct ip) + sizeof (struct tcphdr);
	trc_pkt.iphdr.ip_id = htons (START_IP_ID);	//Id of this packet
	trc_pkt.iphdr.ip_off = htons(16384);
	trc_pkt.iphdr.ip_ttl = 1;
	trc_pkt.iphdr.ip_p = IPPROTO_TCP;
	trc_pkt.iphdr.ip_sum = 0;		//Set to 0 before calculating checksum
	trc_pkt.iphdr.ip_src.s_addr = inet_addr ( source_ip );	//Spoof the source ip address
	trc_pkt.iphdr.ip_dst = addr->sin_addr;
 


    int sport = 12345;
    trc_pkt.hdr.source = htons( sport);
    trc_pkt.hdr.dest = htons( 80);
    trc_pkt.hdr.ack_seq = 0;
    trc_pkt.hdr.seq = htonl(10000010);
    trc_pkt.hdr.doff = sizeof(struct tcphdr)/4;
    trc_pkt.hdr.fin = 0;
    trc_pkt.hdr.syn = 1;
    trc_pkt.hdr.rst = 0;
    trc_pkt.hdr.psh = 0;
    trc_pkt.hdr.ack = 0;
    trc_pkt.hdr.urg = 0;
    trc_pkt.hdr.window = htons(8192);
    trc_pkt.hdr.check = 0; //Let IP stack calculate checksum
    trc_pkt.hdr.urg_ptr = 0;

    int one = 1;
	const int *val = &one;
    if (setsockopt (sock_fd, IPPROTO_IP, IP_HDRINCL, val, sizeof (one)) < 0)
	{
		printf ("Error setting IP_HDRINCL. Error number : %d . Error message : %s \n" , errno , strerror(errno));
		exit(0);
	}

    printf("Starting sniffer thread...\n");
	char *message1 = "Thread 1";
	int  iret1;
	pthread_t sniffer_thread;

	if( pthread_create( &sniffer_thread , NULL ,  receive_ack , (void*) message1) < 0)
	{
		printf ("Could not create sniffer thread. Error number : %d . Error message : %s \n" , errno , strerror(errno));
		exit(0);
	}

    struct pseudo_header psh;
    psh.source_address = inet_addr( source_ip );
	psh.dest_address = addr->sin_addr.s_addr;
	psh.placeholder = 0;
	psh.protocol = IPPROTO_TCP;
	psh.tcp_length = htons( sizeof(struct tcphdr) );
		
	memcpy(&psh.tcp , &trc_pkt.hdr , sizeof (struct tcphdr));
    trc_pkt.hdr.check = csum( (unsigned short*) &psh , sizeof (struct pseudo_header));

    for (ttl=1; ttl<MAX_TTL && done_flag==false; ttl++) {
        printf ("ttl = %d \n", ttl);
        for (i=0; i<REPEAT_HOP; i++) {
            int offset = (ttl*3) + i;
            trc_pkt.iphdr.ip_ttl = ttl;
            trc_pkt.iphdr.ip_id = htons (START_IP_ID + offset);	//Id of this packet
            trc_pkt.hdr.source = htons( (START_IP_ID + offset));
            trc_pkt.hdr.check = 0;
	        memcpy(&psh.tcp , &trc_pkt.hdr , sizeof (struct tcphdr));
            trc_pkt.hdr.check = csum( (unsigned short*) &psh , sizeof (struct pseudo_header));


            //trc_pkt.hdr.source = htons( sport++);


            /*
            if (setsockopt(sock_fd, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl))!=0) {
                printf ("Setting socket option for TTLfailed \n");
                return -1;
            }
            */
            usleep(1000);
            rxtime[offset].tv_sec = -1;
            clock_gettime(CLOCK_MONOTONIC, &txtime[(offset)]);
            printf ("Sending packet %d \n", offset);
            if (sendto(sock_fd, &trc_pkt, sizeof(trc_pkt), 0, (struct sockaddr *)addr,
                sizeof(*addr)) <= 0) {
                    printf("\nPacket Sending Failed!\n");
            }
        
           /*
            iphop_addr = recv_addr;
            clock_gettime(CLOCK_MONOTONIC, &time_end);
            double timeElapsed = ((double)(time_end.tv_nsec - 
                                     time_start.tv_nsec))/1000000.0;
            rtt[i] = (time_end.tv_sec- time_start.tv_sec) * 1000.0 + timeElapsed;
    
            printf("Error.. Packet received with ICMP type %x code %x \n",
                trc_recv_pkt.tr.hdr.type, trc_recv_pkt.tr.hdr.code);
            printf("Error.. Packet received with ICMP 0x%x \n",
                trc_recv_pkt.iphdr.ip_len );
            */
        }
        sleep(1);
    }
    
    sleep(5);
    int offset=0;
    for (ttl=1; ttl<MAX_TTL;ttl++) {
        for (i=0; i<REPEAT_HOP; i++) {
            offset=(ttl*REPEAT_HOP+i);
            if (rxtime[offset].tv_sec != -1) {
                double timeElapsed = ((double)(rxtime[offset].tv_nsec - 
                                 txtime[offset].tv_nsec))/1000000.0;
                rtt[i] = (rxtime[offset].tv_sec- txtime[offset].tv_sec) * 1000.0 + timeElapsed;
            } else {
                rtt[i] = 0;
            }
        }
        inet_ntop(AF_INET, &(iphop_addr[offset].sin_addr), iphop, INET_ADDRSTRLEN);
        printf (" %2d  %s  %3.3fms %3.3fms  %3.3fms \n", ttl, iphop, rtt[0], rtt[1], rtt[2]);
    }
    return 0;
}

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

    
    dest_ip.s_addr = sa.sin_addr.s_addr;
    inet_ntop(AF_INET, &(sa.sin_addr), dest_addr, INET_ADDRSTRLEN);
    printf ("traceroute to %s (%s), %d hops max \n", argv[1], dest_addr, MAX_TTL);
    //traceroute_icmp(&sa);
    traceroute_tcp(&sa);

    //printf ("traceroute to %s 0x%x tcp = %s \n", argv[ip_arg], ntohl(sa.sin_addr.s_addr), (tcp_traceroute == true)?"true":"false");
    return 0;
}

/*
	Method to sniff incoming packets and look for Ack replies
*/
void * receive_ack( void *ptr )
{
	//Start the sniffer thing
	start_sniffer();
}

static struct epoll_event *events;
int start_sniffer()
{
	int sock_tcp;
	int sock_icmp;
	
	int saddr_size , data_size;
    struct sockaddr_in saddr;

	//struct sockaddr saddr;
	
	unsigned char *buffer = (unsigned char *)malloc(65536); //Its Big!
	
	printf("Sniffer initialising...\n");
	fflush(stdout);

    int epollfd = -1;
    struct epoll_event ev;
    if ( (epollfd = epoll_create(4096)) < 0) {
        perror("epoll_create error");
        exit(EXIT_FAILURE);
    }
    events = calloc(50, sizeof(struct epoll_event));

	//Create a raw socket that shall sniff
	sock_tcp = socket(AF_INET , SOCK_RAW , IPPROTO_TCP);
	if(sock_tcp < 0)
	{
		printf("Socket Error\n");
		fflush(stdout);
		return 1;
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
		printf("Socket Error\n");
		fflush(stdout);
		return 1;
	}
    ev.events = EPOLLIN | EPOLLET;
    ev.data.fd = sock_icmp;
    if (epoll_ctl(epollfd, EPOLL_CTL_ADD, sock_icmp, &ev) == -1) {
        perror("epoll_ctl: sock_tcp");
        exit(EXIT_FAILURE);
    }
	
	saddr_size = sizeof saddr;
    int client_fd = -1;
    int res = -1;

    while (1) {
        res = epoll_wait(epollfd, events, 1, -1);
        client_fd = events[0].data.fd;
        if (client_fd == sock_tcp) {
		    data_size = recvfrom(sock_tcp , buffer , 65536 , 0 , (struct sockaddr *)&saddr , &saddr_size);
        }
        if (client_fd == sock_icmp) {
		    data_size = recvfrom(sock_icmp , buffer , 65536 , 0 , (struct sockaddr *)&saddr , &saddr_size);
        }
		//Receive a packet
		process_packet(buffer , data_size, &saddr);
    }
	
 #if 0
	while(1)
	{
		
		if(data_size <0 )
		{
			printf("Recvfrom error , failed to get packets\n");
			fflush(stdout);
			return 1;
		}
		
		//Now process the packet
		process_packet(buffer , data_size);
	}
#endif
	
	close(sock_tcp);
	printf("Sniffer finished.");
	fflush(stdout);
	return 0;
}

void process_packet(unsigned char* buffer, int size, struct sockaddr_in *recv_addr)
{
	//Get the IP Header part of this packet
	struct ip *iph = (struct ip*)buffer;
    struct icmphdr icmp_hdr;

	struct sockaddr_in source,dest;
	unsigned short iphdrlen;
	iphdrlen = iph->ip_hl*4;
    int ip_id = ntohs(iph->ip_id) - START_IP_ID;

	if ((iph->ip_p == IPPROTO_TCP) || (iph->ip_p == IPPROTO_ICMP)) {
		memset(&source, 0, sizeof(source));
		source.sin_addr.s_addr = iph->ip_src.s_addr;
	
		memset(&dest, 0, sizeof(dest));
		dest.sin_addr.s_addr = iph->ip_dst.s_addr;
		
		if ( dest.sin_addr.s_addr != src_ip.s_addr ) {
            return;
        }
    }

	if (iph->ip_p == IPPROTO_TCP) {
	
		struct tcphdr *tcph=(struct tcphdr*)(buffer + iphdrlen);
			
		if(tcph->syn == 1 && tcph->ack == 1 && source.sin_addr.s_addr == dest_ip.s_addr) {
            ip_id = ntohs(tcph->th_dport) - START_IP_ID;
            clock_gettime(CLOCK_MONOTONIC, &rxtime[ip_id]);
			printf("Port %d open , ip_id = %d\n" , ntohs(tcph->source), ip_id);
            done_flag = true;
			fflush(stdout);
		}
	} else {
		struct icmphdr *icmp_hdr=(struct icmphdr*)(buffer + iphdrlen);
        struct ip *inner_ip = (struct ip*)((uint8_t *)icmp_hdr + sizeof(struct icmphdr));
        uint16_t inner_ip_len = inner_ip->ip_hl*4;; 
        struct tcphdr *inner_tcp = (struct tcphdr*)((uint8_t *)inner_ip + inner_ip_len);
        uint16_t sport = ntohs(inner_tcp->th_sport);
        ip_id = ntohs(inner_ip->ip_id) - START_IP_ID;
        printf("ip_id = %d port = %d \n", ip_id, sport-START_IP_ID);
        if((icmp_hdr->type == ICMP_TIME_EXCEEDED && icmp_hdr->code == ICMP_EXC_TTL))  {
            printf(" Packet received with ICMP timeout\n");
            clock_gettime(CLOCK_MONOTONIC, &rxtime[ip_id]);
            iphop_addr[ip_id] = *recv_addr;
        } else if((icmp_hdr->type == ICMP_ECHOREPLY && icmp_hdr->code == 0))  {
            clock_gettime(CLOCK_MONOTONIC, &rxtime[ip_id]);
            iphop_addr[ip_id] = *recv_addr;
            done_flag=true;
        } else {
            printf("Error.. Packet received with ICMP type %d code %d \n",
                icmp_hdr->type, icmp_hdr->code);
        }
        fflush(stdout);
    }
}
