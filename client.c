#include <pthread.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <asm/types.h>
#include <math.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <linux/if.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/if_arp.h>
#include <arpa/inet.h>
#include <stdio.h>

#include "rawsend.h"

struct raw_result client_result;
int sock_fd = 0;
unsigned char* out_buff = NULL;
unsigned char* in_buff = NULL;
unsigned char snd_mac[6];
char *src_ifname;
char *dst_ifname;
long total_sent_packets = 0;
long total_recv_packets = 0;
long total_sent_bytes = 0;
int running = 1, waiting = 1;

void print_result(struct raw_result *result)
{
    double diff, rate;

    diff = result->useconds;
    diff /= 1000000;
    diff += result->seconds;

    rate = 8*(double)result->bytes/diff/1024;

    printf(" time:    %3u.%02u\n", result->seconds, result->useconds/10000);
    printf(" packets: %6u\n", result->packets);
    printf(" bytes:   %6u\n", result->bytes);
    printf(" rate:    %6.2f\n", rate);
    printf(" loss:    %6.2f\n", 1 - (double)result->packets/(double)(client_result.packets));
    printf(" dups:    %6u\n", result->duplicates);
}

void print_server_result(struct raw_result *result)
{
    result->seconds = ntohl(result->seconds);
    result->useconds = ntohl(result->useconds);
    result->packets = ntohl(result->packets);
    result->bytes = ntohl(result->bytes);
    result->duplicates = ntohl(result->duplicates);

    printf("server report:\n");
    print_result(result);
}

int open_socket(const char *ifname)
{
    struct ifreq ifr;
    int sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL)); 
    if (sock < 0)
        exit(EXIT_FAILURE);

    /* set promiscuous mode */
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
    ioctl(sock, SIOCGIFFLAGS, &ifr);
    ifr.ifr_flags |= IFF_PROMISC;
    ioctl(sock, SIOCGIFFLAGS, &ifr);

    return sock;
}

void close_socket(int sock)
{
    struct ifreq ifr;

    /* reset promiscuous mode */
    strncpy(ifr.ifr_name, src_ifname, IFNAMSIZ);
    ioctl(sock_fd, SIOCGIFFLAGS, &ifr);
    ifr.ifr_flags &= ~IFF_PROMISC;
    ioctl(sock_fd, SIOCSIFFLAGS, &ifr);
    shutdown(sock_fd, SHUT_RD);
    close(sock_fd);
}

void print_mac(const char *addr)
{
    int i;

    for (i = 0; i < ETH_ALEN - 1; i++)
        printf("%02hhx:", addr[i]);
    printf("%02hhx\n", addr[ETH_ALEN - 1]);
}

int interface_index(int sock, char *ifname)
{
    struct ifreq ifr;
    int i;

    /* retrieve source ethernet interface index */
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
    if (ioctl(sock_fd, SIOCGIFINDEX, &ifr) < 0)
        return -EXIT_FAILURE;

    return ifr.ifr_ifindex;
}

int interface_addr(int sock, char *ifname, char *addr)
{
    struct ifreq ifr;

    /* retrieve corresponding source MAC */
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
    if (ioctl(sock_fd, SIOCGIFHWADDR, &ifr) < 0)
        return -EXIT_FAILURE;
    memcpy(addr, ifr.ifr_hwaddr.sa_data, ETH_ALEN);

    return EXIT_SUCCESS;
}

void *read_packets(void *ptr)
{
    struct ethhdr *in_hdr;
    char *addr = ptr;
    int recv;

    in_buff = malloc(PACKET_SIZE);
    in_hdr = (struct ethhdr *)in_buff;

    while (waiting) {
        recv = recvfrom(sock_fd, in_buff, PACKET_SIZE, 0, NULL, NULL);

        if (recv == -1)
            break;

        if (recv < sizeof(*in_hdr))
            continue;

        /* do not consider packets with wrong destination */
        if (memcmp((const void*)in_hdr->h_dest, addr, ETH_ALEN) != 0)
            continue;

        /* check if a result was received */
        if (memcmp(in_buff + ETH_HLEN, END_OF_STREAM, sizeof(END_OF_STREAM)) == 0) {
            print_server_result((struct raw_result *)(in_buff + ETH_HLEN + sizeof(END_OF_STREAM)));
            break;
        }
    }

    close_socket(sock_fd);
    free(out_buff);
    free(in_buff);
    exit(EXIT_SUCCESS);
}

void sigint(int signum)
{
    if (!running)
        exit(EXIT_FAILURE);

    running = 0;
}

void sigalarm(int signum)
{
    if (!running)
        exit(EXIT_FAILURE);

    running = 0;
}

double timeval_subtract(struct timeval *result, struct timeval *t2, struct timeval *t1)
{
    double ret;
    long int diff;

    diff = (t2->tv_usec + 1000000 * t2->tv_sec) - (t1->tv_usec + 1000000 * t1->tv_sec);
    result->tv_sec = diff / 1000000;
    result->tv_usec = diff % 1000000;

    ret = diff;
    ret /= 1000000.0;

    return ret;
}

/* calc interval in microseconds */
int calc_interval(int rate)
{
    return 1e6 * 8 / rate;
}

int main(int argc, char *argv[]) {
    pthread_t thread;
    out_buff = (void*)malloc(PACKET_SIZE);
    unsigned char *data_ptr = out_buff + ETH_HLEN;
    unsigned char src_addr[ETH_HLEN], dst_addr[ETH_HLEN];
    struct ethhdr *out_hdr = (struct ethhdr *)out_buff;
    struct sockaddr_ll s_addr;
    struct timeval begin, end, elapsed;
    double diff;
    int i, sent, rate, interval, timeout = 0, src_idx, dst_idx;

    if (argc < 4)
    {
        printf("Missing arguments.\n"
                "%s [src_ifname] [dest_ifname] [kbit/s] [seconds] \n", argv[0]);
        exit(EXIT_FAILURE);
    }

    src_ifname = argv[1];
    dst_ifname = argv[2];
    rate = atoi(argv[3]);
    interval = calc_interval(rate);
    if (argc == 5)
        timeout = atoi(argv[4]);

    /* open raw socket */
    if ((sock_fd = open_socket(src_ifname)) < 0)
        exit(EXIT_FAILURE);

    /* prepare source interface */
    if ((src_idx = interface_index(sock_fd, src_ifname)) < 0)
        exit(EXIT_FAILURE);

    if (interface_addr(sock_fd, src_ifname, src_addr) < 0)
        exit(EXIT_FAILURE);

    /* prepare destination interface */
    if ((dst_idx = interface_index(sock_fd, dst_ifname)) < 0)
        exit(EXIT_FAILURE);

    if (interface_addr(sock_fd, dst_ifname, dst_addr) < 0)
        exit(EXIT_FAILURE);

    /* prepare sockaddr_ll */
    memset(&s_addr, 0, sizeof(s_addr));
    s_addr.sll_family   = AF_PACKET;
    s_addr.sll_protocol = htons(ETH_P_ALL);
    s_addr.sll_ifindex  = src_idx;
    s_addr.sll_halen    = ETH_ALEN;
    memcpy(s_addr.sll_addr, dst_addr, ETH_ALEN);


    /* bind to interface */
    if (bind(sock_fd, (struct sockaddr *)&s_addr, sizeof(s_addr)) < 0)
        exit(EXIT_FAILURE);

    /* enable signals */
    signal(SIGINT, sigint);
    signal(SIGALRM, sigalarm);

    if (timeout)
        alarm(timeout);

    /* prepare ethernet header */
    memcpy(out_hdr->h_dest, dst_addr, ETH_ALEN);
    memcpy(out_hdr->h_source, src_addr, ETH_ALEN);

    /* fill ethernet payload with some data */
    for (i = 0; i < PACKET_SIZE - ETH_HLEN; i++)
        data_ptr[i] = (unsigned char)(0);

    pthread_create(&thread, NULL, read_packets, src_addr);
    printf("sending packets\n");

    /* record timestamp */
    if (gettimeofday(&begin, 0) < 0)
        exit(EXIT_FAILURE);

    /* prepare counters */
    client_result.sequence = 1;

    while (running) {
        *(int *)data_ptr = htonl(client_result.sequence++);
        sent = sendto(sock_fd, out_buff, PACKET_SIZE, 0, (struct sockaddr *)&s_addr, sizeof(s_addr));
        client_result.packets++;
        client_result.bytes += sent;
        usleep(interval);
    }

    printf("packets sent\n");

    /* record timestamp */
    if (gettimeofday(&end, 0) < 0)
        exit(EXIT_FAILURE);

    /* prepare and pring result */
    diff = timeval_subtract(&elapsed, &end, &begin);
    client_result.seconds = elapsed.tv_sec;
    client_result.useconds = elapsed.tv_usec;
    printf("client report:\n");
    print_result(&client_result);

    /* send final packets */
    memcpy(data_ptr, END_OF_STREAM, sizeof(END_OF_STREAM));
    for (i = 0; i < 10; i++)
        sendto(sock_fd, out_buff, ETH_HLEN + sizeof(END_OF_STREAM), 0,
                (struct sockaddr *)&s_addr, sizeof(s_addr));

    /* wait 5 seconds for server result */
    sleep(5);
    waiting = 0;
    close_socket(sock_fd);

    free(out_buff);
    free(in_buff);

    return EXIT_SUCCESS;
}
