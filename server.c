/*
   ============================================================================
Name        : server.c
Author      : Javier Lopez
Version     :
Copyright   : 
Description :
============================================================================
*/

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

int sock_fd = 0;
char *ifname;
int running = 1;
struct raw_result server_result;

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
    printf(" loss:    %6.2f\n", 1 - (double)result->packets/(double)(server_result.sequence));
    printf(" dups:    %6u\n", result->duplicates);
}

int open_socket(const char *ifname)
{
    struct ifreq ifr;
    int sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL)); 
    if (sock < 0)
        exit(EXIT_FAILURE);

    return sock;

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
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
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

void sigint(int signum)
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


int main(int argc, char *argv[]) {
    unsigned char *buff = (void *)malloc(PACKET_SIZE);
    unsigned char *data_ptr = buff + ETH_HLEN;
    unsigned char dst_mac[ETH_ALEN];
    struct ethhdr *eth_hdr = (struct ethhdr *)buff;
    struct sockaddr_ll s_addr;
    struct timeval begin, end, elapsed;
    struct raw_result *result = (struct raw_result *)(data_ptr + sizeof(END_OF_STREAM));
    double diff;
    int if_index = 0, recv, i, seq;

    if (argc < 2)
    {
        printf("Missing arguments.\n"
                "%s [ifname] \n",argv[0]);
        exit(EXIT_FAILURE);
    }

    ifname = argv[1];

    /* open socket */
    if ((sock_fd = open_socket(ifname)) < 0)
        exit(EXIT_FAILURE);

    /* get ethernet interface index */
    if ((if_index = interface_index(sock_fd, ifname)) < 0)
        exit(EXIT_FAILURE);

    /* get ethernet interface address */
    if (interface_addr(sock_fd, ifname, dst_mac) < 0)
        exit(EXIT_FAILURE);

    /* prepare sockaddr_ll */
    memset(&s_addr, 0, sizeof(s_addr));
    s_addr.sll_family   = AF_PACKET;
    s_addr.sll_protocol = htons(ETH_P_ALL);
    s_addr.sll_ifindex  = if_index;

    /* bind to interface */
    if (bind(sock_fd, (struct sockaddr *) &s_addr, sizeof(s_addr)) == -1)
        exit(EXIT_FAILURE);

    /* enable signal */
    signal(SIGINT, sigint);

    printf("listening on ");
    print_mac(dst_mac);

    while (running) {
        recv = recvfrom(sock_fd, buff, PACKET_SIZE, 0, NULL, NULL);

        if (recv <= 0)
            break;

        /* check if packet is for us */
        if (memcmp(eth_hdr->h_dest, dst_mac, ETH_ALEN) != 0)
            continue;

        /* break on special packet */
        if (memcmp(data_ptr, END_OF_STREAM, sizeof(END_OF_STREAM))== 0)
            break;

        /* record timestamp on first received packet */
        if (server_result.packets == 0) {
            if (gettimeofday(&begin, 0) < 0)
                exit(EXIT_FAILURE);
            printf("connect from ");
            print_mac(eth_hdr->h_source);
        }

        seq = ntohl(*(unsigned int *)data_ptr);
        if (seq > server_result.sequence) {
            server_result.sequence = seq;
        } else {
            server_result.duplicates++;
            continue;
        }

        /* update counters */
        server_result.packets++;
        server_result.bytes += recv;
    }

    /* record timestamp */
    if (gettimeofday(&end, 0) < 0)
        exit(EXIT_FAILURE);

    /* prepare report */
    diff = timeval_subtract(&elapsed, &end, &begin);
    result->seconds = htonl(elapsed.tv_sec);
    result->useconds = htonl(elapsed.tv_usec);
    result->packets = htonl(server_result.packets);
    result->bytes = htonl(server_result.bytes);
    result->duplicates = htonl(server_result.duplicates);

    /* prepare header */
    memcpy(eth_hdr->h_dest, eth_hdr->h_source, ETH_ALEN);
    memcpy(eth_hdr->h_source, dst_mac, ETH_ALEN);

    /* prepare sockaddr */
    memcpy(s_addr.sll_addr, eth_hdr->h_dest, ETH_ALEN);

    /* send server report */
    for (i = 0; i < 10; i++)
        sendto(sock_fd, buff, ETH_HLEN + sizeof(END_OF_STREAM) + sizeof(*result), 0,
                (struct sockaddr *)&s_addr, sizeof(s_addr));

    close_socket(sock_fd);
    free(buff);

    /* prepare and print result */
    server_result.seconds = elapsed.tv_sec;
    server_result.useconds = elapsed.tv_usec;
    printf("server report:\n");
    print_result(&server_result);

    return EXIT_SUCCESS;
}
