#include "ft_nmap.h"
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#define ICMP_BUF_SIZE 1024

static t_state classify_icmp_reply(const char *buf, ssize_t n,
                                   uint32_t dest_addr, uint16_t port) {
    const struct iphdr *ip  = (struct iphdr *)buf;
    int                 ihl = ip->ihl * 4;
    if (n < ihl + (int)sizeof(struct icmphdr))
        return STATE_UNKNOWN;

    const struct icmphdr *icmp = (struct icmphdr *)(buf + ihl);
    if (icmp->type != ICMP_DEST_UNREACH)
        return STATE_UNKNOWN;

    /* the original IP+UDP headers are embedded after the ICMP header */
    int orig_off = ihl + (int)sizeof(struct icmphdr);
    if (n < orig_off + (int)sizeof(struct iphdr))
        return STATE_UNKNOWN;

    const struct iphdr *orig_ip = (struct iphdr *)(buf + orig_off);
    if (orig_ip->protocol != IPPROTO_UDP)
        return STATE_UNKNOWN;
    if (orig_ip->daddr != dest_addr)
        return STATE_UNKNOWN;

    int orig_ihl = orig_ip->ihl * 4;
    if (n < orig_off + orig_ihl + (int)sizeof(struct udphdr))
        return STATE_UNKNOWN;

    const struct udphdr *orig_udp =
        (struct udphdr *)(buf + orig_off + orig_ihl);
    if (ntohs(orig_udp->dest) != port)
        return STATE_UNKNOWN;

    if (icmp->code == ICMP_PORT_UNREACH)
        return STATE_CLOSED;
    return STATE_FILTERED;
}

t_state udp_scan(struct sockaddr_in *dest, uint16_t port) {
    int icmp_sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (icmp_sock < 0)
        return STATE_OPEN_FILTERED;

    int udp_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (udp_sock < 0) {
        close(icmp_sock);
        return STATE_OPEN_FILTERED;
    }

    struct sockaddr_in target = *dest;
    target.sin_port = htons(port);
    if (sendto(udp_sock, "", 0, 0,
               (struct sockaddr *)&target, sizeof(target)) < 0) {
        close(udp_sock);
        close(icmp_sock);
        return STATE_OPEN_FILTERED;
    }
    close(udp_sock);

    struct timeval tv = { .tv_sec = UDP_TIMEOUT, .tv_usec = 0 };
    setsockopt(icmp_sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    char buf[ICMP_BUF_SIZE];
    struct sockaddr_in from;
    socklen_t fromlen = sizeof(from);

    while (1) {
        ssize_t n = recvfrom(icmp_sock, buf, sizeof(buf), 0,
                             (struct sockaddr *)&from, &fromlen);
        if (n < 0) {
            close(icmp_sock);
            return STATE_OPEN_FILTERED;
        }
        t_state s = classify_icmp_reply(buf, n, dest->sin_addr.s_addr, port);
        if (s != STATE_UNKNOWN) {
            close(icmp_sock);
            return s;
        }
    }
}
