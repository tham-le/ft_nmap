#include "ft_nmap.h"
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <arpa/inet.h>

struct pseudo_hdr {
    uint32_t src;
    uint32_t dst;
    uint8_t  zero;
    uint8_t  proto;
    uint16_t tcp_len;
};

static uint16_t tcp_checksum(uint32_t src_ip, uint32_t dst_ip,
                              struct tcphdr *tcp) {
    struct pseudo_hdr phdr;
    phdr.src     = src_ip;
    phdr.dst     = dst_ip;
    phdr.zero    = 0;
    phdr.proto   = IPPROTO_TCP;
    phdr.tcp_len = htons(sizeof(struct tcphdr));

    char buf[sizeof(phdr) + sizeof(struct tcphdr)];
    memcpy(buf, &phdr, sizeof(phdr));
    memcpy(buf + sizeof(phdr), tcp, sizeof(struct tcphdr));
    return checksum(buf, sizeof(buf));
}

static void build_packet(char *pkt, uint32_t src_ip, uint32_t dst_ip,
                         uint16_t src_port, uint16_t dst_port,
                         uint8_t tcp_flags) {
    struct iphdr  *iph = (struct iphdr *)pkt;
    struct tcphdr *tcp = (struct tcphdr *)(pkt + sizeof(struct iphdr));

    iph->version  = 4;
    iph->ihl      = 5;
    iph->tos      = 0;
    iph->tot_len  = htons(sizeof(struct iphdr) + sizeof(struct tcphdr));
    iph->id       = htons((uint16_t)(rand() & 0xFFFF));
    iph->frag_off = 0;
    iph->ttl      = 64;
    iph->protocol = IPPROTO_TCP;
    iph->check    = 0;  /* kernel fills this with IP_HDRINCL */
    iph->saddr    = src_ip;
    iph->daddr    = dst_ip;

    tcp->th_sport = htons(src_port);
    tcp->th_dport = htons(dst_port);
    tcp->th_seq   = htonl((uint32_t)rand());
    tcp->th_ack   = 0;
    tcp->th_off   = 5;
    tcp->th_flags = tcp_flags;
    tcp->th_win   = htons(65535);
    tcp->th_sum   = 0;
    tcp->th_urp   = 0;

    tcp->th_sum = tcp_checksum(src_ip, dst_ip, tcp);
}

t_state tcp_scan(struct sockaddr_in *dest, uint16_t port,
                 uint16_t src_port, uint32_t src_ip,
                 uint8_t tcp_flags, int scan_bit,
                 int raw_sock, void *pcap) {
    (void)pcap;
    (void)scan_bit;

    char pkt[sizeof(struct iphdr) + sizeof(struct tcphdr)];
    memset(pkt, 0, sizeof(pkt));
    build_packet(pkt, src_ip, dest->sin_addr.s_addr,
                 src_port, port, tcp_flags);

    if (sendto(raw_sock, pkt, sizeof(pkt), 0,
               (struct sockaddr *)dest, sizeof(*dest)) < 0)
        return STATE_FILTERED;

    /* no capture yet: always report Filtered */
    return STATE_FILTERED;
}
