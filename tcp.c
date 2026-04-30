#include "ft_nmap.h"
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/ip_icmp.h>
#include <net/ethernet.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <pcap.h>

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
    iph->check    = 0;
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

/*
 * Returns STATE_UNKNOWN if this packet is not a reply to our probe.
 * pkt points to the start of the Ethernet frame captured by pcap.
 */
static t_state classify_tcp_pkt(const u_char *pkt, int pkt_len,
                                 uint16_t target_port, uint16_t src_port,
                                 int scan_bit) {
    if (pkt_len < (int)(sizeof(struct ether_header) + sizeof(struct iphdr)))
        return STATE_UNKNOWN;

    const struct iphdr *ip =
        (struct iphdr *)(pkt + sizeof(struct ether_header));
    int ihl = ip->ihl * 4;

    if (ip->protocol == IPPROTO_TCP) {
        if (pkt_len < (int)(sizeof(struct ether_header) + ihl
                            + (int)sizeof(struct tcphdr)))
            return STATE_UNKNOWN;

        const struct tcphdr *tcp =
            (struct tcphdr *)((const char *)ip + ihl);

        if (ntohs(tcp->th_sport) != target_port) return STATE_UNKNOWN;
        if (ntohs(tcp->th_dport) != src_port)    return STATE_UNKNOWN;

        uint8_t flags = tcp->th_flags;

        if (scan_bit == SCAN_SYN) {
            if ((flags & (TH_SYN | TH_ACK)) == (TH_SYN | TH_ACK))
                return STATE_OPEN;
            if (flags & TH_RST)
                return STATE_CLOSED;
        }
        if (scan_bit == SCAN_NULL || scan_bit == SCAN_FIN
                || scan_bit == SCAN_XMAS) {
            if (flags & TH_RST)
                return STATE_CLOSED;
        }
        if (scan_bit == SCAN_ACK) {
            if (flags & TH_RST)
                return STATE_UNFILTERED;
        }
    }

    if (ip->protocol == IPPROTO_ICMP) {
        if (pkt_len < (int)(sizeof(struct ether_header) + ihl
                            + (int)sizeof(struct icmphdr)))
            return STATE_UNKNOWN;

        const struct icmphdr *icmp =
            (struct icmphdr *)((const char *)ip + ihl);

        if (icmp->type == ICMP_DEST_UNREACH)
            return STATE_FILTERED;
    }

    return STATE_UNKNOWN;
}

t_state tcp_scan(struct sockaddr_in *dest, uint16_t port,
                 uint16_t src_port, uint32_t src_ip,
                 uint8_t tcp_flags, int scan_bit,
                 int raw_sock, void *pcap_handle) {
    char pkt[sizeof(struct iphdr) + sizeof(struct tcphdr)];
    memset(pkt, 0, sizeof(pkt));
    build_packet(pkt, src_ip, dest->sin_addr.s_addr,
                 src_port, port, tcp_flags);

    if (sendto(raw_sock, pkt, sizeof(pkt), 0,
               (struct sockaddr *)dest, sizeof(*dest)) < 0)
        return STATE_FILTERED;

    if (!pcap_handle)
        return STATE_FILTERED;

    pcap_t *pcap = pcap_handle;

    struct timeval deadline;
    gettimeofday(&deadline, NULL);
    deadline.tv_sec += SCAN_TIMEOUT;

    while (1) {
        struct timeval now;
        gettimeofday(&now, NULL);
        if (timercmp(&now, &deadline, >=))
            break;

        struct pcap_pkthdr *hdr;
        const u_char       *raw;
        int ret = pcap_next_ex(pcap, &hdr, &raw);
        if (ret <= 0)
            continue;

        t_state s = classify_tcp_pkt(raw, (int)hdr->caplen,
                                     port, src_port, scan_bit);
        if (s != STATE_UNKNOWN)
            return s;
    }

    if (scan_bit == SCAN_NULL || scan_bit == SCAN_FIN || scan_bit == SCAN_XMAS)
        return STATE_OPEN_FILTERED;
    if (scan_bit == SCAN_ACK)
        return STATE_FILTERED;
    return STATE_FILTERED;
}
