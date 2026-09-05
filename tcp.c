#include "ft_nmap.h"
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <net/ethernet.h>
#include <sys/socket.h>
#include <arpa/inet.h>

/* an ICMP error embeds at least 8 bytes of the probe: sport, dport, seq */
#define ICMP_EMBEDDED_MIN 8

struct pseudo_hdr {
    uint32_t src;
    uint32_t dst;
    uint8_t  zero;
    uint8_t  proto;
    uint16_t tcp_len;
};

/* one source port per thread and scan type, so pcap filters never overlap */
static uint16_t src_port(int thread_id, int scan_idx) {
    return (uint16_t)(SRC_PORT_BASE + thread_id * SCAN_COUNT + scan_idx);
}

static uint16_t checksum(const void *data, size_t len) {
    const uint16_t *ptr = data;
    uint32_t        sum = 0;
    while (len > 1) {
        sum += *ptr++;
        len -= 2;
    }
    if (len)
        sum += *(const uint8_t *)ptr;
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    return (uint16_t)~sum;
}

/* the address the kernel would route from, 0 on failure */
static uint32_t get_local_ip(const struct sockaddr_in *dest) {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0)
        return 0;
    struct sockaddr_in tmp = *dest, local;
    socklen_t          len = sizeof(local);
    tmp.sin_port = htons(80);
    int ok = connect(sock, (struct sockaddr *)&tmp, sizeof(tmp)) == 0
          && getsockname(sock, (struct sockaddr *)&local, &len) == 0;
    close(sock);
    return ok ? local.sin_addr.s_addr : 0;
}

static int open_raw_socket(void) {
    int fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (fd < 0) {
        perror("ft_nmap: raw socket");
        return -1;
    }
    int one = 1;
    if (setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
        perror("ft_nmap: setsockopt");
        close(fd);
        return -1;
    }
    return fd;
}

static int find_iface(uint32_t local_ip, char *out, size_t out_size) {
    pcap_if_t *devs;
    char       errbuf[PCAP_ERRBUF_SIZE];
    int        found = -1;

    if (pcap_findalldevs(&devs, errbuf) < 0)
        return -1;
    for (pcap_if_t *d = devs; d && found < 0; d = d->next)
        for (pcap_addr_t *a = d->addresses; a && found < 0; a = a->next)
            if (a->addr && a->addr->sa_family == AF_INET
                    && ((struct sockaddr_in *)a->addr)->sin_addr.s_addr == local_ip) {
                snprintf(out, out_size, "%s", d->name);
                found = 0;
            }
    pcap_freealldevs(devs);
    return found;
}

static int set_filter(pcap_t *pcap, const char *dest_ip, int thread_id) {
    char               filter[256];
    struct bpf_program fp;

    snprintf(filter, sizeof(filter),
             "(tcp and src host %s and dst portrange %u-%u) or (icmp and src host %s)",
             dest_ip, src_port(thread_id, 0), src_port(thread_id, SCAN_COUNT - 1), dest_ip);
    if (pcap_compile(pcap, &fp, filter, 1, PCAP_NETMASK_UNKNOWN) < 0)
        return -1;
    int ret = pcap_setfilter(pcap, &fp);
    pcap_freecode(&fp);
    return ret;
}

static pcap_t *open_pcap(uint32_t local_ip, const char *dest_ip, int thread_id) {
    char iface[64], errbuf[PCAP_ERRBUF_SIZE];

    if (find_iface(local_ip, iface, sizeof(iface)) < 0) {
        fprintf(stderr, "ft_nmap: no interface owns the local IP\n");
        return NULL;
    }
    pcap_t *pcap = pcap_open_live(iface, 65535, 0, 1, errbuf);
    if (!pcap) {
        fprintf(stderr, "ft_nmap: pcap_open_live: %s\n", errbuf);
        return NULL;
    }
    if (set_filter(pcap, dest_ip, thread_id) < 0 || pcap_setnonblock(pcap, 1, errbuf) < 0) {
        fprintf(stderr, "ft_nmap: pcap setup on %s: %s\n", iface, pcap_geterr(pcap));
        pcap_close(pcap);
        return NULL;
    }
    return pcap;
}

int probe_open(t_probe *p, int thread_id, const struct sockaddr_in *dest,
               const char *dest_ip) {
    p->thread_id = thread_id;
    p->seed      = (unsigned int)time(NULL) ^ ((unsigned int)thread_id * 2654435761u);
    p->pcap      = NULL;
    p->src_ip    = get_local_ip(dest);
    p->raw_sock  = open_raw_socket();
    if (p->src_ip == 0)
        fprintf(stderr, "ft_nmap: cannot determine local IP\n");
    else if (p->raw_sock >= 0)
        p->pcap = open_pcap(p->src_ip, dest_ip, thread_id);
    return p->pcap ? 0 : -1;
}

void probe_close(t_probe *p) {
    if (p->pcap)
        pcap_close(p->pcap);
    if (p->raw_sock >= 0)
        close(p->raw_sock);
}

static void build_packet(char *pkt, t_probe *p, uint32_t dst_ip,
                         uint16_t src_port, uint16_t dst_port, uint8_t tcp_flags) {
    struct iphdr  *iph = (struct iphdr *)pkt;
    struct tcphdr *tcp = (struct tcphdr *)(pkt + sizeof(struct iphdr));

    iph->version  = 4;
    iph->ihl      = 5;
    iph->tot_len  = htons(sizeof(struct iphdr) + sizeof(struct tcphdr));
    iph->id       = htons((uint16_t)rand_r(&p->seed));
    iph->ttl      = 64;
    iph->protocol = IPPROTO_TCP;
    iph->saddr    = p->src_ip;
    iph->daddr    = dst_ip;

    tcp->th_sport = htons(src_port);
    tcp->th_dport = htons(dst_port);
    tcp->th_seq   = htonl((uint32_t)rand_r(&p->seed));
    tcp->th_off   = 5;
    tcp->th_flags = tcp_flags;
    tcp->th_win   = htons(65535);

    struct pseudo_hdr phdr = { p->src_ip, dst_ip, 0, IPPROTO_TCP, htons(sizeof(*tcp)) };
    char buf[sizeof(phdr) + sizeof(*tcp)];
    memcpy(buf, &phdr, sizeof(phdr));
    memcpy(buf + sizeof(phdr), tcp, sizeof(*tcp));
    tcp->th_sum = checksum(buf, sizeof(buf));
}

static t_state classify_tcp(const u_char *l4, int len, uint16_t target_port,
                            uint16_t src_port, t_scan scan) {
    const struct tcphdr *tcp = (const struct tcphdr *)l4;
    if (len < (int)sizeof(*tcp))
        return STATE_UNKNOWN;
    if (ntohs(tcp->th_sport) != target_port || ntohs(tcp->th_dport) != src_port)
        return STATE_UNKNOWN;

    uint8_t flags = tcp->th_flags;
    if (scan == SCAN_SYN && (flags & (TH_SYN | TH_ACK)) == (TH_SYN | TH_ACK))
        return STATE_OPEN;
    if (!(flags & TH_RST))
        return STATE_UNKNOWN;
    return scan == SCAN_ACK ? STATE_UNFILTERED : STATE_CLOSED;
}

/* Filtered when the ICMP unreachable error embeds our own probe, else Unknown */
static t_state classify_icmp(const u_char *l4, int len, uint16_t target_port,
                             uint16_t src_port) {
    const struct icmphdr *icmp = (const struct icmphdr *)l4;
    if (len < (int)(sizeof(*icmp) + sizeof(struct iphdr)) || icmp->type != ICMP_DEST_UNREACH)
        return STATE_UNKNOWN;
    const struct iphdr *orig = (const struct iphdr *)(l4 + sizeof(*icmp));
    const u_char       *otcp = (const u_char *)orig + orig->ihl * 4;
    if (orig->protocol != IPPROTO_TCP || otcp + ICMP_EMBEDDED_MIN > l4 + len)
        return STATE_UNKNOWN;
    uint16_t sport, dport;
    memcpy(&sport, otcp, 2);
    memcpy(&dport, otcp + 2, 2);
    if (ntohs(sport) != src_port || ntohs(dport) != target_port)
        return STATE_UNKNOWN;
    return STATE_FILTERED;
}

/* STATE_UNKNOWN when the Ethernet frame is not an answer to our probe */
static t_state classify(const u_char *pkt, int len, uint16_t target_port,
                        uint16_t src_port, t_scan scan) {
    if (len < (int)(sizeof(struct ether_header) + sizeof(struct iphdr)))
        return STATE_UNKNOWN;
    const struct iphdr *ip     = (const struct iphdr *)(pkt + sizeof(struct ether_header));
    const u_char       *l4     = (const u_char *)ip + ip->ihl * 4;
    int                 l4_len = len - (int)(l4 - pkt);

    if (ip->protocol == IPPROTO_TCP)
        return classify_tcp(l4, l4_len, target_port, src_port, scan);
    if (ip->protocol == IPPROTO_ICMP)
        return classify_icmp(l4, l4_len, target_port, src_port);
    return STATE_UNKNOWN;
}

/* the first answer to our probe before the deadline, else STATE_UNKNOWN */
static t_state wait_reply(pcap_t *pcap, uint16_t port, uint16_t src_port, t_scan scan) {
    struct timespec deadline;
    int             fd = pcap_get_selectable_fd(pcap);

    deadline_after(&deadline, TCP_TIMEOUT_MS);
    while (wait_fd(fd, &deadline) > 0) {
        struct pcap_pkthdr *hdr;
        const u_char       *data;
        if (pcap_next_ex(pcap, &hdr, &data) != 1)
            continue;
        t_state s = classify(data, (int)hdr->caplen, port, src_port, scan);
        if (s != STATE_UNKNOWN)
            return s;
    }
    return STATE_UNKNOWN;
}

t_state tcp_scan(t_probe *p, const struct sockaddr_in *dest, uint16_t port, int scan_idx) {
    t_scan   scan = g_scan_types[scan_idx].bit;
    uint16_t sp   = src_port(p->thread_id, scan_idx);
    char     pkt[sizeof(struct iphdr) + sizeof(struct tcphdr)];

    memset(pkt, 0, sizeof(pkt));
    build_packet(pkt, p, dest->sin_addr.s_addr, sp, port, g_scan_types[scan_idx].tcp_flags);
    if (sendto(p->raw_sock, pkt, sizeof(pkt), 0,
               (const struct sockaddr *)dest, sizeof(*dest)) < 0)
        return STATE_FILTERED;

    t_state s = wait_reply(p->pcap, port, sp, scan);
    if (s != STATE_UNKNOWN)
        return s;
    /* no answer: NULL, FIN and XMAS cannot tell open from filtered */
    if (scan == SCAN_NULL || scan == SCAN_FIN || scan == SCAN_XMAS)
        return STATE_OPEN_FILTERED;
    return STATE_FILTERED;
}
