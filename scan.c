#include "ft_nmap.h"
#include <netinet/ip.h>
#include <sys/socket.h>
#include <arpa/inet.h>

/* index 0..4 are TCP scans, index 5 is UDP */
static const uint8_t g_tcp_flags[SCAN_COUNT] = {
    TH_SYN,
    0,
    TH_ACK,
    TH_FIN,
    TH_FIN | TH_PUSH | TH_URG,
    0,
};

static const int g_scan_bits[SCAN_COUNT] = {
    SCAN_SYN, SCAN_NULL, SCAN_ACK, SCAN_FIN, SCAN_XMAS, SCAN_UDP,
};

static uint32_t get_local_ip(struct sockaddr_in *dest) {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0)
        return 0;
    struct sockaddr_in tmp = *dest;
    tmp.sin_port = htons(80);
    connect(sock, (struct sockaddr *)&tmp, sizeof(tmp));
    struct sockaddr_in local;
    socklen_t len = sizeof(local);
    getsockname(sock, (struct sockaddr *)&local, &len);
    close(sock);
    return local.sin_addr.s_addr;
}

static void scan_port(struct sockaddr_in *dest, uint16_t port,
                      int scan_flags, uint32_t src_ip,
                      int raw_sock, t_result *res) {
    res->port = port;
    for (int i = 0; i < SCAN_COUNT - 1; i++) {
        if (!(scan_flags & g_scan_bits[i]))
            continue;
        uint16_t src_port = (uint16_t)(SRC_PORT_BASE + i);
        res->states[i] = tcp_scan(dest, port, src_port, src_ip,
                                  g_tcp_flags[i], g_scan_bits[i],
                                  raw_sock, NULL);
    }
    /* UDP stub for now */
    if (scan_flags & SCAN_UDP)
        res->states[5] = STATE_OPEN_FILTERED;
}

void run_scan(t_options *opts, struct sockaddr_in *dest,
              const char *dest_ip, t_result *results) {
    (void)dest_ip;

    int raw_sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (raw_sock < 0) { perror("socket"); return; }
    int one = 1;
    setsockopt(raw_sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));

    uint32_t src_ip = get_local_ip(dest);

    for (int i = 0; i < opts->port_count; i++) {
        memset(&results[i], 0, sizeof(results[i]));
        scan_port(dest, opts->ports[i], opts->scan_flags, src_ip,
                  raw_sock, &results[i]);
    }
    close(raw_sock);
}
