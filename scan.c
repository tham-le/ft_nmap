#include "ft_nmap.h"
#include <netinet/ip.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <pcap.h>

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
    if (sock < 0) return 0;
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
                      int scan_flags, uint32_t src_ip, int thread_id,
                      int raw_sock, pcap_t *pcap, t_result *res) {
    res->port = port;
    for (int i = 0; i < SCAN_COUNT - 1; i++) {
        if (!(scan_flags & g_scan_bits[i]))
            continue;
        /* unique src port per thread and scan type so pcap filter matches */
        uint16_t src_port = (uint16_t)(SRC_PORT_BASE + thread_id * SCAN_COUNT + i);
        res->states[i] = tcp_scan(dest, port, src_port, src_ip,
                                  g_tcp_flags[i], g_scan_bits[i],
                                  raw_sock, pcap);
    }
    if (scan_flags & SCAN_UDP)
        res->states[5] = udp_scan(dest, port);
}

static void *thread_worker(void *arg) {
    t_thread_arg *a = arg;

    int raw_sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (raw_sock < 0) { perror("socket"); return NULL; }
    int one = 1;
    if (setsockopt(raw_sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
        perror("setsockopt"); close(raw_sock); return NULL;
    }

    /* each thread has its own source port range so filters don't overlap */
    uint16_t sp_min = (uint16_t)(SRC_PORT_BASE + a->thread_id * SCAN_COUNT);
    uint16_t sp_max = (uint16_t)(sp_min + SCAN_COUNT - 2);

    /* get local IP first so pcap opens on the correct interface */
    uint32_t src_ip = get_local_ip(&a->dest);
    if (src_ip == 0) {
        fprintf(stderr, "ft_nmap: failed to determine local IP\n");
        close(raw_sock);
        return NULL;
    }

    pcap_t *pcap = NULL;
    if (a->scan_flags & (SCAN_SYN | SCAN_NULL | SCAN_ACK | SCAN_FIN | SCAN_XMAS)) {
        pcap = open_pcap(a->dest_ip, src_ip, sp_min, sp_max);
        if (!pcap) { close(raw_sock); return NULL; }
    }

    for (int i = 0; i < a->port_count; i++) {
        t_result res;
        memset(&res, 0, sizeof(res));
        scan_port(&a->dest, a->ports[i], a->scan_flags, src_ip,
                  a->thread_id, raw_sock, pcap, &res);

        if (a->mutex) pthread_mutex_lock(a->mutex);
        a->results[i] = res;
        if (a->mutex) pthread_mutex_unlock(a->mutex);
    }

    if (pcap) pcap_close(pcap);
    close(raw_sock);
    return NULL;
}

void run_scan(t_options *opts, struct sockaddr_in *dest,
              const char *dest_ip, t_result *results) {
    int nthreads = opts->speedup ? opts->speedup : 1;
    if (nthreads > opts->port_count)
        nthreads = opts->port_count;

    pthread_t       threads[MAX_SPEEDUP];
    t_thread_arg    args[MAX_SPEEDUP];
    pthread_mutex_t mutex;
    pthread_mutex_init(&mutex, NULL);

    int chunk = opts->port_count / nthreads;
    int rem   = opts->port_count % nthreads;

    for (int i = 0; i < nthreads; i++) {
        int offset = i * chunk + (i < rem ? i : rem);
        int count  = chunk + (i < rem ? 1 : 0);

        args[i].dest       = *dest;
        args[i].scan_flags = opts->scan_flags;
        args[i].ports      = opts->ports + offset;
        args[i].port_count = count;
        args[i].results    = results + offset;
        args[i].thread_id  = i;
        args[i].mutex      = (nthreads > 1) ? &mutex : NULL;
        strncpy(args[i].dest_ip, dest_ip, INET_ADDRSTRLEN - 1);
        args[i].dest_ip[INET_ADDRSTRLEN - 1] = '\0';

        pthread_create(&threads[i], NULL, thread_worker, &args[i]);
    }

    for (int i = 0; i < nthreads; i++)
        pthread_join(threads[i], NULL);

    pthread_mutex_destroy(&mutex);
}
