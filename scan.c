#include "ft_nmap.h"
#include <netinet/ip.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <pthread.h>

static void scan_port(struct sockaddr_in *dest, uint16_t port,
                      int scan_flags, uint32_t src_ip, int thread_id,
                      int raw_sock, pcap_t *pcap, t_result *res) {
    res->port = port;
    for (int i = 0; i < SCAN_COUNT; i++) {
        if (g_scan_types[i].bit == SCAN_UDP)
            continue;
        if (!(scan_flags & g_scan_types[i].bit))
            continue;
        uint16_t src_port = (uint16_t)(SRC_PORT_BASE + thread_id * SCAN_COUNT + i);
        res->states[i] = tcp_scan(dest, port, src_port, src_ip,
                                  g_scan_types[i].tcp_flags, g_scan_types[i].bit,
                                  raw_sock, pcap);
    }
    for (int i = 0; i < SCAN_COUNT; i++) {
        if (g_scan_types[i].bit == SCAN_UDP) {
            if (scan_flags & SCAN_UDP)
                res->states[i] = udp_scan(dest, port);
            break;
        }
    }
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
    uint16_t sp_max = (uint16_t)(sp_min + SCAN_COUNT - 2); /* -1 count→index, -1 exclude UDP slot */

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

        a->results[i] = res;
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

    pthread_t    threads[MAX_SPEEDUP];
    t_thread_arg args[MAX_SPEEDUP];

    int chunk = opts->port_count / nthreads;
    int rem   = opts->port_count % nthreads;

    int ok[MAX_SPEEDUP] = {0};
    for (int i = 0; i < nthreads; i++) {
        int offset = i * chunk + (i < rem ? i : rem);
        int count  = chunk + (i < rem ? 1 : 0);

        args[i].dest       = *dest;
        args[i].scan_flags = opts->scan_flags;
        args[i].ports      = opts->ports + offset;
        args[i].port_count = count;
        args[i].results    = results + offset;
        args[i].thread_id  = i;
        strncpy(args[i].dest_ip, dest_ip, INET_ADDRSTRLEN - 1);
        args[i].dest_ip[INET_ADDRSTRLEN - 1] = '\0';

        ok[i] = (pthread_create(&threads[i], NULL, thread_worker, &args[i]) == 0);
        if (!ok[i])
            fprintf(stderr, "ft_nmap: pthread_create failed\n");
    }

    for (int i = 0; i < nthreads; i++)
        if (ok[i])
            pthread_join(threads[i], NULL);
}
