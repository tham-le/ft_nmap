#include "ft_nmap.h"

const t_scan_type g_scan_types[SCAN_COUNT] = {
    { SCAN_SYN,  TH_SYN,                   "SYN"  },
    { SCAN_NULL, 0,                        "NULL" },
    { SCAN_ACK,  TH_ACK,                   "ACK"  },
    { SCAN_FIN,  TH_FIN,                   "FIN"  },
    { SCAN_XMAS, TH_FIN | TH_PUSH | TH_URG, "XMAS" },
    { SCAN_UDP,  0,                        "UDP"  },
};

typedef struct s_worker {
    pthread_t                 tid;
    int                       id;
    int                       started;
    int                       failed;
    const struct sockaddr_in *dest;
    const char               *dest_ip;
    t_scan                    scan_flags;
    t_result                 *results;
    int                       port_count;
} t_worker;

static void scan_port(const t_worker *w, t_probe *p, t_result *res) {
    for (int s = 0; s < SCAN_COUNT && !g_stop; s++) {
        if (!(w->scan_flags & g_scan_types[s].bit))
            continue;
        if (g_scan_types[s].bit == SCAN_UDP)
            res->states[s] = udp_scan(w->dest, res->port);
        else
            res->states[s] = tcp_scan(p, w->dest, res->port, s);
    }
}

static void *worker(void *arg) {
    t_worker *w = arg;
    t_probe   p;

    /* only the TCP scans craft packets, a UDP-only scan needs no probe */
    if ((w->scan_flags & SCAN_TCP) && probe_open(&p, w->id, w->dest, w->dest_ip) < 0)
        w->failed = 1;
    for (int i = 0; i < w->port_count && !w->failed && !g_stop; i++)
        scan_port(w, &p, &w->results[i]);
    if (w->scan_flags & SCAN_TCP)
        probe_close(&p);
    return NULL;
}

static void start_worker(t_worker *w) {
    int err = pthread_create(&w->tid, NULL, worker, w);
    w->started = (err == 0);
    if (err) {
        fprintf(stderr, "ft_nmap: pthread_create: %s\n", strerror(err));
        w->failed = 1;
    }
}

/* results must already hold the port numbers; returns -1 if a worker failed */
int run_scan(const t_options *opts, const struct sockaddr_in *dest,
             const char *dest_ip, t_result *results) {
    int nthreads = opts->speedup > 0 ? opts->speedup : 1;
    if (nthreads > opts->port_count)
        nthreads = opts->port_count;
    int      chunk  = opts->port_count / nthreads;
    int      rem    = opts->port_count % nthreads;
    int      failed = 0;
    t_worker w[MAX_SPEEDUP];

    memset(w, 0, sizeof(w[0]) * (size_t)nthreads);
    for (int i = 0, offset = 0; i < nthreads; i++) {
        w[i].id         = i;
        w[i].dest       = dest;
        w[i].dest_ip    = dest_ip;
        w[i].scan_flags = opts->scan_flags;
        w[i].results    = results + offset;
        w[i].port_count = chunk + (i < rem);
        offset += w[i].port_count;
        start_worker(&w[i]);
    }
    for (int i = 0; i < nthreads; i++) {
        if (w[i].started)
            pthread_join(w[i].tid, NULL);
        failed |= w[i].failed;
    }
    return failed ? -1 : 0;
}
