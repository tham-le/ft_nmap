#include "ft_nmap.h"
#include <arpa/inet.h>

volatile sig_atomic_t g_stop;

static void on_signal(int sig) {
    (void)sig;
    g_stop = 1;
}

static void install_signals(void) {
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = on_signal;
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
}

/* scans one target and prints its table, -1 if it could not be scanned */
static int scan_target(const t_options *opts, const char *host, t_result *results) {
    struct sockaddr_in dest;
    char               ip[INET_ADDRSTRLEN];
    struct timespec    t0, t1;

    if (resolve_target(host, &dest) < 0) {
        fprintf(stderr, "ft_nmap: cannot resolve %s\n", host);
        return -1;
    }
    inet_ntop(AF_INET, &dest.sin_addr, ip, sizeof(ip));
    memset(results, 0, sizeof(results[0]) * (size_t)opts->port_count);
    for (int p = 0; p < opts->port_count; p++)
        results[p].port = opts->ports[p];
    print_scan_header(opts, ip);

    clock_gettime(CLOCK_MONOTONIC, &t0);
    int ret = run_scan(opts, &dest, ip, results);
    clock_gettime(CLOCK_MONOTONIC, &t1);
    if (ret < 0 || g_stop)
        return ret;
    double elapsed = (double)(t1.tv_sec - t0.tv_sec)
                   + (double)(t1.tv_nsec - t0.tv_nsec) / 1e9;
    print_results(results, opts->port_count, ip, opts->scan_flags, elapsed);
    return 0;
}

int main(int argc, char **argv) {
    static t_result results[MAX_PORTS];
    t_options       opts;
    int             failed = 0;

    memset(&opts, 0, sizeof(opts));
    if (parse_arguments(argc, argv, &opts) < 0) {
        free_options(&opts);
        return 1;
    }
    if ((opts.scan_flags & SCAN_TCP) && geteuid() != 0) {
        fprintf(stderr, "ft_nmap: TCP scans need raw sockets, run as root\n");
        free_options(&opts);
        return 1;
    }
    install_signals();
    for (int i = 0; i < opts.ip_count && !g_stop; i++)
        if (scan_target(&opts, opts.ips[i], results) < 0)
            failed = 1;
    free_options(&opts);
    if (g_stop) {
        fprintf(stderr, "\nft_nmap: interrupted\n");
        return 130;
    }
    return failed;
}
