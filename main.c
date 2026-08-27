#include "ft_nmap.h"
#include <arpa/inet.h>
#include <time.h>

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "ft_nmap: use --help for usage\n");
        return 1;
    }

    t_options opts;
    memset(&opts, 0, sizeof(opts));
    parse_arguments(argc, argv, &opts);

    /* Only the five TCP scans need raw sockets, so check after parsing and
       only for those. UDP reads its ICMP answer off the socket error queue. */
    if ((opts.scan_flags & SCAN_RAW_TCP) && !have_raw_privilege(&opts)) {
        fprintf(stderr,
                "ft_nmap: you requested a scan type which requires root"
                " privileges\n"
                "ft_nmap: run it under sudo, or pass --privileged if this"
                " binary has cap_net_raw\n");
        free_options(&opts);
        return 1;
    }

    t_result results[MAX_PORTS];

    for (int i = 0; i < opts.ip_count; i++) {
        struct sockaddr_in dest;
        if (resolve_target(opts.ips[i], &dest) < 0) {
            fprintf(stderr, "ft_nmap: cannot resolve %s\n", opts.ips[i]);
            continue;
        }
        char ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &dest.sin_addr, ip, sizeof(ip));

        print_scan_header(&opts, ip);

        struct timespec t0, t1;
        clock_gettime(CLOCK_MONOTONIC, &t0);
        run_scan(&opts, &dest, ip, results);
        clock_gettime(CLOCK_MONOTONIC, &t1);

        double elapsed = (t1.tv_sec - t0.tv_sec)
                       + (t1.tv_nsec - t0.tv_nsec) / 1e9;
        print_results(results, opts.port_count, ip, opts.scan_flags, elapsed);
    }
    free_options(&opts);
    return 0;
}
