#include "ft_nmap.h"
#include <arpa/inet.h>
#include <time.h>

int main(int argc, char **argv) {
    if (geteuid() != 0) {
        fprintf(stderr, "ft_nmap: must run as root\n");
        return 1;
    }
    if (argc < 2) {
        fprintf(stderr, "ft_nmap: use --help for usage\n");
        return 1;
    }

    srand((unsigned)time(NULL) ^ (unsigned)getpid());

    t_options opts;
    memset(&opts, 0, sizeof(opts));
    parse_arguments(argc, argv, &opts);

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
    return 0;
}
