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

    t_result results[MAX_PORTS];
    int      failed = 0;

    for (int i = 0; i < opts.ip_count; i++) {
        struct sockaddr_in dest;
        if (resolve_target(opts.ips[i], &dest) < 0) {
            fprintf(stderr, "ft_nmap: cannot resolve %s\n", opts.ips[i]);
            continue;
        }
        char ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &dest.sin_addr, ip, sizeof(ip));

        /* Clear the table and fill in the port numbers before scanning. A
           worker that dies during setup never writes its slice, and without
           this we would print whatever was on the stack. */
        memset(results, 0, sizeof(results[0]) * (size_t)opts.port_count);
        for (int p = 0; p < opts.port_count; p++)
            results[p].port = opts.ports[p];

        print_scan_header(&opts, ip);

        struct timespec t0, t1;
        clock_gettime(CLOCK_MONOTONIC, &t0);
        if (run_scan(&opts, &dest, ip, results) < 0)
            failed = 1;
        clock_gettime(CLOCK_MONOTONIC, &t1);

        double elapsed = (t1.tv_sec - t0.tv_sec)
                       + (t1.tv_nsec - t0.tv_nsec) / 1e9;
        print_results(results, opts.port_count, ip, opts.scan_flags, elapsed);
    }
    free_options(&opts);
    return failed;
}
