#include "ft_nmap.h"

void print_scan_header(t_options *opts, const char *ip) {
    printf("\nScanning %s, %d ports\n", ip, opts->port_count);
    fflush(stdout);
}

void print_results(t_result *results, int count, const char *ip,
                   int scan_flags, double elapsed) {
    (void)scan_flags;
    printf("\nScan of %s took %.3f s\n", ip, elapsed);
    for (int i = 0; i < count; i++) {
        if (results[i].states[0] == STATE_OPEN)
            printf("  port %-5u OPEN\n", results[i].port);
    }
}
