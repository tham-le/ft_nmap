#include "ft_nmap.h"

int main(int argc, char **argv) {
    if (geteuid() != 0) {
        fprintf(stderr, "ft_nmap: must run as root\n");
        return 1;
    }

    if (argc < 2) {
        fprintf(stderr, "ft_nmap: use --help for usage\n");
        return 1;
    }

    t_options opts;
    memset(&opts, 0, sizeof(opts));
    parse_arguments(argc, argv, &opts);

    printf("Targets (%d):\n", opts.ip_count);
    for (int i = 0; i < opts.ip_count; i++)
        printf("  %s\n", opts.ips[i]);
    printf("Ports  : %d ports\n", opts.port_count);
    printf("Scans  : 0x%02x\n", opts.scan_flags);
    printf("Threads: %d\n", opts.speedup);
    return 0;
}
