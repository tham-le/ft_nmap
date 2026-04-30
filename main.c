#include "ft_nmap.h"
#include <arpa/inet.h>

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

    printf("Threads: %d | Ports: %d | Scans: 0x%02x\n",
           opts.speedup, opts.port_count, opts.scan_flags);

    for (int i = 0; i < opts.ip_count; i++) {
        struct sockaddr_in dest;
        if (resolve_target(opts.ips[i], &dest) < 0) {
            fprintf(stderr, "ft_nmap: cannot resolve %s\n", opts.ips[i]);
            continue;
        }
        char ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &dest.sin_addr, ip, sizeof(ip));
        printf("Target: %s -> %s\n", opts.ips[i], ip);
    }
    return 0;
}
