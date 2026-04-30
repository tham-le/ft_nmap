#include "ft_nmap.h"

static void usage(const char *prog) {
    printf("Usage: %s [OPTIONS]\n"
           "  --help               Show this help\n"
           "  --ip <addr>          Target IP or hostname (repeatable)\n"
           "  --file <path>        File with one target per line\n"
           "  --ports <spec>       Ports to scan, e.g. 1-1024,8080\n"
           "  --scan <types>       Comma-separated: SYN,NULL,ACK,FIN,XMAS,UDP\n"
           "  --speedup <n>        Number of threads (1-%d, default 1)\n",
           prog, MAX_SPEEDUP);
}

int main(int argc, char **argv) {
    if (geteuid() != 0) {
        fprintf(stderr, "ft_nmap: must run as root\n");
        return 1;
    }

    t_options opts;
    memset(&opts, 0, sizeof(opts));

    if (argc < 2) {
        usage(argv[0]);
        return 1;
    }

    /* stub: just show usage for now */
    (void)argc;
    usage(argv[0]);
    return 0;
}
