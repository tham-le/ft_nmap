#include "ft_nmap.h"

static void parse_ports(const char *spec, t_options *opts) {
    char buf[4096];
    strncpy(buf, spec, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';

    char *tok = strtok(buf, ",");
    while (tok) {
        char *dash = strchr(tok, '-');
        if (dash) {
            int lo = atoi(tok);
            int hi = atoi(dash + 1);
            if (lo < 1 || hi > 65535 || lo > hi) {
                fprintf(stderr, "ft_nmap: invalid port range: %s\n", tok);
                exit(1);
            }
            for (int p = lo; p <= hi && opts->port_count < MAX_PORTS; p++)
                opts->ports[opts->port_count++] = (uint16_t)p;
        } else {
            int p = atoi(tok);
            if (p < 1 || p > 65535) {
                fprintf(stderr, "ft_nmap: invalid port: %s\n", tok);
                exit(1);
            }
            if (opts->port_count < MAX_PORTS)
                opts->ports[opts->port_count++] = (uint16_t)p;
        }
        tok = strtok(NULL, ",");
    }
}

static void parse_scan_types(const char *spec, t_options *opts) {
    char buf[256];
    strncpy(buf, spec, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';

    char *tok = strtok(buf, ",");
    while (tok) {
        if      (strcmp(tok, "SYN")  == 0) opts->scan_flags |= SCAN_SYN;
        else if (strcmp(tok, "NULL") == 0) opts->scan_flags |= SCAN_NULL;
        else if (strcmp(tok, "ACK")  == 0) opts->scan_flags |= SCAN_ACK;
        else if (strcmp(tok, "FIN")  == 0) opts->scan_flags |= SCAN_FIN;
        else if (strcmp(tok, "XMAS") == 0) opts->scan_flags |= SCAN_XMAS;
        else if (strcmp(tok, "UDP")  == 0) opts->scan_flags |= SCAN_UDP;
        else {
            fprintf(stderr, "ft_nmap: unknown scan type: %s\n", tok);
            exit(1);
        }
        tok = strtok(NULL, ",");
    }
}

static void parse_ips_from_file(const char *path, t_options *opts) {
    FILE *f = fopen(path, "r");
    if (!f) {
        perror(path);
        exit(1);
    }
    char line[256];
    while (fgets(line, sizeof(line), f) && opts->ip_count < MAX_IPS) {
        line[strcspn(line, "\n")] = '\0';
        if (line[0])
            opts->ips[opts->ip_count++] = strdup(line);
    }
    fclose(f);
}

static void usage(const char *prog) {
    printf("Usage: %s [OPTIONS]\n"
           "  --help               Show this help\n"
           "  --ip <addr>          Target IP or hostname (repeatable)\n"
           "  --file <path>        File with one target per line\n"
           "  --ports <spec>       Ports to scan, e.g. 1-1024,8080\n"
           "  --scan <types>       Comma-separated: SYN,NULL,ACK,FIN,XMAS,UDP\n"
           "  --speedup <n>        Number of threads (1-%d, default 1)\n",
           prog, MAX_SPEEDUP);
    exit(0);
}

void parse_arguments(int argc, char **argv, t_options *opts) {
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--help") == 0) {
            usage(argv[0]);
        } else if (strcmp(argv[i], "--ip") == 0 && i + 1 < argc) {
            if (opts->ip_count < MAX_IPS)
                opts->ips[opts->ip_count++] = argv[++i];
        } else if (strcmp(argv[i], "--file") == 0 && i + 1 < argc) {
            parse_ips_from_file(argv[++i], opts);
        } else if ((strcmp(argv[i], "--ports") == 0 || strcmp(argv[i], "--port") == 0) && i + 1 < argc) {
            parse_ports(argv[++i], opts);
        } else if (strcmp(argv[i], "--scan") == 0 && i + 1 < argc) {
            parse_scan_types(argv[++i], opts);
        } else if (strcmp(argv[i], "--speedup") == 0 && i + 1 < argc) {
            opts->speedup = atoi(argv[++i]);
            if (opts->speedup < 1 || opts->speedup > MAX_SPEEDUP) {
                fprintf(stderr, "ft_nmap: speedup must be 1-%d\n", MAX_SPEEDUP);
                exit(1);
            }
        } else {
            fprintf(stderr, "ft_nmap: unknown option: %s\n", argv[i]);
            exit(1);
        }
    }

    if (opts->ip_count == 0) {
        fprintf(stderr, "ft_nmap: no target specified (use --ip or --file)\n");
        exit(1);
    }

    /* defaults */
    if (opts->port_count == 0) {
        for (int p = 1; p <= 1024; p++)
            opts->ports[opts->port_count++] = (uint16_t)p;
    }
    if (opts->scan_flags == 0)
        opts->scan_flags = SCAN_ALL;
    if (opts->speedup == 0)
        opts->speedup = 1;
}
