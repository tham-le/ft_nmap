#include "ft_nmap.h"
#include <errno.h>
#include <limits.h>

/* strict base-10 parse, rejects empty input and trailing garbage */
static int parse_uint(const char *s, int *out) {
    char *end;
    errno = 0;
    long v = strtol(s, &end, 10);
    if (errno != 0 || end == s || *end != '\0' || v < 0 || v > INT_MAX)
        return -1;
    *out = (int)v;
    return 0;
}

static int add_ip(t_options *opts, const char *s) {
    if (opts->ip_count >= MAX_IPS) {
        fprintf(stderr, "ft_nmap: too many targets, maximum is %d\n", MAX_IPS);
        return -1;
    }
    opts->ips[opts->ip_count] = strdup(s);
    if (!opts->ips[opts->ip_count]) {
        perror("ft_nmap: strdup");
        return -1;
    }
    opts->ip_count++;
    return 0;
}

static int add_port(t_options *opts, int port) {
    for (int i = 0; i < opts->port_count; i++)
        if (opts->ports[i] == port)
            return 0;
    if (opts->port_count >= MAX_PORTS) {
        fprintf(stderr, "ft_nmap: too many ports, maximum is %d\n", MAX_PORTS);
        return -1;
    }
    opts->ports[opts->port_count++] = (uint16_t)port;
    return 0;
}

static int parse_ports(const char *spec, t_options *opts) {
    char buf[4096];
    strncpy(buf, spec, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';

    for (char *tok = strtok(buf, ","); tok; tok = strtok(NULL, ",")) {
        char *dash = strchr(tok, '-');
        int lo, hi;
        if (dash)
            *dash = '\0';
        if (parse_uint(tok, &lo) < 0 || lo < 1 || lo > 65535) {
            fprintf(stderr, "ft_nmap: invalid port: %s\n", tok);
            return -1;
        }
        hi = lo;
        if (dash && (parse_uint(dash + 1, &hi) < 0 || hi < lo || hi > 65535)) {
            fprintf(stderr, "ft_nmap: invalid port range: %s-%s\n", tok, dash + 1);
            return -1;
        }
        for (int p = lo; p <= hi; p++)
            if (add_port(opts, p) < 0)
                return -1;
    }
    return 0;
}

static int parse_scan_types(const char *spec, t_options *opts) {
    char buf[256];
    strncpy(buf, spec, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';

    for (char *tok = strtok(buf, ",/"); tok; tok = strtok(NULL, ",/")) {
        int i;
        for (i = 0; i < SCAN_COUNT; i++)
            if (strcmp(tok, g_scan_types[i].name) == 0)
                break;
        if (i == SCAN_COUNT) {
            fprintf(stderr, "ft_nmap: unknown scan type: %s\n", tok);
            return -1;
        }
        opts->scan_flags |= g_scan_types[i].bit;
    }
    return 0;
}

static int parse_ips_from_file(const char *path, t_options *opts) {
    FILE *f = fopen(path, "r");
    if (!f) {
        perror(path);
        return -1;
    }
    char line[256];
    int  ret = 0;
    while (ret == 0 && fgets(line, sizeof(line), f)) {
        line[strcspn(line, "\r\n")] = '\0';
        if (line[0])
            ret = add_ip(opts, line);
    }
    fclose(f);
    return ret;
}

static void usage(const char *prog) {
    printf("Usage: %s [OPTIONS]\n"
           "  --help               Show this help\n"
           "  --ip <addr>          Target IP or hostname (repeatable)\n"
           "  --file <path>        File with one target per line\n"
           "  --ports <spec>       Ports to scan, e.g. 1-1024,8080 (default 1-1024)\n"
           "  --scan <types>       Comma separated: SYN,NULL,ACK,FIN,XMAS,UDP (default all)\n"
           "  --speedup <n>        Number of threads, 0-%d (default 0)\n",
           prog, MAX_SPEEDUP);
}

static int parse_speedup(const char *val, t_options *opts) {
    if (parse_uint(val, &opts->speedup) < 0 || opts->speedup > MAX_SPEEDUP) {
        fprintf(stderr, "ft_nmap: speedup must be 0-%d\n", MAX_SPEEDUP);
        return -1;
    }
    return 0;
}

static int parse_option(const char *opt, const char *val, t_options *opts) {
    if (strcmp(opt, "--ip") == 0)
        return add_ip(opts, val);
    if (strcmp(opt, "--file") == 0)
        return parse_ips_from_file(val, opts);
    if (strcmp(opt, "--ports") == 0 || strcmp(opt, "--port") == 0)
        return parse_ports(val, opts);
    if (strcmp(opt, "--scan") == 0)
        return parse_scan_types(val, opts);
    if (strcmp(opt, "--speedup") == 0)
        return parse_speedup(val, opts);
    fprintf(stderr, "ft_nmap: unknown option: %s (see --help)\n", opt);
    return -1;
}

/* returns -1 on bad input, after printing why */
int parse_arguments(int argc, char **argv, t_options *opts) {
    for (int i = 1; i < argc; i += 2) {
        if (strcmp(argv[i], "--help") == 0) {
            usage(argv[0]);
            free_options(opts);
            exit(0);
        }
        if (i + 1 >= argc) {
            fprintf(stderr, "ft_nmap: %s needs a value\n", argv[i]);
            return -1;
        }
        if (parse_option(argv[i], argv[i + 1], opts) < 0)
            return -1;
    }
    if (opts->ip_count == 0) {
        fprintf(stderr, "ft_nmap: no target given, use --ip or --file\n");
        return -1;
    }
    if (opts->port_count == 0)
        for (int p = 1; p <= 1024; p++)
            opts->ports[opts->port_count++] = (uint16_t)p;
    if (opts->scan_flags == 0)
        opts->scan_flags = SCAN_ALL;
    return 0;
}

void free_options(t_options *opts) {
    for (int i = 0; i < opts->ip_count; i++)
        free(opts->ips[i]);
    opts->ip_count = 0;
}
