#include "ft_nmap.h"
#include <netdb.h>

static const char *g_scan_names[SCAN_COUNT] = {
    "SYN", "NULL", "ACK", "FIN", "XMAS", "UDP",
};

static const int g_scan_bits[SCAN_COUNT] = {
    SCAN_SYN, SCAN_NULL, SCAN_ACK, SCAN_FIN, SCAN_XMAS, SCAN_UDP,
};

static const char *state_str(t_state s) {
    switch (s) {
    case STATE_OPEN:          return "Open";
    case STATE_CLOSED:        return "Closed";
    case STATE_FILTERED:      return "Filtered";
    case STATE_UNFILTERED:    return "Unfiltered";
    case STATE_OPEN_FILTERED: return "Open|Filtered";
    default:                  return "Unknown";
    }
}

/*
 * Open wins, then Closed, then Unfiltered, then Filtered.
 * This mirrors nmap's conclusion logic across multiple scan types.
 */
static t_state get_conclusion(const t_result *res, int scan_flags) {
    for (int i = 0; i < SCAN_COUNT; i++)
        if ((scan_flags & g_scan_bits[i]) && res->states[i] == STATE_OPEN)
            return STATE_OPEN;
    for (int i = 0; i < SCAN_COUNT; i++)
        if ((scan_flags & g_scan_bits[i]) && res->states[i] == STATE_CLOSED)
            return STATE_CLOSED;
    for (int i = 0; i < SCAN_COUNT; i++)
        if ((scan_flags & g_scan_bits[i]) && res->states[i] == STATE_UNFILTERED)
            return STATE_UNFILTERED;
    return STATE_FILTERED;
}

static void lookup_service(t_result *res, int scan_flags) {
    const char *proto = (scan_flags == SCAN_UDP) ? "udp" : "tcp";
    struct servent *se = getservbyport(htons(res->port), proto);
    if (se)
        strncpy(res->service, se->s_name, sizeof(res->service) - 1);
    else
        strncpy(res->service, "unassigned", sizeof(res->service) - 1);
    res->service[sizeof(res->service) - 1] = '\0';
}

static void build_results_str(const t_result *res, int scan_flags,
                               char *buf, size_t size) {
    buf[0] = '\0';
    for (int i = 0; i < SCAN_COUNT; i++) {
        if (!(scan_flags & g_scan_bits[i]))
            continue;
        char tmp[64];
        snprintf(tmp, sizeof(tmp), "%s(%s) ",
                 g_scan_names[i], state_str(res->states[i]));
        strncat(buf, tmp, size - strlen(buf) - 1);
    }
    size_t len = strlen(buf);
    if (len > 0 && buf[len - 1] == ' ')
        buf[len - 1] = '\0';
}

void print_scan_header(t_options *opts, const char *ip) {
    const char *scan_names[SCAN_COUNT] = {
        "SYN", "NULL", "FIN", "XMAS", "ACK", "UDP"
    };
    char scans[128] = "";
    for (int i = 0; i < SCAN_COUNT; i++) {
        if (opts->scan_flags & g_scan_bits[i]) {
            if (scans[0])
                strncat(scans, " ", sizeof(scans) - strlen(scans) - 1);
            strncat(scans, scan_names[i], sizeof(scans) - strlen(scans) - 1);
        }
    }
    printf("\nScan Configurations\n");
    printf("Target IP           : %s\n", ip);
    printf("Ports to scan       : %d\n", opts->port_count);
    printf("Scans               : %s\n", scans);
    printf("Threads             : %d\n", opts->speedup);
    printf("\nScanning..\n");
    fflush(stdout);
}

static void print_port_line(t_result *res, int scan_flags, t_state conclusion) {
    char results_str[256];
    build_results_str(res, scan_flags, results_str, sizeof(results_str));
    printf("%-6u %-22s %-40s %s\n",
           res->port, res->service, results_str, state_str(conclusion));
}

void print_results(t_result *results, int count, const char *ip,
                   int scan_flags, double elapsed) {
    t_state conclusions[MAX_PORTS];
    for (int i = 0; i < count; i++) {
        lookup_service(&results[i], scan_flags);
        conclusions[i] = get_conclusion(&results[i], scan_flags);
    }

    printf("\nScan took %.5f secs\n", elapsed);
    printf("IP address: %s\n", ip);

    const char *sep = "------------------------------------------------------------"
                      "----------------------------------------------------";

    int has_open = 0;
    for (int i = 0; i < count; i++)
        if (conclusions[i] == STATE_OPEN) { has_open = 1; break; }

    if (has_open) {
        printf("\nOpen ports:\n");
        printf("%-6s %-22s %-40s %s\n",
               "Port", "Service", "Results", "Conclusion");
        printf("%s\n", sep);
        for (int i = 0; i < count; i++)
            if (conclusions[i] == STATE_OPEN)
                print_port_line(&results[i], scan_flags, conclusions[i]);
    }

    int has_other = 0;
    for (int i = 0; i < count; i++)
        if (conclusions[i] != STATE_OPEN) { has_other = 1; break; }

    if (has_other) {
        printf("\nClosed/Filtered/Unfiltered ports:\n");
        printf("%-6s %-22s %-40s %s\n",
               "Port", "Service", "Results", "Conclusion");
        printf("%s\n", sep);
        for (int i = 0; i < count; i++)
            if (conclusions[i] != STATE_OPEN)
                print_port_line(&results[i], scan_flags, conclusions[i]);
    }
    printf("\n");
}
