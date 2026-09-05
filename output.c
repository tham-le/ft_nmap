#include "ft_nmap.h"
#include <netdb.h>

#define COL_FMT "%-6s %-22s %-40s %s\n"

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

/* Open wins, then Closed, then Unfiltered, then Filtered */
static t_state conclusion(const t_result *res, t_scan scan_flags) {
    static const t_state order[] = { STATE_OPEN, STATE_CLOSED, STATE_UNFILTERED };
    for (size_t k = 0; k < sizeof(order) / sizeof(order[0]); k++)
        for (int i = 0; i < SCAN_COUNT; i++)
            if ((scan_flags & g_scan_types[i].bit) && res->states[i] == order[k])
                return order[k];
    return STATE_FILTERED;
}

static const char *service_name(uint16_t port, t_scan scan_flags) {
    const char     *proto = (scan_flags & SCAN_TCP) ? "tcp" : "udp";
    struct servent *se    = getservbyport(htons(port), proto);
    return se ? se->s_name : "Unassigned";
}

static void print_port_line(const t_result *res, t_scan scan_flags) {
    char port[8], results[256] = "";
    for (int i = 0; i < SCAN_COUNT; i++) {
        if (!(scan_flags & g_scan_types[i].bit))
            continue;
        size_t len = strlen(results);
        snprintf(results + len, sizeof(results) - len, "%s%s(%s)",
                 len ? " " : "", g_scan_types[i].name, state_str(res->states[i]));
    }
    snprintf(port, sizeof(port), "%u", res->port);
    printf(COL_FMT, port, service_name(res->port, scan_flags), results,
           state_str(conclusion(res, scan_flags)));
}

static void print_section(const char *title, const t_result *results, int count,
                          t_scan scan_flags, int want_open) {
    int shown = 0;
    for (int i = 0; i < count; i++) {
        if ((conclusion(&results[i], scan_flags) == STATE_OPEN) != want_open)
            continue;
        if (!shown++) {
            printf("\n%s:\n" COL_FMT, title, "Port", "Service", "Results", "Conclusion");
            printf("--------------------------------------------------------"
                   "--------------------------------------------------------\n");
        }
        print_port_line(&results[i], scan_flags);
    }
}

void print_scan_header(const t_options *opts, const char *ip) {
    printf("\nScan Configurations\n");
    printf("Target Ip-Address     : %s\n", ip);
    printf("No of Ports to scan   : %d\n", opts->port_count);
    printf("Scans to be performed :");
    for (int i = 0; i < SCAN_COUNT; i++)
        if (opts->scan_flags & g_scan_types[i].bit)
            printf(" %s", g_scan_types[i].name);
    printf("\nNo of threads         : %d\n", opts->speedup);
    printf("\nScanning..\n");
    fflush(stdout);
}

void print_results(const t_result *results, int count, const char *ip,
                   t_scan scan_flags, double elapsed) {
    printf("\nScan took %.5f secs\n", elapsed);
    printf("IP address: %s\n", ip);
    print_section("Open ports", results, count, scan_flags, 1);
    print_section("Closed/Filtered/Unfiltered ports", results, count, scan_flags, 0);
    printf("\n");
}
