#ifndef FT_NMAP_H
#define FT_NMAP_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>

#define MAX_IPS      256
#define MAX_PORTS    1024
#define MAX_SPEEDUP  250

/* scan type bitmask */
#define SCAN_SYN   (1 << 0)
#define SCAN_NULL  (1 << 1)
#define SCAN_ACK   (1 << 2)
#define SCAN_FIN   (1 << 3)
#define SCAN_XMAS  (1 << 4)
#define SCAN_UDP   (1 << 5)
#define SCAN_ALL   0x3F
#define SCAN_COUNT 6

typedef struct s_options {
    char     *ips[MAX_IPS];
    int       ip_count;
    uint16_t  ports[MAX_PORTS];
    int       port_count;
    int       scan_flags;
    int       speedup;
} t_options;

/* args.c */
void parse_arguments(int argc, char **argv, t_options *opts);

#endif
