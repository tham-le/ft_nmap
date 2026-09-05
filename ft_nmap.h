#ifndef FT_NMAP_H
#define FT_NMAP_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <pthread.h>
#include <pcap.h>

#define MAX_IPS      256
#define MAX_PORTS    1024
#define MAX_SPEEDUP  250

#define SCAN_COUNT 6

typedef enum e_scan {
    SCAN_SYN  = 1 << 0,
    SCAN_NULL = 1 << 1,
    SCAN_ACK  = 1 << 2,
    SCAN_FIN  = 1 << 3,
    SCAN_XMAS = 1 << 4,
    SCAN_UDP  = 1 << 5,
    SCAN_ALL  = (1 << SCAN_COUNT) - 1,
    SCAN_TCP  = SCAN_ALL & ~SCAN_UDP,
} t_scan;

#define SRC_PORT_BASE   40000
#define TCP_TIMEOUT_MS  500
#define UDP_TIMEOUT_MS  1500

typedef enum e_state {
    STATE_UNKNOWN = 0,
    STATE_OPEN,
    STATE_CLOSED,
    STATE_FILTERED,
    STATE_UNFILTERED,
    STATE_OPEN_FILTERED,
} t_state;

typedef struct s_scan_type {
    t_scan      bit;
    uint8_t     tcp_flags;
    const char *name;
} t_scan_type;

extern const t_scan_type g_scan_types[SCAN_COUNT];

/* set by SIGINT and SIGTERM, every wait loop checks it */
extern volatile sig_atomic_t g_stop;

typedef struct s_result {
    uint16_t port;
    t_state  states[SCAN_COUNT];
} t_result;

typedef struct s_options {
    char     *ips[MAX_IPS];
    int       ip_count;
    uint16_t  ports[MAX_PORTS];
    int       port_count;
    t_scan    scan_flags;
    int       speedup;
} t_options;

/* args.c */
int       parse_arguments(int argc, char **argv, t_options *opts);
void      free_options(t_options *opts);

/* utils.c */
int       resolve_target(const char *host, struct sockaddr_in *out);
void      deadline_after(struct timespec *deadline, int ms);
int       wait_fd(int fd, const struct timespec *deadline);

/* tcp.c: one raw socket and one pcap handle per thread */
typedef struct s_probe {
    int          thread_id;
    int          raw_sock;
    uint32_t     src_ip;
    pcap_t      *pcap;
    unsigned int seed;
} t_probe;

int       probe_open(t_probe *p, int thread_id, const struct sockaddr_in *dest,
                     const char *dest_ip);
void      probe_close(t_probe *p);
t_state   tcp_scan(t_probe *p, const struct sockaddr_in *dest, uint16_t port,
                   int scan_idx);

/* udp.c */
t_state   udp_scan(const struct sockaddr_in *dest, uint16_t port);

/* scan.c */
int       run_scan(const t_options *opts, const struct sockaddr_in *dest,
                   const char *dest_ip, t_result *results);

/* output.c */
void      print_scan_header(const t_options *opts, const char *ip);
void      print_results(const t_result *results, int count, const char *ip,
                        t_scan scan_flags, double elapsed);

#endif
