#ifndef FT_NMAP_H
#define FT_NMAP_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <pthread.h>
#include <pcap.h>

#define MAX_IPS      256
#define MAX_PORTS    1024
#define MAX_SPEEDUP  250

/* highest port covered by the built-in service name table */
#define SERVICE_MAX_PORT 1024

#define SCAN_SYN   (1 << 0)
#define SCAN_NULL  (1 << 1)
#define SCAN_ACK   (1 << 2)
#define SCAN_FIN   (1 << 3)
#define SCAN_XMAS  (1 << 4)
#define SCAN_UDP   (1 << 5)
#define SCAN_ALL   0x3F
/* the scans that need a raw socket to send and pcap to receive */
#define SCAN_RAW_TCP (SCAN_SYN | SCAN_NULL | SCAN_ACK | SCAN_FIN | SCAN_XMAS)
#define SCAN_COUNT 6

#define SRC_PORT_BASE 40000
#define SCAN_TIMEOUT_MS  500   /* ms to wait for a TCP reply */
#define UDP_TIMEOUT_MS   1500  /* ms to wait for ICMP unreachable */

typedef enum e_state {
    STATE_UNKNOWN = 0,
    STATE_OPEN,
    STATE_CLOSED,
    STATE_FILTERED,
    STATE_UNFILTERED,
    STATE_OPEN_FILTERED,
} t_state;

typedef struct s_scan_type {
    int         bit;
    uint8_t     tcp_flags;
    const char *name;
} t_scan_type;

extern const t_scan_type g_scan_types[SCAN_COUNT];

typedef struct s_result {
    uint16_t port;
    t_state  states[SCAN_COUNT];
    char     service[64];
} t_result;

typedef struct s_thread_arg {
    struct sockaddr_in  dest;
    char                dest_ip[INET_ADDRSTRLEN];
    uint16_t           *ports;
    int                 port_count;
    int                 scan_flags;
    t_result           *results;
    int                 thread_id;
} t_thread_arg;

/* how to decide whether we may use raw sockets, like nmap's o.isr00t */
typedef enum e_priv_mode {
    PRIV_AUTO = 0,  /* look at the effective uid */
    PRIV_FORCE_ON,  /* --privileged */
    PRIV_FORCE_OFF, /* --unprivileged */
} t_priv_mode;

typedef struct s_options {
    char        *ips[MAX_IPS];
    int          ip_count;
    uint16_t     ports[MAX_PORTS];
    int          port_count;
    int          scan_flags;
    int          speedup;
    t_priv_mode  priv_mode;
} t_options;

/* args.c */
void      parse_arguments(int argc, char **argv, t_options *opts);
void      free_options(t_options *opts);
int       have_raw_privilege(const t_options *opts);

/* utils.c */
uint16_t  checksum(const void *data, size_t len);
int       resolve_target(const char *host, struct sockaddr_in *out);
uint32_t  get_local_ip(struct sockaddr_in *dest);

/* pcap_utils.c */
pcap_t   *open_pcap(const char *dest_ip, uint32_t local_ip,
                    uint16_t sp_min, uint16_t sp_max);

/* tcp.c */
t_state   tcp_scan(struct sockaddr_in *dest, uint16_t port,
                   uint16_t src_port, uint32_t src_ip,
                   uint8_t tcp_flags, int scan_bit,
                   int raw_sock, pcap_t *pcap, unsigned int *seed);

/* udp.c */
t_state   udp_scan(struct sockaddr_in *dest, uint16_t port);

/* scan.c */
/* returns 0 if every worker ran, -1 if any of them could not start */
int       run_scan(t_options *opts, struct sockaddr_in *dest,
                   const char *dest_ip, t_result *results);

/* services.c */
const char *service_name_fallback(uint16_t port, int is_udp);

/* output.c */
void      print_scan_header(t_options *opts, const char *ip);
void      print_results(t_result *results, int count, const char *ip,
                        int scan_flags, double elapsed);

#endif
