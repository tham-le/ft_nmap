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

#define MAX_IPS      256
#define MAX_PORTS    1024
#define MAX_SPEEDUP  250

#define SCAN_SYN   (1 << 0)
#define SCAN_NULL  (1 << 1)
#define SCAN_ACK   (1 << 2)
#define SCAN_FIN   (1 << 3)
#define SCAN_XMAS  (1 << 4)
#define SCAN_UDP   (1 << 5)
#define SCAN_ALL   0x3F
#define SCAN_COUNT 6

#define SRC_PORT_BASE 40000
#define SCAN_TIMEOUT  1   /* seconds to wait for a TCP reply */
#define UDP_TIMEOUT   2   /* seconds to wait for ICMP unreachable */

typedef enum e_state {
    STATE_UNKNOWN = 0,
    STATE_OPEN,
    STATE_CLOSED,
    STATE_FILTERED,
    STATE_UNFILTERED,
    STATE_OPEN_FILTERED,
} t_state;

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
    pthread_mutex_t    *mutex;
} t_thread_arg;

typedef struct s_options {
    char     *ips[MAX_IPS];
    int       ip_count;
    uint16_t  ports[MAX_PORTS];
    int       port_count;
    int       scan_flags;
    int       speedup;
} t_options;

/* args.c */
void     parse_arguments(int argc, char **argv, t_options *opts);

/* utils.c */
uint16_t checksum(const void *data, int len);
int      resolve_target(const char *host, struct sockaddr_in *out);

/* pcap_utils.c */
#include <pcap.h>
pcap_t  *open_pcap(const char *dest_ip, uint32_t local_ip,
                   uint16_t sp_min, uint16_t sp_max);

/* tcp.c */
t_state  tcp_scan(struct sockaddr_in *dest, uint16_t port,
                  uint16_t src_port, uint32_t src_ip,
                  uint8_t tcp_flags, int scan_bit,
                  int raw_sock, void *pcap);

/* udp.c */
t_state  udp_scan(struct sockaddr_in *dest, uint16_t port);

/* scan.c */
void     run_scan(t_options *opts, struct sockaddr_in *dest,
                  const char *dest_ip, t_result *results);

/* output.c */
void     print_scan_header(t_options *opts, const char *ip);
void     print_results(t_result *results, int count, const char *ip,
                       int scan_flags, double elapsed);

#endif
