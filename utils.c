#include "ft_nmap.h"
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/socket.h>

uint16_t checksum(const void *data, int len) {
    const uint16_t *ptr = data;
    uint32_t        sum = 0;
    while (len > 1) {
        sum += *ptr++;
        len -= 2;
    }
    if (len)
        sum += *(uint8_t *)ptr;
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    return (uint16_t)~sum;
}

int resolve_target(const char *host, struct sockaddr_in *out) {
    struct addrinfo hints, *res;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family   = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    if (getaddrinfo(host, NULL, &hints, &res) != 0)
        return -1;

    *out = *(struct sockaddr_in *)res->ai_addr;
    freeaddrinfo(res);
    return 0;
}
