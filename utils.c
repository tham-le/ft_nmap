#include "ft_nmap.h"
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/socket.h>

uint16_t checksum(const void *data, size_t len) {
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

uint32_t get_local_ip(struct sockaddr_in *dest) {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0)
        return 0;
    struct sockaddr_in tmp = *dest;
    tmp.sin_port = htons(80);
    connect(sock, (struct sockaddr *)&tmp, sizeof(tmp));
    struct sockaddr_in local;
    socklen_t len = sizeof(local);
    getsockname(sock, (struct sockaddr *)&local, &len);
    close(sock);
    return local.sin_addr.s_addr;
}
