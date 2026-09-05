#include "ft_nmap.h"
#include <netdb.h>
#include <poll.h>
#include <errno.h>

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

void deadline_after(struct timespec *deadline, int ms) {
    clock_gettime(CLOCK_MONOTONIC, deadline);
    deadline->tv_sec  += ms / 1000;
    deadline->tv_nsec += (ms % 1000) * 1000000L;
    if (deadline->tv_nsec >= 1000000000L) {
        deadline->tv_sec++;
        deadline->tv_nsec -= 1000000000L;
    }
}

/* Waits until fd is readable or has an error. Returns poll's revents,
   0 when the deadline passes or g_stop is set, -1 on error. */
int wait_fd(int fd, const struct timespec *deadline) {
    struct pollfd pfd = { .fd = fd, .events = POLLIN, .revents = 0 };
    while (!g_stop) {
        struct timespec now;
        clock_gettime(CLOCK_MONOTONIC, &now);
        long ms = (deadline->tv_sec - now.tv_sec) * 1000
                + (deadline->tv_nsec - now.tv_nsec) / 1000000;
        if (ms <= 0)
            return 0;
        int pr = poll(&pfd, 1, (int)ms);
        if (pr > 0)
            return pfd.revents;
        if (pr < 0 && errno != EINTR)
            return -1;
    }
    return 0;
}
