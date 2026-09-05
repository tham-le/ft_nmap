#include "ft_nmap.h"
#include <netinet/ip_icmp.h>
#include <sys/socket.h>
#include <linux/errqueue.h>
#include <poll.h>
#include <errno.h>

/*
 * The ICMP answer is read off the socket error queue (IP_RECVERR), not off a
 * raw ICMP socket. The queue belongs to this one socket, so threads cannot
 * steal each other's replies, and it needs no privilege. The extended error
 * keeps the ICMP code, so Closed and Filtered stay distinguishable.
 */

static t_state classify_sock_error(const struct sock_extended_err *ee) {
    if (ee->ee_origin == SO_EE_ORIGIN_ICMP) {
        if (ee->ee_type != ICMP_DEST_UNREACH)
            return STATE_UNKNOWN;
        return ee->ee_code == ICMP_PORT_UNREACH ? STATE_CLOSED : STATE_FILTERED;
    }
    /* the local stack refused to send the probe, e.g. a firewall rule */
    if (ee->ee_origin == SO_EE_ORIGIN_LOCAL)
        return STATE_FILTERED;
    return STATE_UNKNOWN;
}

/* one message off the error queue, STATE_UNKNOWN if it held nothing usable */
static t_state read_error_queue(int fd) {
    char          buf[512], ctl[512];
    struct iovec  iov = { .iov_base = buf, .iov_len = sizeof(buf) };
    struct msghdr msg;

    memset(&msg, 0, sizeof(msg));
    msg.msg_iov        = &iov;
    msg.msg_iovlen     = 1;
    msg.msg_control    = ctl;
    msg.msg_controllen = sizeof(ctl);
    if (recvmsg(fd, &msg, MSG_ERRQUEUE | MSG_DONTWAIT) < 0)
        return STATE_UNKNOWN;

    for (struct cmsghdr *c = CMSG_FIRSTHDR(&msg); c; c = CMSG_NXTHDR(&msg, c))
        if (c->cmsg_level == SOL_IP && c->cmsg_type == IP_RECVERR)
            return classify_sock_error((const struct sock_extended_err *)CMSG_DATA(c));
    return STATE_UNKNOWN;
}

/* a datagram socket connected to the target port, -1 on failure */
static int open_probe(const struct sockaddr_in *dest, uint16_t port) {
    struct sockaddr_in target = *dest;
    int                on     = 1;
    int                fd     = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

    target.sin_port = htons(port);
    /* Linux only reports ICMP errors on a connected socket with IP_RECVERR */
    if (fd >= 0 && (setsockopt(fd, IPPROTO_IP, IP_RECVERR, &on, sizeof(on)) < 0
                    || connect(fd, (struct sockaddr *)&target, sizeof(target)) < 0)) {
        close(fd);
        return -1;
    }
    return fd;
}

static t_state wait_reply(int fd) {
    struct timespec deadline;
    int             ev;

    deadline_after(&deadline, UDP_TIMEOUT_MS);
    while ((ev = wait_fd(fd, &deadline)) > 0) {
        if (ev & POLLIN)
            return STATE_OPEN;
        if (!(ev & POLLERR))
            break;
        t_state s = read_error_queue(fd);
        if (s != STATE_UNKNOWN)
            return s;
    }
    return STATE_OPEN_FILTERED;
}

t_state udp_scan(const struct sockaddr_in *dest, uint16_t port) {
    int fd = open_probe(dest, port);
    if (fd < 0)
        return STATE_UNKNOWN;

    t_state state;
    if (send(fd, "", 0, 0) < 0)
        state = (errno == EPERM || errno == EACCES) ? STATE_FILTERED : STATE_UNKNOWN;
    else
        state = wait_reply(fd);
    close(fd);
    return state;
}
