#include "ft_nmap.h"
#include <netinet/ip_icmp.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <linux/errqueue.h>
#include <poll.h>
#include <errno.h>

/*
 * The ICMP port unreachable answer is read off the socket error queue, not off
 * a raw ICMP socket. Two reasons:
 *   - the error queue belongs to this one socket, so threads cannot steal each
 *     other's replies the way they do when every thread reads all host ICMP;
 *   - it needs no privilege, so the UDP scan runs without root.
 * IP_RECVERR keeps the full ICMP type and code, so Closed and Filtered stay
 * distinguishable. Plain errno would only give ECONNREFUSED.
 */

#define ERRQ_BUF_SIZE 512

static t_state classify_sock_error(const struct sock_extended_err *ee) {
    if (ee->ee_origin == SO_EE_ORIGIN_ICMP) {
        if (ee->ee_type != ICMP_DEST_UNREACH)
            return STATE_UNKNOWN;
        if (ee->ee_code == ICMP_PORT_UNREACH)
            return STATE_CLOSED;
        /* net, host or proto unreachable, or admin prohibited */
        return STATE_FILTERED;
    }
    /* the local stack refused to send the probe, e.g. a firewall rule */
    if (ee->ee_origin == SO_EE_ORIGIN_LOCAL)
        return STATE_FILTERED;
    return STATE_UNKNOWN;
}

/* Reads one message off the error queue.
   Returns 0 and sets *out, or -1 if the queue held nothing. */
static int read_error_queue(int fd, t_state *out) {
    char          buf[ERRQ_BUF_SIZE];
    char          ctl[ERRQ_BUF_SIZE];
    struct iovec  iov;
    struct msghdr msg;

    iov.iov_base = buf;
    iov.iov_len  = sizeof(buf);
    memset(&msg, 0, sizeof(msg));
    msg.msg_iov        = &iov;
    msg.msg_iovlen     = 1;
    msg.msg_control    = ctl;
    msg.msg_controllen = sizeof(ctl);

    if (recvmsg(fd, &msg, MSG_ERRQUEUE | MSG_DONTWAIT) < 0)
        return -1;

    *out = STATE_UNKNOWN;
    for (struct cmsghdr *c = CMSG_FIRSTHDR(&msg); c; c = CMSG_NXTHDR(&msg, c)) {
        if (c->cmsg_level != SOL_IP || c->cmsg_type != IP_RECVERR)
            continue;
        t_state s = classify_sock_error(
            (const struct sock_extended_err *)CMSG_DATA(c));
        if (s != STATE_UNKNOWN) {
            *out = s;
            break;
        }
    }
    return 0;
}

t_state udp_scan(struct sockaddr_in *dest, uint16_t port) {
    int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0)
        return STATE_UNKNOWN;

    /* without this the kernel drops the ICMP error instead of queueing it */
    int on = 1;
    if (setsockopt(fd, IPPROTO_IP, IP_RECVERR, &on, sizeof(on)) < 0) {
        close(fd);
        return STATE_UNKNOWN;
    }

    /* the socket must be connected: Linux only reports ICMP errors for a
       destination the socket itself is bound to */
    struct sockaddr_in target = *dest;
    target.sin_port = htons(port);
    if (connect(fd, (struct sockaddr *)&target, sizeof(target)) < 0) {
        close(fd);
        return STATE_UNKNOWN;
    }

    if (send(fd, "", 0, 0) < 0) {
        t_state s = (errno == EPERM || errno == EACCES)
                  ? STATE_FILTERED : STATE_UNKNOWN;
        close(fd);
        return s;
    }

    struct timeval deadline;
    gettimeofday(&deadline, NULL);
    deadline.tv_sec  += UDP_TIMEOUT_MS / 1000;
    deadline.tv_usec += (UDP_TIMEOUT_MS % 1000) * 1000;
    if (deadline.tv_usec >= 1000000) {
        deadline.tv_sec++;
        deadline.tv_usec -= 1000000;
    }

    while (1) {
        struct timeval now;
        gettimeofday(&now, NULL);
        if (timercmp(&now, &deadline, >=))
            break;

        struct timeval tv;
        timersub(&deadline, &now, &tv);
        long remaining_ms = tv.tv_sec * 1000 + tv.tv_usec / 1000;

        struct pollfd pfd;
        pfd.fd      = fd;
        pfd.events  = POLLIN;
        pfd.revents = 0;

        int pr = poll(&pfd, 1, (int)remaining_ms);
        if (pr < 0) {
            if (errno == EINTR)
                continue;
            break;
        }
        if (pr == 0)
            continue;

        /* POLLERR arrives whether or not we asked for it */
        if (pfd.revents & POLLERR) {
            t_state s;
            if (read_error_queue(fd, &s) < 0)
                break;
            if (s != STATE_UNKNOWN) {
                close(fd);
                return s;
            }
            continue; /* an ICMP we cannot use, keep waiting */
        }
        if (pfd.revents & POLLIN) {
            /* the service answered, so the port is open */
            close(fd);
            return STATE_OPEN;
        }
        break; /* POLLHUP or POLLNVAL, nothing left to wait for */
    }

    close(fd);
    return STATE_OPEN_FILTERED;
}
