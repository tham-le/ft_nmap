#include "ft_nmap.h"
#include <pcap.h>
#include <arpa/inet.h>

static int get_iface_for_ip(uint32_t local_ip, char *out, size_t out_size) {
    pcap_if_t *devs;
    char errbuf[PCAP_ERRBUF_SIZE];
    if (pcap_findalldevs(&devs, errbuf) < 0)
        return -1;

    for (pcap_if_t *d = devs; d; d = d->next) {
        for (pcap_addr_t *a = d->addresses; a; a = a->next) {
            if (!a->addr || a->addr->sa_family != AF_INET)
                continue;
            struct sockaddr_in *sin = (struct sockaddr_in *)a->addr;
            if (sin->sin_addr.s_addr == local_ip) {
                strncpy(out, d->name, out_size - 1);
                out[out_size - 1] = '\0';
                pcap_freealldevs(devs);
                return 0;
            }
        }
    }

    /* fallback: first non-loopback interface */
    for (pcap_if_t *d = devs; d; d = d->next) {
        if (!(d->flags & PCAP_IF_LOOPBACK)) {
            strncpy(out, d->name, out_size - 1);
            out[out_size - 1] = '\0';
            pcap_freealldevs(devs);
            return 0;
        }
    }

    pcap_freealldevs(devs);
    return -1;
}

pcap_t *open_pcap(const char *dest_ip, uint32_t local_ip,
                  uint16_t sp_min, uint16_t sp_max) {
    char iface[64];
    if (get_iface_for_ip(local_ip, iface, sizeof(iface)) < 0) {
        fprintf(stderr, "ft_nmap: no usable network interface\n");
        return NULL;
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_live(iface, 65535, 0, 1, errbuf);
    if (!handle) {
        fprintf(stderr, "ft_nmap: pcap_open_live: %s\n", errbuf);
        return NULL;
    }

    char filter[256];
    snprintf(filter, sizeof(filter),
             "(tcp and src host %s and dst portrange %u-%u)"
             " or (icmp and src host %s)",
             dest_ip, sp_min, sp_max, dest_ip);

    struct bpf_program fp;
    if (pcap_compile(handle, &fp, filter, 1, PCAP_NETMASK_UNKNOWN) < 0) {
        fprintf(stderr, "ft_nmap: pcap filter error: %s\n",
                pcap_geterr(handle));
        pcap_close(handle);
        return NULL;
    }
    if (pcap_setfilter(handle, &fp) < 0) {
        fprintf(stderr, "ft_nmap: pcap filter error: %s\n",
                pcap_geterr(handle));
        pcap_freecode(&fp);
        pcap_close(handle);
        return NULL;
    }
    pcap_freecode(&fp);
    pcap_setnonblock(handle, 1, errbuf);
    return handle;
}
