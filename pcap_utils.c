#include "ft_nmap.h"
#include <pcap.h>
#include <arpa/inet.h>

/* find the interface whose address matches local_ip */
static const char *get_iface_for_ip(uint32_t local_ip) {
    pcap_if_t *devs;
    char errbuf[PCAP_ERRBUF_SIZE];
    if (pcap_findalldevs(&devs, errbuf) < 0)
        return NULL;

    static char name[64];
    for (pcap_if_t *d = devs; d; d = d->next) {
        for (pcap_addr_t *a = d->addresses; a; a = a->next) {
            if (!a->addr || a->addr->sa_family != AF_INET)
                continue;
            struct sockaddr_in *sin = (struct sockaddr_in *)a->addr;
            if (sin->sin_addr.s_addr == local_ip) {
                strncpy(name, d->name, sizeof(name) - 1);
                name[sizeof(name) - 1] = '\0';
                pcap_freealldevs(devs);
                return name;
            }
        }
    }

    /* fallback: first non-loopback interface */
    for (pcap_if_t *d = devs; d; d = d->next) {
        if (!(d->flags & PCAP_IF_LOOPBACK)) {
            strncpy(name, d->name, sizeof(name) - 1);
            name[sizeof(name) - 1] = '\0';
            pcap_freealldevs(devs);
            return name;
        }
    }

    pcap_freealldevs(devs);
    return NULL;
}

pcap_t *open_pcap(const char *dest_ip, uint32_t local_ip,
                  uint16_t sp_min, uint16_t sp_max) {
    const char *iface = get_iface_for_ip(local_ip);
    if (!iface) {
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
    if (pcap_compile(handle, &fp, filter, 1, PCAP_NETMASK_UNKNOWN) < 0
            || pcap_setfilter(handle, &fp) < 0) {
        fprintf(stderr, "ft_nmap: pcap filter error: %s\n",
                pcap_geterr(handle));
        pcap_close(handle);
        return NULL;
    }
    pcap_freecode(&fp);
    pcap_setnonblock(handle, 1, errbuf);
    return handle;
}
