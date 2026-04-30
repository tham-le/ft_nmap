# ft_nmap

A partial reimplementation of [nmap](https://nmap.org) in C, using raw sockets, libpcap, and pthreads.

## Requirements

```
libpcap-dev
```

## Build

```bash
make
```

## Usage

```
./ft_nmap [--help] [--ip ADDRESS] [--file FILE] [--ports RANGE] [--scan TYPES] [--speedup N]
```

| Option | Description |
|---|---|
| `--ip` | Target IP or hostname (repeatable) |
| `--file` | File with one target per line |
| `--port`, `--ports` | Ports to scan, e.g. `1-1024` or `22,80,443` (default: 1-1024) |
| `--scan` | Comma-separated scan types: `SYN,NULL,ACK,FIN,XMAS,UDP` (default: all) |
| `--speedup` | Number of parallel threads, max 250 (default: 1) |

Must run as root.

## Scan types

| Type | How it works |
|---|---|
| SYN | Half-open: SYN-ACK = open, RST = closed |
| NULL | No flags: RST = closed, no reply = open/filtered |
| FIN | FIN flag: RST = closed, no reply = open/filtered |
| XMAS | FIN+PSH+URG: RST = closed, no reply = open/filtered |
| ACK | RST = unfiltered, no reply = filtered |
| UDP | ICMP port unreachable = closed, timeout = open/filtered |

## Example

```bash
./ft_nmap --ip scanme.nmap.org --port 1-1024 --speedup 50 --scan SYN
```

## Notes

Concepts used in this project:

- [Port Scanning](https://notes.thamle.live/Networking/Port-Scanning)
- [Raw Sockets](https://notes.thamle.live/Networking/Raw-Sockets)
- [PCAP](https://notes.thamle.live/Networking/PCAP)
- [TCP](https://notes.thamle.live/Networking/TCP) and [TCP Header](https://notes.thamle.live/Networking/TCP-Header)
- [UDP](https://notes.thamle.live/Networking/UDP)
- [ICMP](https://notes.thamle.live/Networking/ICMP)
- [IP](https://notes.thamle.live/Networking/IP)
- [Traceroute](https://notes.thamle.live/Networking/Traceroute)
- [getaddrinfo](https://notes.thamle.live/Syscalls/getaddrinfo)
