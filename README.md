# ft_nmap

A small reimplementation of nmap in C, using raw sockets, libpcap and pthreads.

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
| `--ports` | Ports to scan, e.g. `1-1024` or `22,80,443` (default: 1-1024, max 1024 ports) |
| `--scan` | Comma separated scan types: `SYN,NULL,ACK,FIN,XMAS,UDP` (default: all) |
| `--speedup` | Number of parallel threads, 0 to 250 (default: 0, one thread) |

The five TCP scans craft their own packets and read the replies with pcap, so they need root: run them with `sudo`. The UDP scan reads the ICMP answer off the socket error queue (`IP_RECVERR`) and needs no privilege.

`Ctrl+C` or `SIGTERM` stops the scan: the workers finish the probe they are on, close their sockets and pcap handles, and the program exits with status 130.

## Scan types

| Type | How it works |
|---|---|
| SYN | SYN-ACK = open, RST = closed, no reply or ICMP unreachable = filtered |
| NULL | No flags: RST = closed, ICMP unreachable = filtered, no reply = open/filtered |
| FIN | FIN flag: RST = closed, ICMP unreachable = filtered, no reply = open/filtered |
| XMAS | FIN+PSH+URG: RST = closed, ICMP unreachable = filtered, no reply = open/filtered |
| ACK | RST = unfiltered, no reply or ICMP unreachable = filtered |
| UDP | Datagram reply = open, ICMP port unreachable = closed, other ICMP unreachable = filtered, timeout = open/filtered |

Service names come from `getservbyport()`, so from `/etc/services`. Ports it does not list print `Unassigned`.

## Example

```bash
sudo ./ft_nmap --ip scanme.nmap.org --ports 1-1024 --speedup 50 --scan SYN
```

## Checking against nmap

nmap runs one scan type per invocation: `-sS` SYN, `-sN` NULL, `-sA` ACK, `-sF` FIN, `-sX` XMAS, `-sU` UDP. Add `-Pn -n` so it skips host discovery and DNS, which ft_nmap never does, and `--reason` to see the packet behind each verdict.

Every state can be produced on localhost:

```bash
python3 -m http.server 8080 &                                   # 8080 open
sudo iptables -A INPUT -p tcp --dport 9997 -j DROP               # 9997 silent
sudo iptables -A INPUT -p udp --dport 9997 -j DROP
sudo iptables -A INPUT -p tcp --dport 9996 -j REJECT --reject-with icmp-admin-prohibited
sudo iptables -A INPUT -p udp --dport 9996 -j REJECT --reject-with icmp-admin-prohibited

sudo ./ft_nmap --ip 127.0.0.1 --ports 8080,9998,9997,9996
sudo nmap -Pn -n --reason -sS -p 8080,9998,9997,9996 127.0.0.1
sudo nmap -Pn -n --reason -sU -p 8080,9998,9997,9996 127.0.0.1

sudo iptables -F INPUT; kill %1
```

Expected: 8080 Open on SYN and Open|Filtered on NULL/FIN/XMAS, 9998 Closed, 9997 Filtered on SYN/ACK and Open|Filtered on the rest, 9996 Filtered everywhere.

Two things differ by design. nmap names more ports because it ships its own service database. nmap retransmits unanswered probes, ft_nmap sends once and waits 500 ms for TCP and 1.5 s for UDP, so on a lossy link nmap may say closed where ft_nmap says Filtered.
