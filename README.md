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
| `--privileged` | Assume raw sockets are allowed, skipping the uid check |
| `--unprivileged` | Assume raw sockets are not allowed |

The five TCP scans need `CAP_NET_RAW`, so run those under `sudo`. `--scan UDP` needs no privilege. See [Privileges](#privileges) for why, and for how the check is made.

## Privileges

Five of the six scan types need `CAP_NET_RAW`, so in practice you run ft_nmap under `sudo`. The UDP scan does not need it.

This is not a shortcut taken here. Real nmap has the same rule for the same scan types, and has had it since 1997.

| Scan | Needs privilege | Reason |
|---|---|---|
| SYN, NULL, FIN, XMAS, ACK | yes, unavoidable | crafted packets out, packet capture in |
| UDP | no | plain datagram socket out, ICMP error read off the socket error queue |

### Why the TCP scans cannot avoid it

Those five write their own IP and TCP headers, so a normal socket cannot carry them. They need privilege twice over, once to send and once to receive.

| Step | Call | Why an ordinary socket cannot do it |
|---|---|---|
| Send | `socket(AF_INET, SOCK_RAW, IPPROTO_RAW)` with `IP_HDRINCL`, in `scan.c` | On a normal socket the kernel builds the headers. NULL, FIN and XMAS are flag combinations the TCP stack will never emit, so we must build the packet ourselves. |
| Receive | `pcap_open_live()`, in `pcap_utils.c` | A SYN/ACK or RST answering a port we never bound is dropped by the stack before any socket can read it. Only a capture handle sees it. |

Both go through raw or `AF_PACKET` access, which the kernel gates on `CAP_NET_RAW`. Measured on Linux 7.0 as uid 1000, no sudo:

| Call | Result |
|---|---|
| `socket(AF_INET, SOCK_RAW, IPPROTO_RAW)` | fails, `EPERM` |
| `pcap_open_live("lo", ...)` | fails, "Attempt to create packet socket failed - CAP_NET_RAW may be required" |
| `socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)` | works |

`scan.c` opens the raw socket and the pcap handle only when one of those five scans is requested, so asking for `--scan UDP` alone opens neither.

### How the UDP scan avoids it

Sending a UDP probe needs nothing special. The only reason to want privilege is to read the ICMP port unreachable answer, and Linux hands that over without a raw socket. `udp.c` does this:

1. `connect()` the datagram socket to the target port. Linux only reports ICMP errors for a destination the socket itself is bound to.
2. `setsockopt(IP_RECVERR)`, so the kernel queues the ICMP error instead of dropping it.
3. `send()` an empty datagram, then `poll()`.
4. On `POLLERR`, `recvmsg(..., MSG_ERRQUEUE)` and read `struct sock_extended_err`.

`ee_type` and `ee_code` carry the full ICMP values, so `ICMP_PORT_UNREACH` stays Closed while other unreachable codes are Filtered. Plain `errno` would collapse both into `ECONNREFUSED`. A datagram arriving instead of an error means Open, and silence until the timeout means Open|Filtered.

This replaced a raw `IPPROTO_ICMP` socket, and gains two things beyond dropping the privilege requirement. A raw ICMP socket receives a copy of every ICMP packet reaching the host, so with `--speedup 250` every thread read the same stream, and a thread that dequeued a reply addressed to another thread discarded it on the port check. The owning thread then saw nothing and reported Open|Filtered instead of Closed. An error queue belongs to one socket, so there is nothing to steal.

Checked with every capability dropped, `docker run --cap-drop=ALL`, against a closed port and a port with a listener:

```
9998   UDP(Closed)        ICMP port unreachable, read off the error queue
9999   UDP(Open)          the listener answered
```

The same binary with the previous raw ICMP implementation reported `Open|Filtered` for both, because its `socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)` returned `EPERM`.

### Why real nmap seems not to need privilege either

Running `nmap <host>` as a normal user works, which makes it look like nmap avoids raw sockets. It does not. That command gets the default scan, which is TCP connect (`-sT`), one `connect()` per port and nothing raw. Ask for a raw scan type and nmap quits the same way ft_nmap does.

nmap 7.98, as a normal user:

```
$ nmap -sS -p 22,80 127.0.0.1
You requested a scan type which requires root privileges.
QUITTING!
```

The same check exists in nmap 1.51 from 1997, in `nmap.c`:

```c
o.isr00t = !(geteuid()|geteuid());
...
if ((o.synscan || o.finscan || o.fragscan || pingscan) && !o.isr00t)
  fatal("Options specified require r00t privileges.  You don't have them!");
```

Its own usage text says `-s tcp SYN stealth port scan (must be root)`. Old nmap runs without sudo for the same reason the current one does: its default is the connect scan, chosen in `nmap.c` when no scan flag is given. ft_nmap has no connect scan because the subject does not ask for one.

Note that both versions test the effective uid, not the actual capability. That is why nmap ships `--privileged` and `NMAP_PRIVILEGED`, so a binary carrying `cap_net_raw` can be told to try anyway. Its man page states the rule directly: "By default Nmap quits if such operations are requested but geteuid is not zero." ft_nmap follows the same model, described under [The privilege check](#the-privilege-check).

nmap 1.51 also already had the unprivileged UDP scan, picking an implementation by privilege:

```c
if (o.udpscan) {
  if (!o.isr00t || o.lamerscan)
    lamer_udp_scan(currenths, ports);
  else udp_scan(currenths, ports);
}
```

`udp_scan()` read raw ICMP. `lamer_udp_scan()` needed no privilege and read `errno` from a plain datagram socket, treating `ECONNREFUSED` as closed. So a UDP scan without root has been possible since 1997. Its exact method no longer works though: it calls `sendto()` on an unconnected socket, and Linux reports ICMP errors only on a connected socket or with `IP_RECVERR` set. The `connect()` plus `IP_RECVERR` form in `udp.c` is that same idea in the shape the kernel accepts today, and it keeps the ICMP code that bare `errno` throws away.

### How to run it

Grant privilege for the run:

```bash
sudo ./ft_nmap --ip 127.0.0.1 --ports 1-1024 --scan SYN
```

The narrower alternative is to grant the capability once to the binary, so the scan runs as a normal user:

```bash
sudo setcap cap_net_raw,cap_net_admin+ep ./ft_nmap
getcap ./ft_nmap
```

`cap_net_raw` is what the kernel actually tests for the raw socket and the pcap handle, and `cap_net_admin` covers interface queries. This is the set nmap's own man page recommends.

A uid check cannot see a capability, so pass `--privileged` to say the raw sockets will work:

```bash
./ft_nmap --privileged --ip 127.0.0.1 --ports 22 --scan SYN
```

Verified as uid 1000 against a binary carrying `cap_net_raw`: the SYN scan runs and reports `SYN(Closed)`, with no root anywhere.

### The privilege check

`main.c` decides this the way nmap does, in `have_raw_privilege()` (`args.c`):

1. `--privileged` forces yes, `--unprivileged` forces no.
2. Otherwise `FT_NMAP_PRIVILEGED` or `FT_NMAP_UNPRIVILEGED` in the environment, if set.
3. Otherwise `geteuid() == 0`.

The result only gates `SCAN_RAW_TCP`, the five scans that craft packets, and it is tested after `parse_arguments()` rather than at program entry. Three things follow, all matching nmap:

- `--help` works as a normal user, because nothing is checked before parsing.
- `--scan UDP` works as a normal user, because that path opens no raw socket.
- `--privileged` gets you past the check on a `setcap` binary. If the capability is not really there, the scan fails at the socket with `Operation not permitted`, which is what nmap does too.

Checked as uid 1000 with no capabilities:

| Command | Result |
|---|---|
| `--help` | usage, exit 0 |
| `--scan UDP` | runs, reports `UDP(Closed)` |
| `--scan SYN` | "you requested a scan type which requires root privileges", exit 1 |
| `--scan SYN --privileged` | past the check, then `socket: Operation not permitted` |
| `--scan SYN --unprivileged` as root | refused, same message |

One difference from nmap remains, and it cannot be closed. Given no `--scan`, ft_nmap defaults to all six types, so a normal user is refused rather than falling back. nmap falls back to its connect scan, which the subject does not ask us to implement. Ask for `--scan UDP` explicitly to scan as a normal user.

## Scan types

| Type | How it works |
|---|---|
| SYN | Half-open: SYN-ACK = open, RST = closed |
| NULL | No flags: RST = closed, no reply = open/filtered |
| FIN | FIN flag: RST = closed, no reply = open/filtered |
| XMAS | FIN+PSH+URG: RST = closed, no reply = open/filtered |
| ACK | RST = unfiltered, no reply = filtered |
| UDP | Datagram reply = open, ICMP port unreachable = closed, other ICMP unreachable = filtered, timeout = open/filtered |

## Service names

The service column comes from `getservbyport()` first, so a machine with a full `/etc/services` keeps using it. Debian and Ubuntu trimmed that file years ago, which left most of the default 1 to 1024 range printing `Unassigned`, so `services.c` carries a fallback table for that range built from the [IANA port registry](https://www.iana.org/assignments/service-names-port-numbers/), plus four older names IANA dropped but `/etc/services` still has. Real nmap has the same table shipped as `nmap-services` and never asks the system at all.

Of the 726 ports nmap names in 1 to 1024, ft_nmap now names 684. The rest differ because nmap's database is its own rather than IANA's: 42 are names only nmap carries, and 68 are ports both name but spell differently, such as `67=bootps` here against `dhcps` in nmap, or `88=kerberos` against `kerberos-sec`. Where they differ, ft_nmap matches `/etc/services` and IANA. Closing the last gap would mean shipping nmap's own data file.

## Example

```bash
./ft_nmap --ip scanme.nmap.org --port 1-1024 --speedup 50 --scan SYN
```
