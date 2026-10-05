# network-appliance-simulator
Python firewall and router simulator with four interfaces
# Network Security Appliance Simulator (Python)

A simulation of a four-interface network security appliance (a firewall and router in one). It reads raw packets from a capture file, applies a security policy to each, and either drops them with an alert or routes them to the correct interface.

Written for a University of Queensland cybersecurity course assignment, 2025.

## What it does

The appliance has four interfaces:

| Interface | Address |
|-----------|---------|
| `mgt` (management) | 192.168.96.23/20 |
| `int` (internal) | 10.0.0.1/16 |
| `dmz` | 10.1.0.1/24 |
| `ext` (external) | 130.102.184.1/24 |

For each packet in `traffic.spcap` (one hex-encoded packet per line) it:

1. **Parses** the custom frame header: ingress interface, MACs, protocol, and source and destination IPv4 addresses.
2. **Diverts management frames** to a separate management handler.
3. **Applies the security policy**, printing an `ALERT drop: ...` message when a packet is rejected:
   - **ICMP**: only echo requests are allowed; other ICMP types are dropped. Oversized pings (over 64 bytes) are dropped, and repeated pings from one source are rate limited.
   - **TCP**: new inbound connections from the external side are only allowed to ports 22, 80 and 443. Packets are dropped when there are too many incomplete (half-open) connections, a basic SYN-flood defence.
   - **UDP**: DNS (port 53) arriving from the external side is silently dropped.
4. **Routes** accepted packets using **longest-prefix-match** over the interface subnets, and builds ICMP echo replies, TCP frames and UDP frames for the egress interface.

## Code structure

| Class | Role |
|-------|------|
| `Interface` | One network interface: MAC, IP, mask, default gateway, with validation |
| `InterfaceHandler` | Owns the interfaces and reads packets from the capture file |
| `RouteTable` | Longest-prefix-match routing over interface subnets |
| `PatTable` / `Connections` | Port-address-translation table and connection tracking |
| `PacketEngine` | Parsing, policy checks, and ICMP/TCP/UDP handling |

## Running it

```
python3 appliance.py
```

It needs `traffic.spcap` in the same folder, and a `support.py` helper module (IP/MAC conversion and validation helpers) that was supplied by the course. Neither file is included here.

## Known limitations

This is a working core rather than a complete appliance. The PAT table and connection-tracking classes are defined, but full NAT translation and stateful connection handling are not wired into the TCP/UDP forwarding path (the code notes this as skipped), so TCP and UDP packets are forwarded without address translation.
