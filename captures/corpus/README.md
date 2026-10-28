# Calibration corpus of the zenoh verdict

Real packet captures, read by `crates/wz-capture/src/zenoh_corpus_tests.rs` to
measure the two error rates of the sequential test described in
`docs/flow-zenoh-verdict.md`: a flow of another protocol read as zenoh, and a
zenoh flow read as not zenoh.

Unlike the files in `captures/`, which are written by this workspace's own
encoders, every file here was captured from real software on a real network
interface, and `corpus.json5` says for each one what it is, where it was taken
and whether its flows are zenoh.

## How a file got here

1. Captured with `tcpdump -w` into a classic pcap, Ethernet link type, on the
   interface the traffic used: `lo` for zenoh 1.10.1 (the pinned zenohd and its
   example clients), the bridge of a docker network of its own for the other
   protocols' real implementations run in containers, and a Wi-Fi interface for
   the devices of the network it joined.
2. Anonymised by `scripts/lib/capture_anonymise.py`, with the scope the manifest
   names: `lan` for traffic of other devices, where every payload goes through a
   parser per protocol (DNS, mDNS and LLMNR names, SSDP header values, NTP
   reference ids) and a packet of a protocol without one is dropped, and `own`
   for traffic the capturer made itself, whose payloads are kept as sent (an
   ARP or neighbour discovery packet on a bridge is dropped and counted). MAC and IP addresses map to
   locally administered MACs and the documentation ranges; every length stays
   what it was.
3. Checked: the anonymiser refuses an output in which an original address or
   replaced name survives, and `capture_anonymise.py --verify-corpus
   captures/corpus` holds every file here to being one the anonymiser would
   leave unchanged, which a raw capture is not.

The original captures are not kept anywhere.

## What it holds today

| file | flows | protocol | how |
|---|---|---|---|
| `zenoh-tcp-full.pcap` | zenoh | TCP | a router and two clients, from before the first Init |
| `zenoh-tcp-midsession.pcap` | zenoh | TCP | the same, joined six seconds in |
| `zenoh-udp-full.pcap` | zenoh | UDP unicast | from before the first Init |
| `zenoh-tcp-lz4.pcap` | zenoh | TCP, lz4 | compression enabled on all three |
| `zenoh-udp-lz4-midsession.pcap` | zenoh | UDP, lz4 | joined six seconds in |
| `zenoh-tcp-lz4-midsession.pcap` | zenoh | TCP, lz4 | joined six seconds in |
| `zenoh15-tcp-full.pcap` | zenoh | TCP | an upstream zenohd 1.5.0 router |
| `zenoh15-tcp-midsession.pcap` | zenoh | TCP | the same, joined six seconds in |
| `zenoh15-udp-full.pcap` | zenoh | UDP unicast | the same, from before the first Init |
| `zenoh-v1-10-0-tcp-full.pcap`, `zenoh-v1-10-0-udp-full.pcap` | zenoh | TCP, UDP unicast | an upstream zenohd 1.10.0 router (the eclipse/zenoh image), from before the first Init |
| `zenoh-v1-9-0-tcp-full.pcap`, `zenoh-v1-9-0-udp-full.pcap` | zenoh | TCP, UDP unicast | the same with 1.9.0 |
| `zenoh-v1-8-0-tcp-full.pcap`, `zenoh-v1-8-0-udp-full.pcap` | zenoh | TCP, UDP unicast | the same with 1.8.0 |
| `zenoh-v1-7-2-tcp-full.pcap`, `zenoh-v1-7-2-udp-full.pcap` | zenoh | TCP, UDP unicast | the same with 1.7.2 |
| `zenoh-pico-tcp.pcap` | zenoh | TCP | zenoh-pico 1.10.1 clients |
| `zenoh-pico-udp.pcap` | zenoh | UDP unicast | zenoh-pico 1.10.1 clients |
| `zenoh-handshakes.pcap` | zenoh | TCP and UDP | 240 short sessions, the handshake checks' population |
| `zenoh-udp-lossy.pcap` | zenoh | UDP unicast | a link that drops 5% each way |
| `link-tcp-full.pcap` | zenoh | TCP | a router and clients on two machines over an office Wi-Fi, from before the first Init |
| `link-tcp-large.pcap` | zenoh | TCP | the same with 3000-byte samples, so a sample spans segments |
| `link-tcp-midsession.pcap` | zenoh | TCP | the same, joined seven seconds in |
| `link-udp-full.pcap` | zenoh | UDP unicast | the same over UDP |
| `link-pico-tcp.pcap` | zenoh | TCP | zenoh-pico 1.10.1 clients on the Wi-Fi link |
| `lan-dns.pcap` | other | DNS | one host's queries and answers, fifteen minutes |
| `lan-mdns.pcap` | other | mDNS | the devices of an office Wi-Fi, fifteen minutes |
| `lan-ssdp.pcap` | other | SSDP | one search and the devices' answers |
| `stack-mqtt.pcap` | other | MQTT | eclipse-mosquitto 2.0.18, containers |
| `stack-rtps.pcap` | other | RTPS | ROS 2 Jazzy publisher and subscriber, containers |
| `stack-coap.pcap` | other | CoAP | libcoap 4.3.1 server and client, containers |
| `stack-someip.pcap` | other | SOME/IP, SOME/IP-SD | upstream vsomeip 3.7.6 service and client, containers |
| `stack-quic.pcap` | other | QUIC v1 and v2, HTTP/3 | aioquic 1.2.0 server and client, containers |
| `busylan-dhcp.pcap` | other | DHCPv4 | dnsmasq 2.90 and twelve udhcpc clients, containers |
| `busylan-ntp.pcap` | other | NTP | a chrony 4.3 server and six clients, containers |
| `busylan-wsd.pcap` | other | LLMNR, WS-Discovery | wsdd2 1.8.7 and four askers, containers |
| `stack-http.pcap` | other | HTTP/1.1 | python 3.12 http.server, keep-alive and short connections, containers |
| `stack-tls.pcap` | other | TLS 1.2 and 1.3 | the same behind OpenSSL 3, containers |
| `stack-http-post.pcap` | other | HTTP/1.1 opening with POST, PUT or HEAD | the same server, bodies up to 30000 bytes, containers |
| `stack-redis.pcap` | other | Redis (RESP) | redis 7 server, one-shot and pipelining redis-cli and a small redis-benchmark, containers |
| `stack-postgres.pcap` | other | PostgreSQL | postgres 16 server, psql one-shot queries, a statement script and queries returning thousands of rows, containers |

## What it does not hold yet

On the zenoh side versions other than
1.10.1, 1.10.0, 1.9.0, 1.8.0, 1.7.2 and 1.5.0 (all with 1.10.1 clients) and
links other than loopback, an emulated lossy one and one office Wi-Fi link.
Each is added the same way: captured from the real
implementation, a parser in the anonymiser where a payload of other devices can
carry an identity, and the measured tally pinned beside the others. QUIC needed
such a parser even for the capturer's own traffic, because its Initial packets
carry the server name under keys anyone can derive: the anonymiser opens them
(`scripts/lib/quic_initial.py`), replaces the name and seals them again.
