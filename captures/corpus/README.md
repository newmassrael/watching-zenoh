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
   example clients), a Wi-Fi interface for the devices of the network it joined.
2. Anonymised by `scripts/lib/capture_anonymise.py`, with the scope the manifest
   names: `lan` for traffic of other devices, where every payload goes through a
   parser per protocol (DNS, mDNS and LLMNR names, SSDP header values, NTP
   reference ids) and a packet of a protocol without one is dropped, and
   `loopback` for traffic the capturer made itself. MAC and IP addresses map to
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
| `lan-dns.pcap` | other | DNS | one host's queries and answers, fifteen minutes |
| `lan-mdns.pcap` | other | mDNS | the devices of an office Wi-Fi, fifteen minutes |
| `lan-ssdp.pcap` | other | SSDP | one search and the devices' answers |

## What it does not hold yet

The protocols that run beside zenoh in the deployments it serves: RTPS (ROS 2),
SOME/IP, CoAP, MQTT, QUIC, LLMNR, WS-Discovery, NTP, DHCP, and structured TCP
such as HTTP and TLS. Each is added the same way, with a parser in the
anonymiser where its payload can carry an identity, and the measured tally
pinned beside the others.
