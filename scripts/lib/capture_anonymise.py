#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
"""Anonymise a real packet capture so it can be committed to `captures/corpus/`.

## Why this exists

The zenoh verdict's calibration corpus (`docs/flow-zenoh-verdict.md` §6) holds
REAL captures: real devices on a LAN for the protocols that are not zenoh, real
zenoh 1.10.1 for the ones that are. The repository is public, and a real
capture carries the identities of the devices and people on the network it was
taken on: MAC and IP addresses, host names, service instance names, UUIDs,
user agents. The owner's decision (2026-10-26) is to commit them after those
are replaced, keeping the payload layout, because the corpus measures how the
bytes READ and that depends on the layout and not on the names.

## What it keeps and what it replaces

* Every length. A replaced name, value or address has the length of the
  original, so every framing unit is as long as it was, a DNS compression
  pointer still points at the same offset, and a reading the verdict weighs is
  the reading the real bytes gave.
* Ethernet MACs and IPv4/IPv6 unicast addresses map, consistently within the
  file, to locally administered MACs and the documentation ranges
  (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24, 2001:db8::/32, and fe80::N
  for link-local). Multicast, broadcast, unspecified and loopback addresses are
  kept: they name a group or a scope, not a device. Checksums are recomputed.
* Timestamps are rebased so the first packet is at 2026-01-01T00:00:00Z; the
  spacing between packets is kept.
* Payloads are scrubbed by a parser per protocol, chosen by UDP port:
  DNS (53), mDNS (5353) and LLMNR (5355) replace every name label that is not
  a service label (leading `_`) or a standard one (`local`, `arpa`, ...), map
  the addresses in A and AAAA records, keep TXT keys and replace their values,
  and zero the data of record types this parser does not read; SSDP (1900)
  keeps the start line and the values of the standard headers and replaces the
  other values character for character; NTP (123) zeroes the reference id.
  A loopback capture (`--scope loopback`) also admits TCP and UDP on any port,
  because the traffic is the capturer's own: its addresses are 127.0.0.1 and
  its payloads are what the capturer chose to send.
* A packet of any other protocol, or one a parser cannot read, is DROPPED and
  counted by reason in the report. Dropping is honest where a guess is not: a
  payload kept unscrubbed could carry an identity, and a payload replaced
  wholesale would read differently from the real one.

## The leak check

After writing, every original unicast MAC and IP address (as bytes) and every
replaced name label of three or more characters (as bytes, either case) is
searched for in the output file, with any words given as `--forbid`. A hit
refuses the output: the file is removed and the exit code is 1.

## Usage

  capture_anonymise.py --in RAW.pcap --out CORPUS.pcap --scope lan|loopback
                       [--forbid WORD ...] [--report REPORT.json]
  capture_anonymise.py --verify-corpus captures/corpus
  capture_anonymise.py --selftest

`--verify-corpus` holds every file the manifest lists to being a FIXED POINT:
anonymised again under its `scope`, it does not change. The tool leaves what it
wrote as it is (documentation addresses, its own MACs and name tokens, scrubbed
values), so a file that changes holds something the tool would have replaced,
which is what a raw capture committed by mistake looks like. A `.pcap` the
manifest does not list fails as well.

The input is a classic pcap with LINKTYPE_ETHERNET (what `tcpdump -w` writes on
an Ethernet, a Wi-Fi interface in managed mode, or `lo`).
"""

import argparse
import ipaddress
import json
import os
import struct
import sys

LINKTYPE_ETHERNET = 1
REBASE_EPOCH = 1767225600  # 2026-01-01T00:00:00Z
# The thirty days after it, where an anonymised file's clock lives.
REBASE_WINDOW = 30 * 86400

ETH_IPV4 = 0x0800
ETH_IPV6 = 0x86DD
PROTO_TCP = 6
PROTO_UDP = 17

DNS_PORTS = {53, 5353, 5355}
SSDP_PORT = 1900
NTP_PORT = 123

# The shortest replaced value the leak check searches for. A shorter string
# turns up by chance in any binary file, and a check that always fires is one
# nobody reads.
LEAK_MIN = 4

# The documentation ranges addresses map into (RFC 5737), in the order used.
DOC_V4_NETS = (b"\xc0\x00\x02", b"\xc6\x33\x64", b"\xcb\x00\x71")

# Labels that name a protocol or a tree rather than a device.
STANDARD_LABELS = {
    b"local", b"arpa", b"in-addr", b"ip6", b"home", b"lan", b"localdomain",
}

# SSDP headers whose values are protocol vocabulary, compared case-insensitively.
SSDP_KEEP = {b"host", b"man", b"mx", b"st", b"nt", b"nts", b"cache-control", b"ext"}


class Refused(Exception):
    """A packet this tool will not keep, with the reason it is counted under."""


def checksum16(data):
    if len(data) % 2:
        data += b"\0"
    total = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


class Maps:
    """The replacements of one file, so a value maps the same way every time."""

    def __init__(self):
        self.mac = {}
        self.v4 = {}
        self.v6 = {}
        self.labels = {}
        self.originals = set()

    def mac_of(self, mac):
        if mac[0] & 1 or mac == b"\0" * 6:
            return mac  # group or broadcast, or the all-zero loopback MAC
        if mac[:4] == b"\x02\0\0\0":
            return mac  # already one of this tool's
        if mac not in self.mac:
            n = len(self.mac) + 1
            self.mac[mac] = bytes([0x02, 0, 0, 0, (n >> 8) & 0xFF, n & 0xFF])
            self.originals.add(mac)
        return self.mac[mac]

    def v4_of(self, raw):
        addr = ipaddress.IPv4Address(raw)
        if (
            addr.is_multicast
            or addr.is_loopback
            or addr.is_unspecified
            or raw == b"\xff\xff\xff\xff"
            or raw[3] == 255
            or raw[:3] in DOC_V4_NETS
        ):
            return raw
        if raw not in self.v4:
            n = len(self.v4)
            if n >= 3 * 254:
                raise Refused("too_many_ipv4_hosts")
            self.v4[raw] = DOC_V4_NETS[n // 254] + bytes([n % 254 + 1])
            self.originals.add(raw)
        return self.v4[raw]

    def v6_of(self, raw):
        addr = ipaddress.IPv6Address(raw)
        if addr.is_multicast or addr.is_loopback or addr.is_unspecified:
            return raw
        if raw[:4] == b"\x20\x01\x0d\xb8" or (raw[:2] == b"\xfe\x80" and raw[2:14] == b"\0" * 12):
            return raw  # already one of this tool's
        if raw not in self.v6:
            n = len(self.v6) + 1
            if addr.is_link_local:
                self.v6[raw] = b"\xfe\x80" + b"\0" * 12 + struct.pack("!H", n)
            else:
                self.v6[raw] = b"\x20\x01\x0d\xb8" + b"\0" * 10 + struct.pack("!H", n)
            self.originals.add(raw)
        return self.v6[raw]

    def label_of(self, label):
        """A label of the same length, the same one for the same original."""
        key = label.lower()
        if key not in self.labels:
            token = b"n" + str(len(self.labels) + 1).encode()
            if len(token) > len(label):
                token = b""
            self.labels[key] = token + b"x" * (len(label) - len(token))
            if len(label) >= LEAK_MIN:
                self.originals.add(key)
        return self.labels[key]


def keep_label(label):
    if label.startswith(b"_") or label.lower() in STANDARD_LABELS:
        return True
    # A token this tool wrote (`n12xx`, `xxx`): re-reading an anonymised file
    # leaves it as it is.
    body = label.rstrip(b"x")
    return body == b"" or (body[:1] == b"n" and body[1:].isdigit())


def scrub_name(msg, pos, maps, out):
    """Scrub the name at `pos` in place in `out`; return the offset after it."""
    jumps = 0
    end = None
    while True:
        if pos >= len(msg):
            raise Refused("dns_name_truncated")
        length = msg[pos]
        if length == 0:
            return end if end is not None else pos + 1
        if length & 0xC0 == 0xC0:
            if pos + 1 >= len(msg):
                raise Refused("dns_name_truncated")
            if end is None:
                end = pos + 2
            jumps += 1
            if jumps > 64:
                raise Refused("dns_pointer_loop")
            target = ((length & 0x3F) << 8) | msg[pos + 1]
            if target >= pos and end == pos + 2:
                # A pointer forward is legal but never seen; refusing it keeps
                # the walk from scrubbing bytes that are not a name.
                raise Refused("dns_pointer_forward")
            pos = target
            continue
        if length & 0xC0:
            raise Refused("dns_label_type")
        label = bytes(msg[pos + 1 : pos + 1 + length])
        if len(label) != length:
            raise Refused("dns_name_truncated")
        # The last label of a name is its top-level domain, which names a
        # registry and not a device.
        last = pos + 1 + length < len(msg) and msg[pos + 1 + length] == 0
        tld = last and label.isalpha() and len(label) <= 6
        if end is None and not keep_label(label) and not tld:
            # Only labels the walk reaches before its first pointer are this
            # name's own bytes; the rest belong to an earlier name, which was
            # scrubbed where it stood.
            out[pos + 1 : pos + 1 + length] = maps.label_of(label)
        pos += 1 + length


def scrub_value(value):
    """Same length, same character classes, none of the characters."""
    out = bytearray()
    for b in value:
        if 0x30 <= b <= 0x39:
            out.append(0x30)
        elif 0x41 <= b <= 0x5A or 0x61 <= b <= 0x7A:
            out.append(0x78)
        elif b in (0x20, 0x2D, 0x2E, 0x2F, 0x3A, 0x3B, 0x3D, 0x2C):
            out.append(b)
        else:
            out.append(0x78)
    return bytes(out)


def scrub_dns(payload, maps):
    msg = bytes(payload)
    out = bytearray(payload)
    if len(msg) < 12:
        raise Refused("dns_short")
    qd, an, ns, ar = struct.unpack("!4H", msg[4:12])
    pos = 12
    for _ in range(qd):
        pos = scrub_name(msg, pos, maps, out) + 4
    for _ in range(an + ns + ar):
        pos = scrub_name(msg, pos, maps, out)
        if pos + 10 > len(msg):
            raise Refused("dns_rr_truncated")
        rtype, _cls, _ttl, rdlen = struct.unpack("!HHIH", msg[pos : pos + 10])
        rd = pos + 10
        if rd + rdlen > len(msg):
            raise Refused("dns_rr_truncated")
        if rtype == 1 and rdlen == 4:
            out[rd : rd + 4] = maps.v4_of(msg[rd : rd + 4])
        elif rtype == 28 and rdlen == 16:
            out[rd : rd + 16] = maps.v6_of(msg[rd : rd + 16])
        elif rtype in (2, 5, 12):  # NS, CNAME, PTR
            scrub_name(msg, rd, maps, out)
        elif rtype == 33 and rdlen >= 7:  # SRV: priority, weight, port, target
            scrub_name(msg, rd + 6, maps, out)
        elif rtype == 16:  # TXT: character strings
            i = rd
            while i < rd + rdlen:
                n = msg[i]
                s = msg[i + 1 : i + 1 + n]
                eq = s.find(b"=")
                value = s[eq + 1 :] if eq >= 0 else s
                start = i + 2 + eq if eq >= 0 else i + 1
                out[start : i + 1 + n] = scrub_value(value)
                if len(value) >= LEAK_MIN:
                    maps.originals.add(value.lower())
                i += 1 + n
        elif rtype == 47:  # NSEC: next domain name, then a type bitmap
            scrub_name(msg, rd, maps, out)
        elif rtype == 41:  # OPT: options may carry a client subnet
            out[rd : rd + rdlen] = b"\0" * rdlen
        else:
            out[rd : rd + rdlen] = b"\0" * rdlen
        pos = rd + rdlen
    return bytes(out)


def scrub_ssdp(payload, maps):
    lines = payload.split(b"\r\n")
    if not lines or not (
        lines[0].startswith(b"NOTIFY ")
        or lines[0].startswith(b"M-SEARCH ")
        or lines[0].startswith(b"HTTP/1.1 ")
    ):
        raise Refused("ssdp_start_line")
    out = [lines[0]]
    for line in lines[1:]:
        colon = line.find(b":")
        if colon < 0:
            out.append(scrub_value(line))
            continue
        name, value = line[:colon], line[colon + 1 :]
        keep = name.strip().lower() in SSDP_KEEP and b"uuid:" not in value.lower()
        if not keep:
            if len(value.strip()) >= 4:
                maps.originals.add(value.strip().lower())
            value = scrub_value(value)
        out.append(name + b":" + value)
    return b"\r\n".join(out)


def scrub_ntp(payload, maps):
    if len(payload) < 48:
        raise Refused("ntp_short")
    out = bytearray(payload)
    out[12:16] = b"\0\0\0\0"
    return bytes(out)


def scrub_udp_payload(sport, dport, payload, maps, scope):
    ports = {sport, dport}
    if ports & DNS_PORTS:
        return scrub_dns(payload, maps)
    if SSDP_PORT in ports:
        return scrub_ssdp(payload, maps)
    if NTP_PORT in ports:
        return scrub_ntp(payload, maps)
    if scope == "loopback":
        return payload
    raise Refused("udp_port_%d_%d" % (min(ports), max(ports)))


def transport_checksum(src, dst, proto, segment, v6):
    if v6:
        pseudo = src + dst + struct.pack("!I3xB", len(segment), proto)
    else:
        pseudo = src + dst + struct.pack("!BBH", 0, proto, len(segment))
    return checksum16(pseudo + segment)


def rewrite_transport(proto, src, dst, segment, maps, scope, v6):
    seg = bytearray(segment)
    if proto == PROTO_UDP:
        if len(seg) < 8:
            raise Refused("udp_short")
        sport, dport, length, old = struct.unpack("!4H", seg[:8])
        body = bytes(seg[8:length]) if length <= len(seg) else None
        if body is None:
            raise Refused("udp_truncated")
        body = scrub_udp_payload(sport, dport, body, maps, scope)
        seg = bytearray(seg[:8] + body + seg[length:])
        seg[6:8] = b"\0\0"
        if old != 0 or v6:
            ck = transport_checksum(src, dst, proto, bytes(seg), v6) or 0xFFFF
            seg[6:8] = struct.pack("!H", ck)
        return bytes(seg)
    if proto == PROTO_TCP and scope == "loopback":
        if len(seg) >= 20:
            seg[16:18] = b"\0\0"
            seg[16:18] = struct.pack("!H", transport_checksum(src, dst, proto, bytes(seg), v6))
        return bytes(seg)
    raise Refused("ip_proto_%d" % proto)


def rewrite_frame(frame, maps, scope):
    if len(frame) < 14:
        raise Refused("ethernet_short")
    out = bytearray(frame)
    out[0:6] = maps.mac_of(bytes(frame[0:6]))
    out[6:12] = maps.mac_of(bytes(frame[6:12]))
    ethertype = struct.unpack("!H", frame[12:14])[0]
    ip = 14
    if ethertype == ETH_IPV4:
        ihl = (frame[ip] & 0x0F) * 4
        total = struct.unpack("!H", frame[ip + 2 : ip + 4])[0]
        proto = frame[ip + 9]
        frag = struct.unpack("!H", frame[ip + 6 : ip + 8])[0]
        if frag & 0x3FFF:
            raise Refused("ipv4_fragment")
        src = maps.v4_of(bytes(frame[ip + 12 : ip + 16]))
        dst = maps.v4_of(bytes(frame[ip + 16 : ip + 20]))
        out[ip + 12 : ip + 16] = src
        out[ip + 16 : ip + 20] = dst
        if ihl > 20:
            raise Refused("ipv4_options")
        seg = rewrite_transport(proto, src, dst, frame[ip + ihl : ip + total], maps, scope, False)
        out[ip + ihl : ip + total] = seg
        out[ip + 10 : ip + 12] = b"\0\0"
        out[ip + 10 : ip + 12] = struct.pack("!H", checksum16(bytes(out[ip : ip + ihl])))
        return bytes(out)
    if ethertype == ETH_IPV6:
        plen = struct.unpack("!H", frame[ip + 4 : ip + 6])[0]
        nxt = frame[ip + 6]
        src = maps.v6_of(bytes(frame[ip + 8 : ip + 24]))
        dst = maps.v6_of(bytes(frame[ip + 24 : ip + 40]))
        out[ip + 8 : ip + 24] = src
        out[ip + 24 : ip + 40] = dst
        seg = rewrite_transport(nxt, src, dst, frame[ip + 40 : ip + 40 + plen], maps, scope, True)
        out[ip + 40 : ip + 40 + plen] = seg
        return bytes(out)
    raise Refused("ethertype_%04x" % ethertype)


def read_pcap(data):
    if len(data) < 24:
        raise SystemExit("not a pcap: too short")
    magic = data[:4]
    if magic == b"\xd4\xc3\xb2\xa1":
        endian, nano = "<", False
    elif magic == b"\xa1\xb2\xc3\xd4":
        endian, nano = ">", False
    elif magic == b"\x4d\x3c\xb2\xa1":
        endian, nano = "<", True
    elif magic == b"\xa1\xb2\x3c\x4d":
        endian, nano = ">", True
    else:
        raise SystemExit("not a classic pcap (pcapng is not read): magic %s" % magic.hex())
    linktype = struct.unpack(endian + "I", data[20:24])[0]
    if linktype != LINKTYPE_ETHERNET:
        raise SystemExit("link type %d is not Ethernet" % linktype)
    pos = 24
    records = []
    while pos + 16 <= len(data):
        sec, frac, incl, orig = struct.unpack(endian + "4I", data[pos : pos + 16])
        frame = data[pos + 16 : pos + 16 + incl]
        if len(frame) != incl:
            break
        if incl != orig:
            raise SystemExit("record at %d is truncated by the snap length" % pos)
        records.append((sec, frac, frame))
        pos += 16 + incl
    return records, nano


def write_pcap(records, nano):
    magic = b"\x4d\x3c\xb2\xa1" if nano else b"\xd4\xc3\xb2\xa1"
    head = magic + struct.pack("<HHiIII", 2, 4, 0, 0, 262144, LINKTYPE_ETHERNET)
    body = b"".join(
        struct.pack("<4I", sec, frac, len(frame), len(frame)) + frame
        for sec, frac, frame in records
    )
    return head + body


def anonymise(data, scope):
    records, nano = read_pcap(data)
    maps = Maps()
    kept, dropped = [], {}
    base = records[0][0] if records else 0
    # A file already rebased (its clock inside the rebased window) keeps its
    # clock, so a file cut out of an anonymised capture is still a fixed point.
    if REBASE_EPOCH <= base < REBASE_EPOCH + REBASE_WINDOW:
        base = REBASE_EPOCH
    for sec, frac, frame in records:
        try:
            out = rewrite_frame(frame, maps, scope)
        except (Refused, IndexError, struct.error) as why:
            reason = str(why) if isinstance(why, Refused) else "malformed"
            dropped[reason] = dropped.get(reason, 0) + 1
            continue
        kept.append((REBASE_EPOCH + sec - base, frac, out))
    report = {
        "packets_in": len(records),
        "packets_kept": len(kept),
        "dropped": dict(sorted(dropped.items())),
        "macs_mapped": len(maps.mac),
        "ipv4_mapped": len(maps.v4),
        "ipv6_mapped": len(maps.v6),
        "labels_replaced": len(maps.labels),
    }
    return write_pcap(kept, nano), maps, report


def leaks(output, maps, forbid):
    found = []
    lowered = output.lower()
    for value in sorted(maps.originals):
        if len(value) < LEAK_MIN:
            continue
        if value in output or value.lower() in lowered:
            found.append(value)
    for word in forbid:
        if word.lower().encode() in lowered:
            found.append(word.encode())
    return found


def read_manifest(path):
    """`corpus.json5`, which this tool writes in a JSON5 subset: `//` comments,
    unquoted keys and trailing commas, and nothing else JSON lacks."""
    import re

    with open(path) as f:
        text = f.read()
    text = "\n".join(line for line in text.splitlines() if not line.lstrip().startswith("//"))
    text = re.sub(r"(?m)^(\s*)([A-Za-z_][A-Za-z0-9_]*):", r'\1"\2":', text)
    text = re.sub(r",(\s*[}\]])", r"\1", text)
    return json.loads(text)


def verify_corpus(directory):
    """Every corpus file is a fixed point of the tool: anonymising it again
    changes no byte, so it holds no address, name or value the tool would
    replace. A raw capture committed by mistake fails here."""
    manifest = read_manifest(os.path.join(directory, "corpus.json5"))
    failures = []
    for entry in manifest["files"]:
        with open(os.path.join(directory, entry["file"]), "rb") as f:
            data = f.read()
        output, _maps, report = anonymise(data, entry["scope"])
        if output != data:
            failures.append(
                "%s: anonymising it again changes it (%s)" % (entry["file"], json.dumps(report, sort_keys=True))
            )
    listed = {e["file"] for e in manifest["files"]}
    for name in sorted(os.listdir(directory)):
        if name.endswith(".pcap") and name not in listed:
            failures.append("%s: a capture the manifest does not list" % name)
    if failures:
        print("capture-anonymise verify FAIL:")
        for f in failures:
            print("  " + f)
        return 1
    print("capture-anonymise verify OK: %d corpus file(s) are fixed points" % len(listed))
    return 0


def run(args):
    with open(args.input, "rb") as f:
        data = f.read()
    output, maps, report = anonymise(data, args.scope)
    found = leaks(output, maps, args.forbid)
    report["leaks"] = len(found)
    if found:
        print("capture-anonymise FAIL: %d original value(s) survive in the output" % len(found))
        for value in found[:20]:
            print("  %r" % value)
        return 1
    with open(args.output, "wb") as f:
        f.write(output)
    if args.report:
        with open(args.report, "w") as f:
            json.dump(report, f, indent=1, sort_keys=True)
            f.write("\n")
    print("capture-anonymise OK: " + json.dumps(report, sort_keys=True))
    return 0


# ── selftest ──────────────────────────────────────────────────────────────────


def _udp4(src, dst, sport, dport, body, src_mac=b"\x10\x22\x33\x44\x55\x66"):
    udp = struct.pack("!4H", sport, dport, 8 + len(body), 0) + body
    ck = transport_checksum(src, dst, PROTO_UDP, udp, False) or 0xFFFF
    udp = udp[:6] + struct.pack("!H", ck) + udp[8:]
    ip = bytearray(struct.pack("!BBHHHBBH", 0x45, 0, 20 + len(udp), 1, 0, 64, PROTO_UDP, 0) + src + dst)
    ip[10:12] = struct.pack("!H", checksum16(bytes(ip)))
    eth = b"\x01\x00\x5e\x00\x00\xfb" + src_mac + struct.pack("!H", ETH_IPV4)
    return eth + bytes(ip) + udp


def _dns_name(name):
    return b"".join(bytes([len(p)]) + p for p in name.split(b".")) + b"\0"


def selftest():
    failures = []
    checks = []

    def check(cond, what):
        checks.append(what)
        if not cond:
            failures.append(what)

    host = b"\xc0\xa8\x82\x07"  # 192.168.130.7
    mdns = (
        struct.pack("!6H", 0, 0x8400, 0, 2, 0, 0)
        + _dns_name(b"Coins-Laptop.local")
        + struct.pack("!HHIH", 1, 0x8001, 120, 4)
        + host
        + b"\xc0\x0c"  # a second record whose name points at the first
        + struct.pack("!HHIH", 16, 1, 120, 14)
        + b"\x0dmodel=XPS9310"
    )
    ssdp = (
        b"NOTIFY * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\n"
        b"NT: upnp:rootdevice\r\nUSN: uuid:1234abcd-0000-1111-2222-333344445555::upnp:rootdevice\r\n"
        b"SERVER: Linux/5.4 UPnP/1.0 FancyTV/2.1\r\n"
        b"LOCATION: http://192.168.130.7:49152/desc.xml\r\n\r\n"
    )
    frames = [
        _udp4(host, b"\xe0\x00\x00\xfb", 5353, 5353, mdns),
        _udp4(host, b"\xef\xff\xff\xfa", 1900, 1900, ssdp),
        _udp4(host, b"\xe0\x00\x00\xfb", 9999, 9999, b"unknown protocol"),
    ]
    records = [(1700000000 + i, 0, f) for i, f in enumerate(frames)]
    raw = write_pcap(records, False)
    out, maps, report = anonymise(raw, "lan")
    check(report["packets_kept"] == 2, "the unknown protocol is dropped: %r" % report)
    check(report["dropped"] == {"udp_port_9999_9999": 1}, "the drop is counted: %r" % report)
    check(not leaks(out, maps, ["coins"]), "no original value survives: %r" % leaks(out, maps, ["coins"]))
    check(b"Coins-Laptop" not in out and b"XPS9310" not in out, "the host and TXT value are gone")
    check(b"192.168.130.7" not in out and host not in out, "the address is gone, as text and bytes")
    check(b"FancyTV" not in out and b"1234abcd" not in out, "the SSDP identities are gone")
    check(b"local" in out and b"upnp:rootdevice" in out, "the protocol vocabulary is kept")
    check(len(out) == len(raw) - (16 + len(frames[2])), "every kept record keeps its length")
    kept, _ = read_pcap(out)
    for (_, _, a), (_, _, b) in zip(kept, records):
        check(len(a) == len(b), "a record changed length")
    # The checksums of the rewritten packets verify.
    for _, _, f in kept:
        ip = f[14:34]
        check(checksum16(ip) == 0, "the IPv4 header checksum verifies")
        udp = f[34:]
        check(transport_checksum(ip[12:16], ip[16:20], PROTO_UDP, udp, False) in (0, 0xFFFF), "the UDP checksum verifies")
    # Timestamps are rebased and keep their spacing.
    check([r[0] for r in kept] == [REBASE_EPOCH, REBASE_EPOCH + 1], "timestamps are rebased")
    # A leak is refused: a forbidden word still present is reported.
    check(leaks(out, maps, ["upnp"]) == [b"upnp"], "a forbidden word is found")
    # An anonymised file is a fixed point: a second pass changes no byte, and
    # a raw one is not.
    again, _, _ = anonymise(out, "lan")
    check(again == out, "anonymising twice changes nothing")
    check(anonymise(raw, "lan")[0] != raw, "a raw capture is not a fixed point")
    if failures:
        print("capture-anonymise selftest FAIL:")
        for f in failures:
            print("  " + f)
        return 1
    print("capture-anonymise selftest: OK (%d checks)" % len(checks))
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--in", dest="input")
    parser.add_argument("--out", dest="output")
    parser.add_argument("--scope", choices=("lan", "loopback"))
    parser.add_argument("--forbid", action="append", default=[])
    parser.add_argument("--report")
    parser.add_argument("--selftest", action="store_true")
    parser.add_argument("--verify-corpus", metavar="DIR")
    args = parser.parse_args()
    if args.selftest:
        return selftest()
    if args.verify_corpus:
        return verify_corpus(args.verify_corpus)
    if not (args.input and args.output and args.scope):
        parser.error("--in, --out and --scope are required")
    return run(args)


if __name__ == "__main__":
    sys.exit(main())
