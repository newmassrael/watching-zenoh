#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
"""R4131 (no register item) -- the seed corpus of each fuzz target of
`crates/wz-fuzz`, written into a directory from the files this tree already
holds, so the seeds follow the captures and the examples instead of a second
copy of them.

    fuzz_seeds.py <target> <out-dir>     write the seeds of <target>
    fuzz_seeds.py --targets              print the targets, one a line
    fuzz_seeds.py --packages             print each target and the package it is a binary of
    fuzz_seeds.py --reads <target>       print the target whose corpus <target> also reads
    fuzz_seeds.py --features-of <package>
                                         print the features a package is built with, resolved
                                         (empty for a package whose manifest states them)
    fuzz_seeds.py --resolved-packages    print the packages whose features are resolved
    fuzz_seeds.py --selftest             check every target writes seeds

Each seed is the input layout its target's header comment states:

- `pcap`, `live`, `selector_term`: eight bytes of arguments, then a capture from `captures/`
  (classic pcap or pcapng, at most `MAX_CAPTURE` bytes; files with the same
  bytes count once).
- `transport`: four bytes of arguments, a session context and a ring word
  (each to a NUL), then the UDP or TCP payload of an Ethernet/IPv4 packet of
  those captures.
- `text`, `proto`, `e2e`, `replay`: the examples the crate's own tests use
  (`crates/wz-capi-dissect/tests/c_abi_consumer.c`, `src/lib.rs`), written here
  in the target's layout, and the `.proto` files of
  `crates/wz-capture/testdata/nanopb/`.
- `config`, `sender`: config texts of the line form `zc_config_from_str` reads
  and the sender calls of `crates/wz-capi-c/tests/e2e_sender_roundtrip.rs`,
  written here in the target's layout.
- `ingress_frames`, `codec_roundtrip`, `session_unicast`, `slot_session`,
  `coop_read`, `pico_transport`: a few bytes of arguments, then the units a
  session reads off its link, each behind its two-byte little-endian length:
  each UDP payload of the captures is one, a TCP payload holds them already
  framed so, and a few written here (an empty Frame each way, a KeepAlive)
  stand for a capture that holds none.
- `pico_config`, `pico_e2e`, `pico_instance_key`, `pico_catalog`,
  `pico_payload`: the pico C ABI's own doors, with the documents, profiles,
  schemas and catalogs the crate's own tests use (`crates/wz-capi-pico/tests`,
  `crates/wz-app-frame/catalog/synthetic.json5`, the `.proto` files of
  `crates/wz-capture/testdata/nanopb/`), written here in the target's layout:
  arguments, texts each to a NUL, then operations each behind its two-byte
  little-endian length.

The output is a pure function of the tree: names are the SHA-256 of the
bytes, so writing twice changes nothing.
"""

from __future__ import annotations

import base64
import hashlib
import pathlib
import re
import struct
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
CAPTURES = ROOT / "captures"
PROTOS = ROOT / "crates" / "wz-capture" / "testdata" / "nanopb"
# A capture larger than this is left out: libFuzzer runs every seed on every
# pass, and a few of the corpus files are megabytes of the same flows.
MAX_CAPTURE = 64 * 1024
# How many packet payloads the `transport` target is seeded with.
MAX_PAYLOADS = 256

# The targets that read what a peer sends into a session (`crates/wz-fuzz`'s
# README): the bytes as units of a link, and the session's own decoders,
# walks and engines behind them.
INGRESS = ("ingress_frames", "codec_roundtrip", "session_unicast", "slot_session", "coop_read")

# The targets of the pico C ABI's own doors (`wz_ext_*`), built as the release
# package builds the library (`crates/wz-fuzz/pico-ext`). `pico_transport`
# reads its input as an ingress target does.
PICO_EXT = ("pico_transport", "pico_config", "pico_e2e", "pico_instance_key", "pico_catalog", "pico_payload")

TARGETS = ("pcap", "live", "transport", "text", "proto", "e2e", "replay", "config", "sender", "selector_term",
           *INGRESS, *PICO_EXT)

# The package of the fuzz workspace each target is a binary of, where it is
# not `wz-fuzz` itself. Cargo unifies the features of the packages one
# invocation builds, and these targets each build the session shell on a
# profile of its own (the heap profile, the per-session slot profile, the C
# ABI's engine), which must meet neither another's nor the dissector's;
# `fuzz.sh build` builds each package by itself.
PACKAGES = {
    "session_unicast": "wz-fuzz-session-heap",
    "slot_session": "wz-fuzz-session-slot",
    "coop_read": "wz-fuzz-coop-engine",
    **{target: "wz-fuzz-pico-ext" for target in PICO_EXT},
}
DEFAULT_PACKAGE = "wz-fuzz"

# The packages whose features are not written in their manifest but resolved
# when they are built, and the manifest whose `[features]` forwards each name
# to the library unchanged. The pico C ABI's own doors are fuzzed in the build
# the release package makes, `configs/profiles/host-peer-ext.conf` resolved by
# the resolver the verification lanes use (`verify_plan.Resolver.profile`), so
# the targets follow the profile with no second copy of its list to drift.
RESOLVED_PACKAGES = {"wz-fuzz-pico-ext": "crates/wz-fuzz/pico-ext/Cargo.toml"}
# The library whose features the resolved packages forward.
FORWARDED_TO = "wz-capi-pico"

# How many units, and how many bytes of them, one ingress seed holds at most:
# a session target steps its session a few times for each unit.
MAX_UNITS = 64
MAX_STREAM = 16 * 1024

# The argument bytes in front of an ingress seed, taken in turn (each target's
# header comment states them).
INGRESS_HEADS = {
    "ingress_frames": (bytes([0, 0]), bytes([0x07, 0x10]), bytes([0x0D, 0])),
    "codec_roundtrip": (bytes([0]),),
    "session_unicast": (bytes([0]), bytes([5])),
    "slot_session": (bytes([0]), bytes([5])),
    "coop_read": (bytes([0]), bytes([5])),
    # A stream handed in a unit at a time, a datagram link, a stream handed in
    # seven bytes at a time.
    "pico_transport": (bytes([0]), bytes([1]), bytes([7 << 1])),
}

# Units no capture is needed for: an empty reliable Frame, an empty
# best-effort Frame (each at sequence number 1), and a KeepAlive.
SYNTHETIC_UNITS = (bytes([0x25, 0x01]), bytes([0x05, 0x01]), bytes([0x04]))

# A target whose input layout is another's, and which also reads the corpus
# that target's fuzzing grows: `selector_term` holds the sentences of the field
# document to their soundness property over every capture the `pcap` target has
# reached, beside the ones it reaches itself. `fuzz.sh run` adds that corpus as
# an input directory it reads and does not write.
READS_CORPUS_OF = {"selector_term": "pcap"}

# Inputs that once made a target fail and are made of a tracked capture: the
# arguments and the capture's path under `captures/`, so the reproducer is
# committed as these lines and not as a copy of the file. Each is a seed on
# every replay whatever the rotation above gives that capture. A reproducer
# that is not made of a tracked file goes to `crates/wz-fuzz/regressions/`.
PINNED: dict[str, tuple[tuple[bytes, str], ...]] = {
    # `wz_dissect_live_follow_lent` lent a container it then refused as shrunk,
    # and the next read of a flow panicked (`Dissection::follow_lent`).
    # The drain's two byte doors found a record's row by decoding every row
    # before it, each by reading its whole unit again, and a pushed capture of
    # NTP datagrams that read as many messages each took past ten seconds
    # (`LiveDissection::resolve` finds the row on its head now).
    "live": (
        (bytes([1, 3, 0, 128, 1, 1, 0, 0x44]), "corpus/zenoh-v1-10-0-tcp-full.pcap"),
        (bytes([0, 4, 0, 128, 1, 1, 0, 0x44]), "corpus/busylan-ntp.pcap"),
    ),
}

# Inputs that once made a target fail and are small enough to read: the bytes
# libFuzzer wrote, as the base64 it printed beside them. Text here rather than a
# binary file under `crates/wz-fuzz/regressions/`, so the commit that fixes the
# defect shows the input it fixes it for.
LITERAL: dict[str, tuple[str, ...]] = {
    # `wz_replay_mutate` built an EXTEND by the caller's count on the heap before
    # comparing it with the caller's buffer: an allocation larger than any memory
    # ended the process (`Mutation::changes` and `apply_into` into `out` now).
    "replay": (
        "AwMAAAAEAw==",
        "AwMA/f////kABwAAAAAAAABACgAAAAABAAAAAABhZCBieXRlcw==",
        "AwAAACgDAAAABwAAAAAAAABAAAMA0dHR0dHR0dHR0dHR0dHR0dHR0dHR0dHR0dHR0dHRAAAAAAAABwAAAAAAAAC1AAEKAAEAAAAAAA==",
    ),
    # The dissection walker showed a timestamp zid of twenty bytes that the
    # codec refuses, printed as its first sixteen, so the term written from the
    # print was `Unknown` over its own record (S1). Cut from the crash to the one
    # datagram it needed: a `Frame` whose `Push` carries a `Del` with that
    # timestamp (`SpanCursor::zid` now refuses a zid past sixteen bytes).
    # `keyexpr_relate` of two patterns with many `**` on both sides took over
    # ten seconds: the intersection and inclusion tried each `**` both ways and
    # asked the same pair of suffixes again on every path. Cut from the night's
    # timeout to its shape, door 3 with `(**/x/)x24 y` against `(**/x/)x24 z`
    # (the two relations remember the suffix pairs they refuted now).
    "text": (
        "AwAqKi94LyoqL3gvKioveC8qKi94LyoqL3gvKioveC8qKi94LyoqL3gvKioveC8qKi94LyoqL3gvKioveC8qKi94LyoqL3gvKioveC8qKi94LyoqL3gvKioveC8qKi94LyoqL3gvKioveC8qKi94LyoqL3gvKioveC95ACoqL3gvKioveC8qKi94LyoqL3gvKioveC8qKi94LyoqL3gvKioveC8qKi94LyoqL3gvKioveC8qKi94LyoqL3gvKioveC8qKi94LyoqL3gvKioveC8qKi94LyoqL3gvKioveC8qKi94LyoqL3gvKioveC8qKi94L3o=",
    ),
    "selector_term": (
        "AQQBAAABAQDUw7KhAgAEAAAAAAAAAAAA//8AAAEAAAAAAAAAAAAAAEgAAABIAAAAAAAAAAAAAgAAAAABCABFAAA6AAAAAEARZrEKAAABCgAAAqjKHRcAJgAAJb3B8T9dASJBFFsgIDQ5XSBjb3JwdXMgc2FtcGxl",
    ),
}

CONTEXT = b'{"negotiated":true,"lowlatency":false}'

E2E_PROFILE = b"""{
  "name": "abi-demo",
  "fields": [
    {"name": "kind", "bytes": 1},
    {"name": "crc", "bytes": 2},
    {"name": "counter", "bytes": 1},
    {"name": "length", "bytes": 2},
    {"name": "ident", "bytes": 2, "xor": "0x00FF",
     "split": [{"name": "hi", "lsb": 8, "width": 8}, {"name": "lo", "lsb": 0, "width": 8}]}
  ],
  "crc": {"field": "crc", "width": 16, "poly": "0x1021", "init": "0xFFFF",
          "refin": false, "refout": false, "xorout": 0,
          "cover": ["kind", "ident", "@payload", "counter", "length"]},
  "length": {"field": "length", "counts": "frame"},
  "counter": {"field": "counter", "max_gap": 4, "timeout_ms": 100}
}"""
E2E_VALUES = b'{"kind": 3, "counter": 7, "ident": {"hi": 1, "lo": 2}}'
E2E_BODY = (
    b'{"kind": 3, "counter": 7, "ident": {"hi": 1, "lo": 2}, "@body": {"files": [{"name": "pose.proto", '
    b'"text": "syntax = \\"proto3\\";\\npackage demo;\\nmessage Pose { sint32 x = 1; string label = 2; }"}], '
    b'"message": "demo.Pose", "values": {"x": -3, "label": "hi"}}}'
)

# (config texts, node names, external endpoints) of the `config` target. The
# texts are the line form `zc_config_from_str` reads: `key:value`, json5 values.
CONFIGS = (
    ((), (), b""),
    ((b"mode:\"router\"\nlisten/endpoints:[\"tcp/127.0.0.1:7447\"]",), (b"",), b""),
    ((b"mode:\"peer\"\nconnect/endpoints:[\"tcp/127.0.0.1:7447\"]",), (b"edge",), b"tcp/10.0.0.9:7447\0"),
    (
        (
            b"mode:\"router\"\nlisten/endpoints:[\"tcp/127.0.0.1:7447\"]",
            b"mode:\"router\"\nlisten/endpoints:[\"tcp/127.0.0.1:7447\"]",
            b"mode:\"client\"\nconnect/endpoints:[\"tcp/127.0.0.1:7447\"]",
        ),
        (b"a", b"b", b""),
        b"",
    ),
    ((b"mode:\"peer\"\nscouting/multicast/enabled:false",), (b"",), b""),
    ((b"mode:\"nonsense\"",), (b"",), b""),
    ((b"not a config line",), (b"x",), b""),
    ((b"listen/endpoints:[\"quic/127.0.0.1:7447\", \"udp/127.0.0.1:7447\"]\nmode:\"router\"",), (b"",), b""),
)

# (choices, first counter, values, payload) of the `sender` target: the
# rollover that wraps and the one that refuses, a refusal asked for, a refused
# frame, and a payload given both ways.
SENDERS = (
    (4, 7, E2E_VALUES, b"hi"),
    (5, 255, E2E_VALUES, b"hi"),
    (4, 0, b'{"kind": 3, "ident": {"hi": 1, "lo": 2}}', b""),
    (4, 0, b'{"nope": 1}', b"x"),
    (12, 3, E2E_VALUES, b"hi"),
    (6, 1, E2E_VALUES, b"hi"),
)

PROTO_ROOT = (
    b'syntax = "proto3";\npackage m;\nimport "common/stamp.proto";\n'
    b"message Root {\n  int32 id = 1;\n  common.Stamp at = 2;\n  map<string, int32> counts = 3;\n}\n"
)
PROTO_STAMP = b'syntax = "proto3";\npackage common;\nmessage Stamp { int64 secs = 1; }\n'

# (door, framing, first text, second text) of the `text` target.
TEXTS = (
    (0, 0, b"kind == put", b""),
    (0, 0, b"key == demo/**", b""),
    (0, 0, b"key === x", b""),
    (1, 0, b"kind == put", b""),
    (1, 0, b"kind == put", b'["kind"]'),
    (2, 0, b"demo/**", b""),
    (2, 0, b"demo/$*/a", b""),
    (3, 0, b"demo/**", b"demo/a"),
    (3, 0, b"demo/*", b"other/x"),
    (4, 0, b"demo/**=protobuf\ndemo/a=json", b""),
    (4, 0, b"not a declaration", b""),
    (5, 0, b"demo/**=protobuf\ndemo/a=json", b"demo/a"),
    (5, 0, b"demo/a=json", b"other/x"),
    (6, 1, b'{"message":"frame","reliable":true,"sn":5,"priority":3,"payload":"dead"}', b""),
    (6, 1, b'{"message":"init_syn","version":5,"whatami":"peer","zid":"b0b1b2b3"}', b""),
    (6, 1, b'{"message":"close","reason":2,"session":true}', b""),
    (6, 0, b'{"message":"open_syn","lease_ms":10000,"initial_sn":7,"cookie":"01","sn_resolution":"32bit"}', b""),
    (6, 2, b'{"message":"scout"}', b""),
)


def captures() -> list[bytes]:
    """The captures of `captures/`, smallest first, each once."""
    seen: dict[str, bytes] = {}
    for path in sorted(CAPTURES.rglob("*")):
        if path.suffix not in (".pcap", ".pcapng") or not path.is_file():
            continue
        data = path.read_bytes()
        if len(data) <= MAX_CAPTURE:
            seen.setdefault(hashlib.sha256(data).hexdigest(), data)
    return sorted(seen.values(), key=len)


def classic_packets(data: bytes) -> list[tuple[int, bytes]]:
    """The (link type, bytes) of each record of a classic pcap; [] for any
    other container."""
    if len(data) < 24:
        return []
    magic = data[:4]
    if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
        order = "<"
    elif magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
        order = ">"
    else:
        return []
    link = struct.unpack(order + "I", data[20:24])[0] & 0x0FFFFFFF
    out, at = [], 24
    while at + 16 <= len(data):
        incl = struct.unpack(order + "I", data[at + 8 : at + 12])[0]
        out.append((link, data[at + 16 : at + 16 + incl]))
        at += 16 + incl
    return out


def transport_payload(link: int, frame: bytes) -> bytes | None:
    """The UDP or TCP payload of an Ethernet/IPv4 frame, if it is one."""
    carried = ip_payload(link, frame)
    return None if carried is None else carried[1]


def ip_payload(link: int, frame: bytes) -> tuple[int, bytes] | None:
    """The IP protocol and the UDP or TCP payload of an Ethernet/IPv4 frame,
    if it is one."""
    if link != 1 or len(frame) < 14 or frame[12:14] != b"\x08\x00":
        return None
    ip = frame[14:]
    if len(ip) < 20 or ip[0] >> 4 != 4:
        return None
    ihl = (ip[0] & 0x0F) * 4
    proto, body = ip[9], ip[ihl:]
    if proto == 17 and len(body) > 8:
        return proto, body[8:]
    if proto == 6 and len(body) >= 20:
        payload = body[(body[12] >> 4) * 4 :]
        return (proto, payload) if payload else None
    return None


def link_units(proto: int, payload: bytes) -> list[bytes]:
    """The units a session reads off one datagram or segment: a UDP datagram
    is one; a TCP segment holds units each behind its two-byte little-endian
    length, of which the whole ones are kept."""
    if proto == 17:
        return [payload]
    units, at = [], 0
    while at + 2 <= len(payload):
        size = int.from_bytes(payload[at : at + 2], "little")
        if size == 0 or at + 2 + size > len(payload):
            break
        units.append(payload[at + 2 : at + 2 + size])
        at += 2 + size
    return units


def unit_stream(units: list[bytes]) -> bytes:
    """`units` in the layout the ingress targets read: each behind its
    two-byte little-endian length."""
    return b"".join(len(unit).to_bytes(2, "little") + unit for unit in units if len(unit) <= 0xFFFF)


def ingress_streams() -> list[bytes]:
    """The units of each capture that holds any, in the order its packets
    came, at most `MAX_UNITS` and `MAX_STREAM` bytes of them, each stream
    once; and the stream of `SYNTHETIC_UNITS`."""
    seen: dict[bytes, None] = {unit_stream(list(SYNTHETIC_UNITS)): None}
    for c in captures():
        units: list[bytes] = []
        for link, frame in classic_packets(c):
            carried = ip_payload(link, frame)
            if carried is not None:
                units.extend(link_units(*carried))
        stream = unit_stream(units[:MAX_UNITS])[:MAX_STREAM]
        if stream:
            seen.setdefault(stream, None)
    return list(seen)


def seeds(target: str) -> list[bytes]:
    pinned = [head + (CAPTURES / path).read_bytes() for head, path in PINNED.get(target, ())]
    literal = [base64.b64decode(text, validate=True) for text in LITERAL.get(target, ())]
    return pinned + literal + derived(target)


def derived(target: str) -> list[bytes]:
    # Each capture once, with the arguments taken in turn: every set of
    # arguments meets many captures and every capture is read, at the cost of
    # one pass over the captures. Every set crossed with every capture made the
    # replay six times longer for coverage the fuzzer reaches in its first
    # minutes anyway.
    # `selector_term` takes the `pcap` layout and reads only its byte 0 (the
    # limits preset), so the same inputs are its seeds.
    if target in ("pcap", "selector_term"):
        heads = (bytes(8), bytes([1, 4, 1, 0, 0, 1, 1, 0]), bytes([0, 255, 3, 0, 1, 2, 2, 0]))
        return [heads[n % len(heads)] + c for n, c in enumerate(captures())]
    if target == "live":
        # The six ways of opening a handle (`Feed`), in turn.
        return [bytes([n % 2, n % 6, 0, 128, 1, 1, 0, 0x44]) + c for n, c in enumerate(captures())]
    if target in INGRESS or target == "pico_transport":
        heads = INGRESS_HEADS[target]
        return [heads[n % len(heads)] + stream for n, stream in enumerate(ingress_streams())]
    if target == "transport":
        payloads: dict[bytes, None] = {}
        for c in captures():
            for link, frame in classic_packets(c):
                payload = transport_payload(link, frame)
                if payload is not None:
                    payloads.setdefault(payload, None)
        out = []
        for payload in list(payloads)[:MAX_PAYLOADS]:
            out.append(bytes([0, 2, 0, 0]) + CONTEXT + b"\0" + b"32bit\0" + payload)
            out.append(bytes([1, 4, 0, 0]) + CONTEXT + b"\0" + b"\0" + payload)
        return out
    if target == "text":
        return [bytes([door, framing]) + a + b"\0" + b for door, framing, a, b in TEXTS]
    if target == "proto":
        two = b"m/root.proto\0" + PROTO_ROOT + b"\0common/stamp.proto\0" + PROTO_STAMP
        out = [
            b"\0m.Root\0" + b'{"id":150,"at":{"secs":"7"},"counts":{"a":1}}' + b"\0demo/temp\0" + two,
            b"\0m.Root\0" + b'{"id":"x"}' + b"\0demo/**\0" + two,
        ]
        for path in sorted(PROTOS.glob("*.proto")):
            out.append(b"\0Leaf\0{}\0demo/**\0" + path.name.encode() + b"\0" + path.read_bytes())
        return out
    if target == "e2e":
        return [
            E2E_PROFILE + b"\0" + E2E_VALUES + b"\0" + b"hi",
            E2E_PROFILE + b"\0" + E2E_BODY + b"\0",
            E2E_PROFILE + b"\0" + E2E_VALUES + b"\0" + b"\x01\x02",
            b"{}\0{}\0",
        ]
    if target == "replay":
        out = []
        for mutation in range(5):
            args = struct.pack("<bQQH", mutation, 3, 7, 64)
            plan = struct.pack("<bQdQQB", 1, 10, 1.0, 1000, 60000, 8) + bytes([3]) + struct.pack("<3Q", 0, 5, 12)
            out.append(args + plan + b"payload bytes")
        return out
    if target == "config":
        return [bytes([len(texts)]) + b"".join(t + b"\0" for t in texts) + b"".join(n + b"\0" for n in names) + external
                for texts, names, external in CONFIGS]
    if target == "sender":
        # The choices byte, the first counter, the profile, the values, the payload.
        return [bytes([choices]) + struct.pack("<Q", first) + E2E_PROFILE + b"\0" + values + b"\0" + payload
                for choices, first, values, payload in SENDERS]
    if target in PICO_EXT:
        return pico_ext_seeds(target)
    raise SystemExit(f"fuzz_seeds: no target `{target}`; the targets are {', '.join(TARGETS)}")

# ─── the pico C ABI's own doors ─────────────────────────────────────────────

# The catalog the reader's tests use, which the `pico_catalog` seeds are made
# of and `pico_payload` makes its payloads for.
SYNTHETIC_CATALOG = ROOT / "crates" / "wz-app-frame" / "catalog" / "synthetic.json5"

# A profile whose identifier is judged and whose message cell names a sender
# derived from the node's address, as the crate's door tests make one, and its
# header values. Synthetic.
E2E_JUDGED_PROFILE = b"""{
  "name": "door-demo",
  "fields": [
    {"name": "length", "bytes": 2},
    {"name": "ident", "bytes": 3, "xor": "0x3C3C3C",
     "split": [{"name": "app", "lsb": 12, "width": 12}, {"name": "msg", "lsb": 0, "width": 12}]},
    {"name": "crc", "bytes": 2},
    {"name": "cell", "bytes": 4,
     "split": [{"name": "kind", "lsb": 28, "width": 4},
               {"name": "sender", "lsb": 0, "width": 28,
                "derive": {"from": "address", "mask": "0x0F00FF00", "xor": "0x77"}}]},
    {"name": "counter", "bytes": 2}
  ],
  "crc": {"field": "crc", "width": 16, "poly": "0x1021", "init": "0xFFFF",
          "refin": false, "refout": false, "xorout": "0x0000",
          "cover": ["length", "ident", "cell", "@payload", "counter"]},
  "length": {"field": "length", "counts": "frame"},
  "counter": {"field": "counter", "max_gap": 2, "timeout_ms": 50},
  "judge": {"ident": "ident", "length": true},
  "cell": {"field": "cell", "kind": "kind", "sender": "sender"}
}"""
E2E_JUDGED_VALUES = b'{"ident": {"app": 801, "msg": 99}, "cell": {"kind": 5}, "@address": 4660}'

# The schema and the description of the instance keys' door tests: three bays
# and two tilts, six instances. Synthetic.
KEYED_SCHEMA = (
    b'syntax = "proto3";\npackage syn.door;\n'
    b"message Reading {\n  optional uint32 bay = 1;\n  sint32 tilt = 2;\n  bytes body = 3;\n}\n"
)
KEYED_DESCRIPTION = (
    b'{"message": "syn.door.Reading", "fields": [{"path": "bay", "values": [12, 30, 44]}, '
    b'{"path": "tilt", "values": [-3, 5]}], "report_interval_ms": 1000}'
)

# The schema of the message payloads' door tests. Synthetic.
PAYLOAD_SCHEMA = (
    b'syntax = "proto3";\npackage syn.door;\n'
    b"enum Tone {\n  TONE_NONE = 0;\n  TONE_WARM = 1;\n  TONE_COLD = 2;\n}\n"
    b"message Point {\n  sint32 x = 1;\n  sint32 y = 2;\n}\n"
    b"message Pose {\n  uint32 serial = 1;\n  int32 offset = 2;\n  double weight = 3;\n  bool lit = 4;\n"
    b"  string label = 5;\n  bytes blob = 6;\n  Tone tone = 7;\n  Point origin = 8;\n"
    b"  repeated Point path = 9;\n  optional uint64 stamp = 10;\n}\n"
)

# The operations of the `pico_config` seeds: zenoh documents, policies,
# profiles, key ids, key-wire forms, a runtime's limits, locators, and the
# question of what an open would ask of the system (the target's header comment
# states each op).
CONFIG_OPS = (
    b"\0" + b'{ wz: { "key-ids": { dictionary: [ { id: 40, key: "lab/rig" } ] } } }',
    b"\0" + b'{ mode: "peer", wz: { profile: "upstream" } }',
    b"\0" + b"{ wz: { limits: { MAX_SUBSCRIPTIONS: 1 } } }",
    b"\0" + b"{ wz: { limits: { NO_SUCH_LIMIT: 1 } } }",
    b"\0" + b"{ wz: {}, wz: {} }",
    b"\0" + b"not a document",
    b"\x01" + b"key-set\0closed\0",
    b"\x01" + b"sn-resolution\0bits-16\0",
    b"\x01" + b"no-such-policy\0on\0",
    b"\x02" + b"upstream\0",
    b"\x02" + b"no-such-profile\0",
    b"\x03\x02" + struct.pack("<H", 40) + b"lab/rig\0" + struct.pack("<H", 41) + b"lab/rig/alpha\0",
    b"\x03\x01" + struct.pack("<H", 0) + b"lab/a\0",
    b"\x03\x00",
    b"\x04" + b"tcp/192.0.2.7:7447\0declared\0",
    b"\x04" + b"\0shared\0",
    b"\x05" + b"{ wz: { limits: { MESSAGE_CATALOG_ENTRIES: 4 } } }",
    b"\x05" + b'{ wz: { profile: "upstream" } }',
    bytes([6 + 8]) + b"tcp/192.0.2.7:7447\0",
    bytes([6 + 16]) + b"udp/192.0.2.8:7447\0",
    bytes([6]) + b"peer\0",
    b"\x07",
)


def varint(value: int) -> bytes:
    """`value` as a protobuf varint."""
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value == 0:
            out.append(byte)
            return bytes(out)
        out.append(byte | 0x80)


def keyed_reading(bay: int, tilt: int, body: bytes) -> bytes:
    """A `syn.door.Reading` of `bay` and `tilt` (zigzag, as `sint32` is) with `body`."""
    zigzag = ((tilt << 1) ^ (tilt >> 31)) & 0xFFFFFFFF
    return (varint(1 << 3) + varint(bay) + varint(2 << 3) + varint(zigzag)
            + varint((3 << 3) | 2) + varint(len(body)) + body)


def proto_messages(text: bytes) -> list[bytes]:
    """The full names of the top-level messages a `.proto` text declares."""
    package = re.search(rb"^\s*package\s+([\w.]+)\s*;", text, re.M)
    prefix = package.group(1) + b"." if package else b""
    return [prefix + name for name in re.findall(rb"^message\s+(\w+)", text, re.M)]


def pico_ext_seeds(target: str) -> list[bytes]:
    if target == "pico_config":
        return [unit_stream(list(CONFIG_OPS)), unit_stream(list(CONFIG_OPS[6:])),
                unit_stream([CONFIG_OPS[0], CONFIG_OPS[-1]]), unit_stream([CONFIG_OPS[-1]])]
    if target == "pico_e2e":
        def e2e(choices: int, first: int, gap: int, profile: bytes, values: bytes, ops: list[bytes]) -> bytes:
            return (bytes([choices]) + struct.pack("<Q", first) + bytes([gap]) + profile + b"\0" + values
                    + b"\0" + unit_stream(ops))
        # Choices: bits 3 to 5 the streams, bit 2 the expected values, bit 1
        # the CRC cache, bit 0 wrapping, bits 6 and 7 the judge's keying.
        one, two, expected = 1 << 3, 2 << 3, 4
        return [
            e2e(one | expected, 0, 0, E2E_PROFILE, E2E_VALUES,
                [b"\x01hi", b"\x01hi", b"\x00\x03\x12\x34\x07\x00\x08\x01\x02hi", b"\x02" + struct.pack("<Q", 5),
                 b"\x01x"]),
            e2e(two | expected | 3, 254, 2, E2E_PROFILE, E2E_VALUES, [b"\x01a", b"\x04b", b"\x01a", b"\x01a"]),
            e2e(one | expected, 0, 0, E2E_JUDGED_PROFILE, E2E_JUDGED_VALUES, [b"\x01hello", b"\x00abc"]),
            e2e(two | expected | (1 << 6), 0, 0, E2E_JUDGED_PROFILE, E2E_JUDGED_VALUES,
                [b"\x01hello", b"\x00" + bytes(16)]),
            e2e(two | expected | (2 << 6), 7, 0, E2E_JUDGED_PROFILE, E2E_JUDGED_VALUES, [b"\x01hello"]),
            e2e(one, 0, 0, b"{}", b"{}", [b"\x00x"]),
        ]
    if target == "pico_instance_key":
        def keyed(choices: int, ops: list[bytes]) -> bytes:
            return (bytes([choices]) + b"door.proto\0" + KEYED_SCHEMA + b"\0" + KEYED_DESCRIPTION + b"\0"
                    + unit_stream(ops))
        ops = [b"\x00" + keyed_reading(12, -3, b"\0\0"), b"\x00" + keyed_reading(30, 5, b"x"), b"\x00\xff\xff",
               b"\x01", b"\x03" + bytes([16]), b"\x07" + bytes([2]), b"\x02set", b"\x03" + bytes([16]),
               b"\x00" + keyed_reading(99, -3, b""), b"\x05", b"\x00" + keyed_reading(44, 5, bytes(40))]
        # Bit 0 keeps last values; bits 1 to 3 choose the room: 16 bytes, then 1.
        return [keyed(1 | (4 << 1), ops), keyed(0, ops), keyed(1, ops)]
    if target == "pico_catalog":
        text = SYNTHETIC_CATALOG.read_bytes()
        names = b"demo/catalog/pose\0south\0nobody\0"
        return [text + b"\0" + names, text.replace(b"id: 402", b"id: 401") + b"\0" + names,
                text.replace(b"replay_depth: 6", b"replay_depth: 100000") + b"\0", b"{}\0", b"not a catalog\0"]
    if target == "pico_payload":
        def payload(choices: int, message: bytes, name: bytes, text: bytes, ops: list[bytes]) -> bytes:
            return bytes([choices]) + message + b"\0" + name + b"\0" + text + b"\0" + unit_stream(ops)
        pose = b"\x08\x01" + b"\x2a\x02hi" + b"\x4a\x02\x08\x02" + b"\x50\x07"
        ops = [b"\x00" + pose, b"\x01offset\0" + struct.pack("<q", -5), b"\x02serial\0" + struct.pack("<Q", 7),
               b"\x03weight\0" + struct.pack("<d", 1.5), b"\x04lit\0\x01", b"\x05label\0hello\0",
               b"\x05tone\0TONE_WARM\0", b"\x06blob\0\x01\x02", b"\x07label\0", b"\x07path[0].x\0", b"\x07path\0",
               b"\x0fstamp\0", b"\x09offset\0" + struct.pack("<q", 3), b"\x10" + pose, b"\x00\xff"]
        out = [payload(choices, b"syn.door.Pose", b"syn/door.proto", PAYLOAD_SCHEMA, ops) for choices in (0, 1, 4, 2)]
        for path in sorted(PROTOS.glob("*.proto")):
            text = path.read_bytes()
            for message in proto_messages(text)[:1]:
                out.append(payload(0, message, path.name.encode(), text, [b"\x00\x08\x01", b"\x07a\0"]))
        return out
    raise SystemExit(f"fuzz_seeds: no seeds of `{target}`")


class FeatureError(Exception):
    """A package's features that cannot be resolved, said in a sentence."""


def forwarded(manifest: str) -> dict[str, list[str]]:
    """The `[features]` table of a manifest's text: each feature and the names it lists, each row on
    one line, as the resolved packages write theirs."""
    out: dict[str, list[str]] = {}
    inside = False
    for line in manifest.splitlines():
        stripped = line.strip()
        if stripped.startswith("["):
            inside = stripped == "[features]"
            continue
        if not inside or not stripped or stripped.startswith("#"):
            continue
        name, sep, value = stripped.partition("=")
        value = value.strip()
        if not sep or not value.startswith("[") or not value.endswith("]"):
            raise FeatureError(f"a [features] row that is not `name = [...]` on one line: {line}")
        out[name.strip()] = re.findall(r'"([^"]*)"', value)
    return out


def forwarding_findings(table: dict[str, list[str]]) -> list[str]:
    """The rows of a resolved package's `[features]` that do not forward their own name."""
    if not table:
        return ["the manifest forwards no feature"]
    return [f"`{name}` names {names}, not [\"{FORWARDED_TO}/{name}\"]" for name, names in table.items()
            if names != [f"{FORWARDED_TO}/{name}"]]


def features_of(package: str) -> str:
    """The features `package` is built with, comma separated: the release profile's, for a package of
    `RESOLVED_PACKAGES`, and none for a package whose manifest states its own."""
    manifest = RESOLVED_PACKAGES.get(package)
    if manifest is None:
        return ""
    table = forwarded((ROOT / manifest).read_text(encoding="utf-8"))
    findings = forwarding_findings(table)
    if findings:
        raise FeatureError(f"{manifest}: " + "; ".join(findings))
    sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
    from verify_plan import Refused, Resolver  # noqa: E402  (a sibling: the one resolver of the profile)

    try:
        wanted = Resolver().profile()[2].split(",")
    except Refused as error:
        raise FeatureError(str(error)) from None
    missing = [feature for feature in wanted if feature not in table]
    if missing:
        raise FeatureError(f"the release profile names {', '.join(missing)}, which {manifest} does not forward: "
                           f"add a row `<name> = [\"{FORWARDED_TO}/<name>\"]` for each")
    return ",".join(wanted)


def resolved_findings() -> list[str]:
    """What is wrong with the resolved packages' manifests, read without resolving the profile: each
    forwards every feature under its own name, and builds every target `PACKAGES` gives it."""
    findings: list[str] = []
    for package, manifest in RESOLVED_PACKAGES.items():
        path = ROOT / manifest
        if not path.is_file():
            findings.append(f"{package}: {manifest} does not exist")
            continue
        text = path.read_text(encoding="utf-8")
        try:
            findings += [f"{manifest}: {f}" for f in forwarding_findings(forwarded(text))]
        except FeatureError as error:
            findings.append(f"{manifest}: {error}")
        bins = set(re.findall(r'^name = "([^"]+)"', text, re.M))
        for target, owner in PACKAGES.items():
            if owner == package and target not in bins:
                findings.append(f"{manifest}: builds no target `{target}`")
    return findings


def write(target: str, out_dir: pathlib.Path) -> int:
    out_dir.mkdir(parents=True, exist_ok=True)
    written = 0
    for seed in seeds(target):
        path = out_dir / hashlib.sha256(seed).hexdigest()
        if not path.exists():
            path.write_bytes(seed)
            written += 1
    return written


def selftest() -> int:
    for target in [*PACKAGES, *INGRESS_HEADS]:
        if target not in TARGETS:
            print(f"fuzz_seeds: FAIL -- `{target}` is named in PACKAGES or INGRESS_HEADS "
                  "and is no target", file=sys.stderr)
            return 1
    for reader, read in READS_CORPUS_OF.items():
        if reader not in TARGETS or read not in TARGETS or reader == read:
            print(f"fuzz_seeds: FAIL -- `{reader}` reads the corpus of `{read}`, "
                  "and both must be distinct targets", file=sys.stderr)
            return 1
        # Reading another target's corpus is only sound when every input of it
        # is an input of this one: the two derive the same seeds (the pinned
        # reproducers are each target's own).
        if derived(reader) != derived(read):
            print(f"fuzz_seeds: FAIL -- `{reader}` reads the corpus of `{read}` and "
                  "its seeds are not that target's: their layouts have parted", file=sys.stderr)
            return 1
    for target in TARGETS:
        count = len(seeds(target))
        if count == 0:
            print(f"fuzz_seeds: FAIL -- target `{target}` has no seed", file=sys.stderr)
            return 1
        print(f"fuzz_seeds: {target}: {count} seed(s)")
    # The packages built with a resolved feature list forward each feature
    # under its own name and build their targets; read without the resolver.
    findings = resolved_findings()
    for finding in findings:
        print(f"fuzz_seeds: FAIL -- {finding}", file=sys.stderr)
    if findings:
        return 1
    for text, needle in (("[features]\nx = [\n  \"y\",\n]\n", "one line"),):
        try:
            forwarded(text)
        except FeatureError as error:
            assert needle in str(error), str(error)
        else:
            print("fuzz_seeds: FAIL -- a [features] row on several lines was read", file=sys.stderr)
            return 1
    table = forwarded("[package]\nname = \"p\"\n[features]\n# a note\na = [\"wz-capi-pico/a\"]\n"
                      "b = [\"wz-capi-pico/c\"]\n[dependencies]\nd = \"1\"\n")
    if table != {"a": ["wz-capi-pico/a"], "b": ["wz-capi-pico/c"]} or len(forwarding_findings(table)) != 1:
        print(f"fuzz_seeds: FAIL -- the [features] reader read {table}", file=sys.stderr)
        return 1
    print("fuzz_seeds: selftest OK")
    return 0


def main(argv: list[str]) -> int:
    if argv == ["--targets"]:
        print("\n".join(TARGETS))
        return 0
    if argv == ["--packages"]:
        print("\n".join(f"{target} {PACKAGES.get(target, DEFAULT_PACKAGE)}" for target in TARGETS))
        return 0
    if argv == ["--selftest"]:
        return selftest()
    if argv == ["--resolved-packages"]:
        print("\n".join(RESOLVED_PACKAGES))
        return 0
    if len(argv) == 2 and argv[0] == "--features-of":
        try:
            print(features_of(argv[1]))
        except (FeatureError, OSError) as error:
            print(f"fuzz_seeds: the features of {argv[1]} did not resolve: {error}", file=sys.stderr)
            return 1
        return 0
    if len(argv) == 2 and argv[0] == "--reads":
        if argv[1] not in TARGETS:
            print(f"fuzz_seeds: no target `{argv[1]}`", file=sys.stderr)
            return 2
        other = READS_CORPUS_OF.get(argv[1])
        if other is not None:
            print(other)
        return 0
    if len(argv) != 2:
        print(__doc__, file=sys.stderr)
        return 2
    written = write(argv[0], pathlib.Path(argv[1]))
    print(f"fuzz_seeds: {argv[0]}: {written} new seed(s) in {argv[1]}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
