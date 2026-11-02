#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
"""R4131 (no register item) -- the seed corpus of each fuzz target of
`crates/wz-fuzz`, written into a directory from the files this tree already
holds, so the seeds follow the captures and the examples instead of a second
copy of them.

    fuzz_seeds.py <target> <out-dir>     write the seeds of <target>
    fuzz_seeds.py --targets              print the targets, one a line
    fuzz_seeds.py --selftest             check every target writes seeds

Each seed is the input layout its target's header comment states:

- `pcap`, `live`: eight bytes of arguments, then a capture from `captures/`
  (classic pcap or pcapng, at most `MAX_CAPTURE` bytes; files with the same
  bytes count once).
- `transport`: four bytes of arguments, a session context and a ring word
  (each to a NUL), then the UDP or TCP payload of an Ethernet/IPv4 packet of
  those captures.
- `text`, `proto`, `e2e`, `replay`: the examples the crate's own tests use
  (`crates/wz-capi-dissect/tests/c_abi_consumer.c`, `src/lib.rs`), written here
  in the target's layout, and the `.proto` files of
  `crates/wz-capture/testdata/nanopb/`.

The output is a pure function of the tree: names are the SHA-256 of the
bytes, so writing twice changes nothing.
"""

from __future__ import annotations

import hashlib
import pathlib
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

TARGETS = ("pcap", "live", "transport", "text", "proto", "e2e", "replay")

# Inputs that once made a target fail and are made of a tracked capture: the
# arguments and the capture's path under `captures/`, so the reproducer is
# committed as these lines and not as a copy of the file. Each is a seed on
# every replay whatever the rotation above gives that capture. A reproducer
# that is not made of a tracked file goes to `crates/wz-fuzz/regressions/`.
PINNED: dict[str, tuple[tuple[bytes, str], ...]] = {
    # `wz_dissect_live_follow_lent` lent a container it then refused as shrunk,
    # and the next read of a flow panicked (`Dissection::follow_lent`).
    "live": ((bytes([1, 3, 0, 128, 1, 1, 0, 0x44]), "corpus/zenoh-v1-10-0-tcp-full.pcap"),),
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
    if link != 1 or len(frame) < 14 or frame[12:14] != b"\x08\x00":
        return None
    ip = frame[14:]
    if len(ip) < 20 or ip[0] >> 4 != 4:
        return None
    ihl = (ip[0] & 0x0F) * 4
    proto, body = ip[9], ip[ihl:]
    if proto == 17 and len(body) > 8:
        return body[8:]
    if proto == 6 and len(body) >= 20:
        payload = body[(body[12] >> 4) * 4 :]
        return payload or None
    return None


def seeds(target: str) -> list[bytes]:
    pinned = [head + (CAPTURES / path).read_bytes() for head, path in PINNED.get(target, ())]
    return pinned + derived(target)


def derived(target: str) -> list[bytes]:
    # Each capture once, with the arguments taken in turn: every set of
    # arguments meets many captures and every capture is read, at the cost of
    # one pass over the captures. Every set crossed with every capture made the
    # replay six times longer for coverage the fuzzer reaches in its first
    # minutes anyway.
    if target == "pcap":
        heads = (bytes(8), bytes([1, 4, 1, 0, 0, 1, 1, 0]), bytes([0, 255, 3, 0, 1, 2, 2, 0]))
        return [heads[n % len(heads)] + c for n, c in enumerate(captures())]
    if target == "live":
        # The six ways of opening a handle (`Feed`), in turn.
        return [bytes([n % 2, n % 6, 0, 128, 1, 1, 0, 0x44]) + c for n, c in enumerate(captures())]
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
    raise SystemExit(f"fuzz_seeds: no target `{target}`; the targets are {', '.join(TARGETS)}")


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
    for target in TARGETS:
        count = len(seeds(target))
        if count == 0:
            print(f"fuzz_seeds: FAIL -- target `{target}` has no seed", file=sys.stderr)
            return 1
        print(f"fuzz_seeds: {target}: {count} seed(s)")
    print("fuzz_seeds: selftest OK")
    return 0


def main(argv: list[str]) -> int:
    if argv == ["--targets"]:
        print("\n".join(TARGETS))
        return 0
    if argv == ["--selftest"]:
        return selftest()
    if len(argv) != 2:
        print(__doc__, file=sys.stderr)
        return 2
    written = write(argv[0], pathlib.Path(argv[1]))
    print(f"fuzz_seeds: {argv[0]}: {written} new seed(s) in {argv[1]}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
