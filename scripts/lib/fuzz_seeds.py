#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
"""R4131 (no register item) -- the seed corpus of each fuzz target of
`crates/wz-fuzz`, written into a directory from the files this tree already
holds, so the seeds follow the captures and the examples instead of a second
copy of them.

    fuzz_seeds.py <target> <out-dir>     write the seeds of <target>
    fuzz_seeds.py --targets              print the targets, one a line
    fuzz_seeds.py --reads <target>       print the target whose corpus <target> also reads
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

The output is a pure function of the tree: names are the SHA-256 of the
bytes, so writing twice changes nothing.
"""

from __future__ import annotations

import base64
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

TARGETS = ("pcap", "live", "transport", "text", "proto", "e2e", "replay", "config", "sender", "selector_term")

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
    "live": ((bytes([1, 3, 0, 128, 1, 1, 0, 0x44]), "corpus/zenoh-v1-10-0-tcp-full.pcap"),),
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
    print("fuzz_seeds: selftest OK")
    return 0


def main(argv: list[str]) -> int:
    if argv == ["--targets"]:
        print("\n".join(TARGETS))
        return 0
    if argv == ["--selftest"]:
        return selftest()
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
