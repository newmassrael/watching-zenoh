#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
"""R311y888 (debt-packet-fixture-witness, debt-packet-edit-after-build) — the
two halves of the packet-fixture discipline, gated.

## The failures these end

R311y886 found that three crates wrote a ZERO where a checksum goes. Over IPv4
that is present-and-wrong rather than absent, so every capture they built sat
whole in the corruption bucket, and NOTHING WAS RED — no test in any of those
files reads a checksum counter. The bill falls on the next test that does,
which then fails for a reason with no visible connection to it.

Two residues came out of that round and this file is both of them.

### A builder is correct until somebody edits it (`debt-packet-fixture-witness`)

Fixing the builders left six crates building healthy packets and three of them
saying so. A crate with no witness is one round of editing away from the state
357 was found in, and it will be found the same way: late, by a test about
something else.

So every crate that depends on `wz-packet-fixtures` — which is exactly the set
that lays packets by hand — names a test here that reads the checksum counters
back off a capture it built. The population comes from the MANIFESTS, so a
seventh crate joining the fixture crate cannot join quietly.

### An edit after the build is an edit inside the checksum (`debt-packet-edit-after-build`)

A fixture that varies one field to get many flows writes the field straight
into the finished frame, and a TCP checksum covers the ports. R311y886 fixed
`wz-capi-dissect`'s builder and every packet still read as corrupt for exactly
this reason; R311y888 measured three more sites of the same shape in
`wz-capture`. It announces itself only as ONE checksum axis disagreeing with
the other — IPv4 does not cover the ports, so that half stays clean — which is
not a signal anybody reads by accident.

The repair that makes it hard rather than merely fixed is
`wz_packet_fixtures::set_tcp_source_port`, which does the edit and the refill
together. This arm finds the raw shape: a frame bound from a packet builder,
then index-written past the Ethernet header, with no refill of that frame after
it.

## What it deliberately does NOT check

Whether the checksums are RIGHT. The per-crate tests this file's first arm
names do that, against a real reader. A lint that tried to evaluate one's
complement arithmetic would be a second implementation of the thing under test.
"""

from __future__ import annotations

import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
CRATES = ROOT / "crates"
FIXTURE_CRATE = "wz-packet-fixtures"

# crate -> (path to the file holding its witness, test function name)
#
# The witness must READ a checksum counter back off a capture the crate's own
# fixtures built. Naming the test here is what forces the question "and does
# this crate have one?" onto whoever adds the dependency.
WITNESSES = {
    "wz-capture": (
        "crates/wz-capture/src/lib.rs",
        "the_builders_in_this_module_are_checksum_clean",
    ),
    "wz-capi-dissect": (
        "crates/wz-capi-dissect/src/lib.rs",
        "the_fixtures_this_file_builds_are_checksum_clean",
    ),
    "wz-tls-record": (
        "crates/wz-tls-record/tests/end_to_end.rs",
        "the_fixtures_this_file_builds_are_checksum_clean",
    ),
    "wz-analyze": (
        "crates/wz-analyze/tests/binary.rs",
        "the_fixtures_this_file_builds_are_checksum_clean",
    ),
    "wz-replay": (
        "crates/wz-replay/tests/binary.rs",
        "every_fixture_capture_is_checksum_clean",
    ),
    "wz-integration-tests": (
        "crates/wz-integration-tests/src/lib.rs",
        "the_synthesised_pcap_is_checksum_clean",
    ),
}

# The counters a witness has to reach. A test that builds a capture and asserts
# a flow count is not a witness for this, however green it is.
COUNTERS = ("checksum_invalid", "checksum_valid")

# A local bound from one of these is a FRAME, and a checksum covers it.
BUILDER = re.compile(
    r"let mut (\w+)\s*=\s*[\w:]*\b(?:tcp|udp)[a-z_0-9]*\s*\(", re.M
)
# An indexed write into it. `lo` past the Ethernet header means the bytes are
# inside what an IPv4 or TCP checksum covers.
INDEXED_WRITE = re.compile(r"(\w+)\[(\d+)\.\.(\d+)\]\s*\.copy_from_slice")
ETHERNET_HEADER = 14
# What makes such a write safe: the frame's sums are put back.
REFILL = re.compile(r"(?:set_tcp_source_port|fill_\w*checksum)\s*\(")

# How far after the binding a write is still "this frame", and how far after the
# write a refill still counts. Both generous: the sites this finds are inside
# one small fixture closure or loop body, and a window too tight would report a
# refill that is simply two statements further down.
WRITE_WINDOW = 40
REFILL_WINDOW = 15


def rust_files() -> list[pathlib.Path]:
    return sorted(
        p
        for p in CRATES.rglob("*.rs")
        if "target" not in p.parts and "vendor" not in p.parts
    )


def crates_depending_on_fixtures() -> set[str]:
    """Every workspace member whose manifest names the fixture crate."""
    out: set[str] = set()
    for manifest in sorted(CRATES.glob("*/Cargo.toml")):
        name = manifest.parent.name
        if name == FIXTURE_CRATE:
            continue
        if FIXTURE_CRATE in manifest.read_text():
            out.add(name)
    return out


def witness_findings() -> list[str]:
    found = crates_depending_on_fixtures()
    findings: list[str] = []
    if not found:
        return [
            f"no workspace member depends on `{FIXTURE_CRATE}`. An empty "
            f"population is indistinguishable from total compliance, so this "
            f"cannot pass -- the dependency has probably been renamed"
        ]
    for crate in sorted(found - set(WITNESSES)):
        findings.append(
            f"`{crate}` lays packets by hand (it depends on {FIXTURE_CRATE}) and "
            f"this table names no witness for it. Add a test that reads a "
            f"checksum counter back off a capture its own fixtures built -- a "
            f"builder is correct until somebody edits it, and the edit costs "
            f"nothing in a file that never looks"
        )
    for crate in sorted(set(WITNESSES) - found):
        findings.append(
            f"the table names `{crate}` and its manifest no longer depends on "
            f"{FIXTURE_CRATE} -- the row is stale"
        )
    for crate, (rel, test) in sorted(WITNESSES.items()):
        if crate not in found:
            continue
        path = ROOT / rel
        if not path.exists():
            findings.append(f"`{crate}`'s row names {rel}, which is not there")
            continue
        src = path.read_text()
        m = re.search(rf"\bfn {re.escape(test)}\s*\(", src)
        if m is None:
            findings.append(
                f"`{crate}`'s row names test `{test}`, which is not in {rel} -- "
                f"a renamed test holds nothing"
            )
            continue
        rest = src[m.end() :]
        nxt = re.search(r"\n\s*(?:pub )?(?:async )?fn ", rest)
        body = rest[: nxt.start()] if nxt else rest
        if not any(c in body for c in COUNTERS):
            findings.append(
                f"`{crate}`'s witness `{test}` does not read any of "
                f"{list(COUNTERS)}. It may assert something true; it is not "
                f"asserting that this crate's fixtures are checksum-clean"
            )
    return findings


def edit_findings() -> list[str]:
    findings: list[str] = []
    for path in rust_files():
        lines = path.read_text().splitlines()
        # frame local -> line it was bound on
        bound: dict[str, int] = {}
        for i, line in enumerate(lines):
            m = BUILDER.search(line)
            if m:
                bound[m.group(1)] = i
            w = INDEXED_WRITE.search(line)
            if not w:
                continue
            name, lo = w.group(1), int(w.group(2))
            at = bound.get(name)
            if at is None or i - at > WRITE_WINDOW or lo < ETHERNET_HEADER:
                continue
            window = "\n".join(lines[i : i + REFILL_WINDOW + 1])
            if REFILL.search(window) and name in window:
                continue
            findings.append(
                f"{path.relative_to(ROOT)}:{i + 1}: `{name}` was built by a "
                f"packet builder on line {at + 1} and is written at byte {lo}, "
                f"which is inside what its checksums cover, with no refill "
                f"after it. Use `wz_packet_fixtures::set_tcp_source_port` (or "
                f"refill explicitly) -- a raw write leaves the frame corrupt on "
                f"the TRANSPORT axis alone, and the IPv4 axis staying clean is "
                f"why nobody notices"
            )
    return findings


def main() -> int:
    findings = witness_findings() + edit_findings()
    if findings:
        print("packet-fixture-lint: FAIL", file=sys.stderr)
        for f in findings:
            print(f"  - {f}", file=sys.stderr)
        print(
            f"\n  Edit {pathlib.Path(__file__).name} in the same commit as the "
            f"change.",
            file=sys.stderr,
        )
        return 1
    print(
        f"  packet-fixture-lint: {len(WITNESSES)} crate(s) lay packets by hand, "
        f"each with a witness that reads a checksum counter; 0 post-build edit(s) "
        f"left unrepaired"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
