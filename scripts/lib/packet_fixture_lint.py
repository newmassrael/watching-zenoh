#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
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

# A local bound from a function CALL, whatever that function is named.
#
# R2043 (open-debt item 368) — the population used to be `tcp|udp` in the
# callee's NAME, and a naming convention deciding a population is the shape
# that fails in silence. MEASURED before this changed: ZERO locals in the tree
# matched it, so every run reported "0 post-build edit(s) left unrepaired" over
# nothing at all — and the `0` in that sentence was a literal, not a count, so
# the emptiness could not be seen from the output either.
#
# The names it missed are ordinary: `padded_frame`, `frame`, `segment`,
# `make_packet`. What separates a frame this arm has an opinion about from one
# it does not is not the builder's name but its BEHAVIOUR — see
# [`CHECKSUMMED_BUILDER`].
BOUND_FROM_CALL = re.compile(r"let mut (\w+)\s*=\s*([\w:]*[a-z_0-9]+)\s*\(", re.M)

# A builder whose body FILLS a checksum, which is what makes the frame it
# returns one a later write can corrupt.
#
# R2043 (item 368) — derived rather than named, and the derivation is what
# stops the widening from being wrong. `raweth_link.rs` builds a RAW ETHERNET
# frame with `frame(..)` and rewrites its length field on purpose; there is no
# IP or TCP checksum over those bytes, so a gate that claimed it by name would
# report a defect that cannot exist. That builder fills nothing, and this
# rule excludes it for the reason it should be excluded.
FILLS_CHECKSUM = re.compile(r"\bfill_\w*checksum\s*\(")
CHECKSUMMED_BUILDER = re.compile(
    r"\bfn\s+([a-z_0-9]+)\s*\([^)]*\)[^{]*\{", re.M
)
# An indexed write into it. `lo` past the Ethernet header means the bytes are
# inside what an IPv4 or TCP checksum covers.
INDEXED_WRITE = re.compile(r"(\w+)\[(\d+)\.\.(\d+)\]\s*\.copy_from_slice")
ETHERNET_HEADER = 14
# What makes such a write safe: the frame's sums are put back.
REFILL = re.compile(r"(?:set_tcp_source_port|fill_\w*checksum)\s*\(")

# The OTHER thing that makes it safe: the fixture asserts the frame no longer
# verifies.
#
# R2043 (open-debt item 368) — found by the widened population on its FIRST
# run, which is the best evidence the widening was real. `the_port_is_inside_
# what_the_sum_covers` writes a port raw on purpose and asserts the sum breaks:
# "a raw port write must break the sum, or this class is imaginary". That is
# the negative control the repaired arm beside it depends on, and a gate that
# demanded a refill there would delete the proof that the defect exists.
#
# Corrupting a frame and SAYING SO is a different act from corrupting one and
# moving on. This escape is as loose as the refill one above and for the same
# reason: this arm's population is small, and a rule that cannot express "on
# purpose" turns a deliberate control into a lie.
DELIBERATE = re.compile(r"\bassert_ne!\s*\(")

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


IPV4_HEADER_END = ETHERNET_HEADER + 20


def repair_for(lo: int) -> str:
    """The repair that fits a write at byte `lo` — open-debt item 367.

    # What was wrong with one sentence for every edit

    The advice used to be "use `wz_packet_fixtures::set_tcp_source_port` (or
    refill explicitly)". That helper edits ONE field, and it is the only helper
    there is, so the advice was right for a source-port write and wrong for
    every other one: it cannot repair a destination port, an address, or a
    length, and a reader following it would edit a field they did not mean to.
    Item 367 filed that as "the fix becomes a second helper rather than a
    call".

    # Why NOT a second helper

    MEASURED this round, with the population the previous one made visible: the
    whole tree holds ONE post-build write into a checksummed frame, and it is
    the negative control that proves the class is real. There is no fixture
    editing a destination port or an address, so a helper for that edit would
    be API written for nobody. What the class actually needs today is advice
    that fits the edit in front of it.

    # The two layers, and why the offset decides

    A write below `IPV4_HEADER_END` is in the IPv4 header, which its own
    checksum covers and the transport checksum does NOT -- the pseudo-header
    takes the addresses, so an address edit breaks both and a TTL edit breaks
    only one. At or past it the bytes are in the segment, which the transport
    sum covers and IPv4's does not. That asymmetry is the whole reason this
    class is hard to notice, and naming it is what makes the advice actionable.
    """
    if lo < IPV4_HEADER_END:
        return (
            "That is inside the IPv4 HEADER: refill with "
            "`wz_packet_fixtures::fill_ipv4_checksum`, and if the bytes are "
            "the source or destination ADDRESS refill the transport sum too "
            "-- the pseudo-header takes them, so an address edit breaks both "
            "axes while a TTL edit breaks only the IPv4 one"
        )
    return (
        "That is inside the TRANSPORT segment: refill with "
        "`wz_packet_fixtures::fill_tcp_checksum` or `fill_udp_checksum`. "
        "`set_tcp_source_port` does the edit and the refill together, but ONLY "
        "for the TCP source port -- it is the one field with a helper, so any "
        "other edit refills explicitly. A raw write leaves the frame corrupt "
        "on the transport axis alone, and the IPv4 axis staying clean is why "
        "nobody notices"
    )


def checksummed_builders(src: str) -> set[str]:
    """Every function in `src` whose body fills a checksum.

    R2043 (item 368) — a crude body scan on purpose: from each `fn name(` to
    the next one, which is the same slicing this file's witness arm already
    does. A builder that calls into a helper that fills is missed, and that
    residue is STATED rather than hidden — what this replaces missed every
    builder whose name lacked `tcp` or `udp`, which measured as all of them.
    """
    out: set[str] = set()
    starts = [(m.group(1), m.end()) for m in CHECKSUMMED_BUILDER.finditer(src)]
    for idx, (name, at) in enumerate(starts):
        end = starts[idx + 1][1] if idx + 1 < len(starts) else len(src)
        if FILLS_CHECKSUM.search(src[at:end]):
            out.add(name)
    return out


def edit_findings(sources: list[tuple[str, str]] | None = None) -> tuple[list[str], int]:
    """Findings, and HOW MANY candidate writes were examined.

    R2043 (item 368) — the count is returned because the OK line used to
    hardcode a zero. "0 unrepaired" over 0 candidates and over 40 read
    identically, and this arm was the former for its whole life.
    """
    findings: list[str] = []
    examined = 0
    files = sources if sources is not None else [(str(p.relative_to(ROOT)), p.read_text()) for p in rust_files()]
    for rel, text in files:
        lines = text.splitlines()
        builders = checksummed_builders(text)
        # frame local -> line it was bound on
        bound: dict[str, int] = {}
        for i, line in enumerate(lines):
            m = BOUND_FROM_CALL.search(line)
            if m and m.group(2).rsplit("::", 1)[-1] in builders:
                bound[m.group(1)] = i
            w = INDEXED_WRITE.search(line)
            if not w:
                continue
            name, lo = w.group(1), int(w.group(2))
            at = bound.get(name)
            if at is None or i - at > WRITE_WINDOW or lo < ETHERNET_HEADER:
                continue
            # A CANDIDATE: a write into a checksum-covered frame. Counted here
            # rather than after the refill test, because what the OK line has
            # to report is how many writes this arm WEIGHED -- a repaired one
            # is evidence the arm is looking, and an unrepaired one is a
            # finding.
            examined += 1
            window = "\n".join(lines[i : i + REFILL_WINDOW + 1])
            if REFILL.search(window) and name in window:
                continue
            # R2043 (item 368) — or the fixture says the break is the point.
            if DELIBERATE.search(window) and name in window:
                continue
            findings.append(
                f"{rel}:{i + 1}: `{name}` was built by a "
                f"packet builder on line {at + 1} and is written at byte {lo}, "
                f"which is inside what its checksums cover, with no refill "
                f"after it. {repair_for(lo)}"
            )
    return findings, examined


def selftest() -> int:
    """R2043 (item 368) — prove the edit arm still DETECTS.

    Its live population measured ZERO before this round, and a population of
    zero passes every check written over it. The narrow-vle census needed the
    same witness for the same reason two rounds ago: a gate whose recogniser
    can only be exercised by the tree it guards cannot show it recognises
    anything once that tree stops producing candidates.
    """
    checksummed = (
        "fn built(p: &[u8]) -> Vec<u8> {\n    let mut f = vec![0u8; 60];\n"
        "    fill_tcp_checksum([0;4], [0;4], &mut f);\n    f\n}\n"
    )
    raw = "fn frame(p: &[u8]) -> Vec<u8> {\n    vec![0u8; 60]\n}\n"
    cases: list[tuple[str, str, int, int]] = [
        (
            "a raw write into a checksummed frame is CAUGHT",
            checksummed + 'fn t() {\n    let mut f = built(b"x");\n'
            "    f[34..36].copy_from_slice(&1u16.to_be_bytes());\n}\n",
            1,
            1,
        ),
        (
            "and the same write with a refill after it is clean",
            checksummed + 'fn t() {\n    let mut f = built(b"x");\n'
            "    f[34..36].copy_from_slice(&1u16.to_be_bytes());\n"
            "    fill_tcp_checksum([0;4], [0;4], &mut f);\n}\n",
            0,
            1,
        ),
        (
            "A RAW ETHERNET FRAME IS NOT CLAIMED -- its builder fills no "
            "checksum, so there is nothing over those bytes to corrupt. This "
            "is the case a name-based population would have reported as a "
            "defect that cannot exist",
            raw + 'fn t() {\n    let mut f = frame(b"x");\n'
            "    f[14..16].copy_from_slice(&300u16.to_be_bytes());\n}\n",
            0,
            0,
        ),
        (
            "A NEGATIVE CONTROL is not a defect: a fixture that corrupts a "
            "frame and ASSERTS the sum broke is proving the class is real, and "
            "demanding a refill there would delete the proof",
            checksummed + 'fn t() {\n    let mut f = built(b"x");\n'
            "    f[34..36].copy_from_slice(&1u16.to_be_bytes());\n"
            "    assert_ne!(tcp_sum_of(&f), 0, \"must break\");\n}\n",
            0,
            1,
        ),
        (
            "a write INSIDE the Ethernet header is not covered either",
            checksummed + 'fn t() {\n    let mut f = built(b"x");\n'
            "    f[0..6].copy_from_slice(&[1, 2, 3, 4, 5, 6]);\n}\n",
            0,
            0,
        ),
    ]
    # R2044 (open-debt item 367) — THE ADVICE MUST FIT THE EDIT. One sentence
    # naming `set_tcp_source_port` was right for a source-port write and wrong
    # for every other one; a reader following it on an IPv4-header edit would
    # change a field they did not mean to.
    ipv4_write = (
        checksummed + 'fn t() {\n    let mut f = built(b"x");\n'
        "    f[26..30].copy_from_slice(&[1, 2, 3, 4]);\n}\n"
    )
    segment_write = (
        checksummed + 'fn t() {\n    let mut f = built(b"x");\n'
        "    f[36..38].copy_from_slice(&1u16.to_be_bytes());\n}\n"
    )
    for label, src, want in (
        ("an IPv4-header write", ipv4_write, "fill_ipv4_checksum"),
        ("a segment write", segment_write, "fill_tcp_checksum"),
    ):
        got, _ = edit_findings([("fx.rs", src)])
        if len(got) != 1 or want not in got[0]:
            print(
                f"  packet-fixture SELFTEST FAIL: {label} must be told to use "
                f"`{want}`\n    got {got}"
            )
            return 1
    # And the two must not be told the SAME thing, or the offset is decorative.
    if edit_findings([("fx.rs", ipv4_write)])[0] == edit_findings([("fx.rs", segment_write)])[0]:
        print("  packet-fixture SELFTEST FAIL: both layers get one sentence")
        return 1
    # ⚠ AND THE ONE HELPER MUST NOT BE OFFERED AS A GENERAL ONE. This is item
    # 367's own sentence: `set_tcp_source_port` edits the TCP source port and
    # nothing else, so advice that names it without saying so sends a reader to
    # change a field they did not mean to. A mutation that dropped the limit
    # SURVIVED the two checks above -- they only ask which refill is named.
    segment_msg = edit_findings([("fx.rs", segment_write)])[0][0]
    if "ONLY for the TCP source port" not in segment_msg:
        print(
            "  packet-fixture SELFTEST FAIL: the advice offers "
            "`set_tcp_source_port` without saying it edits ONE field\n"
            f"    got {segment_msg}"
        )
        return 1

    failed = False
    for name, src, want_findings, want_examined in cases:
        got, examined = edit_findings([("fx.rs", src)])
        if len(got) != want_findings or examined != want_examined:
            failed = True
            print(
                f"  packet-fixture SELFTEST FAIL: {name}\n"
                f"    want {want_findings} finding(s) over {want_examined} "
                f"candidate(s)\n    got  {len(got)} over {examined}"
            )
    if failed:
        return 1
    print(f"  packet-fixture selftest: {len(cases)} detector case(s) hold")
    return 0


def main() -> int:
    if "--selftest" in sys.argv[1:]:
        return selftest()
    edits, examined = edit_findings()
    findings = witness_findings() + edits
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
    # R2043 (item 368) — the candidate COUNT, not a hardcoded zero. "0
    # unrepaired" said nothing about whether anything was weighed, and this arm
    # weighed nothing at all for its whole life.
    print(
        f"  packet-fixture-lint: {len(WITNESSES)} crate(s) lay packets by hand, "
        f"each with a witness that reads a checksum counter; {examined} "
        f"post-build edit(s) into a checksummed frame, 0 left unrepaired"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
