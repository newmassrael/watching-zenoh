#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
"""R2784 (no register item) -- the ACCEPT COOKIE CARRIER gate.

`session-unicast-accept`'s stateless clause is "the acceptor holds nothing
between InitAck and OpenSyn, because its cookie carries the handshake's
state". Upstream says WHICH state that is in one place: the fields of its
cookie struct,
`io/zenoh-transport/src/unicast/establishment/cookie.rs` @ `pub(crate) struct Cookie {`.
This gate holds wz's carrier to that struct, field by field.

## Why a gate, and why now

The count was short TWICE before this existed. R2774 listed the carried
states by walking upstream's extensions one at a time and missed the region
name; R2777 found it by reading the struct instead, and wrote the corrected
count into prose -- where nothing checks it. A clause whose population is a
struct should be judged against the struct, by code, every time upstream
moves: the day zenoh adds a field to its cookie, wz's claim to carry "all of
it" is stale, and this is what says so. It is the ground the atom's COMPLETE
grade stands on.

## The population is DERIVED on both sides, and an empty one FAILs

Upstream: every `pub(crate) NAME:` field in the body of `struct Cookie`, cfg
attributes and comments skipped -- a field upstream compiles only under a
feature is still a field its cookie can carry. wz: every `pub NAME:` field of
`AcceptCookieState` (crates/wz-session-core/src/accept_cookie.rs) and of the
`NegotiatedExtensions` group it holds (accept_state.rs), read through the
shared comment scanner with literals blanked.

`CARRIED` below maps each upstream field to the wz member that carries it.
The table is hand-written, and that is why BOTH of its ends are checked
against the parsed structs: a row whose upstream field is gone, a row whose
wz member is gone, an upstream field no row names, and a wz member no row
names each FAIL, and so does either population being empty -- a parser that
matched nothing reads exactly like a carrier that matches everything.

## What this does not claim

That a member is CARRIED is not that its slot is RELEASED between InitAck
and OpenSyn; the release is behaviour, and each member's is witnessed by a
test that decodes the cookie off the InitAck the acceptor sent and reads the
slot in between. This gate is the population those witnesses are owed
against: an upstream field with no carried member is a gap no witness could
see.

## Where it runs

`--selftest` drives every refusal arm on synthetic structs and needs no
checkout. The default grades against the pinned upstream tree and DEFERS,
loudly and not as a pass, when none is reachable; `--require` makes that a
FAIL, for the lane that provisions the tree (Layer Z). The shape is
`token_plane_parity_gate.py`'s, the sibling that judges a COMPLETE grade
against an upstream population the same way.
"""

from __future__ import annotations

import pathlib
import re
import sys

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(HERE))
import rust_comments  # noqa: E402

LABEL = "cookie-carrier"
UPSTREAM_REL = "io/zenoh-transport/src/unicast/establishment/cookie.rs"
WZ_COOKIE_REL = "crates/wz-session-core/src/accept_cookie.rs"
WZ_GROUP_REL = "crates/wz-session-core/src/accept_state.rs"

# Upstream `Cookie` field -> the wz member that carries it. A member inside the
# fixed-width group is spelled `negotiated.NAME`; the multilink state sits
# outside it because its encoding is variable (R2783).
CARRIED: dict[str, str] = {
    "zid": "peer_zid",
    "whatami": "peer_whatami",
    "resolution": "sn_res",
    "batch_size": "batch_size",
    "nonce": "nonce",
    "ext_qos": "negotiated.qos",
    "ext_mlink": "multilink",
    "ext_shm": "negotiated.shm",
    "ext_auth": "negotiated.auth",
    "ext_lowlatency": "negotiated.lowlatency",
    "ext_compression": "negotiated.compression",
    "ext_patch": "negotiated.patch",
    "ext_region_name": "negotiated.region",
}

# The carrier's own structure rather than a carried state: the group is a
# container, named so the both-ways check does not read it as unmapped.
CONTAINERS = {"negotiated"}


def struct_fields(text: str, opener: str, vis: str) -> list[str]:
    """Field names declared with `vis` in the body of the struct `opener`
    opens. Comments are stripped and literals blanked first, so a brace or a
    field-shaped phrase in prose cannot move the result."""
    clean = rust_comments.strip_comments(text, blank_literals=True)
    at = clean.find(opener)
    if at < 0:
        return []
    start = clean.find("{", at)
    depth = 0
    end = start
    for i in range(start, len(clean)):
        if clean[i] == "{":
            depth += 1
        elif clean[i] == "}":
            depth -= 1
            if depth == 0:
                end = i
                break
    body = clean[start + 1 : end]
    pat = re.compile(rf"^\s*{re.escape(vis)}\s+([A-Za-z_]\w*)\s*:", re.M)
    return pat.findall(body)


def grade(
    upstream: str, wz_cookie: str, wz_group: str, carried: dict[str, str] | None = None
) -> list[str]:
    carried = CARRIED if carried is None else carried
    up = struct_fields(upstream, "struct Cookie {", "pub(crate)")
    cookie = struct_fields(wz_cookie, "pub struct AcceptCookieState {", "pub")
    group = struct_fields(wz_group, "pub struct NegotiatedExtensions {", "pub")
    wz = set(cookie) | {f"negotiated.{g}" for g in group}
    findings = []
    if not up:
        findings.append("upstream's `struct Cookie` yielded no field -- nothing was graded")
    if not cookie or not group:
        findings.append("wz's carrier yielded no field -- nothing was graded")
    if findings:
        return findings
    for field in up:
        if field not in carried:
            findings.append(
                f"upstream's cookie carries `{field}` and no row says which wz "
                "member carries it: either wz's cookie does not, or this table is behind"
            )
    for field, member in carried.items():
        if field not in up:
            findings.append(f"row `{field}`: upstream's cookie has no such field any more")
        if member not in wz:
            findings.append(f"row `{field}` -> `{member}`: wz's carrier has no such member")
    named = set(carried.values())
    for member in sorted(wz):
        if member in CONTAINERS or member in named:
            continue
        findings.append(f"wz's carrier has `{member}` and no upstream field maps to it")
    return findings


def upstream_root() -> pathlib.Path | None:
    """The pinned checkout, through the one discovery this tree has."""
    try:
        import upstream_citation_anchor_gate as anchor
    except ImportError:
        return None
    return anchor.upstream_root()


def selftest() -> list[str]:
    up = (
        "#[derive(Debug)]\npub(crate) struct Cookie {\n"
        "    pub(crate) zid: Z,\n    // Extensions\n"
        '    #[cfg(feature = "x")]\n    pub(crate) ext_qos: Q,\n}\n'
    )
    cookie = (
        "pub struct AcceptCookieState {\n    /// the zid `pub fake: u8,`\n"
        "    pub peer_zid: Vec<u8>,\n    pub negotiated: N,\n}\n"
    )
    group = "pub struct NegotiatedExtensions {\n    pub qos: Q,\n}\n"
    table = {"zid": "peer_zid", "ext_qos": "negotiated.qos"}
    cases = {
        "a complete table over matching structs": (up, cookie, group, 0),
        # Renamed rather than deleted: deleting the group's only member would
        # take the empty-population arm first, and this case is about the
        # table's wz end -- the row loses its member AND the new name is
        # unmapped, two findings.
        "a row whose wz member is gone": (up, cookie, group.replace("pub qos:", "pub qos2:"), 2),
        "an upstream field no row names": (
            up.replace("pub(crate) ext_qos: Q,", "pub(crate) ext_qos: Q,\n    pub(crate) ext_new: R,"),
            cookie,
            group,
            1,
        ),
        "a wz member no row names": (
            up,
            cookie.replace("pub negotiated: N,", "pub negotiated: N,\n    pub extra: u8,"),
            group,
            1,
        ),
        "a row whose upstream field is gone": (up.replace("pub(crate) zid: Z,", ""), cookie, group, 1),
        "an empty upstream population": ("", cookie, group, 1),
        "an empty wz population": (up, "", group, 1),
    }
    bad = []
    for name, (u, c, g, want) in cases.items():
        got = len(grade(u, c, g, table))
        if got != want:
            bad.append(f"{name}: {got} finding(s), want {want}")
    if "fake" in struct_fields(cookie, "pub struct AcceptCookieState {", "pub"):
        bad.append("a field-shaped phrase in a doc comment was read as a field")
    if struct_fields(up, "struct Cookie {", "pub(crate)") != ["zid", "ext_qos"]:
        bad.append("a cfg-gated upstream field must still be a member")
    return bad


def main() -> int:
    args = set(sys.argv[1:])
    unknown = args - {"--selftest", "--check", "--require"}
    if unknown:
        print(f"{LABEL}: unknown argument(s) {sorted(unknown)}", file=sys.stderr)
        return 2
    bad = selftest()
    if bad:
        for b in bad:
            print(f"  {LABEL}: selftest FAIL -- {b}", file=sys.stderr)
        return 1
    if "--selftest" in args:
        print(f"{LABEL}: selftest ok")
        return 0
    root = upstream_root()
    if root is None:
        msg = (
            f"{LABEL}: DEFERRED -- no pinned zenoh source tree, so upstream's "
            "cookie could not be read; this is NOT a pass. Point ZENOHD_SRC at a "
            "checkout of the pin, or run the lane that provisions one."
        )
        if "--require" in args:
            print(msg.replace("DEFERRED", "FAIL"), file=sys.stderr)
            return 1
        print("  " + msg)
        return 0
    up_path = root / UPSTREAM_REL
    if not up_path.is_file():
        print(f"{LABEL}: FAIL -- the pinned checkout has no {UPSTREAM_REL}", file=sys.stderr)
        return 1
    up_text = up_path.read_text(errors="replace")
    findings = grade(
        up_text,
        (ROOT / WZ_COOKIE_REL).read_text(errors="replace"),
        (ROOT / WZ_GROUP_REL).read_text(errors="replace"),
    )
    up_n = len(struct_fields(up_text, "struct Cookie {", "pub(crate)"))
    print(f"{LABEL}: upstream's cookie has {up_n} field(s); {len(CARRIED)} row(s)")
    for f in findings:
        print(f"  FAIL {f}")
    if findings:
        print(f"{LABEL}: FAIL -- {len(findings)} finding(s)")
        return 1
    print(f"{LABEL}: ok -- every field upstream's cookie carries, wz's carries")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
