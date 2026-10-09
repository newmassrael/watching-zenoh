#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
"""R3152 (no register item) -- the CLOSE REASON gate: wz's `CloseReason`
numbers against upstream's. (It answers the unregistered open-debt entry 896;
that register lives outside the store, so there is no id to cite.)

A Close message carries one reason byte. Upstream names its values in one
place, `commons/zenoh-protocol/src/transport/close.rs` @ `pub const UNRESPONSIVE`
(`GENERIC` 0 through `CONNECTION_TO_SELF` 7), and zenoh-pico mirrors the first
six as `_Z_CLOSE_*` defines. wz's `CloseReason` enum
(`crates/wz-session-core/src/close_reason.rs`) writes its discriminants
straight onto the wire (`reason as u8`), so each discriminant has to BE
upstream's number.

## Why a gate

For a long time they were not. The enum numbered the four reasons the session
state machine sets 0 to 3 -- `Invalid` 1, `Expired` 2, `Unresponsive` 3 -- which
upstream reads as `UNSUPPORTED`, `INVALID` and `MAX_SESSIONS`. A stock zenohd
logs the reason it reads (`Received a close message (reason ...) instead of an
OpenSyn`), so a wz lease expiry showed up there as an invalid close. wz to wz is
symmetric and every wz test that compared a byte compared it to
`CloseReason::X as u8`, so nothing wz owns could see it. Only a comparison with
the upstream SOURCE can, and that is what this is: the numbers are read out of
the pinned tree, not written into a second table here.

## How the two sides are matched

Names, not positions. Upstream's upper-case snake const becomes the camel-case
variant (`MAX_SESSIONS` -> `MaxSessions`), so no hand-written table can fall
behind: a reason upstream adds with no wz variant FAILs, a wz variant upstream
does not have FAILs, and a number that differs FAILs. Either side yielding no
entry also FAILs -- a parser that matched nothing reads exactly like an enum
that matches everything.

zenoh-pico is graded the same way against upstream, through the one rename
that is not mechanical (`MAX_TRANSPORTS` is upstream's `MAX_SESSIONS`): every
define pico has must carry the number upstream gives the same reason. pico
having FEWER reasons than upstream is not a finding -- it has no
`UNRESPONSIVE` -- and the vendored header is a submodule, so its leg defers
loudly where the submodule is not initialised.

## Where it runs

`--selftest` drives every refusal arm on synthetic text and needs no checkout.
The default grades against the pinned upstream tree and DEFERS, loudly and not
as a pass, when none is reachable; `--require` makes that a FAIL, for the lane
that provisions the tree (Layer Z). The shape is `cookie_carrier_gate.py`'s.
"""

from __future__ import annotations

import pathlib
import re
import sys

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(HERE))
import rust_comments  # noqa: E402

LABEL = "close-reason"
# Composed from segments rather than written whole, the way
# `cookie_carrier_gate.py` composes its own: a rooted path spelled in one
# literal is a BARE upstream citation to `upstream_citation_anchor_gate.py`,
# whose budget exists to shrink. The citation is made once, anchored, in this
# module's docstring.
UPSTREAM_REL = pathlib.Path("commons") / "zenoh-protocol" / "src" / "transport" / "close.rs"
WZ_REL = "crates/wz-session-core/src/close_reason.rs"
PICO_REL = "vendor/zenoh-pico/include/zenoh-pico/protocol/definitions/transport.h"

# The one pico name that is not upstream's spelling of the same reason.
PICO_ALIAS = {"MAX_TRANSPORTS": "MAX_SESSIONS"}


def _int(token: str) -> int:
    return int(token, 0)


def upstream_reasons(text: str) -> dict[str, int]:
    """`pub const NAME: u8 = N;` inside upstream's `pub mod reason { .. }`."""
    clean = rust_comments.strip_comments(text, blank_literals=True)
    at = clean.find("pub mod reason {")
    if at < 0:
        return {}
    start = clean.find("{", at)
    end = clean.find("}", start)
    body = clean[start + 1 : end]
    return {
        name: _int(value)
        for name, value in re.findall(
            r"pub\s+const\s+([A-Z][A-Z0-9_]*)\s*:\s*u8\s*=\s*(0x[0-9A-Fa-f]+|\d+)\s*;", body
        )
    }


def wz_reasons(text: str) -> dict[str, int]:
    """`Name = N,` variants of `pub enum CloseReason { .. }`, by Rust name."""
    clean = rust_comments.strip_comments(text, blank_literals=True)
    at = clean.find("pub enum CloseReason {")
    if at < 0:
        return {}
    start = clean.find("{", at)
    end = clean.find("}", start)
    body = clean[start + 1 : end]
    return {
        name: _int(value)
        for name, value in re.findall(
            r"^\s*([A-Z][A-Za-z0-9]*)\s*=\s*(0x[0-9A-Fa-f]+|\d+)\s*,", body, re.M
        )
    }


def pico_reasons(text: str) -> dict[str, int]:
    """`#define _Z_CLOSE_NAME 0xNN` -- pico's close reasons, by upstream-style name."""
    return {
        name: _int(value)
        for name, value in re.findall(
            r"^#define\s+_Z_CLOSE_([A-Z][A-Z0-9_]*)\s+(0x[0-9A-Fa-f]+|\d+)\s*$", text, re.M
        )
    }


def camel(upper_snake: str) -> str:
    return "".join(part.capitalize() for part in upper_snake.split("_"))


def grade_wz(upstream: dict[str, int], wz: dict[str, int]) -> list[str]:
    findings = []
    if not upstream:
        findings.append("upstream's `reason` module yielded no constant -- nothing was graded")
    if not wz:
        findings.append("wz's `CloseReason` yielded no variant -- nothing was graded")
    if findings:
        return findings
    want = {camel(name): (name, value) for name, value in upstream.items()}
    for variant, (name, value) in sorted(want.items()):
        if variant not in wz:
            findings.append(
                f"upstream has {name} = {value} and `CloseReason` has no `{variant}`: a reader "
                "naming a received reason would have nothing to name it with"
            )
        elif wz[variant] != value:
            findings.append(
                f"`CloseReason::{variant}` is {wz[variant]} and upstream's {name} is {value}: "
                "the byte wz writes is not the reason upstream reads"
            )
    for variant, value in sorted(wz.items()):
        if variant not in want:
            findings.append(
                f"`CloseReason::{variant}` = {value} has no upstream `reason` constant of that name"
            )
    return findings


def grade_pico(upstream: dict[str, int], pico: dict[str, int]) -> list[str]:
    findings = []
    if not pico:
        return ["pico's header yielded no `_Z_CLOSE_*` define -- nothing was graded"]
    for name, value in sorted(pico.items()):
        up_name = PICO_ALIAS.get(name, name)
        if up_name not in upstream:
            findings.append(f"pico's _Z_CLOSE_{name} has no upstream constant {up_name}")
        elif upstream[up_name] != value:
            findings.append(
                f"pico's _Z_CLOSE_{name} is {value} and upstream's {up_name} is {upstream[up_name]}"
            )
    return findings


def upstream_root() -> pathlib.Path | None:
    """The pinned checkout, through the one discovery this tree has."""
    try:
        import upstream_citation_anchor_gate as anchor
    except ImportError:
        return None
    return anchor.upstream_root()


SELFTEST_UP = """
pub mod reason {
    // pub const COMMENTED: u8 = 9;
    pub const GENERIC: u8 = 0x00;
    pub const MAX_SESSIONS: u8 = 0x03;
    pub const UNRESPONSIVE: u8 = 0x06;
}
"""
SELFTEST_WZ = """
pub enum CloseReason {
    /// Fake = 9, in prose
    #[default]
    Generic = 0,
    MaxSessions = 3,
    Unresponsive = 6,
}
"""
SELFTEST_PICO = """
#define _Z_CLOSE_GENERIC 0x00
#define _Z_CLOSE_MAX_TRANSPORTS 0x03
"""


def selftest() -> list[str]:
    bad = []
    up = upstream_reasons(SELFTEST_UP)
    wz = wz_reasons(SELFTEST_WZ)
    pico = pico_reasons(SELFTEST_PICO)
    if up != {"GENERIC": 0, "MAX_SESSIONS": 3, "UNRESPONSIVE": 6}:
        bad.append(f"upstream parse read {up}: a commented-out constant must not count")
    if wz != {"Generic": 0, "MaxSessions": 3, "Unresponsive": 6}:
        bad.append(f"wz parse read {wz}: a variant-shaped phrase in a doc comment must not count")
    if pico != {"GENERIC": 0, "MAX_TRANSPORTS": 3}:
        bad.append(f"pico parse read {pico}")

    wz_cases = {
        "matching tables": (up, wz, 0),
        # The defect this gate exists for: two numbers exchanged. Both end up
        # wrong, so two findings, and neither side's names changed.
        "two values swapped": (up, {**wz, "MaxSessions": 6, "Unresponsive": 3}, 2),
        "a wz value shifted": (up, {**wz, "Unresponsive": 3}, 1),
        "an upstream reason with no variant": (
            {**up, "MAX_LINKS": 4},
            wz,
            1,
        ),
        "a variant upstream does not have": (up, {**wz, "Extra": 9}, 1),
        "an empty upstream population": ({}, wz, 1),
        "an empty wz population": (up, {}, 1),
    }
    for name, (u, w, want) in wz_cases.items():
        got = len(grade_wz(u, w))
        if got != want:
            bad.append(f"wz leg, {name}: {got} finding(s), want {want}")

    pico_cases = {
        "pico agrees through the alias": (up, pico, 0),
        "pico number differs": (up, {**pico, "MAX_TRANSPORTS": 4}, 1),
        "pico name upstream lacks": (up, {**pico, "WRITE_ERROR": 6}, 1),
        "pico has fewer reasons": (up, {"GENERIC": 0}, 0),
        "an empty pico population": (up, {}, 1),
    }
    for name, (u, p, want) in pico_cases.items():
        got = len(grade_pico(u, p))
        if got != want:
            bad.append(f"pico leg, {name}: {got} finding(s), want {want}")
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
    require = "--require" in args

    def deferred(what: str) -> int:
        msg = f"{LABEL}: DEFERRED -- {what}; this is NOT a pass."
        if require:
            print(msg.replace("DEFERRED", "FAIL"), file=sys.stderr)
            return 1
        print("  " + msg)
        return 0

    root = upstream_root()
    if root is None:
        return deferred(
            "no pinned zenoh source tree, so upstream's close reasons could not be read; "
            "point ZENOHD_SRC at a checkout of the pin, or run the lane that provisions one"
        )
    up_path = root / UPSTREAM_REL
    if not up_path.is_file():
        print(f"{LABEL}: FAIL -- the pinned checkout has no {UPSTREAM_REL}", file=sys.stderr)
        return 1
    up = upstream_reasons(up_path.read_text(errors="replace"))
    wz = wz_reasons((ROOT / WZ_REL).read_text(errors="replace"))
    findings = grade_wz(up, wz)
    print(f"{LABEL}: upstream names {len(up)} reason(s); CloseReason has {len(wz)}")

    pico_path = ROOT / PICO_REL
    pico_note = ""
    if pico_path.is_file():
        pico = pico_reasons(pico_path.read_text(errors="replace"))
        findings += grade_pico(up, pico)
        pico_note = f"; pico's {len(pico)} define(s) agree"
    else:
        rc = deferred("the zenoh-pico submodule is not initialised, so its leg was not graded")
        if rc:
            return rc
    for f in findings:
        print(f"  FAIL {f}")
    if findings:
        print(f"{LABEL}: FAIL -- {len(findings)} finding(s)")
        return 1
    print(f"{LABEL}: ok -- every reason byte wz writes is the one upstream reads{pico_note}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
