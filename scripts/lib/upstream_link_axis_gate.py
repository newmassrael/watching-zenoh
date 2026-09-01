#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

"""R2260 (no register item) — WZ'S PER-PROTOCOL `is_streamed` / `is_reliable`
MUST BE UPSTREAM'S, BECAUSE THEY ARE UPSTREAM'S ACCESSORS.

## Why the citation says no item while the file answers for one

The debt this answers is open-debt item 593's residue, and 593 lives in the half
of the register that is not the store, so there is no `debt-` id to cite — the
same standing `feature_public_surface_census.py` is in for item 532, and the
convention's explicit declaration is the only true one. The item is named in
full here, which is what a reader grepping for it will find.

## What went wrong, which is the whole reason this exists

R2259 built `z_link_is_streamed` and `z_link_reliability` — zenoh-c accessors —
and derived their values from what WZ'S OWN framing does: "the two datagram
schemes are the unstreamed ones". It then wrote a doc comment asserting that
`Ws` was streamed "as upstream classifies it", citing a path.

Read at the pin, every part of that was wrong:

  * the PATH did not exist (`io/zenoh-link-ws/...`; upstream nests link crates
    one level deeper, under `io/zenoh-links/`);
  * upstream's ws link answers `is_streamed() == false`, the opposite;
  * so does `serial`;
  * and `ws` is the link where the two axes DISAGREE — unstreamed but reliable,
    a WebSocket's discrete BINARY messages over a retransmitting TCP connection.
    R2259 wrote the two as separate matches "so the coincidence does not look
    like a definition" and then filled them identically anyway.

None of that was reachable from wz's own sources. The value of these two
functions is not a wz design decision at all: they answer a zenoh-c accessor, so
upstream IS the specification and any derivation from wz's framing is a bug
wearing a rationale. This gate is what makes that checkable instead of stated.

## Two arms, and only one of them needs a checkout

  * The AGREEMENT arm reads wz's two `matches!` bodies and wz's own doc TABLE
    and refuses any disagreement. It needs nothing but this tree, so it runs
    everywhere — including in the hook. It is NOT the oracle: R2259's table and
    R2259's code agreed with each other perfectly while both were wrong.
  * The ORACLE arm reads each upstream link crate's own `LinkUnicastTrait` impl
    and refuses any disagreement with wz. It needs a checkout at the pin, which
    is machine-local, so it SKIPS when there is none -- and a skip must not
    report green, so `--require` turns that skip into a FAIL and the lane that
    has a checkout passes it.

## `udp` is upstream's one conditional, and it is DECLARED

Upstream's udp link does not answer a constant: it matches on a variant and says
`true` only for the reliable-UDP form. wz has no such link, so `false` is the
row that describes what wz can be. That is declared in `CONDITIONAL` below and
held in BOTH directions -- a link declared conditional whose upstream impl turns
out to be a constant is a FINDING too, so the declaration cannot quietly become
a way to stop grading a link.
"""

from __future__ import annotations

import argparse
import os
import pathlib
import re
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[2]

#: wz's link module, whose two functions and doc table this grades.
WZ_LINK = "crates/wz-session-core/src/link.rs"

#: wz `InterceptorLink` variant -> the config spelling `as_str` gives it, which
#: is also (with `-` for `_`) upstream's link-crate directory suffix.
VARIANTS: dict[str, str] = {
    "Tcp": "tcp",
    "Udp": "udp",
    "Tls": "tls",
    "Quic": "quic",
    "QuicDatagram": "quic-datagram",
    "Serial": "serial",
    "Unixpipe": "unixpipe",
    "UnixsockStream": "unixsock-stream",
    "Vsock": "vsock",
    "Ws": "ws",
}

#: Links whose upstream impl is a MATCH on a variant rather than a constant, and
#: what wz answers instead, with why. Held both ways -- see the module docstring.
CONDITIONAL: dict[str, str] = {
    "udp": (
        "upstream matches on `LinkUnicastUdpVariant` and answers `true` only for "
        "the reliable-UDP form; wz has no reliable-UDP link, so the connected / "
        "unconnected answer is the one that describes what wz can be"
    ),
}

MATCHES = re.compile(
    r"pub fn (is_streamed|is_reliable)\(&self\) -> bool \{\s*!matches!\((.*?)\)\s*\}",
    re.S,
)
ROW = re.compile(
    r"^\s*///\s*\|\s*([a-z][a-z-]*)\s*\|\s*(true|false)\s*\|\s*(true|false|TRUE|FALSE)\s*\|",
    re.M | re.I,
)


def wz_axes(text: str) -> tuple[dict[str, bool], dict[str, bool], list[str]]:
    """(streamed, reliable) per config spelling, from wz's two `matches!` bodies.

    Read from the CODE, never from the table: the table is the other half this
    gate compares against, and deriving both from one of them is the shape that
    can never fail.
    """
    findings: list[str] = []
    axes: dict[str, dict[str, bool]] = {}
    for name, body in MATCHES.findall(text):
        negated = set(re.findall(r"InterceptorLink::([A-Za-z]+)", body))
        unknown = negated - set(VARIANTS)
        if unknown:
            findings.append(
                f"`{name}` names {sorted(unknown)}, which `VARIANTS` does not "
                f"know -- a variant added to the enum has to be added here too, "
                f"or it is graded against nothing"
            )
        axes[name] = {
            spelling: variant not in negated for variant, spelling in VARIANTS.items()
        }
    for want in ("is_streamed", "is_reliable"):
        if want not in axes:
            findings.append(
                f"`{want}` was not found as a `!matches!` body in {WZ_LINK}; this "
                f"gate reads the arms out of that shape and cannot grade another"
            )
    return axes.get("is_streamed", {}), axes.get("is_reliable", {}), findings


def wz_table(text: str) -> dict[str, tuple[bool, bool]]:
    """The doc TABLE, as its own reading of the same fact."""
    out: dict[str, tuple[bool, bool]] = {}
    for link, streamed, reliable in ROW.findall(text):
        if link in ("link", "-"):
            continue
        out[link] = (streamed.lower() == "true", reliable.lower() == "true")
    return out


def agreement_findings(text: str) -> list[str]:
    """wz's code and wz's table must say the same thing."""
    streamed, reliable, findings = wz_axes(text)
    if findings:
        return findings
    table = wz_table(text)
    if not table:
        return [
            f"no `| link | streamed | reliable |` table was found in {WZ_LINK}, so "
            f"the agreement arm graded nothing while reporting clean"
        ]
    missing = set(VARIANTS.values()) - set(table)
    if missing:
        findings.append(
            f"the doc table does not list {sorted(missing)}; every link the enum "
            f"has must have a row, or a wrong arm can hide in the gap"
        )
    extra = set(table) - set(VARIANTS.values())
    if extra:
        findings.append(f"the doc table lists {sorted(extra)}, which the enum has not")
    for link, (want_s, want_r) in sorted(table.items()):
        if link not in streamed:
            continue
        if streamed[link] != want_s:
            findings.append(
                f"`{link}`: the code says streamed={streamed[link]} and the doc "
                f"table says {want_s}"
            )
        if reliable[link] != want_r:
            findings.append(
                f"`{link}`: the code says reliable={reliable[link]} and the doc "
                f"table says {want_r}"
            )
    return findings


def upstream_root() -> pathlib.Path | None:
    """A checkout of the pinned zenoh, or `None`.

    `ZENOHD_SRC` first, because an explicit instruction beats a discovery --
    the order `upstream_feature_census` states for the same question. The
    $HOME-relative fallback is not written into a tracked file as an absolute
    path (the CLAUDE.md rule); it is a name, resolved per machine.
    """
    explicit = os.environ.get("ZENOHD_SRC")
    candidates = [pathlib.Path(explicit)] if explicit else []
    home = pathlib.Path(os.environ.get("HOME", "~")).expanduser()
    candidates.append(home / "zenoh-ref")
    candidates.append(ROOT / "target" / "zenohd-build" / "zenoh-src")
    for c in candidates:
        if (c / "io" / "zenoh-links").is_dir():
            return c
    return None


def upstream_axes(root: pathlib.Path) -> tuple[dict[str, tuple[bool | None, bool | None]], list[str]]:
    """Each upstream link crate's own answer, or `None` where it is a match."""
    findings: list[str] = []
    out: dict[str, tuple[bool | None, bool | None]] = {}
    links = root / "io" / "zenoh-links"
    for d in sorted(links.iterdir()):
        if not d.is_dir() or not d.name.startswith("zenoh-link-"):
            continue
        spelling = d.name[len("zenoh-link-") :].replace("_", "-")
        unicast = [p for p in d.rglob("unicast.rs")]
        if not unicast:
            continue
        streamed: bool | None = None
        for path in unicast:
            body = path.read_text(encoding="utf-8", errors="replace")
            m = re.search(r"fn is_streamed\(&self\) -> bool \{\s*\n(.*?)\n", body)
            if not m:
                continue
            line = m.group(1).strip()
            if line in ("true", "false"):
                streamed = line == "true"
            else:
                streamed = None  # a match arm: conditional
            break
        reliable: bool | None = None
        libs = list(d.rglob("lib.rs")) + list(d.rglob("mod.rs"))
        for path in libs:
            body = path.read_text(encoding="utf-8", errors="replace")
            m = re.search(r"IS_RELIABLE\s*:\s*bool\s*=\s*(true|false)\s*;", body)
            if m:
                reliable = m.group(1) == "true"
                break
        out[spelling] = (streamed, reliable)
    if not out:
        findings.append(
            f"no link crate was read under `{links}`, so the oracle arm graded "
            f"nothing while reporting clean"
        )
    return out, findings


def oracle_findings(text: str, root: pathlib.Path) -> list[str]:
    streamed, reliable, findings = wz_axes(text)
    if findings:
        return findings
    up, findings = upstream_axes(root)
    if findings:
        return findings
    graded = 0
    for link in sorted(VARIANTS.values()):
        if link not in up:
            findings.append(
                f"`{link}` has no upstream link crate at this checkout, so wz's "
                f"answer for it is graded against nothing"
            )
            continue
        up_s, up_r = up[link]
        conditional = link in CONDITIONAL
        if conditional and up_s is not None and up_r is not None:
            findings.append(
                f"`{link}` is declared CONDITIONAL, but upstream answers it with "
                f"constants (streamed={up_s}, reliable={up_r}). Remove the "
                f"declaration and grade it, or the declaration is a way to stop "
                f"grading a link"
            )
            continue
        if not conditional and (up_s is None or up_r is None):
            findings.append(
                f"`{link}` answers upstream with a match rather than a constant "
                f"and is not declared in `CONDITIONAL`; say which arm wz is and "
                f"why"
            )
            continue
        if conditional:
            continue
        graded += 1
        if streamed.get(link) != up_s:
            findings.append(
                f"`{link}`: wz says streamed={streamed.get(link)} and upstream "
                f"says {up_s}. `z_link_is_streamed` is upstream's accessor, so "
                f"upstream is the specification"
            )
        if reliable.get(link) != up_r:
            findings.append(
                f"`{link}`: wz says reliable={reliable.get(link)} and upstream "
                f"says {up_r}. `z_link_reliability` is upstream's accessor, so "
                f"upstream is the specification"
            )
    if graded == 0:
        findings.append(
            "the oracle arm graded ZERO links -- every one was conditional or "
            "absent, which is a population that could never disagree"
        )
    return findings


def check(require: bool) -> int:
    text = (ROOT / WZ_LINK).read_text(encoding="utf-8")
    findings = agreement_findings(text)
    root = upstream_root()
    if root is None:
        if require:
            findings.append(
                "the ORACLE arm needs a checkout of the pinned zenoh and found "
                "none, and `--require` was given. A skip must not report green "
                "(open debt 581 condition 3). Point ZENOHD_SRC at one."
            )
        else:
            print(
                "  upstream-link-axis: the ORACLE arm (does wz agree with each "
                "upstream link crate?) is SKIPPED -- no checkout of the pinned "
                "zenoh on this machine. The AGREEMENT arm graded only; do not "
                "read it as 'wz agrees with upstream'."
            )
    else:
        findings.extend(oracle_findings(text, root))

    if findings:
        print(f"upstream-link-axis: FAIL -- {len(findings)} finding(s)")
        for f in findings:
            print(f"  {f}")
        return 1
    where = "code and table agree" if root is None else f"graded against {root}"
    print(
        f"  upstream-link-axis: wz's {len(VARIANTS)} link protocol(s) carry a "
        f"streamed / reliable answer each, {where}; "
        f"{len(CONDITIONAL)} declared conditional"
    )
    return 0


def _fixture(streamed: str, reliable: str, table: str) -> str:
    return (
        "impl InterceptorLink {\n"
        f"{table}"
        "    pub fn is_streamed(&self) -> bool {\n"
        f"        !matches!(self, {streamed})\n"
        "    }\n"
        "    pub fn is_reliable(&self) -> bool {\n"
        f"        !matches!(self, {reliable})\n"
        "    }\n"
        "}\n"
    )


def _table(rows: dict[str, tuple[bool, bool]]) -> str:
    out = "    /// | link | streamed | reliable |\n    /// |---|---|---|\n"
    for link, (s, r) in rows.items():
        out += f"    /// | {link} | {str(s).lower()} | {str(r).lower()} |\n"
    return out


TRUTH = {
    "tcp": (True, True),
    "udp": (False, False),
    "tls": (True, True),
    "quic": (True, True),
    "quic-datagram": (False, False),
    "serial": (False, False),
    "unixpipe": (True, True),
    "unixsock-stream": (True, True),
    "vsock": (True, True),
    "ws": (False, True),
}
GOOD_S = (
    "InterceptorLink::Udp | InterceptorLink::QuicDatagram | "
    "InterceptorLink::Serial | InterceptorLink::Ws"
)
GOOD_R = "InterceptorLink::Udp | InterceptorLink::QuicDatagram | InterceptorLink::Serial"


def _upstream_tree(tmp: pathlib.Path, ws_streamed: str = "false") -> pathlib.Path:
    """A miniature `io/zenoh-links` answering the real values."""
    consts = {
        "tcp": ("true", "true"),
        "udp": (None, None),
        "tls": ("true", "true"),
        "quic": ("true", "true"),
        "quic_datagram": ("false", "false"),
        "serial": ("false", "false"),
        "unixpipe": ("true", "true"),
        "unixsock_stream": ("true", "true"),
        "vsock": ("true", "true"),
        "ws": (ws_streamed, "true"),
    }
    links = tmp / "io" / "zenoh-links"
    for name, (s, r) in consts.items():
        d = links / f"zenoh-link-{name}" / "src"
        d.mkdir(parents=True, exist_ok=True)
        if s is None:
            body = (
                "fn is_streamed(&self) -> bool {\n"
                "    match &self.variant {\n        Reliable(_) => true,\n    }\n}\n"
            )
            lib = "// no constant: this one matches\n"
        else:
            body = f"fn is_streamed(&self) -> bool {{\n    {s}\n}}\n"
            lib = f"pub const IS_RELIABLE: bool = {r};\n"
        (d / "unicast.rs").write_text(body, encoding="utf-8")
        (d / "lib.rs").write_text(lib, encoding="utf-8")
    return tmp


def selftest() -> int:
    good = _fixture(GOOD_S, GOOD_R, _table(TRUTH))
    if agreement_findings(good):
        print(
            f"upstream-link-axis: SELFTEST FAIL -- the CONTROL must pass and it "
            f"reported {agreement_findings(good)}"
        )
        return 1
    # The agreement arm, driven through each way it refuses.
    drifted = dict(TRUTH)
    drifted["ws"] = (True, True)
    cases = {
        "table-drift": _fixture(GOOD_S, GOOD_R, _table(drifted)),
        "no-table": _fixture(GOOD_S, GOOD_R, ""),
        "missing-row": _fixture(
            GOOD_S, GOOD_R, _table({k: v for k, v in TRUTH.items() if k != "vsock"})
        ),
        "unknown-variant": _fixture(
            GOOD_S + " | InterceptorLink::Carrier", GOOD_R, _table(TRUTH)
        ),
        "not-a-matches": (
            "impl InterceptorLink {\n"
            "    pub fn is_streamed(&self) -> bool { true }\n"
            "    pub fn is_reliable(&self) -> bool { true }\n}\n"
        ),
    }
    for name, body in cases.items():
        if not agreement_findings(body):
            print(
                f"upstream-link-axis: SELFTEST FAIL -- `{name}` must be refused "
                f"by the agreement arm and it passed"
            )
            return 1
    with tempfile.TemporaryDirectory() as tmp:
        root = _upstream_tree(pathlib.Path(tmp))
        if oracle_findings(good, root):
            print(
                f"upstream-link-axis: SELFTEST FAIL -- the oracle CONTROL must "
                f"pass and it reported {oracle_findings(good, root)}"
            )
            return 1
        # R2259's ACTUAL defect, as the fixture: wz calls ws streamed.
        r2259 = _fixture(
            "InterceptorLink::Udp | InterceptorLink::QuicDatagram",
            "InterceptorLink::Udp | InterceptorLink::QuicDatagram",
            _table({**TRUTH, "serial": (True, True), "ws": (True, True)}),
        )
        got = oracle_findings(r2259, root)
        if not any("`ws`" in f and "streamed" in f for f in got):
            print(
                f"upstream-link-axis: SELFTEST FAIL -- the oracle arm must catch "
                f"R2259's own defect (wz calling `ws` streamed) and it reported "
                f"{got}"
            )
            return 1
        if not any("`serial`" in f for f in got):
            print(
                f"upstream-link-axis: SELFTEST FAIL -- the oracle arm must catch "
                f"`serial` too; it reported {got}"
            )
            return 1
    # An undeclared conditional, and a declared one that is not.
    with tempfile.TemporaryDirectory() as tmp:
        root = _upstream_tree(pathlib.Path(tmp))
        d = root / "io" / "zenoh-links" / "zenoh-link-ws" / "src"
        d.joinpath("unicast.rs").write_text(
            "fn is_streamed(&self) -> bool {\n    match x {\n        _ => true,\n    }\n}\n",
            encoding="utf-8",
        )
        d.joinpath("lib.rs").write_text("// matched\n", encoding="utf-8")
        got = oracle_findings(good, root)
        if not any("not declared in `CONDITIONAL`" in f for f in got):
            print(
                f"upstream-link-axis: SELFTEST FAIL -- a link that answers with a "
                f"match and is not declared must be refused; got {got}"
            )
            return 1
    with tempfile.TemporaryDirectory() as tmp:
        root = _upstream_tree(pathlib.Path(tmp))
        d = root / "io" / "zenoh-links" / "zenoh-link-udp" / "src"
        d.joinpath("unicast.rs").write_text(
            "fn is_streamed(&self) -> bool {\n    false\n}\n", encoding="utf-8"
        )
        d.joinpath("lib.rs").write_text(
            "pub const IS_RELIABLE: bool = false;\n", encoding="utf-8"
        )
        got = oracle_findings(good, root)
        if not any("declared CONDITIONAL, but upstream answers it with" in f for f in got):
            print(
                f"upstream-link-axis: SELFTEST FAIL -- a DECLARED conditional that "
                f"upstream answers with constants must be refused, or the "
                f"declaration stops grading a link for free; got {got}"
            )
            return 1
    # An empty upstream tree grades nothing and must say so.
    with tempfile.TemporaryDirectory() as tmp:
        empty = pathlib.Path(tmp)
        (empty / "io" / "zenoh-links").mkdir(parents=True)
        if not any("graded\nnothing" in f or "graded nothing" in f for f in oracle_findings(good, empty)):
            print(
                "upstream-link-axis: SELFTEST FAIL -- an upstream tree with no "
                "link crate must FAIL rather than report clean"
            )
            return 1
    print(
        "upstream-link-axis: selftest OK -- the agreement arm refuses a table "
        "that drifts from the code, a missing table, a missing row, a variant "
        "`VARIANTS` does not know and a body that is not a `matches!`; the "
        "oracle arm reproduces R2259's own defect on BOTH links it got wrong, "
        "refuses an undeclared conditional, refuses a DECLARED conditional that "
        "upstream answers with constants, and refuses an empty upstream tree -- "
        "past two clean controls"
    )
    return 0


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--check", action="store_true", help="read the real tree")
    ap.add_argument(
        "--require",
        action="store_true",
        help="the oracle arm must run; a missing checkout FAILs instead of skipping",
    )
    ap.add_argument("--selftest", action="store_true", help="drive the verdicts")
    args = ap.parse_args(argv)
    if args.selftest:
        return selftest()
    if args.check:
        return check(args.require)
    ap.print_usage()
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
