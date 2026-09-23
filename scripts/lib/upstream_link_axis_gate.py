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

## R2810 — the population is the ENUM, and a `match` is graded per arm

Until R2810 the set of kinds this gate graded was a dict written in this file,
ten entries long. R2810 added an eleventh kind to `LinkKind`, and the gate went
on printing "wz's 10 link kind(s) ... graded" and passing: the new kind named no
variant in either `!matches!` body (it is streamed AND reliable), so nothing the
gate read mentioned it, and a hand-written population cannot notice what it was
never told. The population is now READ off `pub enum LinkKind`, and the mapping
below must cover it exactly — an enum variant the mapping does not name is a
finding, as is a mapping entry the enum does not have, and an enum that cannot
be read (population zero) is a finding rather than a clean grade.

The same round retired the `CONDITIONAL` escape. Upstream's udp link answers
both accessors with a `match` on its variant, and this gate used to DECLARE it
conditional and stop grading it, on the ground that "wz has no reliable-UDP
link". wz now has one, so the declaration had become a way to leave a link
ungraded. Instead each wz kind names the upstream ARM(S) it stands for, and the
oracle reads the arms out of upstream's `match` and grades each kind against
its own: `Udp` against `Connected` and `Unconnected`, `UdpReliable` against
`Reliable`. Held in every direction: a kind mapped to arms of a link that
answers with a constant is a finding, a link that answers with a `match` while
its kind names no arm is a finding, and an upstream arm no wz kind stands for
is a finding — that last one is the parity statement the old declaration was
quietly waiving.

Upstream's `is_reliable` for most links is `super::IS_RELIABLE`, the crate's
constant; for udp's two datagram arms it is that constant too, inside the
`match`. So the oracle resolves the constant wherever it appears rather than
reading it in place of the function, which is what the pre-R2810 reader did —
and for udp that constant is the answer of two arms out of three.
"""

from __future__ import annotations

import argparse
import pathlib
import re
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[2]

#: wz's link module, whose two functions and doc table this grades.
WZ_LINK = "crates/wz-session-core/src/link.rs"

#: The upstream answer a wz kind stands for: which link crate (its directory
#: suffix, with `-` for `_`) and, where that crate answers with a `match` on its
#: variant, WHICH arms. `None` means the crate answers with a constant.
#:
#: This mapping is knowledge — nothing in either tree says which upstream crate a
#: wz kind mirrors — but it is not the POPULATION. The population is read off
#: `pub enum LinkKind` (see `wz_kinds`), and this dict must cover it exactly.
#: The first element is the kind's ROW in wz's doc table.
#:
#: R2794 (open-debt item 814) -- these two axes moved from `InterceptorLink` to
#: `LinkKind`. They are the LINK's own answers, and the rule-facing enum no longer
#: carries a datagram value (upstream files that link under `quic`). The kind
#: still does, and it has to: `quic-datagram` answers unstreamed and unreliable,
#: which `quic` does not.
KINDS: dict[str, tuple[str, str, tuple[str, ...] | None]] = {
    "Tcp": ("tcp", "tcp", None),
    "Udp": ("udp", "udp", ("Connected", "Unconnected")),
    "UdpReliable": ("udp-reliable", "udp", ("Reliable",)),
    "Tls": ("tls", "tls", None),
    "Quic": ("quic", "quic", None),
    "QuicDatagram": ("quic-datagram", "quic-datagram", None),
    "Serial": ("serial", "serial", None),
    "Unixpipe": ("unixpipe", "unixpipe", None),
    "UnixsockStream": ("unixsock-stream", "unixsock-stream", None),
    "Vsock": ("vsock", "vsock", None),
    "Ws": ("ws", "ws", None),
}

ENUM = re.compile(r"pub enum LinkKind \{(.*?)\n\}", re.S)
MATCHES = re.compile(
    r"pub fn (is_streamed|is_reliable)\(&self\) -> bool \{\s*!matches!\((.*?)\)\s*\}",
    re.S,
)
ROW = re.compile(
    r"^\s*///\s*\|\s*([a-z][a-z-]*)\s*\|\s*(true|false)\s*\|\s*(true|false|TRUE|FALSE)\s*\|",
    re.M | re.I,
)


def wz_kinds(text: str) -> list[str]:
    """The variants of `pub enum LinkKind`, in declaration order.

    Doc comments and attributes are stripped first, so a variant NAMED in prose
    (this enum's docs name several) is not counted twice or invented.
    """
    m = ENUM.search(text)
    if not m:
        return []
    body = re.sub(r"^\s*(///|//|#\[).*$", "", m.group(1), flags=re.M)
    return re.findall(r"^\s*([A-Z][A-Za-z0-9]*)\s*,", body, re.M)


def population_findings(
    kinds: list[str], mapping: dict[str, tuple[str, str, tuple[str, ...] | None]]
) -> list[str]:
    """The mapping must cover the enum exactly, and the enum must be read."""
    if not kinds:
        return [
            f"no `pub enum LinkKind` variant was read in {WZ_LINK}, so the gate's "
            f"population is ZERO -- that is a failed reading, not a clean grade"
        ]
    findings: list[str] = []
    unmapped = [k for k in kinds if k not in mapping]
    if unmapped:
        findings.append(
            f"`LinkKind` has {unmapped}, which `KINDS` does not map -- say which "
            f"upstream link (and, where it answers with a `match`, which arm) each "
            f"one stands for, or it is graded against nothing"
        )
    stale = [k for k in mapping if k not in kinds]
    if stale:
        findings.append(f"`KINDS` maps {stale}, which `LinkKind` does not have")
    return findings


def wz_axes(
    text: str, mapping: dict[str, tuple[str, str, tuple[str, ...] | None]]
) -> tuple[dict[str, bool], dict[str, bool], list[str]]:
    """(streamed, reliable) per KIND, from wz's two `matches!` bodies.

    Read from the CODE, never from the table: the table is the other half this
    gate compares against, and deriving both from one of them is the shape that
    can never fail. Keyed by the enum's own variant names.
    """
    kinds = wz_kinds(text)
    findings = population_findings(kinds, mapping)
    axes: dict[str, dict[str, bool]] = {}
    for name, body in MATCHES.findall(text):
        negated = set(re.findall(r"LinkKind::([A-Za-z]+)", body))
        # R2794 -- a body read as naming NO variant is a failure, not an answer.
        # Every link would then grade streamed and reliable, which is how an
        # extractor whose pattern stopped matching the enum's name reports: the
        # R2794 rename did exactly that to this line before it was updated. No
        # real body is empty, so zero names can only mean the reading failed.
        if not negated:
            findings.append(
                f"`{name}`'s `!matches!` body names no `LinkKind` variant -- the "
                f"reading found nothing to grade, which is not the same as every "
                f"link being streamed and reliable"
            )
        unknown = negated - set(kinds)
        if unknown:
            findings.append(
                f"`{name}` names {sorted(unknown)}, which `LinkKind` does not "
                f"declare -- the body and the enum disagree about what exists"
            )
        axes[name] = {kind: kind not in negated for kind in kinds}
    for want in ("is_streamed", "is_reliable"):
        if want not in axes:
            findings.append(
                f"`{want}` was not found as a `!matches!` body in {WZ_LINK}; this "
                f"gate reads the arms out of that shape and cannot grade another"
            )
    return axes.get("is_streamed", {}), axes.get("is_reliable", {}), findings


def wz_table(text: str) -> dict[str, tuple[bool, bool]]:
    """The doc TABLE, as its own reading of the same fact, keyed by row label."""
    out: dict[str, tuple[bool, bool]] = {}
    for link, streamed, reliable in ROW.findall(text):
        if link in ("link", "-"):
            continue
        out[link] = (streamed.lower() == "true", reliable.lower() == "true")
    return out


def agreement_findings(
    text: str, mapping: dict[str, tuple[str, str, tuple[str, ...] | None]] = KINDS
) -> list[str]:
    """wz's code and wz's table must say the same thing, for every kind."""
    streamed, reliable, findings = wz_axes(text, mapping)
    if findings:
        return findings
    table = wz_table(text)
    if not table:
        return [
            f"no `| link | streamed | reliable |` table was found in {WZ_LINK}, so "
            f"the agreement arm graded nothing while reporting clean"
        ]
    rows = {mapping[k][0]: k for k in streamed}
    missing = set(rows) - set(table)
    if missing:
        findings.append(
            f"the doc table does not list {sorted(missing)}; every kind the enum "
            f"has must have a row, or a wrong arm can hide in the gap"
        )
    extra = set(table) - set(rows)
    if extra:
        findings.append(f"the doc table lists {sorted(extra)}, which the enum has not")
    for row, (want_s, want_r) in sorted(table.items()):
        kind = rows.get(row)
        if kind is None:
            continue
        if streamed[kind] != want_s:
            findings.append(
                f"`{row}`: the code says streamed={streamed[kind]} and the doc "
                f"table says {want_s}"
            )
        if reliable[kind] != want_r:
            findings.append(
                f"`{row}`: the code says reliable={reliable[kind]} and the doc "
                f"table says {want_r}"
            )
    return findings


def upstream_root() -> pathlib.Path | None:
    """A checkout of the pinned zenoh, or `None`.

    DELEGATED to `upstream_citation_anchor_gate.upstream_root`, which is itself
    derived through `upstream_feature_census.upstream_anchors()` — the chain
    `build-zenohd.sh` mirrors, WITH the version check that makes it the pinned
    one rather than whichever checkout sorts first. A second discovery of my own
    could disagree about which upstream the tree means, and that disagreement is
    what open debt 578 was opened for. One derivation, three consumers.
    """
    try:
        sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
        import upstream_citation_anchor_gate as cite
    except ImportError:  # pragma: no cover - the sibling is tracked beside this
        return None
    root = cite.upstream_root()
    # That chain answers "the pinned zenoh"; this gate additionally needs the
    # link crates to BE there, and says so rather than reporting an empty grade.
    if root is not None and (root / "io" / "zenoh-links").is_dir():
        return root
    return None


def _fn_body(src: str, name: str) -> str | None:
    """The body of `fn <name>(&self) -> bool { ... }`, braces balanced."""
    m = re.search(rf"fn {name}\(&self\) -> bool \{{", src)
    if not m:
        return None
    depth, i = 1, m.end()
    while i < len(src) and depth:
        depth += {"{": 1, "}": -1}.get(src[i], 0)
        i += 1
    return src[m.end() : i - 1] if depth == 0 else None


#: One answer: a constant, or a map from upstream variant name to its answer.
Answer = bool | dict[str, bool] | None


def _resolve(expr: str, is_reliable_const: bool | None) -> bool | None:
    expr = expr.strip().strip("{}").strip().rstrip(",").strip()
    if expr in ("true", "false"):
        return expr == "true"
    if re.fullmatch(r"(super::|crate::)?IS_RELIABLE", expr):
        return is_reliable_const
    return None


def _answer(body: str | None, is_reliable_const: bool | None) -> Answer:
    """A literal, the crate's constant, or a `match` read arm by arm."""
    if body is None:
        return None
    if "match" not in body:
        return _resolve(body, is_reliable_const)
    arms: dict[str, bool] = {}
    for pattern, value in re.findall(
        r"((?:[A-Za-z_][A-Za-z0-9_]*::)*[A-Za-z_][A-Za-z0-9_]*\(_\)"
        r"(?:\s*\|\s*(?:[A-Za-z_][A-Za-z0-9_]*::)*[A-Za-z_][A-Za-z0-9_]*\(_\))*)"
        r"\s*=>\s*(\{[^{}]*\}|[^,\n]+)",
        body,
    ):
        resolved = _resolve(value, is_reliable_const)
        if resolved is None:
            return None
        for variant in re.findall(r"([A-Za-z_][A-Za-z0-9_]*)\(_\)", pattern):
            arms[variant] = resolved
    return arms or None


def upstream_axes(root: pathlib.Path) -> tuple[dict[str, tuple[Answer, Answer]], list[str]]:
    """Each upstream link crate's own two answers, per crate spelling."""
    findings: list[str] = []
    out: dict[str, tuple[Answer, Answer]] = {}
    links = root / "io" / "zenoh-links"
    for d in sorted(links.iterdir()):
        if not d.is_dir() or not d.name.startswith("zenoh-link-"):
            continue
        spelling = d.name[len("zenoh-link-") :].replace("_", "-")
        unicast = list(d.rglob("unicast.rs"))
        if not unicast:
            continue
        const: bool | None = None
        for path in list(d.rglob("lib.rs")) + list(d.rglob("mod.rs")):
            m = re.search(
                r"IS_RELIABLE\s*:\s*bool\s*=\s*(true|false)\s*;",
                path.read_text(encoding="utf-8", errors="replace"),
            )
            if m:
                const = m.group(1) == "true"
                break
        streamed: Answer = None
        reliable: Answer = None
        for path in unicast:
            src = path.read_text(encoding="utf-8", errors="replace")
            if streamed is None:
                streamed = _answer(_fn_body(src, "is_streamed"), const)
            if reliable is None:
                reliable = _answer(_fn_body(src, "is_reliable"), const)
        # A crate whose unicast impl defines no `is_reliable` answers with its
        # constant through the trait default, which is where the pre-R2810
        # reader looked first; keep that as the fallback, not the rule.
        if reliable is None:
            reliable = const
        out[spelling] = (streamed, reliable)
    if not out:
        findings.append(
            f"no link crate was read under `{links}`, so the oracle arm graded "
            f"nothing while reporting clean"
        )
    return out, findings


def oracle_findings(
    text: str,
    root: pathlib.Path,
    mapping: dict[str, tuple[str, str, tuple[str, ...] | None]] = KINDS,
) -> list[str]:
    streamed, reliable, findings = wz_axes(text, mapping)
    if findings:
        return findings
    up, findings = upstream_axes(root)
    if findings:
        return findings
    graded = 0
    covered: dict[str, set[str]] = {}
    for kind in sorted(streamed):
        row, crate, arms = mapping[kind]
        if crate not in up:
            findings.append(
                f"`{row}` stands for upstream `{crate}`, which has no link crate at "
                f"this checkout, so wz's answer is graded against nothing"
            )
            continue
        up_s, up_r = up[crate]
        matched = isinstance(up_s, dict) or isinstance(up_r, dict)
        if up_s is None or up_r is None:
            findings.append(
                f"`{crate}`'s upstream answer could not be read (streamed={up_s}, "
                f"reliable={up_r}); an unreadable answer grades nothing"
            )
            continue
        if arms is not None and not matched:
            findings.append(
                f"`{row}` names upstream arm(s) {list(arms)}, but upstream `{crate}` "
                f"answers with constants (streamed={up_s}, reliable={up_r}). Map it "
                f"to the crate, or the arm names stop grading a link for free"
            )
            continue
        if arms is None and matched:
            findings.append(
                f"upstream `{crate}` answers with a `match` on its variant and "
                f"`{row}` names no arm; say which arm(s) wz's kind stands for"
            )
            continue
        pairs = (
            [(crate, up_s, up_r)]
            if arms is None
            else [
                (f"{crate}::{arm}", _arm(up_s, arm), _arm(up_r, arm)) for arm in arms
            ]
        )
        for where, want_s, want_r in pairs:
            if want_s is None or want_r is None:
                findings.append(
                    f"`{row}` stands for `{where}`, which upstream's `match` does "
                    f"not have"
                )
                continue
            graded += 1
            if streamed[kind] != want_s:
                findings.append(
                    f"`{row}`: wz says streamed={streamed[kind]} and upstream "
                    f"`{where}` says {want_s}. `z_link_is_streamed` is upstream's "
                    f"accessor, so upstream is the specification"
                )
            if reliable[kind] != want_r:
                findings.append(
                    f"`{row}`: wz says reliable={reliable[kind]} and upstream "
                    f"`{where}` says {want_r}. `z_link_reliability` is upstream's "
                    f"accessor, so upstream is the specification"
                )
        if arms is not None:
            covered.setdefault(crate, set()).update(arms)
    # Every arm of a crate wz mirrors must be stood for by some kind: an arm no
    # kind covers is an upstream variant wz does not have, which is the parity
    # gap the pre-R2810 `CONDITIONAL` declaration used to waive.
    for crate, arms in sorted(covered.items()):
        up_arms = set()
        for answer in up[crate]:
            if isinstance(answer, dict):
                up_arms |= set(answer)
        if up_arms - arms:
            findings.append(
                f"upstream `{crate}` has variant arm(s) {sorted(up_arms - arms)} that "
                f"no wz `LinkKind` stands for"
            )
    if graded == 0:
        findings.append(
            "the oracle arm graded ZERO answers -- a population that could never "
            "disagree"
        )
    return findings


def _arm(answer: Answer, arm: str) -> bool | None:
    return answer.get(arm) if isinstance(answer, dict) else None


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
    kinds = wz_kinds(text)
    by_arm = sum(1 for k in kinds if KINDS[k][2] is not None)
    where = "code and table agree" if root is None else f"graded against {root}"
    print(
        f"  upstream-link-axis: wz's {len(kinds)} link kind(s), read off "
        f"`pub enum LinkKind`, carry a streamed / reliable answer each, {where}; "
        f"{by_arm} graded per upstream `match` arm"
    )
    return 0


# ─── selftest ────────────────────────────────────────────────────────────────

TRUTH = {
    "tcp": (True, True),
    "udp": (False, False),
    "udp-reliable": (True, True),
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
    "LinkKind::Udp | LinkKind::QuicDatagram | "
    "LinkKind::Serial | LinkKind::Ws"
)
GOOD_R = "LinkKind::Udp | LinkKind::QuicDatagram | LinkKind::Serial"


def _enum(kinds: list[str]) -> str:
    lines = "".join(f"    /// the {k} kind\n    {k},\n" for k in kinds)
    return f"pub enum LinkKind {{\n{lines}}}\n"


def _fixture(streamed: str, reliable: str, table: str, kinds: list[str] | None = None) -> str:
    return (
        _enum(list(KINDS) if kinds is None else kinds)
        + "impl LinkKind {\n"
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


UDP_MATCH = (
    "fn is_reliable(&self) -> bool {\n"
    "    match &self.variant {\n"
    "        V::Reliable(_) => true,\n"
    "        V::Connected(_) | V::Unconnected(_) => {\n"
    "            super::IS_RELIABLE\n"
    "        }\n"
    "    }\n"
    "}\n"
    "fn is_streamed(&self) -> bool {\n"
    "    match &self.variant {\n"
    "        V::Reliable(_) => true,\n"
    "        V::Connected(_) | V::Unconnected(_) => false,\n"
    "    }\n"
    "}\n"
)


def _upstream_tree(tmp: pathlib.Path, ws_streamed: str = "false") -> pathlib.Path:
    """A miniature `io/zenoh-links` answering the real values in the real shapes."""
    consts = {
        "tcp": ("true", "true"),
        "udp": (None, "false"),
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
            body = UDP_MATCH
        else:
            body = (
                "fn is_reliable(&self) -> bool {\n    super::IS_RELIABLE\n}\n"
                f"fn is_streamed(&self) -> bool {{\n    {s}\n}}\n"
            )
        (d / "unicast.rs").write_text(body, encoding="utf-8")
        (d / "lib.rs").write_text(f"const IS_RELIABLE: bool = {r};\n", encoding="utf-8")
    return tmp


def _refused(label: str, got: list[str], needle: str) -> bool:
    if any(needle in f for f in got):
        return True
    print(f"upstream-link-axis: SELFTEST FAIL -- `{label}` must be refused ({needle!r}); got {got}")
    return False


def selftest() -> int:
    good = _fixture(GOOD_S, GOOD_R, _table(TRUTH))
    if agreement_findings(good):
        print(
            f"upstream-link-axis: SELFTEST FAIL -- the CONTROL must pass and it "
            f"reported {agreement_findings(good)}"
        )
        return 1
    drifted = dict(TRUTH)
    drifted["ws"] = (True, True)
    cases = {
        "table-drift": (_fixture(GOOD_S, GOOD_R, _table(drifted)), "doc table says"),
        "no-table": (_fixture(GOOD_S, GOOD_R, ""), "no `| link"),
        "missing-row": (
            _fixture(GOOD_S, GOOD_R, _table({k: v for k, v in TRUTH.items() if k != "vsock"})),
            "does not list",
        ),
        "unknown-variant": (
            _fixture(GOOD_S + " | LinkKind::Carrier", GOOD_R, _table(TRUTH)),
            "does not declare",
        ),
        "not-a-matches": (
            _enum(list(KINDS))
            + "impl LinkKind {\n"
            "    pub fn is_streamed(&self) -> bool { true }\n"
            "    pub fn is_reliable(&self) -> bool { true }\n}\n",
            "was not found as a `!matches!` body",
        ),
        # R2794 -- well-formed bodies naming a DIFFERENT enum; the all-true table
        # makes only the empty-read guard able to object (see the history of
        # this case: with the real table the table arm refused it regardless).
        "names-another-enum": (
            _fixture(
                GOOD_S.replace("LinkKind::", "InterceptorLink::"),
                GOOD_R.replace("LinkKind::", "InterceptorLink::"),
                _table({link: (True, True) for link in TRUTH}),
            ),
            "names no `LinkKind` variant",
        ),
        # R2810 -- THE DEFECT THIS ROUND FOUND: a kind the enum has and the
        # mapping does not. It names no variant in either body, so every reading
        # the pre-R2810 gate made passed over it. The table even carries a row
        # for it, so nothing but the population check can object.
        "enum-grew-past-the-mapping": (
            _fixture(
                GOOD_S,
                GOOD_R,
                _table({**TRUTH, "carrier": (True, True)}),
                kinds=list(KINDS) + ["Carrier"],
            ),
            "which `KINDS` does not map",
        ),
        # R2810 -- population zero is a failed reading, not a clean grade.
        "no-enum": (
            _fixture(GOOD_S, GOOD_R, _table(TRUTH)).replace("pub enum LinkKind", "enum Other"),
            "population is ZERO",
        ),
    }
    for name, (body, needle) in cases.items():
        if not _refused(name, agreement_findings(body), needle):
            return 1
    with tempfile.TemporaryDirectory() as tmp:
        root = _upstream_tree(pathlib.Path(tmp))
        if oracle_findings(good, root):
            print(
                f"upstream-link-axis: SELFTEST FAIL -- the oracle CONTROL must "
                f"pass and it reported {oracle_findings(good, root)}"
            )
            return 1
        # R2259's ACTUAL defect, as the fixture: wz calls ws and serial streamed.
        r2259 = _fixture(
            "LinkKind::Udp | LinkKind::QuicDatagram",
            "LinkKind::Udp | LinkKind::QuicDatagram",
            _table({**TRUTH, "serial": (True, True), "ws": (True, True)}),
        )
        got = oracle_findings(r2259, root)
        if not (_refused("r2259-ws", got, "`ws`: wz says streamed") and _refused("r2259-serial", got, "`serial`")):
            return 1
        # R2810 -- a reliable-udp kind answering like the DATAGRAM arm. Graded
        # against upstream's `Reliable(_)` arm, it must be refused; the old
        # gate skipped the whole udp crate as conditional and could not.
        wrong_arm = _fixture(
            GOOD_S + " | LinkKind::UdpReliable",
            GOOD_R + " | LinkKind::UdpReliable",
            _table({**TRUTH, "udp-reliable": (False, False)}),
        )
        if not _refused("reliable-udp-graded-per-arm", oracle_findings(wrong_arm, root), "udp::Reliable"):
            return 1
        # R2810 -- the inverse: a plain-udp kind answering like the reliable arm.
        # `is_reliable` for the datagram arms is `super::IS_RELIABLE` INSIDE the
        # match, so this is also the control that the constant is resolved there.
        wrong_datagram = _fixture(
            "LinkKind::QuicDatagram | LinkKind::Serial | LinkKind::Ws",
            "LinkKind::QuicDatagram | LinkKind::Serial",
            _table({**TRUTH, "udp": (True, True)}),
        )
        got = oracle_findings(wrong_datagram, root)
        if not (_refused("udp-connected", got, "udp::Connected") and _refused("udp-unconnected", got, "udp::Unconnected")):
            return 1
    # A link that answers with a `match` while its kind names no arm.
    with tempfile.TemporaryDirectory() as tmp:
        root = _upstream_tree(pathlib.Path(tmp))
        d = root / "io" / "zenoh-links" / "zenoh-link-ws" / "src"
        d.joinpath("unicast.rs").write_text(
            "fn is_streamed(&self) -> bool {\n    match &self.v {\n        V::A(_) => false,\n    }\n}\n",
            encoding="utf-8",
        )
        if not _refused("undeclared-match", oracle_findings(good, root), "names no arm"):
            return 1
    # Kinds naming arms of a link that answers with constants.
    with tempfile.TemporaryDirectory() as tmp:
        root = _upstream_tree(pathlib.Path(tmp))
        d = root / "io" / "zenoh-links" / "zenoh-link-udp" / "src"
        d.joinpath("unicast.rs").write_text(
            "fn is_streamed(&self) -> bool {\n    false\n}\n", encoding="utf-8"
        )
        if not _refused("arms-of-a-constant", oracle_findings(good, root), "answers with constants"):
            return 1
    # An upstream arm no wz kind stands for (the old `CONDITIONAL` waiver).
    with tempfile.TemporaryDirectory() as tmp:
        root = _upstream_tree(pathlib.Path(tmp))
        d = root / "io" / "zenoh-links" / "zenoh-link-udp" / "src"
        d.joinpath("unicast.rs").write_text(
            UDP_MATCH.replace(
                "V::Reliable(_) => true,\n        V::Connected",
                "V::Reliable(_) => true,\n        V::Multicast(_) => false,\n        V::Connected",
            ),
            encoding="utf-8",
        )
        if not _refused("uncovered-arm", oracle_findings(good, root), "no wz `LinkKind` stands for"):
            return 1
    # An empty upstream tree grades nothing and must say so.
    with tempfile.TemporaryDirectory() as tmp:
        empty = pathlib.Path(tmp)
        (empty / "io" / "zenoh-links").mkdir(parents=True)
        if not _refused("empty-upstream", oracle_findings(good, empty), "graded nothing"):
            return 1
    print(
        "upstream-link-axis: selftest OK -- the agreement arm refuses a table "
        "that drifts from the code, a missing table, a missing row, a body naming "
        "a variant the enum lacks, a body that is not a `matches!`, a body naming "
        "another enum, an enum grown past the mapping, and an unreadable enum; the "
        "oracle arm reproduces R2259's defect on both links, grades each udp kind "
        "against its own upstream arm in both directions, refuses an undeclared "
        "match, arms named on a constant, an upstream arm no kind stands for, and "
        "an empty upstream tree -- past two clean controls"
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
