#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

"""R2221 (no register item) -- how many HANDSHAKE-NEGOTIATED axes are witnessed
by a test that drives a FOREIGN implementation, as a ratcheted number.

The citation is `no register item` for the reason `negotiated_axis_witness_gate.py`
gives for its own: the item this answers -- unregistered open-debt item 568,
the consuming surface's 2026-08-31 claim -- lives in the agent-memory register,
which has no store id for `gate_provenance_lint.py` to resolve.

## Why this exists BESIDE the gate it extends, and not inside it

Item 568 closed with a named obligation: decide whether R2199's gate should be
widened, "because otherwise the next axis stands in the same place". R2199 asks
whether every negotiated axis is asserted SOMEWHERE, and its own output is the
argument for widening -- every one of the nine axes reports its FIRST witness
from a `wz-runtime-tokio` test, i.e. from a wire this tree wrote. An encoder and
a decoder in one tree that are wrong together satisfy every such assertion.

It is a SEPARATE gate because the widening needs a second population -- which
tests can witness a foreign implementation -- and that population already has an
owner: `crossimpl_corpus.py`, which derives it by resolving the harness call
graph for Layer A4. Re-deriving foreignness inside R2199's gate would be a
second implementation of it, and this tree's standing finding is that the second
copy is the one that goes wrong (`PassiveFrame::unit_len`'s own doc records the
last time: `wz-analyze` re-read the two prefix bytes and walked the second
message of a batch as the first).

So NEITHER derivation is written here. The axes come from
`negotiated_axis_witness_gate`, the corpus from `crossimpl_corpus`, and this
file is the JOIN plus the ratchet.

## What it checks

For each axis R2199 derives, whether ANY of its result accessors is read inside
an assertion in a file the corpus calls foreign. Then:

  * RED when the axis population is EMPTY. Inherited from the gate it extends,
    and for the same reason: a join over nothing reports success.
  * RED when the corpus is EMPTY. The same trap one level over: if
    `crossimpl_corpus` stopped resolving, every axis would read SYNTHETIC-ONLY
    and the floor would catch it -- but only by luck, and only downward.
  * RED when the genuine count is BELOW the floor. An axis lost its genuine
    witness.
  * RED when the genuine count is ABOVE the floor. The round that gains one
    raises the floor in the same commit, which is what keeps the number a
    ratchet rather than a high-water mark nobody maintains.

A floor rather than "all axes must be genuine": today's answer is not nine, and
a gate that reds on the whole tree from birth is a stop-the-line, not a measure.
What it forbids is going backwards silently, and it names the SYNTHETIC-ONLY
axes on every run so which ones are outstanding is a number anyone can read
instead of a claim in a reply.
"""

import os
import pathlib
import re
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

import crossimpl_corpus  # noqa: E402
import negotiated_axis_witness_gate as base  # noqa: E402

REPO = pathlib.Path(__file__).resolve().parents[2]

# MEASURED, not chosen — the number this gate itself prints. Raise it in the
# commit that adds the next witness; the gate reds in both directions, which is
# the point.
#
# R2221 set this to 3: `body:batch_size` (already witnessed, in
# `wz_fragment_tx_to_pico_zsub.rs`), plus `body:seq_num_res` and
# `ext:negotiate_patch_against_peer` from `wz_negotiated_axes_zenohd_interop.rs`.
#
# R2224 (open-debt item 572) raises it to 7, and the four are NOT four new
# tests. TWO of them — compression and lowlatency — were already witnessed
# against a real zenohd when the item was filed, and this gate could not see it
# because the accessor is read inside the BINARY the test drives.
# `reported_witnesses` is that false negative repaired, and the item's premise
# ("the handle is on the wz side, so a green says nothing") is refuted for both:
# each has its handle on the ROUTER's config and a calibration twin against a
# stock one. The other two are new — `body:req_id_res` and
# `ext:negotiate_qos_against_peer`, both in
# `wz_negotiated_axes_zenohd_interop.rs`, each with an orthogonal mutation
# recorded in that file's ledger entry.
#
# The two that remain SYNTHETIC-ONLY are named on every run and are not an
# oversight. `ext:negotiate_qos_link_against_peer` and
# `ext:negotiate_shm_against_peer` sit outside the set of negotiated axes the
# consuming surface claimed; shm additionally reads its witness through a HELPER
# that parses the demo line, so the value is laundered out of every assertion —
# the shape R2221 recorded as "assert where the session is alive", and the
# repair for it is that leg's to make, not this gate's to chase.
GENUINE_AXIS_FLOOR = 7


def corpus_files() -> set[str]:
    """The foreign-interop corpus, as paths relative to `crates/`.

    Derived by `crossimpl_corpus`, whose own paths are relative to the repo
    root; `base.rust_sources` reports relative to `crates/`. Normalised here so
    the join compares one spelling.
    """
    out: set[str] = set()
    for cf in crossimpl_corpus.scan_all():
        if not cf.classes:
            continue
        rel = cf.path.relative_to(crossimpl_corpus.REPO_ROOT)
        parts = rel.parts
        if parts and parts[0] == "crates":
            rel = pathlib.Path(*parts[1:])
        out.add(str(rel))
    return out


def driven_binaries() -> dict[str, list[str]]:
    """Which BINARIES each foreign-corpus file drives.

    R2224 (open-debt item 572). The same `crossimpl_corpus` resolution the
    corpus itself comes from, asked for its other field: `binary_freshness_lint`
    already reads `cf.binaries` for the staleness question, and this is that
    population put to the witness question. Keyed and spelled exactly like
    `corpus_files`, so the two join without a second normalisation.
    """
    out: dict[str, list[str]] = {}
    for cf in crossimpl_corpus.scan_all():
        if not cf.classes:
            continue
        rel = cf.path.relative_to(crossimpl_corpus.REPO_ROOT)
        parts = rel.parts
        if parts and parts[0] == "crates":
            rel = pathlib.Path(*parts[1:])
        out[str(rel)] = sorted(cf.binaries or [])
    return out


def axes_of(root: pathlib.Path):
    """R2199's axis derivation, called rather than copied.

    Returns `(axes, unresolved)` in that gate's own shape:
    `(label, slot, [(accessor, co-required token or None)])`.
    """
    actions = (root / base.ACTIONS_REL).read_text(encoding="utf-8")
    caps = (root / base.CAPS_REL).read_text(encoding="utf-8")
    bodies = base.fn_bodies(actions)

    axes = []
    unresolved = []
    for method in base.negotiation_methods(actions):
        slot = base.written_slot(method, bodies)
        if slot is None:
            unresolved.append(method)
            continue
        axes.append(
            (
                f"ext:{method}",
                slot,
                [(a, None) for a in base.accessors_reading(slot, bodies)],
            )
        )
    fields = base.caps_fields(caps)
    for field in fields:
        axes.append(
            (
                f"body:{field}",
                field,
                [
                    (name, field if shared else None)
                    for name, shared in base.body_accessors(field, fields, bodies)
                ],
            )
        )
    return axes, unresolved


# R2224 (open-debt item 572) — the log macros a driven binary reports through.
# Derived from what the binaries actually call rather than chosen: `log::` is
# this workspace's only logging facade in a `main`.
LOG_OPEN_RE = re.compile(r"\blog::(?:error|warn|info|debug|trace)!\s*\(")

# String literals inside one macro argument list, escapes honoured.
STR_LIT_RE = re.compile(r'"((?:[^"\\]|\\.)*)"')

# How much of a demo's line an assertion must reproduce before the two are
# joined. MEASURED, not chosen: the two lines this join exists for share
# `compression negotiated = ` (25 chars) and `lowlatency negotiated = ` (24)
# with their assertions, while the LONGEST run any two DIFFERENT demo lines in
# this tree share is ` negotiated = ` (14). Twenty sits between them with room
# on both sides, and `a_short_literal_cannot_be_joined` is the control that
# keeps it from being lowered quietly.
MIN_SHARED_LITERAL = 20


def macro_invocations(text: str, opener: re.Pattern[str]) -> list[str]:
    """Every `opener` macro's argument list, by bracket matching.

    `base.assert_arguments`' scanner with the pattern as a parameter — the same
    string-and-escape handling, because a format string full of braces is
    exactly what a line-anchored or brace-counting reader gets wrong.
    """
    out: list[str] = []
    for m in opener.finditer(text):
        open_at = m.end() - 1
        depth = 0
        in_str = False
        esc = False
        for k in range(open_at, len(text)):
            ch = text[k]
            if esc:
                esc = False
                continue
            if ch == "\\":
                esc = True
                continue
            if ch == '"':
                in_str = not in_str
                continue
            if in_str:
                continue
            if ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
                if depth == 0:
                    out.append(text[open_at + 1 : k])
                    break
    return out


def reported_prefixes(accessor: str, binary_sources: list[str]) -> list[str]:
    """The literal PREFIX of every log line a binary emits FROM `accessor`.

    The macro's own argument list must read the accessor, so a line that merely
    happens to sit near one is not a report of it. The prefix ends at the first
    `{`, which is where the value the accessor returned begins.
    """
    call = re.compile(r"\.\s*" + re.escape(accessor) + r"\s*\(")
    out: list[str] = []
    for text in binary_sources:
        if not call.search(text):
            continue
        for args in macro_invocations(text, LOG_OPEN_RE):
            if not call.search(args):
                continue
            lit = STR_LIT_RE.search(args)
            if not lit:
                continue
            prefix = lit.group(1).split("{", 1)[0]
            if prefix and prefix not in out:
                out.append(prefix)
    return out


def shared_head(prefix: str, literal: str) -> int:
    """How much of `literal`'s HEAD is a TAIL of `prefix`.

    The convention this measures is the one the tree writes: a binary logs
    `"<label>: <fact> = {}"` and a test asserts on `"<fact> = <value>"`, so the
    assertion's head is a suffix of the format string's prefix. Longest-common-
    SUBSTRING would also match two unrelated lines through a shared ` = `;
    anchoring one end of each makes the run mean "the same line".

    ⚠ AN OVERLAP THAT IS NOT A WORD IS NOT AN OVERLAP, and this is a repair
    rather than a refinement. MEASURED on the first run: every report in the
    tree ends its prefix with a space, so every assertion literal beginning with
    one scored 1 — and thirty-nine of those arrived as "near miss" complaints
    about files that are not near anything. Requiring a run of three letters
    makes the number mean "these two lines share a WORD", which is what a
    near-miss report has to be about to be worth printing.
    """
    for k in range(min(len(prefix), len(literal)), 0, -1):
        if prefix.endswith(literal[:k]):
            return k if re.search(r"[A-Za-z]{3}", literal[:k]) else 0
    return 0


def reported_witnesses(
    accessor: str,
    sources: list[tuple[str, str]],
    corpus: set[str],
    binaries: dict[str, list[str]],
    crate_sources,
) -> tuple[list[str], list[str]]:
    """Corpus files that witness `accessor` ACROSS A PROCESS BOUNDARY.

    # The false negative this repairs, measured

    `base.witnesses` asks whether an assertion reads the accessor IN THE FILE.
    Three of this tree's foreign-interop legs cannot answer that and are genuine
    anyway: the reading happens inside the binary the test DRIVES. R2224
    measured it — `wz_compression_zenohd_interop.rs` runs `wz-ap-demo` against a
    zenohd configured `transport/unicast/compression/enabled:true`, the demo
    logs `is_compression()`, the test asserts on that line, and a calibration
    twin against a STOCK zenohd asserts the opposite. That is a router-side
    handle with an orthogonal control — a stronger witness than several the
    in-file rule already accepts — and it read SYNTHETIC-ONLY.

    # Why this cannot manufacture a witness

    Three conditions, each derived and each necessary. The file must be in the
    FOREIGN corpus; it must drive a binary whose OWN source reads the accessor
    inside a log macro; and it must ASSERT on that line, matched by
    `shared_head` rather than by a name either side could have chosen freely.
    Shorten the format string to game it and `MIN_SHARED_LITERAL` refuses —
    loudly, as the second return value, because a report nothing can join is a
    gap and not an absence.

    Returns `(witness paths, unjoinable complaints)`.
    """
    hits: list[str] = []
    unjoinable: list[str] = []
    text_of = dict(sources)
    for path in sorted(corpus):
        text = text_of.get(path)
        if text is None:
            continue
        for binary in binaries.get(path, []):
            prefixes = reported_prefixes(accessor, crate_sources(binary))
            for prefix in prefixes:
                best = 0
                for arg in base.assert_arguments(text):
                    for lit in STR_LIT_RE.finditer(arg):
                        best = max(best, shared_head(prefix, lit.group(1)))
                if best >= MIN_SHARED_LITERAL:
                    if path not in hits:
                        hits.append(path)
                elif 0 < best:
                    unjoinable.append(
                        f"genuine-axis: {path} asserts on {best} character(s) of "
                        f"{binary}'s {accessor!r} report {prefix!r}, below the "
                        f"{MIN_SHARED_LITERAL} this join requires -- a report a "
                        "test cannot be shown to be reading is not a witness"
                    )
    return sorted(hits), unjoinable


def join(axes, sources, corpus: set[str]) -> dict[str, list[str]]:
    """Which FOREIGN-CORPUS files witness each axis.

    A pure function of its three inputs so the selftest can drive it with
    fixtures instead of a repository.
    """
    out: dict[str, list[str]] = {}
    for axis, _slot, accessors in axes:
        hits: list[str] = []
        for accessor, also in accessors:
            for path in base.witnesses(accessor, sources, also):
                if path in corpus and path not in hits:
                    hits.append(path)
        out[axis] = sorted(hits)
    return out


def decide(genuine: int, floor: int) -> tuple[int, str | None]:
    """The ratchet, split out so both directions are testable."""
    if genuine < floor:
        return 1, (
            f"genuine-axis: {genuine} axis(es) have a foreign witness and the "
            f"floor is {floor} -- an axis LOST its genuine witness. Restore it, "
            "or lower the floor in the same commit and say which axis went"
        )
    if genuine > floor:
        return 1, (
            f"genuine-axis: {genuine} axis(es) have a foreign witness and the "
            f"floor is {floor} -- raise GENUINE_AXIS_FLOOR to {genuine} in this "
            "commit. A high-water mark nobody moves stops being a ratchet"
        )
    return 0, None


def run(root: pathlib.Path, floor: int = GENUINE_AXIS_FLOOR) -> int:
    axes, unresolved = axes_of(root)
    failures: list[str] = []
    if not axes:
        failures.append(
            "genuine-axis: the axis population is EMPTY -- the join would "
            "report over nothing"
        )
    for method in unresolved:
        failures.append(
            f"genuine-axis: {method} writes a slot the axis derivation cannot "
            "resolve -- UNCLASSIFIED is red, not a pass"
        )

    corpus = corpus_files()
    if not corpus:
        failures.append(
            "genuine-axis: the FOREIGN CORPUS is empty -- every axis would read "
            "synthetic-only and this gate would be measuring its own inability "
            "to resolve the corpus"
        )

    sources = base.rust_sources(root / "crates")
    witnessed = join(axes, sources, corpus)

    # R2224 (open-debt item 572) — the SECOND route to a witness, joined here
    # rather than folded into `join` so the report can say WHICH route each
    # axis took. An axis read inside the binary a corpus test drives is
    # witnessed by that test; see `reported_witnesses` for what stops that from
    # being a way to manufacture one.
    binaries = driven_binaries()
    crate_dirs = {b for bins in binaries.values() for b in bins}
    crate_text: dict[str, list[str]] = {}
    for binary in sorted(crate_dirs):
        src = root / "crates" / binary / "src"
        if not src.is_dir():
            failures.append(
                f"genuine-axis: the corpus drives {binary!r} and there is no "
                f"{src.relative_to(root)} to read its reports from -- "
                "UNCLASSIFIED is red, not a pass"
            )
            crate_text[binary] = []
            continue
        crate_text[binary] = [t for _, t in base.rust_sources(src)]

    reported: dict[str, list[str]] = {}
    for axis, _slot, accessors in axes:
        hits: list[str] = []
        for accessor, _also in accessors:
            found, unjoinable = reported_witnesses(
                accessor, sources, corpus, binaries, lambda b: crate_text.get(b, [])
            )
            failures.extend(unjoinable)
            for path in found:
                if path not in hits:
                    hits.append(path)
        reported[axis] = sorted(hits)

    genuine = 0
    for axis in sorted(witnessed):
        hits = witnessed[axis]
        via = reported.get(axis, [])
        if hits:
            genuine += 1
            more = f" (+{len(hits) - 1} more)" if len(hits) > 1 else ""
            print(f"  genuine-axis: {axis} witnessed by {hits[0]}{more}")
        elif via:
            genuine += 1
            more = f" (+{len(via) - 1} more)" if len(via) > 1 else ""
            print(
                f"  genuine-axis: {axis} witnessed by {via[0]}{more} "
                "(through the binary it drives)"
            )
        else:
            print(f"  genuine-axis: {axis} SYNTHETIC-ONLY -- no foreign-corpus witness")

    print(
        f"  genuine-axis: {genuine} of {len(axes)} axis(es) have a foreign "
        f"witness (floor {floor})"
    )
    rc, message = decide(genuine, floor)
    if message:
        failures.append(message)
    for line in failures:
        print("  " + line)
    return 1 if failures else rc


def selftest() -> int:
    """The join and the ratchet, each driven to both verdicts.

    Fixtures rather than a repository: the two DERIVATIONS this gate stands on
    have their own selftests in their own files, and re-testing them here would
    be the third copy of what this module exists not to copy. What is this
    module's own is the join and the floor, and those are what is driven.

    The join fixture carries a witness in a NON-corpus file for the same axis
    that has one in a corpus file -- so an implementation that ignored the
    corpus entirely, which is exactly what R2199 does, passes arm 1 and fails
    arm 2.
    """
    rc = 0
    # METHOD calls, because that is the shape the derivation matches -- a
    # result accessor is read off a session, and a bare-function fixture would
    # pass arm 1 for the wrong reason (nothing matched at all) and fail arm 2.
    # Measured: the first draft of this fixture did exactly that.
    sources = [
        (
            "wz-runtime-tokio/tests/synthetic.rs",
            "fn t() { assert_eq!(actions.negotiated_alpha(), 1); }",
        ),
        (
            "wz-integration-tests/tests/foreign.rs",
            "fn t() { assert_eq!(actions.negotiated_beta(), 2); }",
        ),
    ]
    corpus = {"wz-integration-tests/tests/foreign.rs"}
    axes = [
        ("ext:alpha", "alpha", [("negotiated_alpha", None)]),
        ("ext:beta", "beta", [("negotiated_beta", None)]),
    ]
    got = join(axes, sources, corpus)

    def arm(n: int, what: str, ok: bool) -> int:
        print(f"  selftest arm {n} -- {what}: {'ok' if ok else 'FAIL'}")
        return 0 if ok else 1

    rc |= arm(
        1,
        "an axis asserted ONLY in a non-corpus file is synthetic-only",
        got["ext:alpha"] == [],
    )
    rc |= arm(
        2,
        "an axis asserted in a corpus file is genuine",
        got["ext:beta"] == ["wz-integration-tests/tests/foreign.rs"],
    )
    rc |= arm(3, "below the floor is RED", decide(1, 2)[0] == 1)
    rc |= arm(4, "above the floor is RED", decide(3, 2)[0] == 1)
    rc |= arm(5, "at the floor is GREEN", decide(2, 2)[0] == 0)
    # The corpus is not allowed to be the thing that makes a run green. An
    # empty corpus makes every axis synthetic-only, which `decide` alone would
    # answer with "below the floor" -- true, but for the wrong reason, and only
    # while the floor is above zero.
    rc |= arm(
        6,
        "an EMPTY corpus witnesses nothing",
        join(axes, sources, set()) == {"ext:alpha": [], "ext:beta": []},
    )

    # ── R2224 (open-debt item 572) — the PROCESS-BOUNDARY join ────────────
    #
    # Four arms, and three of them are NARROWING. A widening that only ever
    # demonstrates the thing it now accepts is a redefinition with a test
    # beside it; what says this one is a repair is that the same fixture, with
    # ONE condition removed each time, goes back to synthetic-only.
    reported_sources = [
        (
            "wz-integration-tests/tests/drives.rs",
            'fn t() { assert!(log.contains("gamma capability negotiated = true")); }',
        ),
        (
            "wz-integration-tests/tests/mentions.rs",
            'fn t() { let _ = "gamma capability negotiated = true"; assert!(other); }',
        ),
    ]
    reported_corpus = {
        "wz-integration-tests/tests/drives.rs",
        "wz-integration-tests/tests/mentions.rs",
    }
    demo = [
        'fn m() { log::info!("demo: gamma capability negotiated = {}", s.is_gamma()); }'
    ]
    silent = [
        'fn m() { log::info!("demo: gamma capability negotiated = {}", s.other()); }'
    ]
    driving = {
        "wz-integration-tests/tests/drives.rs": ["demo"],
        "wz-integration-tests/tests/mentions.rs": ["demo"],
    }
    # A report whose whole prefix is EIGHT characters, asserted in full by a
    # corpus file: a real word-level overlap, and still under the bar.
    short_sources = [
        (
            "wz-integration-tests/tests/drives.rs",
            'fn t() { assert!(log.contains("gamma = true")); }',
        )
    ]
    short = ['fn m() { log::info!("gamma = {}", s.is_gamma()); }']

    hits, unjoinable = reported_witnesses(
        "is_gamma", reported_sources, reported_corpus, driving, lambda _b: demo
    )
    rc |= arm(
        7,
        "an axis read inside the binary a corpus test DRIVES is genuine",
        hits == ["wz-integration-tests/tests/drives.rs"] and not unjoinable,
    )
    rc |= arm(
        8,
        "a corpus file that MENTIONS the line outside an assertion is not a witness",
        "wz-integration-tests/tests/mentions.rs" not in hits,
    )
    rc |= arm(
        9,
        "a binary that logs the line WITHOUT reading the accessor witnesses nothing",
        reported_witnesses(
            "is_gamma", reported_sources, reported_corpus, driving, lambda _b: silent
        )
        == ([], []),
    )
    hits, unjoinable = reported_witnesses(
        "is_gamma",
        short_sources,
        {"wz-integration-tests/tests/drives.rs"},
        driving,
        lambda _b: short,
    )
    rc |= arm(
        10,
        "a report too SHORT to join is refused BY NAME rather than ignored",
        hits == [] and len(unjoinable) == 1,
    )
    # And the file must be in the corpus at all, which is the condition the
    # whole gate rests on and the one an over-eager join would drop first.
    rc |= arm(
        11,
        "a driven binary's report in a NON-corpus file is not a witness",
        reported_witnesses(
            "is_gamma", reported_sources, set(), driving, lambda _b: demo
        )
        == ([], []),
    )
    return rc


def main(argv: list[str]) -> int:
    mode = argv[1] if len(argv) > 1 else "--check"
    if mode == "--selftest":
        return selftest()
    if mode != "--check":
        print(
            f"genuine_axis_witness_gate: unknown argument {mode!r} "
            "-- use --check or --selftest",
            file=sys.stderr,
        )
        return 2
    return run(pathlib.Path(os.environ.get("WZ_REPO_ROOT", REPO)))


if __name__ == "__main__":
    sys.exit(main(sys.argv))
