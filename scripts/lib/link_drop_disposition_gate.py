#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
r"""R2423 (no register item) — every reason a link driver can REFUSE a write must
have a decided disposition on the session's send gate, and a test that witnesses
it.

The citation is `no register item` for the reason `debt_plane_census.py` gives
for its own: the item this closes -- unregistered open-debt item 688 -- lives in
the agent-memory register, which has no store id for `gate_provenance_lint.py`
to resolve. The item is named in prose here instead.

## The defect this was written after, in the shape it actually had

`BoxedLinkDriver::send_blocking` returns `LinkSendOutcome`, and a refusal
carries a `LinkDropCause`. Seven production drivers produce
`Dropped(WriterGone)` -- five tokio pipelines, `session_glue`, and the lwIP
driver -- and until R2423 the ONLY consumer of any refusal was the `n_dropped`
counter in `emit_on_link`, which is `transport-stats`-gated and therefore not
compiled into a default build at all.

So the refusal was, on a default build, observed by nothing. `WriterGone`'s own
doc-comment said every later write "drops the same way until the session notices
the link is down" -- a clause naming a mechanism that did not exist. Meanwhile
the F2 gate (`session_send_available`) carries the explicit promise that a data
send "rejects typed rather than vanishing into a dead writer channel", and it
read ESTABLISHMENT state only. A writer sealed under a still-established link
(R2367 made `WriterHandle`'s drop a seal) was invisible to it.

Measured cost, against a genuine zenohd on 2026-09-07: wz's REST bridge answered
`200 OK` to an SSE subscribe whose `Declare(DeclSubscriber)` reached no wire,
because `declare_subscriber` was told the send had succeeded, and then streamed
nothing but keepalives for the whole budget. A consumer holding only the HTTP
responses could not attribute it, and their pin migration stopped on it.

## Why a gate, and why this SHAPE of gate

The repair is per-cause: `WriterGone` closes the gate, `Oversize` deliberately
does not (one frame too large for one write on a healthy link -- closing there
would turn an oversize frame into a dead session). That makes the seam's match
EXHAUSTIVE, which is a compile-time tie: a new variant cannot inherit "counted,
then ignored", it has to be decided.

Exhaustiveness is a decision, NOT a proof that either arm fires -- the lesson
this tree pays for repeatedly (`reference_lesson_a_successor_chain_is_not_a_walk
_over_the_type`). So this gate grades the second half: every variant is also
NAMED BY A TEST. Without that, an arm could be written, compile, and never be
reached by anything.

## What it derives rather than declares

Nothing here carries a copy of the variant list:

  * the POPULATION is parsed out of `LinkDropCause`'s own `enum` body in
    `crates/wz-session-core/src/link.rs`, doc comments and attributes stripped.
    An empty population is a HARD FAIL -- a gate whose subject vanished must not
    report green, which is the trap `count_guard_lint.py` had to be taught to
    refuse.
  * the DISPOSITION site is parsed out of `emit_on_link`'s `dispose` closure in
    `session_actions.rs`, anchored to the closure binding so a match moved
    elsewhere reads as absent rather than as covered.
  * the WITNESSES are the test functions in
    `crates/wz-runtime-tokio/src/session/tests.rs` that name a variant, found by
    reading `#[test]` bodies -- so a variant named only in a doc comment does
    not count as witnessed.

Every anchor is a hard fail when it cannot be found.
"""

import argparse
import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]

LINK_RS = REPO / "crates/wz-session-core/src/link.rs"
ACTIONS_RS = REPO / "crates/wz-session-core/src/session_actions.rs"
TESTS_RS = REPO / "crates/wz-runtime-tokio/src/session/tests.rs"

ENUM_NAME = "LinkDropCause"
# The binding the disposition lives behind. Anchored, so a match that migrates
# out of this closure reads as ABSENT rather than as still covering the enum.
DISPOSE_ANCHOR = "let dispose = |outcome: crate::link::LinkSendOutcome|"


def strip_comments(text: str) -> str:
    """Drop `//`-comments (doc comments included) and attributes.

    A variant's rationale routinely names its SIBLING (`Oversize`'s doc explains
    why it is not `WriterGone`), so a reader that keeps comments would count
    prose as membership -- the class R2083 fixed in the config-key gate when a
    regex counted quoted phrases inside an array's own rationales as entries.
    """
    out = []
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("//") or stripped.startswith("#["):
            continue
        out.append(line.split("//", 1)[0])
    return "\n".join(out)


def enum_variants(path: Path, name: str) -> list[str]:
    """The variant identifiers of `enum <name>` in `path`, in declaration order."""
    src = path.read_text(encoding="utf-8")
    m = re.search(rf"\benum\s+{re.escape(name)}\s*\{{", src)
    if not m:
        return []
    # Brace-match the body rather than regex it: a variant with a payload or a
    # nested block would end a lazy match early.
    depth = 0
    start = m.end() - 1
    end = None
    for i in range(start, len(src)):
        if src[i] == "{":
            depth += 1
        elif src[i] == "}":
            depth -= 1
            if depth == 0:
                end = i
                break
    if end is None:
        return []
    body = strip_comments(src[start + 1 : end])
    return re.findall(r"^\s*([A-Z][A-Za-z0-9]*)\s*(?:\(|,|=|$)", body, re.M)


def dispose_arms(path: Path, anchor: str, variants: list[str]) -> tuple[set[str], bool]:
    """Which variants the disposition closure names, and whether the anchor exists.

    Read from the anchor to the end of its closure body by brace matching, so a
    variant named in a NEIGHBOURING function cannot be mistaken for a decided
    arm.
    """
    src = path.read_text(encoding="utf-8")
    at = src.find(anchor)
    if at < 0:
        return set(), False
    depth = 0
    seen_open = False
    end = len(src)
    for i in range(at, len(src)):
        if src[i] == "{":
            depth += 1
            seen_open = True
        elif src[i] == "}":
            depth -= 1
            if seen_open and depth == 0:
                end = i
                break
    body = strip_comments(src[at:end])
    named = {v for v in variants if re.search(rf"\b{re.escape(v)}\b", body)}
    return named, True


def witnesses(path: Path, variants: list[str]) -> dict[str, list[str]]:
    """Variant -> the `#[test]` function names whose BODY names it.

    Only test bodies count. A variant named in a doc comment above a test is the
    claim, not the witness, and the whole point of this half of the gate is that
    the two are different things.
    """
    src = path.read_text(encoding="utf-8")
    found: dict[str, list[str]] = {v: [] for v in variants}
    for m in re.finditer(r"#\[test\]\s*(?:\n\s*)*fn\s+([a-z0-9_]+)\s*\(", src):
        fn = m.group(1)
        depth = 0
        seen_open = False
        end = len(src)
        for i in range(m.end(), len(src)):
            if src[i] == "{":
                depth += 1
                seen_open = True
            elif src[i] == "}":
                depth -= 1
                if seen_open and depth == 0:
                    end = i
                    break
        body = strip_comments(src[m.end() : end])
        for v in variants:
            if re.search(rf"\b{re.escape(v)}\b", body):
                found[v].append(fn)
    return found


def main() -> int:
    ap = argparse.ArgumentParser(
        description=(
            "Grade that every LinkDropCause has a decided disposition on the F2 "
            "send gate and a test that witnesses it."
        )
    )
    ap.add_argument(
        "--selftest",
        action="store_true",
        help="drive the readers against inline fixtures instead of the tree",
    )
    args = ap.parse_args()

    if args.selftest:
        return selftest()

    failures: list[str] = []

    for path in (LINK_RS, ACTIONS_RS, TESTS_RS):
        if not path.is_file():
            failures.append(f"anchor file missing: {path.relative_to(REPO)}")
    if failures:
        return report(failures)

    variants = enum_variants(LINK_RS, ENUM_NAME)
    if not variants:
        # The population trap, named: no variants means the reader lost its
        # subject (enum renamed, moved, or reshaped), and a gate that cannot see
        # its population must never report green.
        failures.append(
            f"derived 0 variants for `{ENUM_NAME}` from "
            f"{LINK_RS.relative_to(REPO)} — the population is empty, so this "
            f"gate has no subject. Fix the reader, do not lower the bar."
        )
        return report(failures)

    named, anchored = dispose_arms(ACTIONS_RS, DISPOSE_ANCHOR, variants)
    if not anchored:
        failures.append(
            f"disposition anchor not found in {ACTIONS_RS.relative_to(REPO)}: "
            f"expected the closure binding `{DISPOSE_ANCHOR}`. A match that "
            f"moved is not a match that covers."
        )
    else:
        for v in variants:
            if v not in named:
                failures.append(
                    f"`{ENUM_NAME}::{v}` has no arm in the disposition closure — "
                    f"decide it (close the F2 gate, or say in a comment why the "
                    f"link survives this cause)."
                )

    seen = witnesses(TESTS_RS, variants)
    for v in variants:
        if not seen[v]:
            failures.append(
                f"`{ENUM_NAME}::{v}` is named by no `#[test]` body in "
                f"{TESTS_RS.relative_to(REPO)} — an exhaustive match is a "
                f"decision, not a proof that the arm fires."
            )

    print(
        f"link-drop-disposition: {len(variants)} cause(s) "
        f"({', '.join(variants)}); {len(named)} with an arm; witnesses "
        + ", ".join(f"{v}={len(seen[v])}" for v in variants)
    )
    return report(failures)


def report(failures: list[str]) -> int:
    if failures:
        print("link-drop-disposition FAIL:", file=sys.stderr)
        for line in failures:
            print(f"  - {line}", file=sys.stderr)
        return 1
    return 0


def selftest() -> int:
    """Drive both readers against fixtures, including the shapes that fooled
    earlier gates in this tree: a sibling named inside a doc comment, and a
    variant named only in a doc comment above a test."""
    import tempfile

    checks = 0
    failures: list[str] = []

    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)

        # 1. The population reader ignores prose that names a sibling.
        link = tmp / "link.rs"
        link.write_text(
            "/// Why a driver refused a write.\n"
            "#[derive(Debug)]\n"
            "pub enum LinkDropCause {\n"
            "    /// Named here on purpose: this doc mentions WriterGone.\n"
            "    Oversize,\n"
            "    /// The writer is gone.\n"
            "    WriterGone,\n"
            "}\n",
            encoding="utf-8",
        )
        got = enum_variants(link, "LinkDropCause")
        checks += 1
        if got != ["Oversize", "WriterGone"]:
            failures.append(f"population reader: expected two variants, got {got}")

        # 2. A renamed enum yields an EMPTY population, which main() must treat
        #    as a failure rather than as "nothing to check".
        checks += 1
        if enum_variants(link, "SomethingElse") != []:
            failures.append("population reader: a missing enum must yield []")

        # 3. The disposition reader is anchored, and does not credit a
        #    neighbouring function that happens to name a variant.
        actions = tmp / "actions.rs"
        actions.write_text(
            "fn neighbour() {\n"
            "    // WriterGone is named here, in another function.\n"
            "    let _ = LinkDropCause::WriterGone;\n"
            "}\n"
            "fn emit_on_link() {\n"
            "    let dispose = |outcome: crate::link::LinkSendOutcome| {\n"
            "        match cause {\n"
            "            crate::link::LinkDropCause::Oversize => {}\n"
            "        }\n"
            "    };\n"
            "}\n",
            encoding="utf-8",
        )
        named, anchored = dispose_arms(actions, DISPOSE_ANCHOR, got)
        checks += 1
        if not anchored:
            failures.append("disposition reader: the anchor was not found")
        checks += 1
        if named != {"Oversize"}:
            failures.append(
                f"disposition reader: expected only the in-closure arm, got {named}"
            )

        # 4. A missing anchor is reported as missing, not as full coverage.
        bare = tmp / "bare.rs"
        bare.write_text("fn emit_on_link() {}\n", encoding="utf-8")
        _, anchored_bare = dispose_arms(bare, DISPOSE_ANCHOR, got)
        checks += 1
        if anchored_bare:
            failures.append("disposition reader: a missing anchor must report absent")

        # 5. The witness reader counts test BODIES only — a variant named in the
        #    doc comment above a test is the claim, not the witness.
        tests = tmp / "tests.rs"
        tests.write_text(
            "/// This doc names WriterGone but the body does not.\n"
            "#[test]\n"
            "fn doc_only() {\n"
            "    assert!(true);\n"
            "}\n"
            "#[test]\n"
            "fn body_names_it() {\n"
            "    let _ = LinkDropCause::Oversize;\n"
            "}\n",
            encoding="utf-8",
        )
        seen = witnesses(tests, got)
        checks += 1
        if seen["Oversize"] != ["body_names_it"]:
            failures.append(
                f"witness reader: expected the body match only, got {seen['Oversize']}"
            )
        checks += 1
        if seen["WriterGone"] != []:
            failures.append(
                f"witness reader: a doc-only mention must not witness, got "
                f"{seen['WriterGone']}"
            )

    if failures:
        print("link-drop-disposition selftest FAIL:", file=sys.stderr)
        for line in failures:
            print(f"  - {line}", file=sys.stderr)
        return 1
    print(f"link-drop-disposition selftest: {checks}/{checks} check(s) passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
