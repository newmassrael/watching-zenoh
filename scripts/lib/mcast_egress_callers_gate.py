#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

"""R2343 (no register item) - who can ATTACH a multicast egress group, and under
which feature, because a residual was withdrawn on that partition.

The citation is `no register item` in the sense the gates beside it use: this
answers for one clause of ONE atom (`router-multicast-faces`), not for a numbered
register entry.

## What was withdrawn, and why a sentence would not have held it

That atom carried a residual saying the multicast egress core is gated on the
broad `transport-multicast` feature "rather than on this atom's own feature, so
turning the atom off does not remove the plane" -- filed as a mis-scoped gate.

R2343 measured it. The OBSERVATION is true and the PRESCRIPTION is false. Moving
those items onto `router-multicast-faces` would not delete dead code: unit tests
exercise the egress plane under `transport-multicast` ALONE, with the atom off,
and re-gating deletes that coverage. The residual was therefore withdrawn.

R2335 measured what happens to a correction that only states a fact: the next
reader greps the claim and gets the sentence back. So the fact is graded here.

## Why `attach_mcast_group` alone, and not the whole plane

The first draft of this gate watched `broadcast_to_mcast_groups` too and reported
that every production caller was atom-gated. That was wrong twice over, and both
errors are worth keeping:

  * its cfg attribution scanned a fixed window of preceding lines and collected
    any `#[cfg]` it passed, so a call inherited gates belonging to unrelated
    items above it. The attribution below walks the enclosing `fn` / `mod` chain
    by brace depth instead, and reads the attributes attached to each.
  * the two entry points are not the same question. `broadcast_to_mcast_groups`
    IS called from production under the broad feature -- unconditionally, at the
    `route_push` tail, which is the documented design -- and it fans out to an
    EMPTY collection unless a group was attached. `attach_mcast_group` is the
    only thing that makes it non-empty, so it is the one that decides whether
    the plane is reachable at all.

Lumping them together produced a green verdict for a false reason, which is the
failure mode this workspace keeps paying for: a check whose population is wider
than its question can be satisfied by the wrong member.

## What is graded

Population: every call to `attach_mcast_group` in a tracked `*.rs`, excluding
comments and the definition. Empty population is a FAIL, not a pass.

  1. At least one TEST caller reachable with `transport-multicast` and WITHOUT
     `router-multicast-faces` -- the withdrawal's basis.
  2. Every PRODUCTION caller under `router-multicast-faces`. If an egress-only
     production attach appears, the partition this round measured has changed
     and that residual needs re-reading, so it reds rather than passing.
"""

from __future__ import annotations

import pathlib
import re
import subprocess
import sys

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]

ENTRY_POINT = "attach_mcast_group"
ATOM_FEATURE = "router-multicast-faces"
BROAD_FEATURE = "transport-multicast"

CALL = re.compile(rf"\b{ENTRY_POINT}\s*\(")
DEF = re.compile(rf"\bfn\s+{ENTRY_POINT}\b")
TEST_ATTR = re.compile(r"^\s*#\[(?:tokio::)?test\b")
CFG_TEST = re.compile(r"^\s*#\[cfg\(test\)\]")
CFG = re.compile(r"^\s*#!?\[cfg\((.*)\)\]\s*$")
ATTR_OR_DOC = re.compile(r"^\s*(?:#!?\[|///|//!|//|$)")
COMMENT = re.compile(r"^\s*(?://|/\*|\*)")


class InputError(RuntimeError):
    """The gate could not read what it grades."""


def tracked_rust(root: pathlib.Path) -> list[pathlib.Path]:
    """Every tracked `*.rs`, from the tree's own VCS rather than a glob."""
    try:
        out = subprocess.run(
            ["git", "-C", str(root), "ls-files", "*.rs"],
            capture_output=True, text=True, check=True,
        ).stdout
    except (OSError, subprocess.CalledProcessError) as exc:
        raise InputError(f"cannot list tracked rust ({exc})") from exc
    return [root / line for line in out.splitlines() if line]


def _attrs_above(lines: list[str], idx: int) -> tuple[list[str], bool]:
    """`(cfg bodies, is a test)` from the attributes CONTIGUOUS above `idx`.

    Contiguous is the whole rule: an attribute belongs to the item it is written
    against, and stopping at the first line that is not an attribute, doc or
    blank is what keeps a neighbour's gate from being read as this one's.
    """
    cfgs: list[str] = []
    is_test = False
    for k in range(idx - 1, -1, -1):
        line = lines[k]
        if not ATTR_OR_DOC.match(line):
            break
        if TEST_ATTR.match(line) or CFG_TEST.match(line):
            is_test = True
        m = CFG.match(line)
        if m:
            cfgs.append(m.group(1))
    return cfgs, is_test


def _depth_delta(line: str) -> int:
    """Brace delta for `line`, ignoring braces in line comments and char/str."""
    body = line.split("//")[0]
    body = re.sub(r'"(?:\\.|[^"\\])*"', '""', body)
    body = re.sub(r"'(?:\\.|[^'\\])'", "''", body)
    return body.count("{") - body.count("}")


def call_sites(rel: str, text: str) -> list[tuple[int, str, list[str]]]:
    """`(line, scope, cfg bodies)` for each call to the entry point.

    Scope and gating come from the chain of enclosing `fn` / `mod` / `impl`
    items, tracked by brace depth, plus the attributes written directly against
    the call itself -- Rust allows `#[cfg]` on a statement, and the routing tail
    uses exactly that.
    """
    lines = text.splitlines()
    file_cfgs = [
        m.group(1)
        for line in lines[:80]
        if line.lstrip().startswith("#![") and (m := CFG.match(line))
    ]
    stack: list[tuple[int, list[str], bool]] = []   # (depth after open, cfgs, is_test)
    depth = 0
    out: list[tuple[int, str, list[str]]] = []

    for i, line in enumerate(lines):
        own_cfgs, own_test = _attrs_above(lines, i)
        delta = _depth_delta(line)
        # ANY attributed line that opens a block is a scope, not just fn/mod/impl.
        # The production attach in the demo sits in a BARE `#[cfg(..)] { .. }`
        # block, which an item-header rule never sees -- that miss is what made
        # the first draft of this gate report the shipped caller as ungated.
        if (own_cfgs or own_test) and delta > 0 and not COMMENT.match(line):
            stack.append((depth + delta, own_cfgs, own_test))
        if CALL.search(line) and not COMMENT.match(line) and not DEF.search(line):
            cfgs = list(file_cfgs) + own_cfgs
            is_test = own_test or "/tests/" in rel
            for _, s_cfgs, s_test in stack:
                cfgs += s_cfgs
                is_test = is_test or s_test
            out.append((i + 1, "test" if is_test else "prod", cfgs))
        depth += delta
        while stack and depth < stack[-1][0]:
            stack.pop()
    return out


def audit(root: pathlib.Path) -> tuple[list[str], list[str], list[str]]:
    """`(findings, egress_only_tests, prod_sites)` over the tracked tree."""
    findings: list[str] = []
    egress_only: list[str] = []
    prod: list[str] = []
    population = 0

    for path in tracked_rust(root):
        rel = path.relative_to(root).as_posix()
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            raise InputError(f"{path} is not readable ({exc})") from exc
        if ENTRY_POINT not in text:
            continue
        for line, scope, cfgs in call_sites(rel, text):
            population += 1
            site = f"{rel}:{line}"
            joined = " ".join(cfgs)
            if scope == "prod":
                prod.append(site)
                if ATOM_FEATURE not in joined:
                    findings.append(
                        f"{site} attaches a multicast egress group from PRODUCTION "
                        f"without `{ATOM_FEATURE}`. R2343 withdrew that atom's "
                        f"mis-scoped-gate residual on the measurement that no such "
                        f"caller exists; one does now, so the residual needs re-reading"
                    )
            elif BROAD_FEATURE in joined and ATOM_FEATURE not in joined:
                egress_only.append(site)

    if population == 0:
        raise InputError(
            f"no call to `{ENTRY_POINT}` anywhere in the tracked tree. It was "
            f"renamed or removed, and a scan that located nothing would report "
            f"green about a plane it never found"
        )
    if not egress_only:
        findings.append(
            f"no TEST attaches an egress group with `{BROAD_FEATURE}` and without "
            f"`{ATOM_FEATURE}`. That coverage is why R2343 refused to re-gate the "
            f"plane onto the atom's own feature and withdrew the residual saying "
            f"it should be; with it gone the withdrawal has no basis"
        )
    return findings, egress_only, prod


def selftest() -> int:
    """Drive the classifier and both rules over synthetic sources."""
    failures: list[str] = []

    def classify(rel: str, src: str) -> list[tuple[str, bool]]:
        return [
            (scope, BROAD_FEATURE in " ".join(c) and ATOM_FEATURE not in " ".join(c))
            for _, scope, c in call_sites(rel, src)
        ]

    def expect(label: str, rel: str, src: str, want: list[tuple[str, bool]]) -> None:
        got = classify(rel, src)
        if got != want:
            failures.append(f"{label}: expected {want}, got {got}")

    expect(
        "a broad-feature unit test is egress-only coverage",
        "crates/x/src/a.rs",
        '#[cfg(feature = "transport-multicast")]\n'
        "#[test]\n"
        "fn t() {\n    fwd.attach_mcast_group(tx);\n}\n",
        [("test", True)],
    )
    expect(
        "an atom-gated test is not egress-only coverage",
        "crates/x/src/a.rs",
        '#[cfg(feature = "transport-multicast")]\n'
        '#[cfg(feature = "router-multicast-faces")]\n'
        "#[test]\n"
        "fn t() {\n    fwd.attach_mcast_group(tx);\n}\n",
        [("test", False)],
    )
    expect(
        "an atom-gated production call is production",
        "crates/x/src/a.rs",
        '#[cfg(feature = "router-multicast-faces")]\n'
        "fn run() {\n    forwarder.attach_mcast_group(tx);\n}\n",
        [("prod", False)],
    )
    # The failing shape rule 2 exists for.
    expect(
        "a broad-only production call is production and ungated by the atom",
        "crates/x/src/a.rs",
        '#[cfg(feature = "transport-multicast")]\n'
        "fn run() {\n    forwarder.attach_mcast_group(tx);\n}\n",
        [("prod", True)],
    )
    expect(
        "a tests/ file inherits its own inner cfg",
        "crates/x/tests/e2e.rs",
        '#![cfg(feature = "transport-multicast")]\n'
        "fn body() {\n    fwd.attach_mcast_group(tx);\n}\n",
        [("test", True)],
    )
    # A statement-level cfg, which is how the routing tail gates its own call.
    expect(
        "a cfg written against the CALL is read",
        "crates/x/src/a.rs",
        "fn run() {\n"
        '    #[cfg(feature = "router-multicast-faces")]\n'
        "    self.attach_mcast_group(tx);\n"
        "}\n",
        [("prod", False)],
    )
    # A NEIGHBOUR's gate must not be inherited -- the first draft's bug.
    expect(
        "a closed sibling's cfg does not leak onto a later call",
        "crates/x/src/a.rs",
        '#[cfg(feature = "router-multicast-faces")]\n'
        "fn other() {\n    noop();\n}\n"
        "\n"
        '#[cfg(feature = "transport-multicast")]\n'
        "fn run() {\n    forwarder.attach_mcast_group(tx);\n}\n",
        [("prod", True)],
    )
    for label, src in (
        ("a doc reference is not a call", "/// see attach_mcast_group(tx)\n"),
        ("a line comment is not a call", "// fwd.attach_mcast_group(tx);\n"),
        ("the definition is not a call", "pub fn attach_mcast_group(&self, tx: T) {}\n"),
    ):
        got = call_sites("crates/x/src/a.rs", src)
        if got:
            failures.append(f"{label}: counted {got}")

    for line in failures:
        print(f"  mcast-egress-callers: SELFTEST FAIL -- {line}")
    if failures:
        return 1
    print(
        "  mcast-egress-callers: selftest ok -- scope, statement-level cfg and "
        "sibling isolation all discriminate; comments and the definition are not calls"
    )
    return 0


def main(argv: list[str]) -> int:
    unknown = [a for a in argv if a not in ("--selftest", "--verbose")]
    if unknown:
        print(f"  mcast-egress-callers: unknown argument(s): {' '.join(unknown)}")
        return 2
    if "--selftest" in argv:
        return selftest()

    try:
        findings, egress_only, prod = audit(REPO_ROOT)
    except InputError as exc:
        print(f"  mcast-egress-callers: INPUT -- {exc}")
        return 2

    if findings:
        for line in findings:
            print(f"  mcast-egress-callers: FAIL -- {line}")
        return 1

    print(
        f"  mcast-egress-callers: {len(prod)} production attach(es), all under "
        f"`{ATOM_FEATURE}`; {len(egress_only)} test attach(es) reach the plane "
        f"with `{BROAD_FEATURE}` alone -- which is why the gate stays where it is"
    )
    if "--verbose" in argv:
        for s in prod:
            print(f"    prod         {s}")
        for s in egress_only:
            print(f"    egress-only  {s}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
