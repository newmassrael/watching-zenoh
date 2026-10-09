#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
"""R3188 (no register item) -- the upstream version CLAUDE.md states is the pin the tree enforces.

The debt it answers for, open-debt item 747, lives in the operator's agent-memory
register, which has no store `debt-` id for `gate_provenance_lint.py` to resolve;
the honest pair is this sentence and `no register item` in the citation.

## The defect this ends

`CLAUDE.md` is the first file every session reads, and its External references
section told the reader which upstream zenoh this tree is compared against. It said
1.5.0 while `UPSTREAM_VERSION` in `upstream_feature_census.py` -- the constant the
whole upstream apparatus enforces -- said 1.10.1, and it said so for months. The
wrong answer was not obviously wrong: a checkout of the old version was still on
disk, so a session that followed the sentence found a real tree, read it coherently
and cited it. The sentence was repaired by hand (item 747); a hand repair of a
number written in two places is the arrangement that failed, so this gate makes
the second place answer to the first.

It is the same shape `mnemosyne.toml::[tool] pin` against `MNEMOSYNE_REV` is in, and
that pair has a gate for the same reason (`job_budget_binding.py` records it).

## What it checks

1. `CLAUDE.md` has a `## External references` section.
2. The section holds at least one bullet that names `UPSTREAM_VERSION` -- the
   bullet that says which version the tree compares against and where that is read
   from. Zero such bullets FAILS: a population of zero is a measurement that did not
   happen, not a pass.
3. Every such bullet states at least one version-shaped token (`N.N.N`). A bullet
   that names the constant and states no number FAILS, because the reader then has
   nothing to be wrong about -- or to be checked.
4. Every version-shaped token in such a bullet equals the constant. One stale
   token among correct ones is still a stale statement of the version.
5. The constant itself is read from `upstream_feature_census.py` with `ast`, never
   by import and never by regex over text, and exactly one module-level assignment
   of a string literal must exist. A file that no longer assigns it FAILS.

## What it does NOT do

It does not read a version token anywhere else in the file. The bullet is the
statement of record; the rest of the file mentions no upstream version, and a gate
that graded every number in a markdown file (AGPL-3.0, a round number) would be
arguing with prose about things that are not the pin. A correct token in some OTHER
section does not satisfy rule 3 -- that is a selftest row, because it is the shape
a lazy repair would take.

## Modes

`--check` grades the tracked `CLAUDE.md` against the tracked constant. `--selftest`
drives the same grading function over fixtures, red-first. There is no default mode:
an unknown or missing argument is refused by name (the lesson of
`relicense_spdx.py`, which fell through to its write path on `--help`).
"""

from __future__ import annotations

import ast
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CLAUDE_MD = ROOT / "CLAUDE.md"
CENSUS = ROOT / "scripts" / "lib" / "upstream_feature_census.py"

CONSTANT = "UPSTREAM_VERSION"
SECTION_HEADING = "## External references"

# A version-shaped token: three dotted numbers, optionally a pre-release or build
# suffix. The lookarounds keep it from matching inside a longer dotted run.
VERSION = re.compile(r"(?<![\w.])\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.]+)?(?![\w])")


class InputError(Exception):
    """An input this gate could not read. Reported as a FAIL, never a traceback."""


def read_pin(census_source: str) -> str:
    """The constant's value, from the module's own AST."""
    try:
        tree = ast.parse(census_source)
    except SyntaxError as e:
        raise InputError(f"{CONSTANT} module does not parse ({e})") from e
    values = []
    for node in tree.body:
        targets = []
        if isinstance(node, ast.Assign):
            targets = [t for t in node.targets if isinstance(t, ast.Name)]
            value = node.value
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            targets = [node.target]
            value = node.value
        else:
            continue
        if any(t.id == CONSTANT for t in targets):
            if isinstance(value, ast.Constant) and isinstance(value.value, str):
                values.append(value.value)
            else:
                raise InputError(f"{CONSTANT} is not assigned a string literal")
    if len(values) != 1:
        raise InputError(
            f"{CONSTANT} must be assigned exactly once at module level, "
            f"found {len(values)} assignment(s)"
        )
    if not VERSION.fullmatch(values[0]):
        raise InputError(f"{CONSTANT} = {values[0]!r} is not a version-shaped string")
    return values[0]


def section_lines(text: str) -> list[str]:
    """The lines of the External references section, heading excluded."""
    lines = text.splitlines()
    try:
        start = next(i for i, ln in enumerate(lines) if ln.strip() == SECTION_HEADING)
    except StopIteration as e:
        raise InputError(f"no `{SECTION_HEADING}` section in CLAUDE.md") from e
    end = len(lines)
    for i in range(start + 1, len(lines)):
        if lines[i].startswith("## "):
            end = i
            break
    return lines[start + 1 : end]


def bullets(lines: list[str]) -> list[str]:
    """Each top-level bullet with its indented continuation lines."""
    out: list[list[str]] = []
    current: list[str] | None = None
    for ln in lines:
        if ln.startswith("- "):
            current = [ln]
            out.append(current)
        elif current is not None and ln[:1] in (" ", "\t") and ln.strip():
            current.append(ln)
        else:
            # A blank or unindented line ends the bullet in progress.
            current = None
    return ["\n".join(b) for b in out]


def grade(claude_text: str, pin: str) -> list[str]:
    """Findings; empty means the statement of record agrees with the pin."""
    try:
        section = section_lines(claude_text)
    except InputError as e:
        return [str(e)]
    holders = [b for b in bullets(section) if CONSTANT in b]
    if not holders:
        return [
            f"no bullet in `{SECTION_HEADING}` names `{CONSTANT}`: nothing states "
            "which upstream version this tree compares against and where that is "
            "read from, and a population of zero is not a pass"
        ]
    findings: list[str] = []
    for b in holders:
        label = b.splitlines()[0][:60]
        tokens = VERSION.findall(b)
        if not tokens:
            findings.append(
                f"the bullet `{label}...` names `{CONSTANT}` and states no version: "
                "there is nothing for the reader to rely on or for this gate to check"
            )
            continue
        for t in sorted(set(tokens)):
            if t != pin:
                findings.append(
                    f"the bullet `{label}...` states version {t} but the tree "
                    f"enforces {pin} (`{CONSTANT}`)"
                )
    return findings


def check() -> int:
    try:
        pin = read_pin(CENSUS.read_text(encoding="utf-8"))
        text = CLAUDE_MD.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as e:
        print(f"  claude-md-upstream-pin FAIL: cannot read an input ({e})", file=sys.stderr)
        return 1
    except InputError as e:
        print(f"  claude-md-upstream-pin FAIL: {e}", file=sys.stderr)
        return 1
    findings = grade(text, pin)
    if findings:
        print("  claude-md-upstream-pin FAIL:", file=sys.stderr)
        for f in findings:
            print(f"    {f}", file=sys.stderr)
        print(
            "    Fix CLAUDE.md to state the enforced pin; the constant is the "
            "SSOT and is not changed to match prose.",
            file=sys.stderr,
        )
        return 1
    print(f"  claude-md-upstream-pin: CLAUDE.md states {pin}, the enforced pin")
    return 0


_FIXTURE_HEAD = "# Guide\n\n## License\n\nAGPL-3.0-or-later, see 1.5.0 of nothing.\n\n"


def _doc(bullet: str, other_section_prose: str = "") -> str:
    return (
        _FIXTURE_HEAD
        + SECTION_HEADING
        + "\n\n- **SCE** - the codegen engine; pinned.\n"
        + bullet
        + "- **zenoh-pico** - vendored, version 0.0.0 unrelated.\n"
        + "\n## Response style\n\n"
        + other_section_prose
    )


def selftest() -> int:
    pin = "1.10.1"
    good_bullet = (
        "- **Zenoh (Rust), at the PINNED version** - read `UPSTREAM_VERSION`\n"
        "  (1.10.1; held by this gate).\n"
    )
    # (name, document, should_fail, substring the finding must carry)
    rows = [
        ("agrees", _doc(good_bullet), False, ""),
        (
            "drifted token",
            _doc(good_bullet.replace("1.10.1;", "1.5.0;")),
            True,
            "states version 1.5.0",
        ),
        (
            "one stale token among correct ones",
            _doc(good_bullet.replace("held by", "was 1.10.0, held by")),
            True,
            "states version 1.10.0",
        ),
        (
            "missing token",
            _doc(
                "- **Zenoh (Rust), at the PINNED version** - read `UPSTREAM_VERSION`.\n"
            ),
            True,
            "states no version",
        ),
        (
            "token only in prose outside the bullet",
            _doc(
                "- **Zenoh (Rust)** - read `UPSTREAM_VERSION`.\n",
                other_section_prose="The pin is 1.10.1, written here instead.\n",
            ),
            True,
            "states no version",
        ),
        (
            "bullet no longer names the constant",
            _doc("- **Zenoh (Rust)** - version 1.10.1, no constant named.\n"),
            True,
            "names `UPSTREAM_VERSION`",
        ),
        (
            "no bullet at all (population zero)",
            _doc(""),
            True,
            "names `UPSTREAM_VERSION`",
        ),
        (
            "section missing",
            "# Guide\n\n- **Zenoh** `UPSTREAM_VERSION` 1.10.1\n",
            True,
            "External references",
        ),
        (
            "continuation line carries the stale token",
            _doc(
                "- **Zenoh (Rust)** - read `UPSTREAM_VERSION`; compared at 1.10.1,\n"
                "  and in older notes 1.5.0.\n"
            ),
            True,
            "states version 1.5.0",
        ),
    ]
    bad = 0
    for name, doc, should_fail, needle in rows:
        findings = grade(doc, pin)
        failed = bool(findings)
        ok = failed == should_fail and (not should_fail or any(needle in f for f in findings))
        print(f"  selftest {'ok  ' if ok else 'BAD '} {name}: "
              f"{'refused' if failed else 'accepted'}")
        if not ok:
            bad += 1
            for f in findings:
                print(f"      {f}", file=sys.stderr)

    # The constant reader: each refusal arm, and the accepting one.
    pin_rows = [
        ('UPSTREAM_VERSION = "1.10.1"\n', "1.10.1", None),
        ('X = 1\n', None, "found 0"),
        ('UPSTREAM_VERSION = "1.10.1"\nUPSTREAM_VERSION = "1.5.0"\n', None, "found 2"),
        ("UPSTREAM_VERSION = f()\n", None, "string literal"),
        ('UPSTREAM_VERSION = "latest"\n', None, "version-shaped"),
        ("UPSTREAM_VERSION = (\n", None, "does not parse"),
    ]
    for src, want, err in pin_rows:
        try:
            got = read_pin(src)
            ok = want is not None and got == want
        except InputError as e:
            ok = err is not None and err in str(e)
        print(f"  selftest {'ok  ' if ok else 'BAD '} pin reader: {src.splitlines()[0]!r}")
        if not ok:
            bad += 1

    # The tracked constant must itself be readable by the reader the gate uses;
    # otherwise the fixtures above would pass against a reader the tree defeats.
    try:
        read_pin(CENSUS.read_text(encoding="utf-8"))
        print("  selftest ok   tracked constant is readable")
    except (OSError, InputError) as e:
        print(f"  selftest BAD  tracked constant unreadable: {e}", file=sys.stderr)
        bad += 1

    if bad:
        print(f"  claude-md-upstream-pin selftest FAIL: {bad} row(s)", file=sys.stderr)
        return 1
    print("  claude-md-upstream-pin selftest: every row held")
    return 0


def main(argv: list[str]) -> int:
    modes = {"--check": check, "--selftest": selftest}
    if len(argv) != 2 or argv[1] not in modes:
        print(
            "usage: claude_md_upstream_pin_gate.py --check | --selftest "
            "(a mode is required; there is no default)",
            file=sys.stderr,
        )
        return 2
    return modes[argv[1]]()


if __name__ == "__main__":
    sys.exit(main(sys.argv))
