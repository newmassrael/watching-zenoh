#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

"""R2284 (no register item) — A GATE THAT CANNOT REFUSE IS A HEADER WITHOUT ITS GATE.

## The citation

This answers condition 0 of the numeric open-debt register's item 622, which
lives in the operator's notes rather than in the store, so
`gate_provenance_lint`'s item grammar cannot resolve it; `zenoh_c_archive_arm.py`
set the precedent for declaring the escape hatch on the first line and naming
the item in the body.

## The defect

`.githooks/pre-push` delimits its gates with `# ─── gate <N>` comment headers and
nothing else, and item 622 wants each gate to DECLARE which artifact it grades.
A declaration is attached to a section, so the sections have to be true first --
and they were not. Measured before this gate was written:

    gate 3   5 code lines,  0 `exit 1`
    gate 5  64 code lines,  2 `exit 1`

The `gate 3` header sat above the `diff_base` precondition -- which guards gate 5
as much as gate 3 -- while gate 3's own body sat BELOW gate 5, unheaded, because
gate 5 "is placed BEFORE gate 3 on purpose" (its own header says so, and it is
right: gate 3's no-crates early exit is the push shape gate 5 exists for). So a
scanner cutting on headers read gate 3 as a section that runs nothing and gate 5
as a section carrying two gates' verdicts, and any `# grades:` line would have
been attached to the wrong code.

R2284's repair is a LABEL move and changes no behaviour: the precondition is
labelled as one, and the `gate 3` header moved down to the code it names.

## What is derived

Sections from the file's own `# ─── ` headers; a section is a GATE when its
header opens `gate <N>`. Both arms are over `exit 1`, which is what a refusal is
in a hook:

  1. every GATE section owns at least one `exit 1`. A gate that cannot refuse is
     a header whose gate is somewhere else -- exactly what gate 3 was.
  2. no NON-gate section owns an `exit 1`. A refusal outside a gate is a gate
     nobody named, which is the same displacement seen from the other end.
     Measured: the four non-gate sections (`R224a guard`, the two hoisted
     preconditions, `housekeeping (NOT a gate)`) and the preamble own zero
     between them, so arm 2 is a live constraint rather than a description.

A population of zero gate sections is a FAIL: that is the header scan having
stopped scanning, not the hook having no gates.

## And then the declaration itself (item 622, conditions 1-3)

With the boundaries true, each gate carries `# grades: <surface>`. The vocabulary
is NOT `pre-commit`'s -- item 622's own starting point is that four values built
for a commit hook cannot cover gate 2c, which reads the previous HOSTED run and
no file at all. Three, derived from what each gate's VERDICT reads:

  pushed-range  the verdict reads the commits being pushed. gate 0 hands
                `"$nda_base..$local_sha"` to a scan that runs `git diff -U0` and
                `git log --format=%B` on it; gate 0c walks `push_shas` into
                `git log --format='%H %ae%n%H %ce'`; gate 1 hands `"${sha}:"` to
                the schema gate, which resolves it with `git show`.
  worktree      the verdict runs a command that can only read the checkout --
                cargo, run-ci.sh, a scripts/ program, mnemosyne-cli.
  not-a-file    the verdict reads no file surface. gate 2c only: `gh run list`
                and `gh run view --json jobs`.

⚠ Item 622 asked whether "select by range, then grade the checkout" is ONE value
or TWO. It is one, and the rule that settles it is: the surface is where the
VERDICT'S INPUT comes from, not where the population came from. gate 3 picks its
crates out of `$diff_base..$local_sha` and then runs `cargo test` on the files on
disk; what a green means is a statement about the checkout. Measured across all
nineteen with that rule, every gate lands in exactly ONE class -- no gate needed
two, which is the evidence that the rule cuts where the code does.

Each class is falsified against the section's code: `pushed-range` with no
range-content read, `worktree` with no checkout-running command, and
`not-a-file` with either, are all refused. An undeclared gate is RED.

## What this does NOT claim

That every section's code is the gate its header names -- only that the refusal
and the verdict input are. A section could still host a neighbour's non-refusing
code and this would not see it.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
HOOK = ".githooks/pre-push"

SECTION_RE = re.compile(r"^# ─── (?P<h>[^\n]*)$", re.M)
GATE_RE = re.compile(r"^gate (?P<n>\d+[a-z]*)\b")
EXIT1_RE = re.compile(r"\bexit\s+1\b")

SURFACES = ("pushed-range", "worktree", "not-a-file")
GRADES_RE = re.compile(r"^#\s*grades:\s*(?P<surface>[a-z-]+)\b", re.M)

# The verdict's INPUT, read from code lines only.
RANGE_CONTENT = (
    re.compile(r"\$\{?sha\}?:"),
    re.compile(r"\bpush_shas\b"),
    re.compile(r'"\$\w+\.\.\$\w+"'),
    re.compile(r"\$\{?\w*base\}?\.\.\$"),
)
WORKTREE_CMD = (
    re.compile(r"cargo\s+(test|build|check|clippy|fmt)"),
    re.compile(r"run-ci\.sh"),
    re.compile(r"(python3|bash)\s+scripts/"),
    re.compile(r"mnemosyne-cli"),
    re.compile(r"--show-toplevel"),
)


def sections(text: str) -> list[tuple[str, str]]:
    """`(header, body)` for every `# ─── ` section, plus the preamble first."""
    hits = [(m.start(), m.group("h")) for m in SECTION_RE.finditer(text)]
    if not hits:
        return []
    out = [("<preamble>", text[:hits[0][0]])]
    for i, (pos, h) in enumerate(hits):
        end = hits[i + 1][0] if i + 1 < len(hits) else len(text)
        out.append((h, text[pos:end]))
    return out


def code_of(body: str) -> str:
    """The section's CODE: no comments, no `echo`/`printf` payloads.

    A fix hint that PRINTS `cargo test` is a string, not a command this gate
    runs -- the same confusion `hook_graded_surface_gate.py` was caught by on
    its own first run, one hook over.
    """
    return "\n".join(ln for ln in body.splitlines()
                     if ln.strip() and not re.match(r"^\s*(#|echo\b|printf\b)", ln))


def refusals(body: str) -> int:
    """`exit 1` occurrences on CODE lines -- a comment quoting one is not one."""
    return sum(1 for ln in code_of(body).splitlines() if EXIT1_RE.search(ln))


def declared(body: str) -> str | None:
    m = GRADES_RE.search(body)
    return m.group("surface") if m else None


def inputs(body: str) -> tuple[bool, bool]:
    """`(reads the pushed range, runs a checkout command)` for one section."""
    code = code_of(body)
    return (any(p.search(code) for p in RANGE_CONTENT),
            any(p.search(code) for p in WORKTREE_CMD))


def check(hook_text: str) -> tuple[bool, list[str]]:
    lines: list[str] = []
    ok = True

    secs = sections(hook_text)
    gates = [(h, b) for h, b in secs if GATE_RE.match(h)]
    if not gates:
        return False, ["hook-gate-boundary FAIL: no `# ─── gate <N>` section was "
                       "found. That is the header scan having stopped scanning, "
                       "not the hook having no gates -- a population of zero is "
                       "not a pass."]

    counts: dict[str, int] = {s: 0 for s in SURFACES}
    for h, body in secs:
        n = refusals(body)
        name = GATE_RE.match(h)
        if not name:
            if n:
                ok = False
                lines.append(
                    f"hook-gate-boundary FAIL: `{h[:48]}` is not a gate and owns "
                    f"{n} `exit 1`. A refusal outside a gate is a gate nobody "
                    f"named. Give it a `# ─── gate <N>` header.")
            continue

        gid = name.group("n")
        if n == 0:
            ok = False
            lines.append(
                f"hook-gate-boundary FAIL: `gate {gid}` owns no `exit 1`. A gate "
                f"that cannot refuse is a header whose gate lives in someone "
                f"else's section, and a `# grades:` declaration attached here "
                f"would describe the wrong code. Move the header to the code it "
                f"names, or label this block as the precondition it is.")
            continue

        surface = declared(body)
        rng, wt = inputs(body)
        if surface is None:
            ok = False
            lines.append(
                f"hook-gate-boundary FAIL: `gate {gid}` declares no `# grades: "
                f"<surface>`. What a gate reads to reach its verdict is the "
                f"difference between blocking the push and blessing it, and "
                f"'nobody wrote it down' must not look like 'this one really "
                f"does read the checkout'. One of {', '.join(SURFACES)}.")
            continue
        if surface not in SURFACES:
            ok = False
            lines.append(f"hook-gate-boundary FAIL: `gate {gid}` declares "
                         f"`{surface}`, which is not one of "
                         f"{', '.join(SURFACES)}.")
            continue
        counts[surface] += 1
        if surface == "pushed-range" and not rng:
            ok = False
            lines.append(
                f"hook-gate-boundary FAIL: `gate {gid}` declares `pushed-range` "
                f"and reads no pushed commit. Naming a range is not reading one "
                f"-- the verdict has to take its input from `$sha:`, "
                f"`push_shas` or a `a..b` spec.")
        elif surface == "worktree" and not wt:
            ok = False
            lines.append(
                f"hook-gate-boundary FAIL: `gate {gid}` declares `worktree` and "
                f"runs no command that reads the checkout, so nothing can ever "
                f"refute the label. Declare what it does read.")
        elif surface == "not-a-file" and (rng or wt):
            ok = False
            lines.append(
                f"hook-gate-boundary FAIL: `gate {gid}` declares `not-a-file` "
                f"and touches a file surface after all.")
        else:
            lines.append(f"  hook-gate-boundary: gate {gid} -> {surface}")

    lines.append("  hook-gate-boundary: %d gate section(s), every one owning its "
                 "own refusal and its surface (%s); %d non-gate section(s) "
                 "owning no refusal"
                 % (len(gates),
                    ", ".join(f"{n} {s}" for s, n in counts.items() if n),
                    len(secs) - len(gates)))
    return ok, lines


# ─── selftest ───────────────────────────────────────────────────────────────
#
# Case 1 is the shape `.githooks/pre-push` actually wore until R2284: a gate
# header over a precondition that only skips, with that gate's refusal stranded
# in the next section. Case 2 is the same displacement seen from the other end.

def _sec(header: str, body: str, grades: str | None = None) -> str:
    head = f"# ─── {header} ──────\n"
    if grades is not None:
        head += f"# grades: {grades}\n"
    return head + body + "\n"


_GUARD = 'if [[ -z "$diff_base" ]]; then\n    exit 0\nfi\n'
_VERDICT = 'if ! cargo test; then\n    exit 1\nfi\n'
_RANGE_VERDICT = ('for sha in "${push_shas[@]}"; do\n'
                  '    wz_schema_pin_gate "${sha}:" || exit 1\ndone\n')
_HOSTED_VERDICT = 'if ! gh run view "$rid" --json jobs; then\n    exit 1\nfi\n'

_CASES = [
    ("the displacement: a gate header over a bare precondition", False,
     _sec("gate 3 — changed-crate tests", _GUARD, "worktree")
     + _sec("gate 5 — the other lanes", _VERDICT + _VERDICT, "worktree")),
    ("repaired: the precondition labelled, the header on its code", True,
     _sec("the diff-base precondition, hoisted", _GUARD)
     + _sec("gate 5 — the other lanes", _VERDICT, "worktree")
     + _sec("gate 3 — changed-crate tests", _VERDICT, "worktree")),
    ("a refusal in a section nobody called a gate", False,
     _sec("housekeeping (NOT a gate)", _VERDICT)
     + _sec("gate 5 — the other lanes", _VERDICT, "worktree")),
    ("a refusal quoted in a COMMENT is not a refusal", False,
     _sec("gate 5 — the other lanes",
          "# the old form ended in `exit 1` here\ncargo test\n", "worktree")),
    ("no gate section at all", False, _sec("housekeeping (NOT a gate)", "true\n")),
    ("a preamble that refuses", False,
     'set -euo pipefail\nexit 1\n' + _sec("gate 5 — x", _VERDICT, "worktree")),
    # --- the surface arm (item 622, conditions 1-3) ---
    ("a gate that declares no surface", False,
     _sec("gate 5 — x", _VERDICT)),
    ("a surface nobody defined", False,
     _sec("gate 5 — x", _VERDICT, "index-content")),
    ("pushed-range declared and the pushed commits read", True,
     _sec("gate 1 — the schema pin", _RANGE_VERDICT, "pushed-range")),
    ("pushed-range declared, only the checkout read", False,
     _sec("gate 1 — the schema pin", _VERDICT, "pushed-range")),
    ("worktree declared with nothing to refute it", False,
     _sec("gate 5 — x", 'if [[ -n "$x" ]]; then\n    exit 1\nfi\n', "worktree")),
    ("not-a-file, and it really is not", True,
     _sec("gate 2c — the previous hosted verdict", _HOSTED_VERDICT, "not-a-file")),
    ("not-a-file while running a checkout command", False,
     _sec("gate 2c — the previous hosted verdict", _VERDICT, "not-a-file")),
    # The shape this gate itself was caught by, one hook over: a fix hint that
    # PRINTS a checkout command is a string, not a command the gate runs.
    ("a fix hint that names cargo leaves `not-a-file` true", True,
     _sec("gate 2c — the previous hosted verdict",
          _HOSTED_VERDICT + '    echo "  fix: cargo test -p x" >&2\n',
          "not-a-file")),
]


def selftest() -> bool:
    ok = True
    for name, want, text in _CASES:
        got, lines = check(text)
        if got != want:
            ok = False
            print(f"  hook-gate-boundary SELFTEST `{name}`: got {got}, expected "
                  f"{want}", file=sys.stderr)
            for ln in lines:
                print(f"      {ln}", file=sys.stderr)
    if ok:
        print(f"  hook-gate-boundary: selftest passed ({len(_CASES)} cases, both "
              f"verdicts)")
    return ok


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true")
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args()
    if not (args.check or args.selftest):
        ap.error("pass exactly one of --check / --selftest")

    if args.selftest and not selftest():
        return 1
    if args.check:
        ok, lines = check((REPO_ROOT / HOOK).read_text())
        for ln in lines:
            print(ln, file=None if ok else sys.stderr)
        if not ok:
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
