#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

"""R2285 (no register item) — A GATE THAT CANNOT REFUSE IS A HEADER WITHOUT ITS GATE.

## The citation

This answers condition 0 of the numeric open-debt register's item 622 (R2284)
and, in the same file, item 623 (R2285 — the attribution arm below). Both live
in the operator's notes rather than in the store, so `gate_provenance_lint`'s
item grammar cannot resolve them; `zenoh_c_archive_arm.py` set the precedent for
declaring the escape hatch on the first line and naming the item in the body.

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

## And a refusal has to say WHOSE it is (item 623)

Arm 1 catches displacement only from the EMPTIED side. Measured against this
gate's own first cut, on the shipped hook body: MOVE one of `gate 4`'s two
refusals into `gate 3`'s section and it PASSES. Gate 4 keeps the other, so arm 1
sees nothing there; gate 3 keeps its own, so it sees nothing there either. "A
gate owns at least one refusal" is not "every refusal here is this gate's", and
the loose form is the one that has to hold: seven of the nineteen own two or
more (gates 0, 0b, 0c, 1, 2, 2c, 4), so "one refusal per section" could never be
a true rule.

So each refusal names its gate in the message it prints, and arm 3 checks that
name against the section hosting it. Measured before the labels went in: 27
refusals, every one of them printing at least one stderr line, and NOT ONE
naming its gate -- the attribution surface was empty rather than partial. Three
of them printed only "bypass with --no-verify" and were given a subject line
first, because a marker on a line that names no verdict labels nothing.

  3. every refusal in a gate section prints a message, and every `[gate <N>]`
     marker in that message is the host section's own. A refusal cut out of one
     section and pasted into a neighbour arrives still carrying its old marker,
     which is the crowded side of the displacement arm 1 only sees the emptied
     side of.

The marker is BRACKETED on purpose. Refusal prose legitimately names other
gates -- gate 7's message says "(gate 3 is default features and runs no clippy)"
-- and a reader keyed on the words would red that. A mention is not a claim of
ownership; `[gate 7]` is.

## What this does NOT claim

That every section's code is the gate its header names -- only that its
refusals, the messages they print, and the verdict input are. Two residues,
named rather than implied:

  * a neighbour's NON-refusing code can still sit in the wrong section and
    nothing here sees it. The structural answer is the "one function per gate
    plus a registry" shape `run-ci.sh` already uses, which is a refactor of the
    push path rather than a round's tail.
  * a refusal moved AND relabelled passes. That is a rename, not a silent
    displacement: arm 3 buys that a cut-and-paste cannot be silent, not that a
    deliberate re-attribution is forbidden.
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
COMMENT_RE = re.compile(r"^\s*#")

# A refusal's MESSAGE: the run of stderr-writing lines directly above `exit 1`.
# Bounded by anything else -- the `if !` that opens the block ends the walk, so
# two adjacent refusals never share a message.
STDERR_ECHO_RE = re.compile(r"^\s*(echo|printf)\b.*>&2\s*$")
# Its ATTRIBUTION. Bracketed so a message that merely NAMES another gate in
# prose is not read as claiming to be one.
MARK_RE = re.compile(r"\[gate (?P<n>\d+[a-z]*)\]")

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


def refusal_messages(body: str) -> list[str]:
    """One entry per `exit 1`: the stderr lines printed directly above it.

    `code_of` cannot be used here -- it strips the very `echo` payloads this
    reads. The walk goes UP from the refusal and stops at the first line that
    is not a stderr write, which is what keeps two adjacent refusals from
    sharing one message.
    """
    lines = body.splitlines()
    out: list[str] = []
    for i, ln in enumerate(lines):
        if COMMENT_RE.match(ln) or not ln.strip() or not EXIT1_RE.search(ln):
            continue
        j = i - 1
        while j >= 0 and STDERR_ECHO_RE.match(lines[j]):
            j -= 1
        out.append("\n".join(lines[j + 1:i]))
    return out


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

        for k, msg in enumerate(refusal_messages(body), start=1):
            if not msg.strip():
                ok = False
                lines.append(
                    f"hook-gate-boundary FAIL: refusal {k} in `gate {gid}` prints "
                    f"nothing before it exits. A refusal that says neither what "
                    f"failed nor whose gate it is cannot be attributed to this "
                    f"section by anything but its position.")
                continue
            marks = set(MARK_RE.findall(msg))
            if not marks:
                ok = False
                lines.append(
                    f"hook-gate-boundary FAIL: refusal {k} in `gate {gid}` names "
                    f"no gate in the message it prints. Add `[gate {gid}]` to it "
                    f"-- an unattributed refusal is one that can be moved into a "
                    f"neighbour without anything noticing.")
            elif marks != {gid}:
                ok = False
                lines.append(
                    f"hook-gate-boundary FAIL: refusal {k} in `gate {gid}` is "
                    f"marked {sorted('[gate %s]' % m for m in marks)}. A refusal "
                    f"carrying another gate's mark is that gate's refusal sitting "
                    f"in this section -- the crowded side of the displacement "
                    f"arm 1 only sees from the emptied side.")

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
                 "own refusal and its surface (%s); %d refusal(s), each marked "
                 "with the gate hosting it; %d non-gate section(s) owning no "
                 "refusal"
                 % (len(gates),
                    ", ".join(f"{n} {s}" for s, n in counts.items() if n),
                    sum(refusals(b) for _, b in gates),
                    len(secs) - len(gates)))
    return ok, lines


# ─── selftest ───────────────────────────────────────────────────────────────
#
# Case 1 is the shape `.githooks/pre-push` actually wore until R2284: a gate
# header over a precondition that only skips, with that gate's refusal stranded
# in the next section. Case 2 is the same displacement seen from the other end.
#
# Every FALSE case carries the phrase its own arm must produce. A control group
# that fails for a neighbour's reason is not a control group -- and the arm
# added by item 623 is invisible without one, because most of its cases were
# already false to the R2284 code for the SILENCE of their refusals rather than
# for the attribution the case is about.

def _sec(header: str, body: str, grades: str | None = None) -> str:
    head = f"# ─── {header} ──────\n"
    if grades is not None:
        head += f"# grades: {grades}\n"
    return head + body + "\n"


def _verdict(gid: str) -> str:
    """A refusal that runs the checkout and says whose it is."""
    return ('if ! cargo test; then\n'
            f'    echo "pre-push: [gate {gid}] changed-crate tests failed." >&2\n'
            '    exit 1\nfi\n')


_GUARD = 'if [[ -z "$diff_base" ]]; then\n    exit 0\nfi\n'
_VERDICT = _verdict("5")
_SILENT = 'if ! cargo test; then\n    exit 1\nfi\n'
_UNMARKED = ('if ! cargo test; then\n'
             '    echo "pre-push: changed-crate tests failed." >&2\n'
             '    exit 1\nfi\n')
_RANGE_VERDICT = ('for sha in "${push_shas[@]}"; do\n'
                  '    if ! wz_schema_pin_gate "${sha}:"; then\n'
                  '        echo "pre-push: [gate 1] the pin refused a commit." >&2\n'
                  '        exit 1\n    fi\ndone\n')
_HOSTED_VERDICT = ('if ! gh run view "$rid" --json jobs; then\n'
                   '    echo "pre-push: [gate 2c] the previous run is red." >&2\n'
                   '    exit 1\nfi\n')

_CASES = [
    ("the displacement: a gate header over a bare precondition", False,
     _sec("gate 3 — changed-crate tests", _GUARD, "worktree")
     + _sec("gate 5 — the other lanes", _VERDICT + _VERDICT, "worktree"),
     "gate 3 owns no exit 1"),
    ("repaired: the precondition labelled, the header on its code", True,
     _sec("the diff-base precondition, hoisted", _GUARD)
     + _sec("gate 5 — the other lanes", _VERDICT, "worktree")
     + _sec("gate 3 — changed-crate tests", _verdict("3"), "worktree"), None),
    ("a refusal in a section nobody called a gate", False,
     _sec("housekeeping (NOT a gate)", _SILENT)
     + _sec("gate 5 — the other lanes", _VERDICT, "worktree"),
     "is not a gate and owns"),
    ("a refusal quoted in a COMMENT is not a refusal", False,
     _sec("gate 5 — the other lanes",
          "# the old form ended in `exit 1` here\ncargo test\n", "worktree"),
     "gate 5 owns no exit 1"),
    ("no gate section at all", False, _sec("housekeeping (NOT a gate)", "true\n"),
     "That is the header scan having stopped scanning"),
    ("a preamble that refuses", False,
     'set -euo pipefail\nexit 1\n' + _sec("gate 5 — x", _VERDICT, "worktree"),
     "is not a gate and owns"),
    # --- the surface arm (item 622, conditions 1-3) ---
    ("a gate that declares no surface", False,
     _sec("gate 5 — x", _VERDICT), "declares no # grades: "),
    ("a surface nobody defined", False,
     _sec("gate 5 — x", _VERDICT, "index-content"), "which is not one of"),
    ("pushed-range declared and the pushed commits read", True,
     _sec("gate 1 — the schema pin", _RANGE_VERDICT, "pushed-range"), None),
    ("pushed-range declared, only the checkout read", False,
     _sec("gate 1 — the schema pin", _verdict("1"), "pushed-range"),
     "reads no pushed commit"),
    ("worktree declared with nothing to refute it", False,
     _sec("gate 5 — x",
          'if [[ -n "$x" ]]; then\n'
          '    echo "pre-push: [gate 5] x is set." >&2\n'
          '    exit 1\nfi\n', "worktree"),
     "runs no command that reads the checkout"),
    ("not-a-file, and it really is not", True,
     _sec("gate 2c — the previous hosted verdict", _HOSTED_VERDICT,
          "not-a-file"), None),
    ("not-a-file while running a checkout command", False,
     _sec("gate 2c — the previous hosted verdict", _verdict("2c"),
          "not-a-file"), "touches a file surface"),
    # The shape this gate itself was caught by, one hook over: a fix hint that
    # PRINTS a checkout command is a string, not a command the gate runs.
    ("a fix hint that names cargo leaves `not-a-file` true", True,
     _sec("gate 2c — the previous hosted verdict",
          _HOSTED_VERDICT + '    echo "  fix: cargo test -p x" >&2\n',
          "not-a-file"), None),
    # --- the attribution arm (item 623) ---
    ("a refusal that prints nothing", False,
     _sec("gate 3 — changed-crate tests", _SILENT, "worktree"),
     "prints nothing before it exits"),
    ("a refusal that names no gate", False,
     _sec("gate 3 — changed-crate tests", _UNMARKED, "worktree"),
     "names no gate in the message it prints"),
    # THE case arm 1 cannot see: gate 8 hands one refusal to gate 7 and keeps
    # one, so both sections own an `exit 1` and the boundary arm stays silent.
    ("the crowded side: a refusal handed to a neighbour that keeps its own",
     False,
     _sec("gate 7 — non-default features", _verdict("7") + _verdict("8"),
          "worktree")
     + _sec("gate 8 — the workspace type-checks", _verdict("8"), "worktree"),
     "is marked ['[gate 8]']"),
    # The control the bracket exists for: gate 7's real message names gate 3.
    ("a message that MENTIONS another gate is not a claim on it", True,
     _sec("gate 7 — non-default features",
          'if ! cargo clippy; then\n'
          '    echo "pre-push: [gate 7] a changed crate is not CLEAN." >&2\n'
          '    echo "          (gate 3 is default features, no clippy)" >&2\n'
          '    exit 1\nfi\n', "worktree"), None),
]


def selftest() -> bool:
    ok = True
    for name, want, text, needle in _CASES:
        got, lines = check(text)
        # Backticks stripped from BOTH sides. A needle is a control, not a
        # citation, and `gate_reason_claims` reads every backticked token in a
        # table like this one as a claim it has to resolve -- which two of
        # these are not (`gate 5` is a section of a hook, not a symbol).
        why = "\n".join(lines).replace("`", "")
        if got != want:
            ok = False
            print(f"  hook-gate-boundary SELFTEST `{name}`: got {got}, expected "
                  f"{want}", file=sys.stderr)
            for ln in lines:
                print(f"      {ln}", file=sys.stderr)
        elif needle is not None and needle not in why:
            ok = False
            print(f"  hook-gate-boundary SELFTEST `{name}`: failed for the wrong "
                  f"reason -- {needle!r} is not in the output, so this case is "
                  f"not the control it claims to be.", file=sys.stderr)
            for ln in lines:
                print(f"      {ln}", file=sys.stderr)
    if ok:
        print(f"  hook-gate-boundary: selftest passed ({len(_CASES)} cases, both "
              f"verdicts, each failing case pinned to its own arm)")
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
