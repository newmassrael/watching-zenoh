#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

"""R2283 (no register item) — A COMMIT HOOK CHECK MUST SAY WHICH SURFACE IT GRADES.

## The citation

This answers the numeric open-debt register's item 621, which lives in the
operator's notes rather than in the store, so `gate_provenance_lint`'s item
grammar cannot resolve it; `zenoh_c_archive_arm.py` set the precedent for
declaring the escape hatch on the first line and naming the item in the body.

## The defect

`pre-commit`'s Check 2 selected its population from the INDEX (`git diff
--cached --name-only`) and then ran `cargo fmt --all -- --check` over the
WORKING TREE. Those are different artifacts. R2282 walked into the gap and it
was reproduced afterwards in a throwaway repo, both directions:

  index unformatted + worktree formatted -> the old check PASSES (a commit
      carrying unformatted bytes is blessed; this is what happened)
  index formatted + worktree drifted     -> the old check FAILS (a false red
      about drift no commit carries)

Which is exactly the pair Check 3's own header already recorded, for the same
mistake, in the same file: "Graded on the INDEX — what this commit will
contain ... The first cut read the store from the WORKING TREE instead and was
wrong in both directions." The principle was written down and not applied to its
neighbour. Prose sits next to code and agrees with nothing; a DECLARATION can be
held to the code beside it, which is what this gate does.

## What is derived, and how the vocabulary was arrived at

The population is every `# ─── Check <n>` section of `.githooks/pre-commit`,
read from the hook's own headers, so a check added later is in it by
construction and a population of zero is a FAIL.

The four surfaces are not a vocabulary someone invented and then sorted the
checks into. They are what the markers in those five sections actually
partition into, measured before any of this was written:

  Check 1  index-paths                     Check 3  index-content
  Check 2  index-paths + WORKTREE COMMAND  Check 5  identity
  Check 4  worktree command

Check 2 is the only one with two, and that pair IS the defect: select from the
index, grade the checkout.

  index-paths    grades WHICH files the commit touches (`git diff --cached
                 --name-only`, `_staged_matching`) and reads no file content.
  index-content  grades the BYTES the commit will carry (`git show ":<path>"`,
                 or a bare `':'` spec handed to a helper that does).
  worktree       grades the checkout, with a command that can only read it.
  not-a-file     grades something that is not a file surface at all -- Check 5
                 grades the identity the commit will carry.

Each is falsifiable against the section body: an index declaration with a
worktree command in it is refused, a worktree declaration with no such command
is refused (an unfalsifiable label is not a declaration), and `not-a-file` is
refused if any file marker is present. A check with no declaration is RED --
"nobody wrote it down" and "this one really does grade the checkout" must not
look alike, which is the argument `gate_provenance_lint` makes for its own
escape hatch.

A formatter fed FROM the index is not a worktree command, and the derivation
says so by construction: lines carrying an index-content read are removed before
the worktree scan, so `git show ":$path" | rustfmt --check` reads as
index-content and `cargo fmt --all` -- which can only take a directory -- reads
as worktree wherever it appears.

## Why the population is `pre-commit` and not both hooks

`pre-push` asks a related question -- the pushed commits versus the checkout --
and it is NOT the same question, established by READING all nineteen of its
gates rather than pattern-matching them: most grade the CHECKOUT after selecting
from the range (gate 3 picks changed crates out of `$diff_base..$local_sha` and
then runs `cargo test` on the working tree), and gate 2c grades no file surface
at all -- it reads the PREVIOUS hosted run's verdict. Declaring nineteen gates
from a heuristic, inside a gate whose subject is declarations that do not match
what they describe, would be the defect wearing the repair's clothes. That half
is filed as its own register item with this reading attached.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
HOOK = ".githooks/pre-commit"
SURFACES = ("index-paths", "index-content", "worktree", "not-a-file")

SECTION_RE = re.compile(r"^# ─── (?P<name>Check \d+)\b[^\n]*$", re.M)
GRADES_RE = re.compile(r"^#\s*grades:\s*(?P<surface>[a-z-]+)\b", re.M)

INDEX_CONTENT = (
    re.compile(r"""git\s+show\s+["']?:"""),
    re.compile(r"""git\s+cat-file\s+\S+\s+["']?:"""),
    re.compile(r"""\s':'(\s|$)"""),
)
INDEX_PATHS = (
    re.compile(r"git\s+diff\s+--cached"),
    re.compile(r"_staged_matching"),
)
# Commands that can only read the checkout. `rustfmt` is here too, but the scan
# runs over a body with the index-content LINES removed, so a `git show ":..."
# | rustfmt` pipeline never reaches it.
WORKTREE_CMD = (
    re.compile(r"cargo\s+fmt"),
    re.compile(r"cargo\s+clippy"),
    re.compile(r"mnemosyne-cli\s+validate-workspace"),
    re.compile(r"\brustfmt\b"),
)


def sections(text: str) -> list[tuple[str, str]]:
    """`(name, body)` for every Check section, each running to the next."""
    hits = [(m.start(), m.group("name")) for m in SECTION_RE.finditer(text)]
    return [(name, text[pos:hits[i + 1][0] if i + 1 < len(hits) else len(text)])
            for i, (pos, name) in enumerate(hits)]


def declared(body: str) -> str | None:
    m = GRADES_RE.search(body)
    return m.group("surface") if m else None


def _any(body: str, pats) -> bool:
    return any(p.search(body) for p in pats)


COMMENT_OR_ECHO = re.compile(r"^\s*(#|echo\b|printf\b)")
# `command -v <tool>` asks whether a tool EXISTS. It runs nothing over anything,
# so a presence probe for `rustfmt` is not the check grading the checkout --
# which is what this gate read it as on its second run, one line after the fix
# hint had already fooled it.
PRESENCE_PROBE = re.compile(r"\bcommand\s+-v\b")


def code_lines(body: str) -> list[str]:
    """The section's CODE: no comments, no `echo`/`printf` payloads.

    A comment that MENTIONS a command is not that command, and neither is a
    fix-hint printed at the user. R2221 paid for this exact confusion one gate
    over -- a doc comment reading "the `#[test]`s ..." armed a scanner -- and
    this gate walked into it on its own first run: the repaired Check 2 tells
    the author to run `cargo fmt --all`, in an `echo`, and the scan read that
    as the check still grading the checkout.
    """
    return [ln for ln in body.splitlines()
            if not COMMENT_OR_ECHO.match(ln) and not PRESENCE_PROBE.search(ln)]


def markers(body: str) -> tuple[bool, bool, bool]:
    """`(index_content, index_paths, worktree_cmd)` for one section body."""
    code = code_lines(body)
    joined = "\n".join(code)
    content = _any(joined, INDEX_CONTENT)
    paths = _any(joined, INDEX_PATHS)
    # Drop the lines that READ the index before asking what touches the
    # checkout, so an index-fed formatter is not mistaken for a worktree one.
    rest = "\n".join(ln for ln in code
                     if not any(p.search(ln) for p in INDEX_CONTENT))
    return content, paths, _any(rest, WORKTREE_CMD)


def check(hook_text: str) -> tuple[bool, list[str]]:
    lines: list[str] = []
    ok = True

    secs = sections(hook_text)
    if not secs:
        return False, ["hook-surface FAIL: no `# ─── Check <n>` section was "
                       "found. That is the scan having stopped scanning, not "
                       "the hook having no checks -- a population of zero is "
                       "not a pass."]

    counts: dict[str, int] = {s: 0 for s in SURFACES}
    for name, body in secs:
        surface = declared(body)
        content, paths, wt = markers(body)
        if surface is None:
            ok = False
            lines.append(
                f"hook-surface FAIL: `{name}` declares no `# grades: "
                f"<surface>`. Which artifact a check grades is the difference "
                f"between blocking a bad commit and blessing one, and 'nobody "
                f"wrote it down' must not look like 'this one really does "
                f"grade the checkout'. One of {', '.join(SURFACES)}.")
            continue
        if surface not in SURFACES:
            ok = False
            lines.append(f"hook-surface FAIL: `{name}` declares `{surface}`, "
                         f"which is not one of {', '.join(SURFACES)}.")
            continue
        counts[surface] += 1

        if surface == "index-content" and not content:
            ok = False
            lines.append(
                f"hook-surface FAIL: `{name}` declares `index-content` and "
                f"reads none. Listing staged PATHS is not reading staged "
                f"BYTES -- `git diff --cached --name-only` picks the "
                f"population and says nothing about what is in it. Read the "
                f"blob with `git show \":$path\"`.")
        elif surface == "index-paths" and not paths:
            ok = False
            lines.append(f"hook-surface FAIL: `{name}` declares `index-paths` "
                         f"and never asks git which paths are staged.")
        elif surface.startswith("index") and wt:
            ok = False
            lines.append(
                f"hook-surface FAIL: `{name}` declares `{surface}` and runs a "
                f"command over the CHECKOUT. Those are different artifacts and "
                f"they disagree in both directions -- a commit carrying "
                f"unformatted bytes passes while the tree is clean, and a "
                f"clean commit is blocked by drift it does not carry. Both "
                f"reproduced for open-debt item 621.")
        elif surface == "worktree" and not wt:
            ok = False
            lines.append(
                f"hook-surface FAIL: `{name}` declares `worktree` and runs no "
                f"command that reads the checkout, so nothing can ever refute "
                f"the label. Declare what it does grade.")
        elif surface == "not-a-file" and (content or paths or wt):
            ok = False
            lines.append(
                f"hook-surface FAIL: `{name}` declares `not-a-file` and "
                f"touches a file surface after all.")
        else:
            lines.append(f"  hook-surface: {name} -> {surface}")

    lines.append("  hook-surface: %d check(s); %s"
                 % (len(secs),
                    ", ".join(f"{n} {s}" for s, n in counts.items() if n)))
    return ok, lines


# ─── selftest ───────────────────────────────────────────────────────────────
#
# The first two cases are shapes this hook has actually worn: Check 2 before
# R2283 (selects from the index, grades the checkout) and a check with no
# declaration at all, which is every check in the file before this round.

def _sec(name: str, grades: str | None, body: str) -> str:
    head = f"# ─── {name} — fixture ──────\n"
    if grades is not None:
        head += f"# grades: {grades}\n"
    return head + body + "\n"


_SELECT = 'staged=$(git diff --cached --name-only)\n'
_FMT_TREE = 'cargo fmt --all -- --check\n'
_READ_BLOB = 'git show ":$path" | rustfmt --check --edition 2021\n'
_SPEC_ARG = "wz_schema_pin_gate ':' 'pre-commit' 'the index'\n"
_IDENT = "wz_ident_gate_pending 'pre-commit'\n"

_CASES = [
    ("the old Check 2: index paths, worktree verdict", False,
     _sec("Check 1", "index-paths", _SELECT + _FMT_TREE)),
    ("no declaration at all", False, _sec("Check 1", None, _READ_BLOB)),
    ("the new Check 2: index paths, index-fed formatter", True,
     _sec("Check 1", "index-content", _SELECT + _READ_BLOB)),
    ("index-content through a ':' spec argument", True,
     _sec("Check 1", "index-content", _SPEC_ARG)),
    ("index-content declared, only paths read", False,
     _sec("Check 1", "index-content", _SELECT)),
    ("index-paths declared, no path query", False,
     _sec("Check 1", "index-paths", "echo hi\n")),
    ("a surface nobody defined", False,
     _sec("Check 1", "staging-area", _READ_BLOB)),
    ("worktree declared and a worktree command present", True,
     _sec("Check 1", "worktree", _FMT_TREE)),
    ("worktree declared with nothing to refute it", False,
     _sec("Check 1", "worktree", "echo hi\n")),
    ("not-a-file, and it really is not", True,
     _sec("Check 1", "not-a-file", _IDENT)),
    ("not-a-file while touching the index", False,
     _sec("Check 1", "not-a-file", _SELECT)),
    ("several checks, one undeclared", False,
     _sec("Check 1", "index-content", _READ_BLOB) + _sec("Check 2", None, _SELECT)),
    # The shape the repaired Check 2 wears, and the one the first draft of this
    # gate got wrong: the fix hint it PRINTS names `cargo fmt --all`, which is
    # a string, not a command this check runs.
    ("a fix hint that names the worktree command", True,
     _sec("Check 1", "index-content",
          _SELECT + _READ_BLOB +
          '    echo "  fix: (cd crates && cargo fmt --all) && git add -u" >&2\n')),
    ("a COMMENT that names the worktree command", True,
     _sec("Check 1", "index-content",
          "# this replaced `cargo fmt --all -- --check`\n" + _READ_BLOB)),
    ("a presence PROBE for the formatter", True,
     _sec("Check 1", "index-content",
          '    if ! command -v rustfmt >/dev/null 2>&1; then\n' + _READ_BLOB)),
    ("no section at all", False, "# just a hook\n"),
]


def selftest() -> bool:
    ok = True
    for name, want, text in _CASES:
        got, lines = check(text)
        if got != want:
            ok = False
            print(f"  hook-surface SELFTEST `{name}`: got {got}, expected {want}",
                  file=sys.stderr)
            for ln in lines:
                print(f"      {ln}", file=sys.stderr)
    if ok:
        print(f"  hook-surface: selftest passed ({len(_CASES)} cases, both verdicts)")
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
