#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

"""R2273 (N46) — every `scripts/…` path a git hook NAMES has to exist.

(The register id is `debt-carry-N46`; the citation spells the carry number
because `gate_provenance_lint`'s item grammar takes `N<nn>` for that namespace
and its `debt-<name>` alternative is lowercase-only, so the full id does not
parse there. Measured, not guessed: the full-id spelling was tried first and
the lint refused it.)

## The debt this pays, and how its own sentence measured out

`debt-carry-N46` reads, in full:

    OPEN: the guard hook points at scripts/verify.sh, which this repo does not
    have

Measured at the start of this round, the sentence is HALF true and half false.
`scripts/verify.sh` really is absent -- but NOTHING points at it. The only file
in the whole tracked tree that spells that name is the store, and inside the
store the only occurrence is that debt item's own `reason`; the ledger does not
name it once. `git log -S` finds the string entering this history in exactly one
commit, `5a8b8a48` ("the register moves into the store"), as a PURE ADDITION --
so the sentence was carried in from the pre-store register and nothing has
measured it since. The hook it accuses vanished with the pre-scrub history, if
it was ever here at all.

That is item 47's shape exactly: a register reason outliving the code it is
about, with nothing that would notice. Deleting the row would close the item and
leave the hole -- so what closes it is an instrument, and this is that.

## What it checks, and why the subject is HOOKS

The population is `git ls-files .githooks` -- three files today -- and every
`scripts/<path>.sh|.py` token they contain must name a file that exists.
Measured when this was written: 22 distinct paths, 0 missing. The finding count
is zero and that is not a weakness: a hook that invokes a gate which is not
there does nothing, silently, which is the whole harm N46 names.

⛔ EVERY MENTION IS CLAIMED, including one inside a comment, and there is NO
exemption table. A hook comment naming a script that no longer exists is the
same defect in prose form -- it is what sent this very item to a file that had
already gone. An exemption list would be the escape hatch this workspace keeps
finding, and the way to be right about a legitimate reference is for the file to
BE there.

## Why not the wider subject

The obvious generalisation -- "every `scripts/…` path named anywhere under
`scripts/` and `.githooks/` must exist" -- was measured first and REFUSED: 125
distinct paths, 5 missing, and all five are legitimate. Three are fixture names
`prose_named_identifier_gate.py` writes into a temp dir (`scripts/lib/base.py`,
`scripts/lib/g.py`, `scripts/run.sh`), one is a comment plus an echo string in
`run-ci.sh` (`scripts/lib/doclink-dependents.sh`, the hyphen spelling of a file
that exists with underscores), and one is a selftest fixture in
`gate_reason_claims.py` (`scripts/provision.sh`). A rule that reds on five
legitimate rows is not a tightening -- R2253 settled that -- and separating
"invoked" from "merely named" inside arbitrary Python and shell is a heuristic,
which is what this workspace throws away. The hooks are the subject the item
names, they are three files, and every reference in them is real.
"""

from __future__ import annotations

import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]

#: A `scripts/…` path token. The negative lookbehind keeps it from starting
#: mid-token inside a longer path, which would invent a reference nobody wrote.
REFERENCE = re.compile(r"(?<![\w/.-])(scripts/[\w./-]+\.(?:sh|py))")


def hook_files(root: pathlib.Path) -> list[str]:
    """The tracked files under `.githooks`, from git rather than from a list."""
    out = subprocess.run(
        ["git", "ls-files", ".githooks"],
        cwd=root,
        capture_output=True,
        text=True,
    )
    return sorted(out.stdout.split())


def references(root: pathlib.Path, files: list[str]) -> dict[str, list[str]]:
    """`path -> the "<file>:<line>" sites naming it`."""
    found: dict[str, list[str]] = {}
    for rel in files:
        try:
            text = (root / rel).read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for number, line in enumerate(text.split("\n"), 1):
            for match in REFERENCE.finditer(line):
                found.setdefault(match.group(1), []).append(f"{rel}:{number}")
    return found


def check(root: pathlib.Path | None = None) -> int:
    root = ROOT if root is None else root
    files = hook_files(root)
    # ⛔ A POPULATION OF ZERO IS RED, not a pass, in BOTH of its shapes. No hook
    # files means the gate was pointed at nothing; hook files with no reference
    # means the hooks stopped calling anything, and a hook that invokes no gate
    # is the failure this file is about, arriving from the other side.
    if not files:
        print(
            "hook-script-reference gate FAIL: `git ls-files .githooks` named no "
            "file, so this gate read nothing. An empty population agrees with "
            "every rule here.",
            file=sys.stderr,
        )
        return 1
    found = references(root, files)
    if not found:
        print(
            f"hook-script-reference gate FAIL: {len(files)} hook file(s) and NOT "
            f"ONE names a `scripts/…` path. The hooks call this tree's gates by "
            f"path; naming none of them means they run none of them.",
            file=sys.stderr,
        )
        return 1
    missing = {p: s for p, s in found.items() if not (root / p).exists()}
    if missing:
        for path, sites in sorted(missing.items()):
            print(
                f"hook-script-reference gate FAIL: `{path}` is named at "
                f"{', '.join(sites)} and no such file exists. A hook that "
                f"reaches for a gate which is not there runs no gate and says "
                f"nothing -- restore the file, or stop naming it.",
                file=sys.stderr,
            )
        return 1
    print(
        f"hook-script-reference: OK — {len(files)} hook file(s) name "
        f"{len(found)} distinct `scripts/…` path(s), every one of them present"
    )
    return 0


#: `(name, files, want_pass)`. The fixture tree is written whole, so a case
#: cannot pass by inheriting the real repository's hooks.
FIXTURES: tuple[tuple[str, dict[str, str], bool], ...] = (
    (
        "present",
        {
            ".githooks/pre-commit": "#!/bin/bash\nbash scripts/lib/real.sh\n",
            "scripts/lib/real.sh": "#!/bin/bash\n",
        },
        True,
    ),
    (
        "missing",
        {".githooks/pre-commit": "#!/bin/bash\nbash scripts/lib/gone.sh\n"},
        False,
    ),
    # THE ITEM ITSELF, as a fixture: a hook that points at `scripts/verify.sh`.
    # This is the shape `debt-carry-N46` describes, and it is here so the claim
    # "that would be caught now" is a test rather than a sentence.
    (
        "n46-shape",
        {".githooks/pre-push": "#!/bin/bash\nexec scripts/verify.sh\n"},
        False,
    ),
    # A COMMENT is claimed too -- deliberately, see the module docstring.
    (
        "named-only-in-a-comment",
        {".githooks/pre-commit": "#!/bin/bash\n# see scripts/lib/gone.py\n"},
        False,
    ),
    # Both floors, from their two sides.
    ("no-hook-files", {"scripts/lib/real.sh": "#!/bin/bash\n"}, False),
    (
        "hooks-that-name-nothing",
        {".githooks/pre-commit": "#!/bin/bash\necho hello\n"},
        False,
    ),
)

#: The sentence each RED fixture is about. Required for every failing case:
#: this gate has three different reds and `rc != 0` does not say which.
FIXTURE_REASON = {
    "missing": "scripts/lib/gone.sh",
    "n46-shape": "scripts/verify.sh",
    "named-only-in-a-comment": "scripts/lib/gone.py",
    "no-hook-files": "named no file",
    "hooks-that-name-nothing": "NOT ONE names",
}


def selftest() -> int:
    import contextlib
    import io
    import tempfile

    bad = 0
    reds = {name for name, _f, want in FIXTURES if not want}
    # The reason table, judged BOTH ways -- the arm R2272 had to add to
    # `prose_named_identifier_gate.py` after writing it as a per-case `if` that
    # no input could reach.
    for name in sorted(reds - set(FIXTURE_REASON)):
        print(f"  {name}: WRONG — a RED fixture pins no reason", file=sys.stderr)
        bad = 1
    for name in sorted(set(FIXTURE_REASON) - reds):
        print(
            f"  {name}: WRONG — a reason is pinned for a case that is not RED",
            file=sys.stderr,
        )
        bad = 1

    for name, files, want_pass in FIXTURES:
        said = io.StringIO()
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            subprocess.run(["git", "init", "-q"], cwd=root, check=False)
            for rel, body in files.items():
                path = root / rel
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(body, encoding="utf-8")
            subprocess.run(["git", "add", "-A"], cwd=root, check=False)
            with contextlib.redirect_stderr(said), contextlib.redirect_stdout(
                io.StringIO()
            ):
                rc = check(root=root)
        ok = (rc == 0) == want_pass
        detail = ""
        why = FIXTURE_REASON.get(name)
        if not want_pass and why is not None and why not in said.getvalue():
            ok = False
            detail = f" — expected the finding about {why!r}"
        print(
            f"hook-script-reference selftest {name}: rc={rc} "
            f"want={'pass' if want_pass else 'fail'} "
            f"{'ok' if ok else 'WRONG'}{detail}"
        )
        if not ok:
            bad = 1
    return bad


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if args == ["--selftest"]:
        return selftest()
    if args in ([], ["--check"]):
        return check()
    print(f"usage: {pathlib.Path(sys.argv[0]).name} [--check | --selftest]", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
