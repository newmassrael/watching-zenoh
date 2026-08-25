#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

"""R2098 (no register item) — the LGPL -> AGPL relicense, as a rerunnable
EXACT-LITERAL substitution.

It closes no register item on purpose: the relicense is an OWNER DECISION, not
a debt anyone had filed. What the gate half of this file does close is the
residue that decision creates -- a substitution over 1032 files whose failure
mode is a silent miss.

It exists as a file rather than a shell one-liner for three reasons, and each
one is a rule this workspace already pays for elsewhere:

1. EXACT LITERAL, NOT REGEX. The thing being replaced is a 68-character SPDX
   expression that occurs at most once per file. A regex over 1000+ files is
   how unrelated assertion strings get damaged; `str.replace` on a full literal
   cannot match anything but the literal.

2. IT REPORTS A COUNT, AND THE COUNT IS THE VERDICT. A relicense that silently
   misses files is worse than one that fails loudly: the misses are invisible
   and they are the files that stay under the old terms. So the run prints how
   many files it touched, and `--check` re-reads the tree and FAILS if any
   tracked file still carries the old expression. That second mode is what the
   gate calls.

3. IT NAMES WHAT IT WILL NOT TOUCH. `out/**` is SCE-generated and SCE owns the
   generation-time header policy (CLAUDE.md, License section); `vendor/**` is
   third-party and keeps its own headers. Both are skipped BY PATH, not by
   pattern, so a file that gains a wz header later cannot quietly slip in.

## R2104b (open-debt item 523) — THE MODE IS NOW REQUIRED, AND THERE IS NO DEFAULT

The first version decided its mode with `check_only = "--check" in sys.argv`,
so EVERY other input -- `--help`, a typo, no argument at all -- fell through to
the REWRITE path. Measured on the tree as it stood: `relicense_spdx.py --help`
printed `relicense-spdx: rewrote 0 file(s)` and exited 0. A person who typed
`--help` to find out what the program does had it walk 1000+ tracked files with
write intent, and a CI step reaching for the gate with `--chek` would have
edited the tree instead of grading it.

It was harmless only because the tree currently carries ZERO occurrences of the
old expression, so the rewrite had nothing to find. That is not a property of
the program; it is a property of today, and it stops holding at the next
relicense -- which is exactly when this file gets run again.

WHY REQUIRING A MODE RATHER THAN DEFAULTING TO `--check`. Defaulting to the
safe mode fixes the damage but leaves an ambiguity that bites the other way: a
person with the old habit types the bare command expecting a rewrite, gets a
check, reads `OK` and believes the rewrite happened. A silent no-op wearing a
success message is the shape this workspace names most often. The two modes
here are READ and WRITE -- opposites, not a default and a variant -- so the
program refuses to guess which one you meant. `--help` answers for real, an
unknown argument is refused by name, and a bare invocation names both modes.

The rewrite mode is `--apply`. No caller passed a bare invocation, so nothing
in the tree had to change with it: `run-ci.sh`'s gate already said `--check`.
"""

import argparse
import pathlib
import subprocess
import sys
import tempfile

# Built by concatenation, and that is not a style choice: this file is itself
# a TRACKED file the check walks, so a whole-literal `OLD` would match its own
# source and the gate could never pass -- it reported exactly one straggler,
# itself, on the relicense commit. Splitting the literal keeps this file IN
# SCOPE (a real stale header here would still be caught) where a path-based
# exemption would have carved it out permanently.
OLD = "LGPL-3.0-or-later" + " OR LicenseRef-watching-zenoh-Commercial"
NEW = "AGPL-3.0-or-later" + " OR LicenseRef-watching-zenoh-Commercial"

# Skipped by PATH prefix, for the reasons in the module docstring.
SKIP_PREFIXES = ("out/", "vendor/")


def tracked_files() -> list[pathlib.Path]:
    """Every tracked file, from this tree's own VCS rather than a glob."""
    out = subprocess.run(
        ["git", "ls-files", "-z"],
        capture_output=True,
        check=True,
    ).stdout
    return [
        pathlib.Path(name)
        for name in out.decode("utf-8").split("\0")
        if name and not name.startswith(SKIP_PREFIXES)
    ]


def carries_old(path: pathlib.Path) -> bool:
    try:
        return OLD in path.read_text(encoding="utf-8")
    except (UnicodeDecodeError, OSError):
        return False


def check() -> int:
    """READ. Fail if any tracked file still carries the old expression."""
    hits = [p for p in tracked_files() if carries_old(p)]
    if hits:
        print(f"relicense-spdx: FAIL -- {len(hits)} tracked file(s) still")
        print(f"  carry `{OLD}`.")
        print("  A relicense that misses files leaves them under the old")
        print("  terms, and nothing else in this tree measures that.")
        for p in hits[:20]:
            print(f"    {p}")
        if len(hits) > 20:
            print(f"    ... and {len(hits) - 20} more")
        return 1
    print("relicense-spdx: OK -- no tracked file carries the old expression")
    return 0


def apply() -> int:
    """WRITE. Substitute the expression in every tracked file that carries it."""
    hits = [p for p in tracked_files() if carries_old(p)]
    for path in hits:
        text = path.read_text(encoding="utf-8")
        path.write_text(text.replace(OLD, NEW), encoding="utf-8")
    print(f"relicense-spdx: rewrote {len(hits)} file(s)")
    return 0


def selftest() -> int:
    """R2104b (item 523) -- drive both arms against a FIXTURE git tree.

    A fixture rather than this repository, and that is not tidiness: half of
    what is under test is the WRITE path, so a test that ran here would be a
    test that relicenses the tree it is grading. The fixture is a real `git
    init` because `tracked_files()` asks git rather than globbing -- a
    directory of files would report an empty population, and an empty
    population is the failure mode that reads as a pass.

    What each non-write arm asserts is not only the exit code but that the
    fixture is UNCHANGED. The defect being closed did not crash and did not
    print an error; it wrote. So "did it write?" is the question, and the exit
    code alone cannot answer it.
    """
    header = f"# SPDX-License-Identifier: {OLD}\n"

    # (label, argv, expected rc, substring the output must carry, may it write?)
    cases: list[tuple[str, list[str], int | None, str, bool]] = [
        ("--help answers and does not write", ["--help"], 0, "usage", False),
        ("an unknown argument is refused", ["--chek"], None, "--chek", False),
        ("a bare invocation is refused", [], None, "--check", False),
        ("--check and --apply together are refused", ["--check", "--apply"], None, "not allowed", False),
        ("--check FAILS on a straggler", ["--check"], 1, "still", False),
        ("--apply rewrites it", ["--apply"], 0, "rewrote 1 file", True),
    ]

    script = pathlib.Path(__file__).resolve()
    failures = 0
    for label, argv, want_rc, want_text, may_write in cases:
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            (root / "a.rs").write_text(header, encoding="utf-8")
            # Under a SKIP prefix: it carries the old expression and must be
            # left alone by BOTH arms, which is the "skipped BY PATH" claim.
            (root / "vendor").mkdir()
            (root / "vendor" / "b.rs").write_text(header, encoding="utf-8")
            subprocess.run(["git", "init", "-q"], cwd=root, check=True)
            subprocess.run(["git", "add", "-A"], cwd=root, check=True,
                           capture_output=True)

            proc = subprocess.run(
                [sys.executable, str(script), *argv],
                cwd=root, capture_output=True, text=True, check=False,
            )
            out = proc.stdout + proc.stderr
            problems = []
            if want_rc is None:
                if proc.returncode == 0:
                    problems.append("expected a refusal, got rc=0")
            elif proc.returncode != want_rc:
                problems.append(f"rc={proc.returncode}, expected {want_rc}")
            if want_text not in out:
                problems.append(f"output does not carry {want_text!r}")

            wrote = OLD not in (root / "a.rs").read_text(encoding="utf-8")
            if wrote != may_write:
                problems.append(
                    "it WROTE and must not have" if wrote
                    else "it did not write and had to"
                )
            if OLD not in (root / "vendor" / "b.rs").read_text(encoding="utf-8"):
                problems.append("it rewrote a file under a SKIP prefix")

            if problems:
                failures += 1
                print(f"  FAIL {label}: {'; '.join(problems)}")
                if out.strip():
                    print(f"       output: {out.strip().splitlines()[0]}")

    # The pair composes: after a write, the check passes. Its own fixture,
    # because it is two invocations against one tree rather than one.
    with tempfile.TemporaryDirectory() as tmp:
        root = pathlib.Path(tmp)
        (root / "a.rs").write_text(header, encoding="utf-8")
        subprocess.run(["git", "init", "-q"], cwd=root, check=True)
        subprocess.run(["git", "add", "-A"], cwd=root, check=True,
                       capture_output=True)
        rc_apply = subprocess.run(
            [sys.executable, str(script), "--apply"],
            cwd=root, capture_output=True, text=True,
        ).returncode
        rc_check = subprocess.run(
            [sys.executable, str(script), "--check"],
            cwd=root, capture_output=True, text=True,
        ).returncode
        text = (root / "a.rs").read_text(encoding="utf-8")
        if rc_apply != 0 or rc_check != 0 or NEW not in text or OLD in text:
            failures += 1
            print(
                f"  FAIL --apply then --check: apply rc={rc_apply}, "
                f"check rc={rc_check}, new-expression-present={NEW in text}"
            )

    total = len(cases) + 1
    print(f"relicense-spdx selftest: {total - failures}/{total} arm(s) pass")
    return 1 if failures else 0


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="relicense_spdx.py",
        description=(
            "Substitute this tree's SPDX licence expression, or check that no "
            "tracked file still carries the old one."
        ),
        epilog=(
            "A MODE IS REQUIRED AND THERE IS NO DEFAULT. This program's two "
            "modes are READ and WRITE -- opposites rather than a default and a "
            "variant -- so it refuses to guess which one was meant. Item 523: "
            "the first version treated every argument that was not --check as "
            "a request to rewrite, so `--help` walked the tree with write "
            "intent and exited 0."
        ),
    )
    # NOT `required=True`, and the reason is the message rather than the rule.
    # argparse checks a required group BEFORE it complains about extras, so
    # `--chek` came back as "one of the arguments --check --apply --selftest is
    # required" -- true, unhelpful, and silent about the typo that is the whole
    # reason the person is reading it. The requirement is enforced below, after
    # the unknown-argument check, so a misspelling is named as one.
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument(
        "--check", action="store_true",
        help="READ. Exit non-zero if any tracked file still carries the old "
             "expression. This is what the CI gate calls.",
    )
    mode.add_argument(
        "--apply", action="store_true",
        help="WRITE. Rewrite every tracked file that carries the old "
             "expression, and report how many were touched.",
    )
    mode.add_argument(
        "--selftest", action="store_true",
        help="Drive both modes against a fixture git tree; touches nothing here.",
    )
    args, extra = parser.parse_known_args()
    if extra:
        parser.error(
            "unrecognized argument(s): " + " ".join(extra) + " -- refused "
            "rather than ignored, because the version this replaced treated "
            "anything that was not --check as a request to REWRITE the tree"
        )
    if not (args.check or args.apply or args.selftest):
        parser.error(
            "a mode is required: --check (read) or --apply (write). There is "
            "no default -- see the epilog in --help for why guessing between "
            "them is the thing this program will not do"
        )

    if args.selftest:
        return selftest()
    if args.check:
        return check()
    return apply()


if __name__ == "__main__":
    sys.exit(main())
