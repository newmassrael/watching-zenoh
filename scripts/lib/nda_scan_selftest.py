#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

"""R2982 (no register item) -- the confidential-vocabulary scan matches a SHAPE
as well as a word.

`scripts/lib/nda-scan.sh` was fixed-string and word-bounded only. That cannot
express a vocabulary made of a prefix followed by any number of digits -- a
tracker's ticket ids, which are minted continuously -- because `grep -w` needs
the character after the match to be a non-word character, and the digits are
word characters. A `re:` line in the term list is a pattern term.

This drives the real shell function against throwaway git repositories, both
ways, so that the scan is proved to BLOCK what it exists to block and to LET
PASS what it must: a diff that deletes the vocabulary is a scrub, and blocking
it would block the fix. The fixtures use an invented prefix (`TKT`), never a
real one -- the real pattern lives in the untracked term list and must not be
written into a tracked file.

Every repository is created under a temporary directory that is removed on
exit; nothing is left behind.
"""

import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCAN = ROOT / "scripts" / "lib" / "nda-scan.sh"

GIT = ["git", "-c", "user.name=selftest", "-c", "user.email=selftest@invalid",
       "-c", "commit.gpgsign=false", "-c", "core.hooksPath=/dev/null"]

FAILURES: list[str] = []


def git(repo: Path, *args: str) -> None:
    subprocess.run([*GIT, *args], cwd=repo, check=True,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def commit(repo: Path, body: str, message: str) -> None:
    (repo / "f.txt").write_text(body, encoding="utf-8")
    git(repo, "add", "f.txt")
    git(repo, "commit", "-q", "-m", message)


def scan(terms: str | None, first: str, second: str,
         first_msg: str = "base", second_msg: str = "change") -> tuple[int, str]:
    """Run `wz_nda_scan base..head` over a two-commit repository."""
    with tempfile.TemporaryDirectory() as tmp:
        repo = Path(tmp) / "repo"
        repo.mkdir()
        git(repo, "init", "-q")
        commit(repo, first, first_msg)
        git(repo, "tag", "base")
        commit(repo, second, second_msg)
        env = {"PATH": "/usr/bin:/bin", "HOME": tmp}
        if terms is not None:
            listing = Path(tmp) / "terms.txt"
            listing.write_text(terms, encoding="utf-8")
            env["WZ_NDA_TERMS"] = str(listing)
        run = subprocess.run(
            ["bash", "-c", 'source "$1" && wz_nda_scan base..HEAD', "_", str(SCAN)],
            cwd=repo, env=env, capture_output=True, text=True)
        return run.returncode, run.stdout + run.stderr


def message_scan(terms: str, message: str) -> tuple[int, str]:
    """Run `wz_nda_scan_message <file>` over one commit message."""
    with tempfile.TemporaryDirectory() as tmp:
        listing = Path(tmp) / "terms.txt"
        listing.write_text(terms, encoding="utf-8")
        msg = Path(tmp) / "msg.txt"
        msg.write_text(message, encoding="utf-8")
        run = subprocess.run(
            ["bash", "-c", 'source "$1" && wz_nda_scan_message "$2"', "_", str(SCAN), str(msg)],
            env={"PATH": "/usr/bin:/bin", "HOME": tmp, "WZ_NDA_TERMS": str(listing)},
            capture_output=True, text=True)
        return run.returncode, run.stdout + run.stderr


def expect(name: str, got: tuple[int, str], rc: int, needle: str | None = None) -> None:
    code, out = got
    if code != rc:
        FAILURES.append(f"{name}: rc {code}, wanted {rc}\n{out}")
    elif needle is not None and needle not in out:
        FAILURES.append(f"{name}: output lacks {needle!r}\n{out}")


def main() -> int:
    if not SCAN.is_file():
        print(f"nda-scan selftest: FAIL {SCAN} is missing")
        return 1

    word = "secretword\n"
    shape = "re:\\bTKT-[0-9]+\\b\n"

    # The fixed-string half, unchanged: the control that the rewrite did not
    # break what already worked.
    expect("word blocks", scan(word, "a\n", "a\nhas secretword here\n"), 1, "BLOCKED")
    expect("word substring passes", scan(word, "a\n", "a\nsecretwords\n"), 0)

    # The shape half. A ticket id is blocked wherever it stands in an added line.
    expect("shape blocks an added id", scan(shape, "a\n", "a\nsee TKT-1234 for why\n"), 1, "TKT-1234")
    expect("shape blocks a longer id", scan(shape, "a\n", "a\n// TKT-99999 --\n"), 1, "TKT-99999")
    # Near misses the boundary and the digits must not catch.
    expect("shape: prefix alone passes", scan(shape, "a\n", "a\nthe TKT- prefix\n"), 0)
    expect("shape: glued prefix passes", scan(shape, "a\n", "a\nXTKT-12 is not one\n"), 0)
    expect("shape: other prefix passes", scan(shape, "a\n", "a\nABC-1234\n"), 0)

    # A diff that only DELETES the vocabulary is a scrub and must go through.
    expect("deleting an id passes", scan(shape, "a\nsee TKT-1234\n", "a\nsee the round\n"), 0)
    # A line that is UNCHANGED context is not an added line.
    expect("untouched id passes", scan(shape, "TKT-1234 stays\n", "TKT-1234 stays\nnew line\n"), 0)

    # The commit messages of the range, where the known incident put it.
    expect("message id blocks", scan(shape, "a\n", "a\nb\n", second_msg="fix TKT-77 thing"), 1, "commit message")
    expect("message word blocks", scan(word, "a\n", "a\nb\n", second_msg="about secretword"), 1, "commit message")

    # Both kinds in one list, and a list of ONLY patterns is a real list, not an
    # empty one.
    expect("mixed list, word", scan(word + shape, "a\n", "a\nsecretword\n"), 1)
    expect("mixed list, shape", scan(word + shape, "a\n", "a\nTKT-5\n"), 1)
    expect("patterns only, clean", scan(shape, "a\n", "a\nnothing\n"), 0, "1 term(s)")

    # An uncompilable pattern matches nothing and would green every push, which
    # is the failure this gate exists to refuse: it must REFUSE, not pass.
    expect("bad pattern refuses", scan("re:(\n", "a\n", "a\nTKT-1\n"), 1, "not a valid")
    # An EMPTY pattern is the opposite failure: it matches every line, so it
    # would block every push and get the list ripped out.
    expect("empty pattern refuses", scan("re:\n", "a\n", "a\nb\n"), 1, "would match every line")
    # One bad pattern among good ones still refuses: the list is one input.
    expect("bad pattern among good refuses", scan(word + "re:(\n", "a\n", "a\nb\n"), 1, "not a valid")

    # The list itself: absent refuses, declared-empty passes -- as before.
    expect("declared empty passes", scan("!acknowledged-empty\n", "a\n", "a\nTKT-1\n"), 0)
    expect("comments only refuses", scan("# nothing\n", "a\n", "a\nb\n"), 1)

    # The message door the commit-msg hook calls, so the refusal comes at commit
    # time and not as a stranded commit at push time.
    expect("message door blocks id", message_scan(shape, "fix: thing (TKT-9)\n"), 1, "TKT-9")
    expect("message door passes", message_scan(shape, "fix: thing\n\n- a bullet\n"), 0)
    expect("message door word", message_scan(word, "about secretword\n"), 1)

    if FAILURES:
        print(f"nda-scan selftest: FAIL ({len(FAILURES)} case(s))")
        for failure in FAILURES:
            print("  - " + failure.replace("\n", "\n    "))
        return 1
    print("nda-scan selftest: OK (fixed-string and pattern terms, blocked and passing, both ways)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
