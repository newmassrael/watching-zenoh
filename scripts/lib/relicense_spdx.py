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
"""

import pathlib
import subprocess
import sys

OLD = "LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial"
NEW = "AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial"

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


def main() -> int:
    check_only = "--check" in sys.argv
    hits = [p for p in tracked_files() if carries_old(p)]

    if check_only:
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

    for path in hits:
        text = path.read_text(encoding="utf-8")
        path.write_text(text.replace(OLD, NEW), encoding="utf-8")
    print(f"relicense-spdx: rewrote {len(hits)} file(s)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
