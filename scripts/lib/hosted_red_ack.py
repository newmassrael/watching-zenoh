#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
"""Is a red hosted run acknowledged by a row THIS push adds?

The previous-run gate (`scripts/lib/previous-run-gate.sh`) refuses a push while the
previous hosted run is red unless someone who looked says so. The saying used to be an
environment variable on the pushing process (`WZ_ACK_RED=<run id>`). A verdict that
depends on the pusher's environment cannot be reproduced by anything that pushes for
the pusher: a queue integrator cherry-picks a commit, runs the repository's pre-push
hook on the result and pushes, and the author's environment is not there. The saying
is therefore a row in `docs/hosted-red-acks.md`, written in a commit of the range being
pushed, and the gate reads the row from the range it is given.

A row acknowledges run R for this push when the range ADDS a table row whose second
cell holds R written in backticks. That is exactly the file's own format: the second
column is `run`, and a row naming two runs holds both (`` `1`,`2` ``). Three properties
are kept on purpose:

  * per push: only a row ADDED in the range counts, so a row from an earlier push
    cannot cover a later red silently, which is what the environment variable's
    "per invocation" guaranteed and the file's own rows record being repeated for;
  * per run: the id is matched whole between backticks, so one run's id never
    acknowledges another whose digits contain it;
  * by the author, not the gate: nothing here reads the first column, so the label is
    the author's (a slug, a debt item), and it needs no round number the commit cannot
    know.

    hosted_red_ack.py --range <base>..<tip> --run <id> [--repo <dir>]
        exit 0 acknowledged; 1 not acknowledged; 2 usage or git failed
    hosted_red_ack.py --selftest
"""

from __future__ import annotations

import re
import subprocess
import sys
import tempfile
from pathlib import Path

ACK_FILE = "docs/hosted-red-acks.md"


def added_rows(repo: Path, rng: str) -> list[str]:
    """The table rows the range adds to the acknowledgement file."""
    out = subprocess.run(
        ["git", "-C", str(repo), "diff", "-U0", "--no-color", rng, "--", ACK_FILE],
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    return [line[1:] for line in out.splitlines() if line.startswith("+") and not line.startswith("+++")]


def acknowledges(rows: list[str], run: str) -> bool:
    """True when a row's second cell holds `run` between backticks."""
    needle = f"`{run}`"
    for row in rows:
        if not row.startswith("|"):
            continue
        cells = row.split("|")
        # cells[0] is the text before the first bar; the first column is cells[1].
        if len(cells) > 2 and needle in cells[2]:
            return True
    return False


def _git(repo: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(repo), "-c", "user.name=t", "-c", "user.email=t@t", *args],
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()


def selftest() -> int:
    header = "| label | run | commit | note |\n|---|---|---|---|\n"
    failed = 0
    with tempfile.TemporaryDirectory() as tmp:
        repo = Path(tmp)
        _git(repo, "init", "-q")
        (repo / "docs").mkdir()
        ack = repo / ACK_FILE
        ack.write_text(header + "| old | `111` | `aaaa` | read earlier |\n", encoding="utf-8")
        (repo / "docs" / "other.md").write_text("x\n", encoding="utf-8")
        _git(repo, "add", "-A")
        _git(repo, "commit", "-q", "-m", "base")
        base = _git(repo, "rev-parse", "HEAD")

        def step(text: str, other: str | None = None) -> str:
            ack.write_text(text, encoding="utf-8")
            if other is not None:
                (repo / "docs" / "other.md").write_text(other, encoding="utf-8")
            _git(repo, "add", "-A")
            _git(repo, "commit", "-q", "-m", "step")
            return _git(repo, "rev-parse", "HEAD")

        old = header + "| old | `111` | `aaaa` | read earlier |\n"
        tip = step(old + "| mine | `222` | `bbbb` | new |\n| two | `333`,`444` | `cccc` | pair |\n")
        rng = f"{base}..{tip}"

        def check(name: str, got: bool, want: bool) -> None:
            nonlocal failed
            ok = got == want
            print(f"  {'ok  ' if ok else 'FAIL'} {name}")
            failed += 0 if ok else 1

        rows = added_rows(repo, rng)
        check("a row added in the range acknowledges its run", acknowledges(rows, "222"), True)
        check("a row naming two runs acknowledges each", acknowledges(rows, "333") and acknowledges(rows, "444"), True)
        check("a run no row names is not acknowledged", acknowledges(rows, "555"), False)
        check("a row of an earlier push does not count", acknowledges(rows, "111"), False)
        check("an id inside a longer id is not the run", acknowledges(rows, "22"), False)
        check("an id not between backticks is not the run", acknowledges(["| x | 222 | y | z |"], "222"), False)
        check("the run named in the note cell is not acknowledged", acknowledges(["| x | `1` | y | `222` |"], "222"), False)
        check("a line that is not a table row is not an acknowledgement", acknowledges(["note `222`"], "222"), False)

        tip2 = step(old, other="y\n")
        check("a range that adds no row acknowledges nothing", acknowledges(added_rows(repo, f"{tip}..{tip2}"), "222"), False)
        check("a row removed in the range acknowledges nothing", acknowledges(added_rows(repo, f"{tip}..{tip2}"), "333"), False)
        check("a row added and removed inside the range counts for nothing", acknowledges(added_rows(repo, f"{base}..{tip2}"), "222"), False)

        tip3 = step(old + "| again | `222` | `dddd` | acknowledged again |\n")
        check("a run acknowledged again by a later push counts there", acknowledges(added_rows(repo, f"{tip2}..{tip3}"), "222"), True)
        check("the CLI form agrees with the function", main(["--repo", str(repo), "--range", f"{tip2}..{tip3}", "--run", "222"]) == 0, True)
        check("the CLI form refuses a run the range does not name", main(["--repo", str(repo), "--range", f"{tip2}..{tip3}", "--run", "999"]) == 1, True)
    total = 14
    print(f"hosted_red_ack selftest: {total - failed}/{total} arm(s) pass")
    return 1 if failed else 0


def main(argv: list[str]) -> int:
    if argv == ["--selftest"]:
        return selftest()
    opts: dict[str, str] = {}
    it = iter(argv)
    for key in it:
        if key not in ("--range", "--run", "--repo"):
            print(__doc__, file=sys.stderr)
            return 2
        try:
            opts[key] = next(it)
        except StopIteration:
            print(__doc__, file=sys.stderr)
            return 2
    if "--range" not in opts or "--run" not in opts or not re.fullmatch(r"[0-9]+", opts["--run"]):
        print(__doc__, file=sys.stderr)
        return 2
    try:
        rows = added_rows(Path(opts.get("--repo", ".")), opts["--range"])
    except (subprocess.CalledProcessError, OSError) as err:
        print(f"hosted_red_ack: git could not read the range: {err}", file=sys.stderr)
        return 2
    return 0 if acknowledges(rows, opts["--run"]) else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
