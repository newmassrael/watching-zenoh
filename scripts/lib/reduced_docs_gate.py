#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
"""R3802 (no register item) — Layer C1bzr: every crate's docs build in its REDUCED configurations,
or spend exactly the ledger.

WHAT IS MEASURED. `doc_feature_sets.py --reduced` names the configurations: each largest set of a
crate without one feature it holds. Its docstring says why that family finds the links that
resolve with every feature on and break without one. This script documents each configuration
with `cargo doc --message-format=short` and reads every rustdoc and rustc error with its place.

WHAT A FINDING IS. One defect shows up in every configuration that gives up the feature it needs,
so a finding is counted once, by where it is: `(crate, file, message)`, with the number of
distinct positions in that file carrying that message. The line and column are not part of the
key, so an edit above a finding does not move the ledger; they are printed with every finding,
with the configurations it was seen in, so a reader can go straight to it.

WHAT A REFUSAL IS. Some reduced configurations are ones a crate turns away on purpose, with a
`compile_error!` guard: `wz-session-core` refuses the lifecycle verbs without a secure channel,
`wz-runtime-coop` a runtime with no task pool. No consumer can build such a configuration, so it
has no docs to break, and the errors after the guard's own follow from it. A configuration whose
errors include a guard firing is recorded as that guard alone, `refused: <its message>`. Those
ledger lines are the crates' design, not debt: one moves when a guard or a feature set does, and
the commit that moves it says which. Whether an error is a guard is read from the source at the
place rustc points to, not from the wording.

THE LEDGER. When the lane was written its measurement of 532 configurations found 597 findings
at 741 places, 477 of them in `wz-session-core` and `wz-runtime-tokio`. They are carried in `reduced_docs_ledger.txt` with a count each, the
way C1bz began with 631 and the T1 orphans are carried: never silenced, and checked in BOTH
directions. A count above the ledger is a regression. A count below it, or a ledger line nothing
measured, is a stale ledger, and the fix is to lower the line in the commit that earned it.

SHARDS. Every configuration costs a `cargo doc`, several hundred of them, so hosted CI splits
them: configuration `k` of the workspace-wide list, in a fixed order, belongs to shard
`k % shards`. A shard can judge the rising direction alone. Only the union of every shard can
judge the falling one, so each shard writes what it measured and `settle` reads them all, and
refuses a set of files that is not exactly one of each shard of one partition: a shard that did
not run must never read as a shard that found nothing.

Usage:
    reduced_docs_gate.py measure --out FILE [--shard I --shards N] [--only "CRATE ..."]
    reduced_docs_gate.py settle FILE...
    reduced_docs_gate.py ledger [--write] FILE...
                                             print the ledger the files measured, or write it
                                             under the ledger's header (the settle job's
                                             artifacts, from `gh run download`, are such files)
    reduced_docs_gate.py --selftest
Exit: 0 at the ledger; 1 above it, below it, or the input could not be read.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import tempfile
import time
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import doc_feature_sets  # noqa: E402

REPO = Path(__file__).resolve().parents[2]
CRATES = REPO / "crates"
LEDGER = Path(__file__).resolve().parent / "reduced_docs_ledger.txt"

# `wz-workload/src/mutation.rs:6:76: error: unresolved link to ...`
PLACED = re.compile(r"^(?P<path>[^\s:][^:]*):(?P<line>\d+):(?P<col>\d+): (?P<message>error.*)$")
UNPLACED = re.compile(r"^(?P<message>error(\[E\d+\])?: .*)$")
# The per-crate summary cargo prints after the findings, one per failing crate, not a finding.
SUMMARY = re.compile(r"^error: could not (document|compile) `")
NOWHERE = "-"
GUARD = "compile_error!"
REFUSED = "refused: "

Key = tuple[str, str, str]


def parse_findings(output: str) -> list[tuple[str, str, str]]:
    """`[(path, "line:col", message)]` of every error cargo printed."""
    found = []
    for line in output.splitlines():
        placed = PLACED.match(line)
        if placed:
            position = f"{placed['line']}:{placed['col']}"
            found.append((placed["path"], position, placed["message"]))
            continue
        unplaced = UNPLACED.match(line)
        if unplaced and not SUMMARY.match(line):
            found.append((NOWHERE, NOWHERE, unplaced["message"]))
    return found


def document(crate: str, arguments: list[str]) -> list[tuple[str, str, str]]:
    """The findings of one `cargo doc` of `crate`; a failure with none readable is one itself."""
    out = subprocess.run(
        ["cargo", "doc", "-p", crate, "--no-deps", "--quiet", "--message-format=short", *arguments],
        cwd=CRATES,
        capture_output=True,
        text=True,
        check=False,
    )
    found = parse_findings(out.stdout + out.stderr)
    if out.returncode != 0 and not found:
        # "Could not read what failed" must never print as "measured clean".
        found.append((NOWHERE, NOWHERE, f"error: cargo doc exited {out.returncode} with no error it could read"))
    return refusals(found, CRATES) or found


def refusals(found: list[tuple[str, str, str]], root: Path) -> list[tuple[str, str, str]]:
    """The findings that are a `compile_error!` guard firing, as `refused:` findings.

    A configuration a guard turns away is one no consumer can build, so it has no docs to break:
    what else it reports follows from the refusal and is not counted. The guard itself is."""
    guards = []
    for path, position, message in found:
        if path == NOWHERE:
            continue
        line, column = (int(n) for n in position.split(":"))
        try:
            text = (root / path).read_text(encoding="utf-8").splitlines()[line - 1]
        except (OSError, UnicodeDecodeError, IndexError):
            continue
        if text[column - 1 :].startswith(GUARD):
            guards.append((path, position, REFUSED + message.removeprefix("error: ")))
    return guards


def workspace_packages() -> list[dict]:
    out = subprocess.run(
        ["cargo", "metadata", "--no-deps", "--format-version", "1"],
        cwd=CRATES,
        capture_output=True,
        text=True,
        check=False,
    )
    if out.returncode != 0:
        raise SystemExit(f"reduced-docs: cargo metadata failed: {out.stderr.strip()}")
    packages = sorted(json.loads(out.stdout)["packages"], key=lambda p: p["name"])
    if not packages:
        raise SystemExit("reduced-docs: cargo metadata listed no workspace member")
    return packages


def configurations(packages: list[dict]) -> list[tuple[str, str, list[str]]]:
    """`[(crate, label, cargo arguments)]` for the whole workspace, in the fixed shard order."""
    listed = []
    for package in packages:
        try:
            reduced = doc_feature_sets.reduced_arguments(package)
        except doc_feature_sets.ManifestError as error:
            raise SystemExit(f"reduced-docs: {package['name']}: {error}")
        listed.extend((package["name"], label, arguments) for label, arguments in reduced)
    return listed


class Measured:
    """Findings by key: the positions each was seen at, and the configurations."""

    def __init__(self) -> None:
        self.positions: dict[Key, set[str]] = defaultdict(set)
        self.seen_in: dict[Key, set[str]] = defaultdict(set)

    def add(self, crate: str, label: str, found: list[tuple[str, str, str]]) -> None:
        for path, position, message in found:
            key = (crate, path, message)
            self.positions[key].add(position)
            self.seen_in[key].add(label)

    def counts(self) -> dict[Key, int]:
        return {key: len(positions) for key, positions in self.positions.items()}

    def to_json(self) -> list[dict]:
        return [
            {
                "crate": crate,
                "path": path,
                "message": message,
                "positions": sorted(self.positions[(crate, path, message)]),
                "configurations": sorted(self.seen_in[(crate, path, message)]),
            }
            for crate, path, message in sorted(self.positions)
        ]

    @classmethod
    def from_json(cls, rows: list[dict]) -> "Measured":
        measured = cls()
        for row in rows:
            key = (row["crate"], row["path"], row["message"])
            measured.positions[key].update(row["positions"])
            measured.seen_in[key].update(row["configurations"])
        return measured


def read_ledger(text: str) -> dict[Key, int]:
    """`crate<TAB>path<TAB>count<TAB>message` per line; `#` lines and blank lines are prose."""
    ledger: dict[Key, int] = {}
    for number, line in enumerate(text.splitlines(), 1):
        if not line.strip() or line.startswith("#"):
            continue
        fields = line.split("\t")
        if len(fields) != 4 or not fields[2].isdigit() or int(fields[2]) < 1:
            raise ValueError(f"ledger line {number} is not crate<TAB>path<TAB>count<TAB>message")
        key = (fields[0], fields[1], fields[3])
        if key in ledger:
            raise ValueError(f"ledger line {number} repeats {key}")
        ledger[key] = int(fields[2])
    return ledger


def format_ledger(counts: dict[Key, int]) -> str:
    return "".join(
        f"{crate}\t{path}\t{counts[(crate, path, message)]}\t{message}\n"
        for crate, path, message in sorted(counts)
    )


def describe(measured: Measured, key: Key) -> str:
    crate, path, message = key
    places = ", ".join(sorted(measured.positions[key]))
    configs = sorted(measured.seen_in[key])
    shown = ", ".join(configs[:4]) + (f" and {len(configs) - 4} more" if len(configs) > 4 else "")
    return f"{crate} {path} [{places}] {message}\n      in {shown}"


def rising(measured: Measured, ledger: dict[Key, int]) -> list[str]:
    """A finding the ledger does not carry, or carries fewer of."""
    problems = []
    for key, count in sorted(measured.counts().items()):
        allowed = ledger.get(key, 0)
        if count > allowed:
            problems.append(f"{count} where the ledger carries {allowed}: {describe(measured, key)}")
    return problems


def falling(measured: Measured, ledger: dict[Key, int]) -> list[str]:
    """A ledger line above what the whole partition measured: lower it or drop it."""
    counts = measured.counts()
    problems = []
    for key, allowed in sorted(ledger.items()):
        count = counts.get(key, 0)
        if count < allowed:
            crate, path, message = key
            problems.append(f"the ledger carries {allowed}, measured {count}: {crate} {path} {message}")
    return problems


def measure(args: argparse.Namespace) -> int:
    if args.shards < 1 or not 0 <= args.shard < args.shards:
        print(f"reduced-docs FAIL: shard {args.shard} of {args.shards} is not a shard", file=sys.stderr)
        return 1
    packages = workspace_packages()
    members = {p["name"] for p in packages}
    only = set(args.only.split()) if args.only else None
    if only is not None:
        unknown = sorted(only - members)
        if unknown or not only:
            print(f"reduced-docs FAIL: --only names {unknown or 'nothing'}, not workspace members", file=sys.stderr)
            return 1
    listed = configurations(packages)

    measured = Measured()
    mine = 0
    # Per crate: configurations measured and seconds spent, printed so a shard's clock is legible.
    spent: dict[str, list[float]] = {}
    for index, (crate, label, arguments) in enumerate(listed):
        if index % args.shards != args.shard or (only is not None and crate not in only):
            continue
        mine += 1
        start = time.monotonic()
        measured.add(crate, label, document(crate, arguments))
        tally = spent.setdefault(crate, [0, 0.0])
        tally[0] += 1
        tally[1] += time.monotonic() - start
    for crate, (count, seconds) in spent.items():
        print(f"  C1bzr: {crate}, {count} configuration(s), {seconds:.0f}s")
    print(f"  C1bzr: shard {args.shard} of {args.shards}: {mine} of {len(listed)} configuration(s)")

    Path(args.out).write_text(
        json.dumps(
            {
                "shards": args.shards,
                "shard": args.shard,
                "only": sorted(only) if only is not None else None,
                "total": len(listed),
                "measured": mine,
                "findings": measured.to_json(),
            },
            indent=1,
        )
        + "\n",
        encoding="utf-8",
    )
    if mine == 0 and only is not None:
        print("  C1bzr FAIL: --only selected no configuration", file=sys.stderr)
        return 1

    problems = rising(measured, read_ledger(LEDGER.read_text(encoding="utf-8")))
    for problem in problems:
        print(f"  C1bzr FAIL: {problem}")
    return 1 if problems else 0


def load_partition(paths: list[str]) -> tuple[Measured, int, int]:
    """The union of one complete partition's shard files: `(measured, total, configurations)`."""
    shards: dict[int, dict] = {}
    for path in paths:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        if data.get("only") is not None:
            raise ValueError(f"{path} measured a subset; only the whole workspace settles")
        if data["shard"] in shards:
            raise ValueError(f"{path} repeats shard {data['shard']}")
        shards[data["shard"]] = data
    counts = {d["shards"] for d in shards.values()}
    totals = {d["total"] for d in shards.values()}
    if len(counts) != 1 or len(totals) != 1:
        raise ValueError(f"the files are of different partitions: shards {counts}, totals {totals}")
    (count,) = counts
    (total,) = totals
    if sorted(shards) != list(range(count)):
        raise ValueError(f"shards {sorted(shards)} are not every shard of {count}")
    done = sum(d["measured"] for d in shards.values())
    if done != total:
        raise ValueError(f"the shards measured {done} of {total} configurations")
    measured = Measured()
    for data in shards.values():
        other = Measured.from_json(data["findings"])
        for key, positions in other.positions.items():
            measured.positions[key] |= positions
            measured.seen_in[key] |= other.seen_in[key]
    return measured, total, count


def settle(paths: list[str]) -> int:
    try:
        measured, total, count = load_partition(paths)
        ledger = read_ledger(LEDGER.read_text(encoding="utf-8"))
    except (OSError, ValueError, KeyError) as error:
        print(f"  C1bzr FAIL: {error}", file=sys.stderr)
        return 1
    problems = rising(measured, ledger) + falling(measured, ledger)
    for problem in problems:
        print(f"  C1bzr FAIL: {problem}")
    if problems:
        return 1
    print(
        f"  C1bzr: {total} reduced configuration(s) over {count} shard(s) document with exactly "
        f"the ledger's {len(ledger)} finding(s) at {sum(ledger.values())} place(s)"
    )
    return 0


def selftest() -> int:
    output = "\n".join(
        [
            "wz-x/src/a.rs:6:76: error: unresolved link to `A`: no item named `A` in scope",
            "wz-x/src/a.rs:28:7: error: unresolved link to `A`: no item named `A` in scope",
            "wz-x/src/b.rs:3:1: error[E0433]: cannot find `rt` in `wz`",
            "wz-x/src/b.rs:4:1: warning: unused import",
            "error[E0463]: can't find crate for `std`",
            "error: could not document `wz-x`",
            "error: could not compile `wz-x` (lib) due to 2 previous errors",
        ]
    )
    found = parse_findings(output)
    assert [f[0] for f in found] == ["wz-x/src/a.rs", "wz-x/src/a.rs", "wz-x/src/b.rs", NOWHERE], found
    assert found[2][2] == "error[E0433]: cannot find `rt` in `wz`", found

    # One defect in two configurations is one finding, counted by its distinct positions.
    measured = Measured()
    measured.add("wz-x", "all-without-a", found)
    measured.add("wz-x", "all-without-b", found[:2])
    counts = measured.counts()
    link = ("wz-x", "wz-x/src/a.rs", "error: unresolved link to `A`: no item named `A` in scope")
    assert counts[link] == 2, counts
    assert measured.seen_in[link] == {"all-without-a", "all-without-b"}

    # Both directions against a ledger, and the ledger's own shape.
    ledger = read_ledger("# prose\n\n" + format_ledger(counts))
    assert ledger == counts and not rising(measured, ledger) and not falling(measured, ledger)
    lower = dict(ledger)
    lower[link] = 1
    assert len(rising(measured, lower)) == 1 and not falling(measured, lower)
    stale = dict(ledger)
    stale[("wz-x", "wz-x/src/gone.rs", "error: x")] = 1
    assert not rising(measured, stale) and len(falling(measured, stale)) == 1
    for bad in ("a\tb\tc\n", "a\tb\t0\tm\n", "a\tb\t1\tm\na\tb\t2\tm\n"):
        try:
            read_ledger(bad)
        except ValueError:
            pass
        else:
            raise AssertionError(f"accepted ledger {bad!r}")

    # A guard firing replaces what the configuration reports; an error at any other place does not.
    with tempfile.TemporaryDirectory() as scratch:
        guarded = Path(scratch) / "wz-x" / "src"
        guarded.mkdir(parents=True)
        (guarded / "lib.rs").write_text('#[cfg(not(feature = "a"))]\ncompile_error!(\n    "no a"\n);\n')
        after = [
            ("wz-x/src/lib.rs", "2:1", "error: wz-x: needs `a`"),
            ("wz-x/src/b.rs", "9:9", "error[E0433]: cannot find `alloc`"),
            ("wz-x/src/lib.rs", "3:5", "error: not a guard"),
        ]
        assert refusals(after, Path(scratch)) == [("wz-x/src/lib.rs", "2:1", "refused: wz-x: needs `a`")]
        assert refusals(after[1:], Path(scratch)) == []
        assert refusals([(NOWHERE, NOWHERE, "error: x")], Path(scratch)) == []

    # A JSON round trip keeps everything settle reads.
    again = Measured.from_json(json.loads(json.dumps(measured.to_json())))
    assert again.counts() == counts and again.seen_in == measured.seen_in

    print("reduced-docs selftest: OK")
    return 0


def main(argv: list[str]) -> int:
    if argv == ["--selftest"]:
        return selftest()
    parser = argparse.ArgumentParser(prog="reduced_docs_gate.py")
    commands = parser.add_subparsers(dest="command", required=True)
    m = commands.add_parser("measure")
    m.add_argument("--out", required=True)
    m.add_argument("--shard", type=int, default=0)
    m.add_argument("--shards", type=int, default=1)
    m.add_argument("--only")
    s = commands.add_parser("settle")
    s.add_argument("files", nargs="+")
    led = commands.add_parser("ledger")
    led.add_argument("--write", action="store_true")
    led.add_argument("files", nargs="+")
    args = parser.parse_args(argv)
    if args.command == "measure":
        return measure(args)
    if args.command == "settle":
        return settle(args.files)
    try:
        measured, _, _ = load_partition(args.files)
    except (OSError, ValueError, KeyError) as error:
        print(f"reduced-docs: {error}", file=sys.stderr)
        return 1
    lines = format_ledger(measured.counts())
    if not args.write:
        sys.stdout.write(lines)
        return 0
    # The header is prose a person wrote; only the findings are what was measured.
    header = [line for line in LEDGER.read_text(encoding="utf-8").splitlines(keepends=True) if line.startswith("#")]
    LEDGER.write_text("".join(header) + lines, encoding="utf-8")
    print(f"reduced-docs: {LEDGER.name}: {len(measured.counts())} finding line(s) written")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
