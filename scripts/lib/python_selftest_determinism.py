#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
"""R4745 (no register item) -- a Python selftest ends the same and says the same when it is run
twice, under two hash seeds and two temporary directories; one that does not is a row of its
table, with its reason.

The design is `docs/deterministic-tests.md` (section 9): a selftest is a function of its script, as
a unit test is a function of its script and its seed.

## The defect

A selftest's exit code is a verdict a lane reads. Python draws the seed of its string hash at
random for each process unless `PYTHONHASHSEED` is set, so the iteration order of a set of strings,
and so anything printed or chosen by that order, can change from one run to the next with nothing
in the tree changed. A selftest that writes its temporary directory into what it compares, or
leaves a file behind that its next run reads, is the same kind of flake. Nothing ran a selftest
twice, so nothing told such a selftest from a deterministic one until a lane went red once.

## What is derived

The POPULATION is every tracked `.py` file below `scripts/` whose code reads `--selftest` from its
command line. A file whose code carries `--selftest` as a string constant (AST, so a mention in a
comment or a docstring is not one) is read for the shape that takes it (`ARMS`): an
`add_argument` call, a comparison (`==`, `in`, against the constant or a list, tuple or set
holding it), a key of a dict of modes, or a `case` of a `match`. A file that names the constant
in no such shape is a finding, never skipped: `changed_gate_selftests.py` measured that a rule
made of the shapes its author thought of missed four real selftests, so a shape this does not
know is to be added here, loudly. A file that does not parse is a member, and its runs fail.

## The runs

Each member is run as `<file> --selftest`, by the interpreter that runs this gate (`python3`
in the lanes), from the repository's root, twice and one after the other: first with
`PYTHONHASHSEED=0` and `TMPDIR` a fresh directory A, then with `PYTHONHASHSEED=1` and `TMPDIR` a
fresh directory B. The two runs are compared on their exit codes and on their stdout and stderr,
each read with its run's `TMPDIR` written as one token and each entry directly below it named by
the order it first appears in (tempfile draws those names from the system's randomness, which no
seed reaches). The verdicts:

- SAME: the exit codes and both texts are equal.
- NONDETERMINISTIC: they differ; the finding shows the first line that differs.
- FAILING: both runs exit non-zero. That is outside this judgement and reported apart.
- STALLED: a run passed the stall guard (`STALL_S`). The guard is named as one and judges
  nothing: a selftest that needs that long is a finding to read, not a verdict on its output.

## The table

`docs/deterministic-tests/python-nondeterministic.tsv`: a header, then one row per selftest known to
differ between the two runs: its path and the reason. A finding is

- a member that differs and has no row;
- a row whose member ran the same twice (the row is stale: take it out);
- a row for a path that is not a member, a second row, a row with no reason, a line that does
  not read as a row, or a table with no header;
- a member that fails both runs, or that stalls;
- a population of no member: the gate ran nothing and must not pass over that.

A table of a header and no row is the ratchet's end, not a lost subject: the subject here is the
population, and a run of no selftest is the finding that stands for it.

## What this does not claim

- That a selftest which ran the same twice is deterministic. Two runs a few seconds apart see
  the same date, the same host, the same network and almost the same clock; a selftest that
  reads one of those differs only when it reads it across a boundary the two runs did not
  straddle.
- A difference in the name of an entry directly below the temporary directory: it is read as its
  order of appearance, so a name drawn from the clock there is not seen.
- A temporary path that is not below `TMPDIR` (a hard-coded `/tmp`), and state left in the tree by
  one run and read by the next is seen only as the difference it makes in the second run.
"""

from __future__ import annotations

import argparse
import ast
import os
import re
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Callable, Dict, List, NamedTuple, Optional, Tuple

REPO_ROOT = Path(__file__).resolve().parents[2]
TABLE = "docs/deterministic-tests/python-nondeterministic.tsv"
HEADER = ("path", "reason")
SCOPE = "scripts"
SELFTEST = "--selftest"

# The two runs: a hash seed and a name for the run's temporary directory each.
RUNS = (("0", "a"), ("1", "b"))
# The stall guard of one run, in seconds. A guard only: no verdict is judged by it.
STALL_S = 300.0
TMP_TOKEN = "$TMPDIR"

# The shapes that read the constant from a command line, in the order they are reported.
ARMS = ("argparse", "compare", "dispatch", "match")
UNPARSED = "unparsed"
UNREAD = "unread"

SAME = "SAME"
NONDETERMINISTIC = "NONDETERMINISTIC"
FAILING = "FAILING"
STALLED = "STALLED"


class Run(NamedTuple):
    """One run of a selftest; `rc` is None when the stall guard ended it."""

    rc: Optional[int]
    stdout: str
    stderr: str
    seconds: float


class Result(NamedTuple):
    """The two runs of one member, judged."""

    path: str
    verdict: str
    seconds: float
    detail: str


# What runs a member: its path, the environment it adds, and the stall guard.
Runner = Callable[[str, Dict[str, str], float], Run]


def _flag(node: ast.AST) -> bool:
    return isinstance(node, ast.Constant) and node.value == SELFTEST


def _holds_flag(node: ast.AST) -> bool:
    """The constant itself, or a list, tuple or set literal holding it."""
    if _flag(node):
        return True
    return isinstance(node, (ast.List, ast.Tuple, ast.Set)) and any(_flag(e) for e in node.elts)


def arms_in(tree: ast.AST) -> set:
    """The shapes of `ARMS` in which a tree reads the constant."""
    found = set()
    for node in ast.walk(tree):
        if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                and node.func.attr == "add_argument" and any(_flag(a) for a in node.args)):
            found.add("argparse")
        elif isinstance(node, ast.Compare) and any(
                _holds_flag(side) for side in [node.left, *node.comparators]):
            found.add("compare")
        elif isinstance(node, ast.Dict) and any(k is not None and _flag(k) for k in node.keys):
            found.add("dispatch")
        elif isinstance(node, ast.match_case) and any(
                isinstance(p, ast.MatchValue) and _flag(p.value) for p in ast.walk(node.pattern)):
            found.add("match")
    return found


def arm_of(source: str) -> Optional[str]:
    """The first shape of `ARMS` in which a file's code reads `--selftest`; `UNPARSED` for a
    file that does not parse, `UNREAD` for code that carries the constant in no such shape, and
    None for code that does not carry it."""
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return UNPARSED
    if not any(_flag(node) for node in ast.walk(tree)):
        return None
    found = arms_in(tree)
    for arm in ARMS:
        if arm in found:
            return arm
    return UNREAD


def members(sources: Dict[str, str]) -> Tuple[List[str], List[str]]:
    """The members of a population (path to text) and the files that carry the constant in no
    shape this reads, each sorted."""
    member: List[str] = []
    unread: List[str] = []
    for path, source in sorted(sources.items()):
        arm = arm_of(source)
        if arm == UNREAD:
            unread.append(path)
        elif arm is not None:
            member.append(path)
    return member, unread


def tracked_sources(root: Path) -> Dict[str, str]:
    """Every tracked `.py` file below `scripts/`, by path, with its text."""
    run = subprocess.run(["git", "-C", str(root), "ls-files", "-z", "--", SCOPE],
                         capture_output=True, text=True, check=True)
    sources: Dict[str, str] = {}
    for path in run.stdout.split("\0"):
        if path.endswith(".py") and (root / path).is_file():
            sources[path] = (root / path).read_text(encoding="utf-8", errors="replace")
    return sources


def host_runner(cwd: Path) -> Runner:
    """A runner that starts `python3 <path> --selftest` in a directory, in a session of its own so
    that the stall guard ends what it started too."""

    def run(path: str, env: Dict[str, str], guard: float) -> Run:
        start = time.monotonic()
        proc = subprocess.Popen([sys.executable, path, SELFTEST], cwd=cwd,
                                env={**os.environ, **env}, stdin=subprocess.DEVNULL,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                start_new_session=True)
        rc: Optional[int]
        try:
            out, err = proc.communicate(timeout=guard)
            rc = proc.returncode
        except subprocess.TimeoutExpired:
            # The leader is not reaped yet, so its group id is still this run's.
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except (ProcessLookupError, PermissionError):
                proc.kill()
            try:
                out, err = proc.communicate(timeout=10)
            except subprocess.TimeoutExpired:
                # A process that left the group still holds the pipes: give their text up.
                for pipe in (proc.stdout, proc.stderr):
                    if pipe is not None:
                        pipe.close()
                proc.wait()
                out, err = b"", b""
            rc = None
        return Run(rc, out.decode("utf-8", "replace"), err.decode("utf-8", "replace"),
                   time.monotonic() - start)

    return run


def normalize(texts: List[str], tmpdir: str) -> List[str]:
    """The texts of one run with its temporary directory written as one token, and each entry
    directly below it named by the order it first appears in across the texts."""
    roots = sorted({tmpdir, os.path.realpath(tmpdir)}, key=len, reverse=True)
    pattern = re.compile("(?:" + "|".join(re.escape(r) for r in roots) + ")"
                         + r"(?:/([^/\s'" + '"' + r"]+))?")
    names: Dict[str, int] = {}

    def token(m: "re.Match[str]") -> str:
        entry = m.group(1)
        if entry is None:
            return TMP_TOKEN
        return f"{TMP_TOKEN}/<{names.setdefault(entry, len(names) + 1)}>"

    return [pattern.sub(token, text) for text in texts]


def transcript(run: Run, tmpdir: str) -> List[str]:
    """What the two runs are compared on: the exit code, then each line of each stream."""
    out, err = normalize([run.stdout, run.stderr], tmpdir)
    return ([f"exit {run.rc}"] + [f"stdout: {line}" for line in out.splitlines()]
            + [f"stderr: {line}" for line in err.splitlines()])


def first_difference(a: List[str], b: List[str]) -> str:
    for i, (x, y) in enumerate(zip(a, b)):
        if x != y:
            return f"line {i + 1}: run 1 `{x[:160]}`, run 2 `{y[:160]}`"
    return f"run 1 has {len(a)} line(s), run 2 has {len(b)}"


def last_line(run: Run) -> str:
    lines = [line for line in (run.stdout + "\n" + run.stderr).splitlines() if line.strip()]
    return lines[-1].strip()[:160] if lines else "(no output)"


def run_twice(path: str, runner: Runner, guard: float, scratch: Path) -> Result:
    """The two runs of one member, each in a temporary directory of its own below a scratch
    directory, judged."""
    runs: List[Tuple[Run, str]] = []
    seconds = 0.0
    for n, (seed, name) in enumerate(RUNS, start=1):
        tmp = scratch / name
        tmp.mkdir()
        run = runner(path, {"PYTHONHASHSEED": seed, "TMPDIR": str(tmp)}, guard)
        seconds += run.seconds
        if run.rc is None:
            return Result(path, STALLED, seconds,
                          f"run {n} (PYTHONHASHSEED={seed}) passed the {guard:g} s stall guard")
        runs.append((run, str(tmp)))
    (one, tmp_one), (two, tmp_two) = runs
    if one.rc != 0 and two.rc != 0:
        return Result(path, FAILING, seconds, f"exit {one.rc} and {two.rc}: {last_line(one)}")
    a, b = transcript(one, tmp_one), transcript(two, tmp_two)
    if a == b:
        return Result(path, SAME, seconds, "")
    return Result(path, NONDETERMINISTIC, seconds, first_difference(a, b))


def parse_table(text: str) -> Tuple[List[Tuple[str, str]], List[str]]:
    """The rows of the table, and a finding for each line that could not be read as one: a row
    that does not read is never dropped from the judgement unseen."""
    rows: List[Tuple[str, str]] = []
    bad: List[str] = []
    header_seen = False
    for line in text.splitlines():
        if not line.strip() or line.startswith("#"):
            continue
        cells = tuple(cell.strip() for cell in line.split("\t"))
        if not header_seen:
            header_seen = True
            if cells != HEADER:
                bad.append(f"the table's header is not {' | '.join(HEADER)} (tab-separated): "
                           f"{line.strip()[:120]}")
            continue
        if len(cells) != len(HEADER):
            bad.append(f"a row not read as {len(HEADER)} tab-separated cells: "
                       f"{line.strip()[:120]}")
            continue
        rows.append((cells[0], cells[1]))
    if not header_seen:
        bad.append(f"the table has no header ({' | '.join(HEADER)}, tab-separated)")
    return rows, bad


def judge(paths: List[str], runner: Runner, table_text: str, guard: float = STALL_S,
          on_result: Optional[Callable[[Result, bool], None]] = None,
          ) -> Tuple[List[Result], List[str]]:
    """Every result of a population run twice, and every finding against the table's text.
    `on_result` hears each result as it comes, with whether its path has a row."""
    rows, found = parse_table(table_text)
    seen: Dict[str, int] = {}
    for path, reason in rows:
        seen[path] = seen.get(path, 0) + 1
        if not reason:
            found.append(f"`{path}`: a row with no reason")
    for path, n in sorted(seen.items()):
        if n > 1:
            found.append(f"`{path}` has {n} rows; give it one")
        if path not in paths:
            found.append(f"`{path}` has a row but is not a tracked script below {SCOPE}/ "
                         f"that takes {SELFTEST}")
    results: List[Result] = []
    with tempfile.TemporaryDirectory(prefix="wz-selftest-twice-",
                                     ignore_cleanup_errors=True) as parent:
        for i, path in enumerate(paths):
            scratch = Path(parent) / str(i)
            scratch.mkdir()
            result = run_twice(path, runner, guard, scratch)
            results.append(result)
            if on_result is not None:
                on_result(result, path in seen)
    for r in results:
        if r.verdict == NONDETERMINISTIC and r.path not in seen:
            found.append(f"`{r.path}` is NONDETERMINISTIC across the two runs ({r.detail}): "
                         "make its selftest a function of its script, or give it a row whose "
                         "reason says why it cannot be one yet")
        elif r.verdict == SAME and r.path in seen:
            found.append(f"`{r.path}` ran the same twice and has a row: the row is stale, take "
                         "it out")
        elif r.verdict == FAILING:
            found.append(f"`{r.path}` is FAILING, outside the determinism judgement "
                         f"({r.detail})")
        elif r.verdict == STALLED:
            found.append(f"`{r.path}` STALLED: {r.detail}")
    if not results:
        found.append(f"ran 0 selftests: no tracked script below {SCOPE}/ takes {SELFTEST}, so "
                     "the gate lost its subject and must not pass over it")
    return results, found


def counts_of(results: List[Result], tabled: set) -> Dict[str, int]:
    def n(verdict: str) -> int:
        return sum(1 for r in results if r.verdict == verdict)

    return {
        "ran": len(results),
        "same": n(SAME),
        "different": n(NONDETERMINISTIC),
        "tabled": sum(1 for r in results if r.verdict == NONDETERMINISTIC and r.path in tabled),
        "failing": n(FAILING),
        "stalled": n(STALLED),
    }


def unread_findings(unread: List[str]) -> List[str]:
    return [f"`{path}` carries {SELFTEST} in its code and no shape of ARMS "
            f"({', '.join(ARMS)}) reads it: add the shape it uses, or take the constant out"
            for path in unread]


def check(root: Path = REPO_ROOT, guard: float = STALL_S) -> int:
    table = root / TABLE
    if not table.is_file():
        print(f"python-selftest-determinism: FAIL -- {TABLE} is missing", file=sys.stderr)
        return 1
    table_text = table.read_text(encoding="utf-8")
    paths, unread = members(tracked_sources(root))

    def progress(result: Result, tabled: bool) -> None:
        verdict = result.verdict + (" (tabled)" if tabled else "")
        print(f"  {verdict:<27} {result.seconds:7.1f}s  {result.path}", flush=True)

    results, found = judge(paths, host_runner(root), table_text, guard, progress)
    tabled = {path for path, _ in parse_table(table_text)[0]}
    c = counts_of(results, tabled)
    print(f"python-selftest-determinism: ran {c['ran']}, same {c['same']}, different "
          f"{c['different']} ({c['tabled']} tabled), failing {c['failing']}, stalled "
          f"{c['stalled']}")
    found = unread_findings(unread) + found
    if found:
        print("python-selftest-determinism: FAIL -- a selftest is not the function of its script "
              "its table says:", file=sys.stderr)
        for f in found:
            print(f"  - {f}", file=sys.stderr)
        print(f"  The runs and the table are docs/deterministic-tests.md section 9; a selftest "
              f"made deterministic takes its row out of {TABLE}.", file=sys.stderr)
        return 1
    print("python-selftest-determinism: ok")
    return 0


def list_population(root: Path = REPO_ROOT) -> int:
    paths, unread = members(tracked_sources(root))
    for path in paths:
        print(path)
    for f in unread_findings(unread):
        print(f"python-selftest-determinism: {f}", file=sys.stderr)
    return 1 if unread else 0


FIXTURES = {
    "steady.py": 'print("one")\nprint("two")\n',
    "set_order.py": ('WORDS = {"alpha", "bravo", "charlie", "delta", "echo", "foxtrot", "golf",\n'
                     '         "hotel", "india", "juliet", "kilo", "lima", "mike", "november",\n'
                     '         "oscar", "papa"}\nprint(" ".join(WORDS))\n'),
    "temp_path.py": ("import os\nimport tempfile\n\nd = tempfile.mkdtemp()\n"
                     "with open(os.path.join(d, 'x'), 'w') as f:\n    f.write('x')\n"
                     "print(tempfile.gettempdir())\nprint(os.path.join(d, 'x'))\n"
                     "print(tempfile.mkdtemp())\nprint(d)\n"),
    "exit_count.py": ("import os\nimport sys\n\nn = 0\nif os.path.exists('count'):\n"
                      "    with open('count') as f:\n        n = int(f.read())\n"
                      "with open('count', 'w') as f:\n    f.write(str(n + 1))\nsys.exit(n)\n"),
    "always_fails.py": 'import sys\n\nprint("broken", file=sys.stderr)\nsys.exit(3)\n',
    "spins.py": "while True:\n    pass\n",
}
# Each fixture once more under a name the table gives a row.
FIXTURES["tabled_differs.py"] = FIXTURES["set_order.py"]
FIXTURES["tabled_steady.py"] = FIXTURES["steady.py"]


def selftest() -> int:
    failures: List[str] = []

    def expect(name: str, got, want) -> None:
        ok = got == want
        print(f"  selftest -- {name}: {'ok' if ok else f'FAIL got {got!r} want {want!r}'}")
        if not ok:
            failures.append(name)

    sources = {
        "scripts/lib/a_argparse.py": 'p.add_argument("--selftest", action="store_true")\n',
        "scripts/lib/a_in.py": 'import sys\nif "--selftest" in sys.argv:\n    pass\n',
        "scripts/lib/a_list.py": 'import sys\nif sys.argv[1:] == ["--selftest"]:\n    pass\n',
        "scripts/lib/a_dispatch.py": 'modes = {"--check": 1, "--selftest": 2}\n',
        "scripts/lib/a_match.py": ('import sys\nmatch sys.argv[1]:\n    case "--selftest":\n'
                                   '        pass\n'),
        "scripts/lib/a_comment.py": '# run with --selftest\n"""or --selftest in a docstring"""\n',
        "scripts/lib/a_passes.py": ('import subprocess\n'
                                    'subprocess.run(["python3", "x.py", "--selftest"])\n'),
        "scripts/lib/a_broken.py": "def (\n",
        "scripts/lib/a_none.py": "X = 1\n",
    }
    expect("each shape that reads the constant is a member, and a file that does not parse",
           members(sources)[0],
           ["scripts/lib/a_argparse.py", "scripts/lib/a_broken.py", "scripts/lib/a_dispatch.py",
            "scripts/lib/a_in.py", "scripts/lib/a_list.py", "scripts/lib/a_match.py"])
    expect("the constant in no shape this reads is a finding, never skipped",
           members(sources)[1], ["scripts/lib/a_passes.py"])
    expect("the shapes are named", [arm_of(sources[p]) for p in (
        "scripts/lib/a_argparse.py", "scripts/lib/a_in.py", "scripts/lib/a_list.py",
        "scripts/lib/a_dispatch.py", "scripts/lib/a_match.py", "scripts/lib/a_comment.py",
        "scripts/lib/a_broken.py")],
        ["argparse", "compare", "compare", "dispatch", "match", None, UNPARSED])

    expect("a temporary path is one token, its entries named by first appearance",
           normalize(["/t/A/tmpq1/f /t/A/tmpz9 /t/A/tmpq1", "/t/A"], "/t/A"),
           ["$TMPDIR/<1>/f $TMPDIR/<2> $TMPDIR/<1>", "$TMPDIR"])

    header = "\t".join(HEADER)
    table = (f"# fixtures\n{header}\ntabled_differs.py\thash order of a set\n"
             f"tabled_steady.py\tno longer differs\n")
    with tempfile.TemporaryDirectory(prefix="wz-selftest-twice-fixtures-") as tmp:
        for name, text in FIXTURES.items():
            (Path(tmp) / name).write_text(text, encoding="utf-8")
        paths = sorted(FIXTURES)
        results, found = judge(paths, host_runner(Path(tmp)), table, guard=1.0)
    verdicts = {r.path: r.verdict for r in results}
    expect("CONTROL: a steady selftest is SAME", verdicts["steady.py"], SAME)
    expect("a set of strings printed in its order is NONDETERMINISTIC",
           verdicts["set_order.py"], NONDETERMINISTIC)
    expect("a printed temporary path is SAME", verdicts["temp_path.py"], SAME)
    expect("an exit code that changes between the runs is NONDETERMINISTIC",
           verdicts["exit_count.py"], NONDETERMINISTIC)
    expect("two failing runs are FAILING", verdicts["always_fails.py"], FAILING)
    expect("a run past the guard is STALLED", verdicts["spins.py"], STALLED)
    expect("a tabled selftest that differs is NONDETERMINISTIC",
           verdicts["tabled_differs.py"], NONDETERMINISTIC)

    def has(fragment: str, among: List[str]) -> bool:
        return any(fragment in f for f in among)

    expect("an untabled difference is a finding",
           has("`set_order.py` is NONDETERMINISTIC", found), True)
    expect("the first line that differs is shown",
           [r.detail for r in results if r.path == "exit_count.py"],
           ["line 1: run 1 `exit 0`, run 2 `exit 1`"])
    expect("a tabled difference is no finding", has("tabled_differs.py", found), False)
    expect("a tabled selftest that ran the same is a stale finding",
           has("`tabled_steady.py` ran the same twice and has a row", found), True)
    expect("FAILING is a finding of its own", has("`always_fails.py` is FAILING", found), True)
    expect("STALLED is a finding naming the run",
           has("`spins.py` STALLED: run 1 (PYTHONHASHSEED=0)", found), True)
    expect("CONTROL: SAME untabled is no finding",
           [has(f"`{p}`", found) for p in ("steady.py", "temp_path.py")], [False, False])

    def fake(stall_seed: str) -> Runner:
        def run(path: str, env: Dict[str, str], guard: float) -> Run:
            if env["PYTHONHASHSEED"] == stall_seed:
                return Run(None, "", "", guard)
            return Run(0, f"tmp {env['TMPDIR']}\n", "", 0.0)
        return run

    with tempfile.TemporaryDirectory(prefix="wz-selftest-twice-fake-") as tmp:
        expect("a stall of the second run is STALLED, through any runner",
               run_twice("x.py", fake("1"), 5.0, Path(tmp)).detail,
               "run 2 (PYTHONHASHSEED=1) passed the 5 s stall guard")

    def table_findings(text: str, paths: List[str]) -> List[str]:
        return judge(paths, fake("none"), text)[1]

    expect("a row for a path that is not a member is a finding",
           has("`gone.py` has a row but is not",
               table_findings(f"{header}\ngone.py\tr\n", ["x.py"])), True)
    expect("a second row is a finding",
           has("`x.py` has 2 rows", table_findings(f"{header}\nx.py\tr\nx.py\tr\n", ["x.py"])),
           True)
    expect("a row with no reason is a finding",
           has("a row with no reason", table_findings(f"{header}\nx.py\t\n", ["x.py"])), True)
    expect("a row of one cell is a finding, not dropped",
           has("a row not read as 2", table_findings(f"{header}\nx.py\n", ["x.py"])), True)
    expect("a wrong header is a finding",
           has("the table's header is not", table_findings("path\tkind\n", ["x.py"])), True)
    expect("a table of no header is a finding",
           has("the table has no header", table_findings("# only a comment\n", ["x.py"])), True)
    expect("CONTROL: a header and no row is no finding over a member that ran the same",
           table_findings(f"{header}\n", ["x.py"]), [])
    expect("a population of no member ran nothing, and that is a finding",
           has("ran 0 selftests", table_findings(f"{header}\n", [])), True)

    print(f"python-selftest-determinism selftest: "
          f"{'OK' if not failures else 'FAILED: ' + ', '.join(failures)}")
    return 1 if failures else 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--check", action="store_true")
    group.add_argument("--selftest", action="store_true")
    group.add_argument("--list", action="store_true")
    parser.add_argument("--stall", type=float, default=STALL_S,
                        help=f"the stall guard of one run, in seconds (default {STALL_S:g})")
    args = parser.parse_args()
    if args.selftest:
        return selftest()
    if args.list:
        return list_population()
    return check(guard=args.stall)


if __name__ == "__main__":
    sys.exit(main())
