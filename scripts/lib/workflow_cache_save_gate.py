#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
"""R2872 (no register item) — every cache in this repository's CI saves as an ordinary STEP.

## The defect, measured twice

The combined `actions/cache` action saves in a POST step, and that post step
does not run when the job ends red. A cache is therefore warmed only by a job
that also went green, so a red anywhere after the cached work throws the work
away, and the next run pays it again.

* Register item 350 (R311y883) found it on the apt archives and split them into
  `actions/cache/restore` + `actions/cache/save`. It fixed the members it was
  looking at and left the class open: seven combined caches remained, every
  one of them an oracle build.
* R2872 met one of those seven. R2863 moved the zenohd key; run 36156369002
  built zenohd and then went red on E6i, so nothing was saved; run 36207477909
  rebuilt it cold and was cut off at 56 minutes inside that build, which took
  every Layer E/Z leg and cross-mcu's artifact download with it.

A fix applied member by member is the arrangement that failed, so this gate
states the class and derives the members.

## What it checks, over every cache step in every workflow and composite action

1. No step `uses: actions/cache@...` (the combined form). Any version.
2. Every `actions/cache/restore` step has, in the SAME job, an
   `actions/cache/save` step whose key either references the restore
   (`steps.<id>.`) or is the restore's key text verbatim. A restore nobody
   saves for is a cache that never warms. In a matrix job a save writes one
   key per cell, so its key is read with each `${{ matrix.<axis> }}` replaced
   by each value the job's matrix lists: a cell that also reads another cell's
   cache (the `selector_term` fuzz target reads the `pcap` corpus) is paired by
   the save that cell runs, and stops being paired the day that cell leaves
   the matrix.

It does NOT require the save to carry `always()`. Measured: two correct saves
(the Zephyr workspace and the rocksdb-engine composite) gate on `success()` or on
nothing, and both are right. Each is an ordinary step placed straight after the
work it saves, so a LATER red cannot reach it. The defect is the post step,
not the condition.

## The population is derived, and zero is a failure

The steps are read by parsing `.github/workflows/*.yml` and
`.github/actions/**/action.yml`, never from a list. A parse that yields no
cache step at all FAILS: this repository has dozens, so zero means the reader
stopped reading.

## Two more rules over the same parse

Both are about whether a hosted run's verdict means what it says, and both are
read off the same steps.

3. THE PINNED KCONFIG INTERPRETER. The build configuration reader
   (`scripts/lib/wz_config.py`) resolves profiles and presets with one pinned
   kconfiglib, which `scripts/provision-kconfiglib.sh` installs. Platform runs
   went red on macOS and Windows with `wz-config FAIL: kconfiglib is not
   installed` because a job ran a script that reaches the reader and nothing in
   the job prepared the interpreter. So every step that reaches the reader, in a
   job or a composite action, needs `uses: ./.github/actions/kconfig-interpreter`
   earlier in its job (directly or inside a local composite action it uses), and
   the interpreter is installed nowhere else in `.github/`. The one other form
   allowed is the provisioner's own line (`bash scripts/provision-kconfiglib.sh`)
   inside a step that runs a lane of `scripts/run-ci.sh`: that is the line
   `runci_plan.py` carries to the build fleet, which reads run lines and not
   actions. What reaches the reader is DERIVED:
   * the reader's functions that reach the interpreter are `resolve` and
     `kconfiglib_module` and every top-level function of the reader that calls
     one of them, to a fixpoint;
   * a python script under `scripts/` reaches it when it imports `wz_config`
     and names one of those functions, or holds the reader's path as a string
     (a subprocess argument);
   * a shell script under `scripts/` reaches it when a line of its code names
     the reader or a script that reaches it, unless a line of its code runs the
     provisioner (it prepares the interpreter for itself, as `run-ci.sh` and
     `pico-compare.sh` do);
   * a step reaches it when a line of its code names the reader or such a script.
   The limit, stated: a script reached through a path built at run time, or a
   python script that runs a shell script that reaches the reader, is not seen.
   A step the rule cannot see is a red on the host, which is where this started.
4. A RUN IN FLIGHT ON MAIN IS NEVER CANCELLED. Every workflow a push to `main`
   starts has a workflow-level concurrency group keyed by `github.ref` with
   `cancel-in-progress: false`, and no job-level group. The group replaces a
   PENDING run with the newest one, which is what keeps the hosted queue bounded
   when landings arrive faster than runs finish; cancelling the RUNNING one would
   leave main with no graded commit at all, the state R311y704 measured. A group
   not keyed by ref lets a pull request's run replace main's, and a job-level
   group replaces a waiting job of an earlier run, which then reports
   `cancelled` for a job it never ran. The cost and verdict balance is in
   `docs/verdicts-in-the-fleet.md` (Hosted runs on main).

A rule whose population is empty FAILS, as rule 2's does: no step reaching the
reader, or no workflow pushed to main, means the reader stopped reading.
"""

from __future__ import annotations

import ast
import itertools
import re
import sys
from pathlib import Path

import yaml

from runci_plan import LANE, PREP

REPO_ROOT = Path(__file__).resolve().parents[2]


def _steps_by_job(doc: dict) -> dict[str, list[dict]]:
    """Workflow jobs, or a composite action's steps under one pseudo-job."""
    if isinstance(doc.get("jobs"), dict):
        return {
            name: list(job.get("steps") or [])
            for name, job in doc["jobs"].items()
            if isinstance(job, dict)
        }
    runs = doc.get("runs") or {}
    return {"<composite>": list(runs.get("steps") or [])}


def _matrices_by_job(doc: dict) -> dict[str, dict[str, list[str]]]:
    """Each job's matrix axes that are plain lists of scalars, as strings. An
    axis built by an expression or from objects is left out, so a key that
    names it is not expanded and pairs only by its text."""
    out: dict[str, dict[str, list[str]]] = {}
    jobs = doc.get("jobs")
    if not isinstance(jobs, dict):
        return out
    for name, job in jobs.items():
        matrix = ((job or {}).get("strategy") or {}).get("matrix") if isinstance(job, dict) else None
        axes: dict[str, list[str]] = {}
        if isinstance(matrix, dict):
            for axis, values in matrix.items():
                if isinstance(values, list) and values and all(
                    isinstance(v, (str, int, float, bool)) for v in values
                ):
                    axes[axis] = [str(v) for v in values]
        out[name] = axes
    return out


_MATRIX_REF = re.compile(r"\$\{\{\s*matrix\.([A-Za-z_][A-Za-z0-9_-]*)\s*\}\}")


def _written_keys(save_key: str, axes: dict[str, list[str]]) -> set[str]:
    """The keys a save step writes across the job's matrix cells: its key text,
    and that text with every `${{ matrix.<axis> }}` replaced by each value of
    the axis. A restore in one cell that reads another cell's cache (the fuzz
    target that also reads the `pcap` target's corpus) is paired by the save
    that cell runs; the key it names is one of these. An axis the job does not
    declare as a list leaves the text unexpanded."""
    keys = {save_key}
    named = sorted(set(_MATRIX_REF.findall(save_key)))
    if not named or any(axis not in axes for axis in named):
        return keys
    for cell in itertools.product(*(axes[axis] for axis in named)):
        value = dict(zip(named, cell))
        keys.add(_MATRIX_REF.sub(lambda m: value[m.group(1)], save_key))
    return keys


def _uses(step: dict) -> str:
    return str(step.get("uses") or "")


def check(docs: dict[str, dict]) -> tuple[list[str], int]:
    """(failures, cache steps seen) over `{path: parsed yaml}`."""
    failures: list[str] = []
    seen = 0
    for path, doc in sorted(docs.items()):
        matrices = _matrices_by_job(doc)
        for job, steps in _steps_by_job(doc).items():
            restores = []
            saves = []
            for step in steps:
                uses = _uses(step)
                if not uses.startswith("actions/cache"):
                    continue
                seen += 1
                name = step.get("name") or step.get("id") or uses
                if uses.startswith("actions/cache@"):
                    failures.append(
                        f"{path} [{job}] `{name}`: the COMBINED actions/cache, which "
                        "saves in a post step that does not run when the job ends red. "
                        "Split it into actions/cache/restore + an actions/cache/save "
                        "step placed right after the step that proves the cached "
                        "work complete."
                    )
                elif uses.startswith("actions/cache/restore@"):
                    restores.append(step)
                elif uses.startswith("actions/cache/save@"):
                    saves.append(step)
            save_keys = [str((s.get("with") or {}).get("key") or "") for s in saves]
            axes = matrices.get(job, {})
            written = set().union(*(_written_keys(sk, axes) for sk in save_keys)) if save_keys else set()
            for step in restores:
                rid = step.get("id")
                key = str((step.get("with") or {}).get("key") or "")
                paired = any(rid and f"steps.{rid}." in sk for sk in save_keys) or (
                    bool(key) and key in written
                )
                if not paired:
                    failures.append(
                        f"{path} [{job}] `{step.get('name') or rid}`: a restore with no "
                        "save in its job (no save key references "
                        f"`steps.{rid}.` or repeats its key), so this cache never warms."
                    )
    return failures, seen


# ── rule 3: the pinned Kconfig interpreter ──────────────────────────────────

KCONFIG_ACTION = "./.github/actions/kconfig-interpreter"
KCONFIG_ACTION_FILE = ".github/actions/kconfig-interpreter/action.yml"
PROVISIONER = "scripts/provision-kconfiglib.sh"
READER = "scripts/lib/wz_config.py"
READER_NAME = "wz_config.py"
# The reader's own ways to the interpreter; every function calling one reaches it too.
INTERPRETER_SEEDS = frozenset({"resolve", "kconfiglib_module"})
# A line that installs the interpreter by some recipe: the provisioner, or the pin file handed to pip.
RECIPE = re.compile(
    r"provision-kconfiglib\.sh|requirements-kconfig\.txt"
    r"|\bkconfiglib\b.*\bpip\b|\bpip\b.*\bkconfiglib\b"
)
# A string constant that is the reader's path, as a subprocess argument holds it.
READER_PATH = re.compile(r"\S*wz_config\.py")


def _code_lines(text: str) -> list[str]:
    """The lines of a script that are code: stripped, neither blank nor a comment."""
    out = []
    for raw in text.splitlines():
        line = raw.strip()
        if line and not line.startswith("#"):
            out.append(line)
    return out


def _names(line: str, name: str) -> bool:
    """`line` names the file `name` (a basename), not a longer name that ends in it."""
    return re.search(rf"(?<![\w.-]){re.escape(name)}(?![\w.-])", line) is not None


def interpreter_functions(reader_source: str) -> frozenset[str]:
    """The reader's top-level functions that reach the interpreter: the seeds it defines and,
    to a fixpoint, every top-level function that calls one by name (how the module calls its
    own functions)."""
    tree = ast.parse(reader_source)
    calls = {
        node.name: {
            c.func.id
            for c in ast.walk(node)
            if isinstance(c, ast.Call) and isinstance(c.func, ast.Name)
        }
        for node in tree.body
        if isinstance(node, ast.FunctionDef)
    }
    reach = set(INTERPRETER_SEEDS & calls.keys())
    grew = True
    while grew:
        grew = False
        for name, called in calls.items():
            if name not in reach and called & reach:
                reach.add(name)
                grew = True
    return frozenset(reach)


def python_reaches(source: str, functions: frozenset[str]) -> str | None:
    """Why a python source reaches the interpreter through the reader, or None."""
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return None
    bound: set[str] = set()
    named: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            bound.update(a.asname or a.name for a in node.names if a.name == "wz_config")
        elif isinstance(node, ast.ImportFrom) and node.module == "wz_config":
            named.update(a.name for a in node.names)
        elif (
            isinstance(node, ast.Constant)
            and isinstance(node.value, str)
            and READER_PATH.fullmatch(node.value)
        ):
            return f"runs {READER_NAME}"
    hit = sorted(named & functions)
    if hit:
        return f"imports wz_config.{hit[0]}"
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Attribute)
            and isinstance(node.value, ast.Name)
            and node.value.id in bound
            and node.attr in functions
        ):
            return f"calls wz_config.{node.attr}"
    return None


def reader_callers(root: Path) -> tuple[dict[str, str], list[str]]:
    """`({basename: why}, failures)`: every script under `scripts/` that reaches the
    interpreter through the reader and does not provision it itself."""
    reader = root / READER
    if not reader.is_file():
        return {}, [f"{READER} is absent, so nothing can be said about what reaches it"]
    functions = interpreter_functions(reader.read_text(encoding="utf-8"))
    missing = sorted(INTERPRETER_SEEDS - functions)
    if missing:
        return {}, [
            f"{READER} no longer defines {', '.join(missing)}: the functions rule 3 starts "
            "from are gone, so it would find no python caller at all"
        ]
    shell: dict[str, list[str]] = {}
    callers: dict[str, str] = {}
    for path in sorted((root / "scripts").rglob("*")):
        if not path.is_file() or path.suffix not in (".sh", ".py"):
            continue
        rel = str(path.relative_to(root))
        if rel in (READER, PROVISIONER):
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        if path.suffix == ".py":
            why = python_reaches(text, functions)
            if why:
                callers[path.name] = why
            continue
        lines = _code_lines(text)
        if any(_names(line, Path(PROVISIONER).name) for line in lines):
            continue
        shell[path.name] = lines
        if any(_names(line, READER_NAME) for line in lines):
            callers[path.name] = f"runs {READER_NAME}"
    grew = True
    while grew:
        grew = False
        for name, lines in shell.items():
            if name in callers:
                continue
            for caller in sorted(callers):
                if any(_names(line, caller) for line in lines):
                    callers[name] = f"runs {caller}"
                    grew = True
                    break
    return callers, []


def _reaching(line: str, callers: dict[str, str]) -> str | None:
    """What a code line of a step runs that reaches the reader, or None."""
    if _names(line, READER_NAME):
        return READER_NAME
    for caller in sorted(callers):
        if _names(line, caller):
            return caller
    return None


def _local_action(uses: str) -> str | None:
    """The `action.yml` path a local `uses:` names, else None."""
    if not uses.startswith("./"):
        return None
    return uses[2:].split("@", 1)[0].rstrip("/") + "/action.yml"


def _provisions(steps: list[dict], docs: dict[str, dict], seen: frozenset[str]) -> bool:
    """Whether running `steps` prepares the interpreter: the action, or a local composite
    action that uses it (an action is read once on a path, so a cycle ends)."""
    for step in steps:
        uses = _uses(step)
        if uses.split("@", 1)[0].rstrip("/") == KCONFIG_ACTION:
            return True
        local = _local_action(uses)
        if local and local not in seen and local in docs:
            if _provisions(_steps_by_job(docs[local]).get("<composite>", []), docs, seen | {local}):
                return True
    return False


def kconfig_check(docs: dict[str, dict], callers: dict[str, str]) -> tuple[list[str], int]:
    """(failures, steps reaching the reader) over `{path: parsed yaml}`."""
    failures: list[str] = []
    seen = 0
    action = docs.get(KCONFIG_ACTION_FILE)
    action_lines = [
        line
        for step in (_steps_by_job(action).get("<composite>", []) if action else [])
        for line in _code_lines(str(step.get("run") or ""))
    ]
    if f"bash {PROVISIONER}" not in action_lines:
        failures.append(
            f"{KCONFIG_ACTION_FILE}: absent, or it no longer runs `bash {PROVISIONER}`, so "
            "every job that uses it reaches the reader with no interpreter"
        )
    for path, doc in sorted(docs.items()):
        for job, steps in _steps_by_job(doc).items():
            provisioned = False
            for step in steps:
                name = step.get("name") or step.get("id") or _uses(step) or "a step"
                if _provisions([step], docs, frozenset({path})):
                    provisioned = True
                lines = _code_lines(str(step.get("run") or ""))
                lane_step = any(LANE.match(line) for line in lines)
                reported = False
                for line in lines:
                    prep = PREP.match(line)
                    if prep and prep.group(1) == PROVISIONER and not prep.group(2):
                        if lane_step:
                            provisioned = True
                        elif path != KCONFIG_ACTION_FILE:
                            failures.append(
                                f"{path} [{job}] `{name}`: runs the provisioner in a step "
                                f"that runs no lane; use `uses: {KCONFIG_ACTION}` instead"
                            )
                        continue
                    if RECIPE.search(line) and path != KCONFIG_ACTION_FILE:
                        failures.append(
                            f"{path} [{job}] `{name}`: installs the Kconfig interpreter by a "
                            f"recipe of its own ({line!r}); the one preparation is "
                            f"`uses: {KCONFIG_ACTION}`"
                        )
                        continue
                    what = _reaching(line, callers)
                    if what is None or reported:
                        continue
                    reported = True
                    seen += 1
                    if not provisioned:
                        failures.append(
                            f"{path} [{job}] `{name}`: runs {what}, which reaches the "
                            "pinned Kconfig interpreter through the build configuration "
                            f"reader, with no `uses: {KCONFIG_ACTION}` before it in the job"
                        )
    return failures, seen


# ── rule 4: a run in flight on main is never cancelled ──────────────────────


def _pushes_main(doc: dict) -> bool:
    """Whether a push to `main` starts the workflow. PyYAML reads the key `on` as True."""
    on = doc.get("on", doc.get(True))
    if on == "push" or (isinstance(on, list) and "push" in on):
        return True
    if not isinstance(on, dict) or "push" not in on:
        return False
    push = on["push"]
    if not isinstance(push, dict):
        return True

    def listed(key: str) -> list[str]:
        value = push.get(key)
        return [str(v) for v in value] if isinstance(value, list) else [str(value)]

    if "branches" in push:
        return "main" in listed("branches")
    if "branches-ignore" in push:
        return "main" not in listed("branches-ignore")
    return "tags" not in push and "tags-ignore" not in push


def concurrency_check(docs: dict[str, dict]) -> tuple[list[str], int]:
    """(failures, workflows a push to main starts) over `{path: parsed yaml}`."""
    failures: list[str] = []
    seen = 0
    for path, doc in sorted(docs.items()):
        if not isinstance(doc.get("jobs"), dict) or not _pushes_main(doc):
            continue
        seen += 1
        group = doc.get("concurrency")
        if not isinstance(group, dict):
            failures.append(
                f"{path}: a push to main starts it and it has no concurrency group with "
                "`cancel-in-progress: false`, so nothing bounds its queue or protects a run "
                "in flight"
            )
        else:
            if group.get("cancel-in-progress") is not False:
                failures.append(
                    f"{path}: `cancel-in-progress` is {group.get('cancel-in-progress')!r}, not "
                    "false: a landing would cancel the run in flight and main would keep no "
                    "graded commit"
                )
            if "github.ref" not in str(group.get("group") or ""):
                failures.append(
                    f"{path}: the concurrency group {group.get('group')!r} is not keyed by "
                    "`github.ref`: another ref's run would replace main's waiting one"
                )
        for job_id, job in doc["jobs"].items():
            if isinstance(job, dict) and "concurrency" in job:
                failures.append(
                    f"{path} [{job_id}]: a job-level concurrency group replaces a waiting job "
                    "of an earlier run, which then reports `cancelled` for a job it never ran"
                )
    return failures, seen


def load_tree() -> dict[str, dict]:
    files = sorted((REPO_ROOT / ".github" / "workflows").glob("*.yml"))
    files += sorted((REPO_ROOT / ".github" / "actions").glob("**/action.yml"))
    return {
        str(f.relative_to(REPO_ROOT)): yaml.safe_load(f.read_text(encoding="utf-8")) or {}
        for f in files
    }


def _report(label: str, failures: list[str], seen: int, zero: str, ok: str) -> int:
    """Print one rule's verdict; 1 when it failed or saw nothing to judge."""
    if seen == 0:
        print(f"{label} FAIL: {zero}", file=sys.stderr)
        return 1
    if failures:
        print(f"{label} FAIL:", file=sys.stderr)
        for f in failures:
            print(f"  - {f}", file=sys.stderr)
        return 1
    print(f"{label}: OK -- {ok}")
    return 0


def main() -> int:
    docs = load_tree()
    failures, seen = check(docs)
    print(
        f"workflow-cache-save: {seen} cache step(s) across {len(docs)} workflow/action "
        "file(s)"
    )
    rc = _report(
        "workflow-cache-save",
        failures,
        seen,
        "parsed ZERO cache steps. This repository has dozens, so the reader stopped "
        "reading; a green here would grade nothing.",
        "no combined cache, and every restore has its save",
    )

    callers, failures = reader_callers(REPO_ROOT)
    more, seen = kconfig_check(docs, callers)
    failures += more
    print(
        f"workflow-kconfig: {seen} step(s) reach the build configuration reader; "
        f"{len(callers)} script(s) under scripts/ reach it without provisioning: "
        + ", ".join(sorted(callers))
    )
    rc |= _report(
        "workflow-kconfig",
        failures,
        seen,
        "no step reaches the build configuration reader, so the derivation stopped "
        "reading; the Platform jobs alone run it in a dozen steps.",
        f"every such step has `uses: {KCONFIG_ACTION}` before it in its job, and no "
        "other recipe installs the interpreter",
    )

    failures, seen = concurrency_check(docs)
    print(f"workflow-concurrency: {seen} workflow(s) start on a push to main")
    rc |= _report(
        "workflow-concurrency",
        failures,
        seen,
        "no workflow starts on a push to main, so the reader stopped reading.",
        "each is grouped by ref and never cancels a run in flight",
    )
    return rc


def selftest() -> int:
    def wf(*steps: dict) -> dict:
        return {"jobs": {"j": {"steps": list(steps)}}}

    restore = {
        "id": "c",
        "uses": "actions/cache/restore@v4",
        "with": {"path": "p", "key": "k-1"},
    }
    save_ref = {
        "uses": "actions/cache/save@v4",
        "with": {"path": "p", "key": "${{ steps.c.outputs.cache-primary-key }}"},
    }
    save_literal = {"uses": "actions/cache/save@v4", "with": {"path": "p", "key": "k-1"}}

    def matrix_wf(targets: list[str], reads: str) -> dict:
        """A matrix job whose cells each save `c-<target>-1`, and one restore
        of `reads` beside its own."""
        own = {
            "id": "own",
            "uses": "actions/cache/restore@v4",
            "with": {"path": "p", "key": "c-${{ matrix.target }}-1"},
        }
        other = {"uses": "actions/cache/restore@v4", "with": {"path": "q", "key": reads}}
        save = {
            "uses": "actions/cache/save@v4",
            "with": {"path": "p", "key": "c-${{ matrix.target }}-1"},
        }
        job = {"strategy": {"matrix": {"target": targets}}, "steps": [own, other, save]}
        return {"jobs": {"j": job}}

    cases = [
        ("combined cache", {"a.yml": wf({"uses": "actions/cache@v4"})}, "COMBINED"),
        ("combined cache, other version", {"a.yml": wf({"uses": "actions/cache@v3"})}, "COMBINED"),
        ("restore with no save", {"a.yml": wf(restore)}, "never warms"),
        (
            "save in ANOTHER job does not pair",
            {"a.yml": {"jobs": {"x": {"steps": [restore]}, "y": {"steps": [save_ref]}}}},
            "never warms",
        ),
        ("save by reference pairs", {"a.yml": wf(restore, save_ref)}, None),
        ("save by verbatim key pairs", {"a.yml": wf(restore, save_literal)}, None),
        (
            "a restore of another matrix cell's cache pairs by that cell's save",
            {"a.yml": matrix_wf(["pcap", "term"], "c-pcap-1")},
            None,
        ),
        (
            "a restore of a cell the matrix does not run does not pair",
            {"a.yml": matrix_wf(["live", "term"], "c-pcap-1")},
            "never warms",
        ),
        (
            "an axis the job does not declare is not expanded",
            {"a.yml": {"jobs": {"j": {"steps": matrix_wf(["pcap"], "c-pcap-1")["jobs"]["j"]["steps"]}}}},
            "never warms",
        ),
        (
            "composite action is read",
            {"x/action.yml": {"runs": {"using": "composite", "steps": [{"uses": "actions/cache@v4"}]}}},
            "COMBINED",
        ),
    ]
    bad = 0
    for label, docs, want in cases:
        failures, seen = check(docs)
        got = "\n".join(failures)
        ok = (want is None and not failures) or (want is not None and want in got)
        print(f"  {'ok ' if ok else 'BAD'}  {label}: expected {want or 'clean'}")
        bad += not ok
    failures, seen = check({"a.yml": wf({"run": "true"})})
    if seen != 0:
        print("  BAD  a workflow with no cache step counted one")
        bad += 1
    else:
        print("  ok   an empty population is seen as zero (main() FAILs on it)")
    arms, more = _selftest_kconfig()
    arms2, more2 = _selftest_concurrency()
    arms3, more3 = _selftest_live()
    total = len(cases) + 1 + arms + arms2 + arms3
    bad += more + more2 + more3
    print(f"  {total - bad}/{total} arm(s) behaved as claimed")
    return 1 if bad else 0


# What rule 3 says of a step that reaches the reader unprovisioned.
_UNPROVISIONED = "with no `uses:"


def _judge(label: str, failures: list[str], want: str | None) -> int:
    """Print one arm's verdict; 1 when the failures are not what the arm claims."""
    got = "\n".join(failures)
    ok = (want is None and not failures) or (want is not None and want in got)
    print(f"  {'ok ' if ok else 'BAD'}  {label}: expected {want or 'clean'}")
    if not ok and failures:
        print(f"         got: {got}")
    return 0 if ok else 1


def _selftest_kconfig() -> tuple[int, int]:
    """Rule 3 over fixtures: the order in a job, a composite action, the recipes, and the
    derivation of what reaches the reader. (arms, bad)."""
    import tempfile

    provision = {"shell": "bash", "run": f"bash {PROVISIONER}"}
    action = {"runs": {"using": "composite", "steps": [provision]}}
    callers = {"pico-c-program.sh": f"runs {READER_NAME}"}
    use = {"name": "kconfig", "uses": KCONFIG_ACTION}
    reach = {"name": "reach", "run": "bash scripts/pico-c-program.sh x.c"}
    direct = {
        "name": "direct",
        "run": 'args="$(python scripts/lib/wz_config.py --resolve-features pico p.conf)"',
    }
    comment = {"name": "comment", "run": f"# python {READER}\ntrue"}

    def tree(*steps: dict, extra: dict | None = None) -> dict:
        docs = {KCONFIG_ACTION_FILE: action, "w.yml": {"jobs": {"j": {"steps": list(steps)}}}}
        docs.update(extra or {})
        return docs

    composite = ".github/actions/p/action.yml"
    pip = "python -m pip install --require-hashes -r scripts/requirements-kconfig.txt"
    cases = [
        ("a step reaching the reader with nothing before it", tree(reach), _UNPROVISIONED),
        ("the action before it provisions it", tree(use, reach), None),
        ("the action after it does not", tree(reach, use), _UNPROVISIONED),
        ("the reader named on a line of the step", tree(direct), _UNPROVISIONED),
        (
            "the action in another job does not count",
            {
                KCONFIG_ACTION_FILE: action,
                "w.yml": {"jobs": {"x": {"steps": [use]}, "y": {"steps": [reach]}}},
            },
            _UNPROVISIONED,
        ),
        (
            "a local composite action that uses the action provisions the job",
            tree({"uses": "./.github/actions/p"}, reach,
                 extra={composite: {"runs": {"steps": [use]}}}),
            None,
        ),
        (
            "a composite action reaching the reader is held on its own",
            tree(extra={composite: {"runs": {"steps": [reach]}}}),
            _UNPROVISIONED,
        ),
        (
            "pip handed the pin file is a recipe of its own",
            tree({"name": "pip", "run": pip}, use, reach),
            "recipe of its own",
        ),
        (
            "the provisioner's line in a step that runs no lane",
            tree({"name": "bare", "run": f"bash {PROVISIONER}"}, reach),
            "runs no lane",
        ),
        (
            "the provisioner's line in a lane step is the planner's form",
            tree({"name": "lane", "run": f"bash {PROVISIONER}\nbash scripts/run-ci.sh --layer E"}),
            None,
        ),
        (
            "an action that no longer runs the provisioner",
            {**tree(use, reach), KCONFIG_ACTION_FILE: {"runs": {"steps": [{"run": "true"}]}}},
            "no longer runs",
        ),
        ("a comment naming the reader is not a call", tree(comment), None),
    ]
    bad = 0
    for label, docs, want in cases:
        failures, _ = kconfig_check(docs, callers)
        bad += _judge(label, failures, want)
    arms = len(cases)

    _, seen = kconfig_check(tree(comment), callers)
    arms += 1
    bad += _judge("a comment is not counted as a step reaching the reader",
                  [] if seen == 0 else [f"counted {seen}"], None)

    reader = (
        "def kconfiglib_module():\n    return None\n\n"
        "def resolve(fragments):\n    return kconfiglib_module()\n\n"
        "def features(path):\n    return resolve([path])\n\n"
        "def table():\n    return 1\n"
    )
    functions = interpreter_functions(reader)
    arms += 1
    bad += _judge(
        "the reader's functions are the seeds and their callers, and no other",
        [] if functions == {"kconfiglib_module", "resolve", "features"} else [f"got {sorted(functions)}"],
        None,
    )
    python_cases = [
        ("a call of a reaching function", "import wz_config\nwz_config.features(1)\n",
         "calls wz_config.features"),
        ("a call of a function that reaches nothing", "import wz_config\nwz_config.table()\n", None),
        ("a reaching function imported by name", "from wz_config import features\n",
         "imports wz_config.features"),
        ("the module imported under another name", "import wz_config as wc\nwc.resolve([])\n",
         "calls wz_config.resolve"),
        ("the reader's path as a subprocess argument",
         "cmd = ['python3', 'scripts/lib/wz_config.py']\n", "runs wz_config.py"),
        ("the reader named in a sentence", "print('run scripts/lib/wz_config.py first')\n", None),
    ]
    for label, source, want in python_cases:
        why = python_reaches(source, functions)
        arms += 1
        bad += _judge(f"python: {label}", [why] if why else [], want)

    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        scripts = root / "scripts"
        (scripts / "lib").mkdir(parents=True)
        (root / READER).write_text(reader, encoding="utf-8")
        (scripts / "a.sh").write_text(f"#!/bin/sh\npython3 {READER} --x\n", encoding="utf-8")
        (scripts / "b.sh").write_text("#!/bin/sh\nbash scripts/a.sh\n", encoding="utf-8")
        (scripts / "c.sh").write_text(
            f"#!/bin/sh\nbash {PROVISIONER}\npython3 {READER} --x\n", encoding="utf-8"
        )
        (scripts / "d.sh").write_text(f"#!/bin/sh\n# python3 {READER}\ntrue\n", encoding="utf-8")
        (scripts / "e.py").write_text("import wz_config\nwz_config.resolve([])\n", encoding="utf-8")
        found, failures = reader_callers(root)
        arms += 1
        bad += _judge(
            "callers: a direct one, one through it and a python one; not one that "
            "provisions itself, not a comment",
            failures + ([] if set(found) == {"a.sh", "b.sh", "e.py"} else [f"got {sorted(found)}"]),
            None,
        )
        (root / READER).write_text("def table():\n    return 1\n", encoding="utf-8")
        _, failures = reader_callers(root)
        arms += 1
        bad += _judge("a reader without the seed functions", failures, "no longer defines")
    return arms, bad


def _selftest_concurrency() -> tuple[int, int]:
    """Rule 4 over fixtures. (arms, bad)."""
    ref_group = {"group": "${{ github.workflow }}-${{ github.ref }}", "cancel-in-progress": False}

    def wf(on, concurrency=None, job: dict | None = None, key: object = "on") -> dict:
        doc = {key: on, "jobs": {"j": job or {"steps": []}}}
        if concurrency is not None:
            doc["concurrency"] = concurrency
        return {".github/workflows/w.yml": doc}

    main_push = {"push": {"branches": ["main"]}}
    tags = {"push": {"tags": ["v*"]}}
    cases = [
        ("grouped by ref, never cancelling", wf(main_push, ref_group), None),
        ("under the key PyYAML reads `on` as", wf(main_push, ref_group, key=True), None),
        ("cancel-in-progress true", wf(main_push, {**ref_group, "cancel-in-progress": True}),
         "not false"),
        (
            "cancel-in-progress as an expression",
            wf(main_push, {**ref_group, "cancel-in-progress": "${{ github.ref != 'refs/heads/main' }}"}),
            "not false",
        ),
        ("no concurrency group", wf(main_push), "no concurrency group"),
        ("a group not keyed by ref", wf(main_push, {"group": "ci", "cancel-in-progress": False}),
         "not keyed"),
        ("a job-level group", wf(main_push, ref_group, job={"concurrency": "x", "steps": []}),
         "job-level"),
        ("a push of every branch", wf({"push": None}), "no concurrency group"),
        ("main not ignored", wf({"push": {"branches-ignore": ["dev"]}}), "no concurrency group"),
        ("a tag push is not held", wf(tags), None),
        ("a schedule is not held", wf({"schedule": [{"cron": "1 1 * * *"}]}), None),
    ]
    bad = 0
    for label, docs, want in cases:
        failures, _ = concurrency_check(docs)
        bad += _judge(f"concurrency: {label}", failures, want)
    _, seen = concurrency_check(wf(tags))
    bad += _judge("a tag push is not counted", [] if seen == 0 else [f"counted {seen}"], None)
    return len(cases) + 1, bad


def _selftest_live() -> tuple[int, int]:
    """Rules 3 and 4 on this repository's own workflows, then on copies mutated: every use of
    the action taken out of the workflows, and main's runs made cancellable. (arms, bad)."""
    import copy

    docs = load_tree()
    callers, failures = reader_callers(REPO_ROOT)
    more, seen = kconfig_check(docs, callers)
    bad = _judge("rule 3 holds on this tree", failures + more + ([] if seen else ["no subject"]), None)
    failures, seen = concurrency_check(docs)
    bad += _judge("rule 4 holds on this tree", failures + ([] if seen else ["no subject"]), None)

    stripped = copy.deepcopy(docs)
    for path, doc in stripped.items():
        jobs = doc.get("jobs")
        if not path.startswith(".github/workflows/") or not isinstance(jobs, dict):
            continue
        for job in jobs.values():
            if isinstance(job, dict) and isinstance(job.get("steps"), list):
                job["steps"] = [
                    s for s in job["steps"]
                    if not (isinstance(s, dict) and _uses(s).split("@", 1)[0] == KCONFIG_ACTION)
                ]
    failures, _ = kconfig_check(stripped, callers)
    bad += _judge(
        "the workflows' uses of the action taken out",
        [f for f in failures if f.startswith(".github/workflows/")],
        _UNPROVISIONED,
    )

    cancelling = copy.deepcopy(docs)
    for doc in cancelling.values():
        if isinstance(doc.get("concurrency"), dict) and _pushes_main(doc):
            doc["concurrency"]["cancel-in-progress"] = True
    failures, _ = concurrency_check(cancelling)
    bad += _judge("main's runs made cancellable", failures, "not false")
    return 4, bad


if __name__ == "__main__":
    if sys.argv[1:] == ["--selftest"]:
        sys.exit(selftest())
    if sys.argv[1:]:
        print(f"usage: {sys.argv[0]} [--selftest]", file=sys.stderr)
        sys.exit(2)
    sys.exit(main())
