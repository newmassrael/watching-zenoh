#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
"""R2276 (no register item) -- every HOSTED caller of `run-ci.sh` arms the
decline assertion, and every LOCAL one does not.

`(no register item)` is a statement about the STORE's `debt-` inventory, which
is what this citation's grammar can resolve against; the item this gate closes
is number 614 of the agent-memory register, which that grammar has no spelling
for. The same is true of every numbered-register gate in this directory --
`self_counted_table_gate.py`, `config_key_fixture_gate.py`,
`flag_precondition_gate.py` -- and it is recorded here rather than left to be
inferred from a bare `(no register item)`.

Open-debt item 614 reads: "nothing arms R2274's `ran nothing` assertion
(`WZ_DECLINED_EXPECT`) -- the reading names the lanes but nothing on hosted
stops them", and prescribes: "read the per-job `ran nothing:` lines off one
hosted run, derive the set, and pin it into that job's `env:`".

## What the arming is, and why a gate has to hold it

`run-ci.sh` treats `WZ_DECLINED_EXPECT` as a SET, asserted BOTH ways: a lane
that ran nothing outside the set is a provisioning regression, and a lane INSIDE
the set that did work is a stale expectation. That is what makes the VALUE
un-gameable -- a caller cannot silence the assertion by listing every lane,
because a listed lane that works is itself a red. So this file does not judge
the value at all. It judges only whether the caller armed it, which is the one
thing the run itself can never notice: an unset variable makes the whole check
disappear, silently, and that is exactly the state R2274 shipped in.

## The population is DERIVED, and the two contexts are opposites

Not a list of jobs. Every workflow under `.github/workflows/` is parsed, and
every `run:` step whose script executes `run-ci.sh` is a caller. Both files
count: item 614's own "location" bullet names `ci.yml` only, and `release.yml`
carries nine more call sites -- MEASURED at this round, and the item's location
is refuted by that count.

  * HOSTED (`.github/workflows/**`)  -- MUST arm. The runner provisions its
    own oracles, so "no lane ran nothing" is a claim that job is entitled to
    make, and a provisioning regression is precisely what it would catch.

  * LOCAL (`.githooks/**`)           -- MUST NOT arm. `pre-push` is a FAST
    gate and fail-open BY DESIGN (CLAUDE.md: "NOT a full CI mirror"). A
    developer without shellcheck makes Layer 0 decline, and arming there would
    turn a provisioning FACT about that machine into a refused push.

Neither is an exemption table: the context is read off the directory the caller
lives in, and both directions are RED. An empty population on either side is
RED too -- a gate whose subject has vanished has lost its subject, not passed.

  * ELSEWHERE -- a caller under neither directory MUST at least NAME
    `WZ_DECLINED_EXPECT`, so that whatever it does with the variable is a
    decision its own source records. `lane_decline_read.py` is the only such
    caller today and it passes by REMOVING the variable from the environment it
    hands its subprocess -- a test harness building its own world, which is a
    different thing from a caller configuring a run, and its source says so.

That third population is derived too, and from the same kind of structural
fact: the files searched are the tracked ones this tree can EXECUTE -- a
shebang or the execute bit -- so a `bash scripts/run-ci.sh` inside a README's
code fence is not a caller, and no extension list decides that.

## The consumer arm

Arming a variable nothing reads is the same defect wearing the other shoe, so
`run-ci.sh` must still consult `WZ_DECLINED_EXPECT`. If it stops, every arming
in the tree becomes decoration and this gate says so.
"""

from __future__ import annotations

import argparse
import re
import sys
import tempfile
from pathlib import Path

try:
    import yaml
except ImportError:  # pragma: no cover - reported, never skipped
    yaml = None

VAR = "WZ_DECLINED_EXPECT"
RUNCI = "run-ci.sh"

WORKFLOW_DIR = Path(".github/workflows")
HOOK_DIR = Path(".githooks")

#: A shell line that EXECUTES run-ci.sh, as opposed to naming it in prose. The
#: interpreter is required because every other mention in `.githooks/` is a
#: comment or an error message, and a bare substring test reads those as calls.
#: The `\S*` after `=` is deliberate and was found by a fixture: an arming
#: prefix is written `WZ_DECLINED_EXPECT= bash ...` with an EMPTY value, and a
#: `\S+` there fails to match exactly the line this gate exists to catch.
SHELL_CALL = re.compile(
    r"(?:^|[;&|]|\bif\s+!?\s*|\bthen\s+)\s*(?:\S+=\S*\s+)*(?:bash|sh)\s+\S*run-ci\.sh\b"
)


class GateError(RuntimeError):
    """The gate could not reach its input. Never a silent green."""


# ── the hosted side: workflow steps ──────────────────────────────────────────


def workflow_files(root: Path) -> list[Path]:
    d = root / WORKFLOW_DIR
    if not d.is_dir():
        raise GateError(f"{WORKFLOW_DIR} is not a directory -- no hosted caller can be read")
    return sorted(p for p in d.iterdir() if p.suffix in (".yml", ".yaml"))


def hosted_callers(root: Path) -> list[tuple[str, str, str, bool]]:
    """`(file, job, step label, armed)` for every workflow step running run-ci.

    `armed` merges the three env scopes GitHub Actions merges -- workflow, job,
    step -- and asks only whether the KEY is present. An empty string is a
    perfectly good arming: it is the claim "no lane here runs nothing", and it
    is a different statement from leaving the variable unset.
    """
    if yaml is None:
        raise GateError(
            "PyYAML is absent, so no workflow could be parsed -- a gate that "
            "cannot reach its input must not report green"
        )
    out: list[tuple[str, str, str, bool]] = []
    for path in workflow_files(root):
        try:
            doc = yaml.safe_load(path.read_text(encoding="utf-8"))
        except yaml.YAMLError as exc:
            raise GateError(f"{path}: not parseable as YAML: {exc}") from exc
        if not isinstance(doc, dict):
            continue
        wf_env = doc.get("env") or {}
        jobs = doc.get("jobs") or {}
        if not isinstance(jobs, dict):
            continue
        for job_id, job in jobs.items():
            if not isinstance(job, dict):
                continue
            job_env = job.get("env") or {}
            steps = job.get("steps") or []
            if not isinstance(steps, list):
                continue
            for i, step in enumerate(steps):
                if not isinstance(step, dict):
                    continue
                script = step.get("run")
                if not isinstance(script, str) or RUNCI not in script:
                    continue
                step_env = step.get("env") or {}
                armed = any(
                    isinstance(e, dict) and VAR in e for e in (step_env, job_env, wf_env)
                )
                label = step.get("name") or f"step[{i}]"
                out.append((str(path.relative_to(root)), str(job_id), str(label), armed))
    return out


# ── the local side: git hooks ────────────────────────────────────────────────


def hook_files(root: Path) -> list[Path]:
    d = root / HOOK_DIR
    if not d.is_dir():
        raise GateError(f"{HOOK_DIR} is not a directory -- no local caller can be read")
    return sorted(p for p in d.iterdir() if p.is_file())


def local_callers(root: Path) -> list[tuple[str, int, str, bool]]:
    """`(file, line, text, armed)` for every hook line that RUNS run-ci.sh."""
    out: list[tuple[str, int, str, bool]] = []
    for path in hook_files(root):
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        exported = re.search(rf"^\s*export\s+{VAR}\b", text, re.M) is not None
        for n, line in enumerate(text.split("\n"), 1):
            if line.lstrip().startswith("#"):
                continue
            if not SHELL_CALL.search(line):
                continue
            armed = exported or VAR in line
            out.append((str(path.relative_to(root)), n, line.strip(), armed))
    return out


# ── the consumer arm ─────────────────────────────────────────────────────────


# ── the third population: executable callers under neither directory ────────

#: An argv-list call, which is how a Python harness spawns the script. The
#: shell form above cannot see it: there is no `bash` token on the line.
ARGV_CALL = re.compile(r'"--layer"')


def executable_tracked(root: Path) -> list[Path]:
    """Tracked files this tree can RUN -- shebang or execute bit.

    Derived rather than filtered by extension, which is what keeps a
    `bash scripts/run-ci.sh` inside a Markdown code fence out of the population
    without anybody writing `.md` down as an exception.
    """
    import subprocess

    try:
        out = subprocess.run(
            ["git", "-C", str(root), "ls-files", "-z"],
            capture_output=True,
            text=True,
            check=True,
        ).stdout
        rels = [r for r in out.split("\0") if r]
    except (OSError, subprocess.CalledProcessError):
        # Not a work tree -- the selftest fixtures and the mirrored copy below.
        # Falling back to every file WIDENS the population, which can only add
        # findings, never hide one; a narrowing fallback would be the shape
        # this repo refuses.
        rels = [str(p.relative_to(root)) for p in root.rglob("*")]
    found = []
    for rel in rels:
        p = root / rel
        if not p.is_file():
            continue
        try:
            if p.stat().st_mode & 0o111:
                found.append(p)
                continue
            with p.open("rb") as fh:
                if fh.read(2) == b"#!":
                    found.append(p)
        except OSError:  # pragma: no cover - unreadable tracked file
            continue
    return found


def other_callers(root: Path) -> list[tuple[str, int, str, bool]]:
    """`(file, line, text, names_var)` for executable callers outside both dirs."""
    out: list[tuple[str, int, str, bool]] = []
    for path in executable_tracked(root):
        rel = path.relative_to(root)
        if str(rel).startswith((str(WORKFLOW_DIR), str(HOOK_DIR))):
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        if RUNCI not in text and "--layer" not in text:
            continue
        names = VAR in text
        for n, line in enumerate(text.split("\n"), 1):
            stripped = line.lstrip()
            if stripped.startswith("#"):
                continue
            if SHELL_CALL.search(line) or (ARGV_CALL.search(line) and RUNCI in text):
                out.append((str(rel), n, stripped, names))
    return out


def consumer_reads(root: Path) -> bool:
    runci = root / "scripts" / RUNCI
    if not runci.is_file():
        raise GateError(f"{runci} is absent -- the arming has no consumer to check")
    return VAR in runci.read_text(encoding="utf-8")


# ── the verdict ──────────────────────────────────────────────────────────────


def check(root: Path) -> tuple[list[str], list[str]]:
    """`(findings, report)`. Findings empty means the arming holds both ways."""
    bad: list[str] = []
    report: list[str] = []

    hosted = hosted_callers(root)
    if not hosted:
        bad.append(
            f"no workflow step runs {RUNCI} -- the hosted side of this gate has "
            "lost its subject, which is not a pass"
        )
    for f, job, label, armed in hosted:
        if not armed:
            bad.append(
                f"{f}: job `{job}` step `{label}` runs {RUNCI} with {VAR} UNSET, "
                "so the run's `ran nothing` assertion is not made at all there"
            )

    local = local_callers(root)
    if not local:
        bad.append(
            f"no hook line runs {RUNCI} -- the local side of this gate has lost "
            "its subject, which is not a pass"
        )
    for f, n, text, armed in local:
        if armed:
            bad.append(
                f"{f}:{n}: a LOCAL caller arms {VAR} ({text!r}). The hooks are "
                "fail-open by design -- a developer without shellcheck makes "
                "Layer 0 decline, and arming turns that machine fact into a "
                "refused push"
            )

    other = other_callers(root)
    for f, n, text, names in other:
        if not names:
            bad.append(
                f"{f}:{n}: runs {RUNCI} ({text!r}) from outside both "
                f"{WORKFLOW_DIR} and {HOOK_DIR}, and its source never names "
                f"{VAR} -- so nothing records whether the assertion is armed, "
                "removed, or simply forgotten there"
            )

    if not consumer_reads(root):
        bad.append(
            f"scripts/{RUNCI} no longer reads {VAR}, so every arming in the "
            "tree is decoration"
        )

    files = sorted({f for f, _, _, _ in hosted})
    report.append(
        f"  decline arming: OK ({len(hosted)} hosted call site(s) in "
        f"{len(files)} workflow(s) armed, {len(local)} local call site(s) "
        f"deliberately not, {len(other)} other executable caller(s) naming "
        f"{VAR}, consumer present)"
    )
    return bad, report


# ── selftest ─────────────────────────────────────────────────────────────────

_WF_TEMPLATE = """\
name: T
on: [push]
env:
{wf_env}
jobs:
  a:
    runs-on: ubuntu-22.04
{job_env}
    steps:
      - name: lane X
{step_env}
        run: bash scripts/run-ci.sh --layer X
"""


def _fixture(td: Path, *, wf=True, job=False, step=False, hook_armed=False,
             consumer=True, with_step=True, stray=None, md_executable=False) -> Path:
    root = td
    (root / WORKFLOW_DIR).mkdir(parents=True, exist_ok=True)
    (root / HOOK_DIR).mkdir(parents=True, exist_ok=True)
    (root / "scripts").mkdir(parents=True, exist_ok=True)
    body = _WF_TEMPLATE.format(
        wf_env=f'  {VAR}: ""\n  X: "1"' if wf else '  X: "1"',
        job_env=f'    env:\n      {VAR}: ""' if job else "",
        step_env=f'        env:\n          {VAR}: ""' if step else "",
    )
    if not with_step:
        body = body.split("    steps:")[0] + "    steps:\n      - run: echo hi\n"
    (root / WORKFLOW_DIR / "t.yml").write_text(body)
    call = "bash scripts/run-ci.sh --layer C1bz"
    if hook_armed:
        call = f"{VAR}= " + call
    (root / HOOK_DIR / "pre-push").write_text(
        "#!/usr/bin/env bash\n"
        "# a comment naming scripts/run-ci.sh must not count as a call\n"
        f"if ! {call}; then\n  exit 1\nfi\n"
    )
    (root / "scripts" / RUNCI).write_text(
        f'#!/usr/bin/env bash\nif [[ -n "${{{VAR}+set}}" ]]; then :; fi\n'
        if consumer
        else "#!/usr/bin/env bash\n:\n"
    )
    # A caller under NEITHER directory. `stray="silent"` never names the
    # variable and must be RED; `stray="aware"` removes it deliberately and
    # must not be. A `.md` carrying the same command is the control: it is not
    # executable, so it is not a caller and neither value changes its verdict.
    howto = root / "HOWTO.md"
    howto.write_text("Run it with:\n\n    bash scripts/run-ci.sh --layer X\n")
    if md_executable:
        howto.chmod(0o755)
    if stray:
        tool = root / "scripts" / "tool.sh"
        body = "#!/usr/bin/env bash\n"
        if stray == "aware":
            body += f"unset {VAR}\n"
        body += "bash scripts/run-ci.sh --layer X\n"
        tool.write_text(body)
        tool.chmod(0o755)
    return root


def _mirror(td: Path, root: Path) -> Path:
    """A tree that IS this repository's real caller surface, file by file.

    Copied rather than synthesised, because the fixtures above prove the rule
    and this proves the rule still describes the tree it is shipped with. The
    copies are what the mutations below edit.
    """
    mirror = td / "tree"
    (mirror / WORKFLOW_DIR).mkdir(parents=True)
    (mirror / HOOK_DIR).mkdir(parents=True)
    (mirror / "scripts").mkdir(parents=True)
    for p in workflow_files(root):
        (mirror / WORKFLOW_DIR / p.name).write_text(p.read_text(encoding="utf-8"))
    for p in hook_files(root):
        try:
            (mirror / HOOK_DIR / p.name).write_text(p.read_text(encoding="utf-8"))
        except UnicodeDecodeError:  # pragma: no cover - binary hook
            continue
    (mirror / "scripts" / RUNCI).write_text(
        (root / "scripts" / RUNCI).read_text(encoding="utf-8")
    )
    return mirror


def _selftest_live(root: Path) -> list[str]:
    """The arms whose SUBJECT is this repository, mutated on a copy of it."""
    bad: list[str] = []
    try:
        found, _ = check(root)
    except GateError as exc:
        return [f"the gate cannot read this tree: {exc}"]
    if found:
        bad.append(f"the gate is RED on the real tree: {found}")

    with tempfile.TemporaryDirectory() as td:
        mirror = _mirror(Path(td), root)

        # M1 -- take the arming out of ci.yml. Every step in that file must go
        # red, and the count is what says the population is the file's own.
        ci = mirror / WORKFLOW_DIR / "ci.yml"
        before = ci.read_text()
        after = re.sub(rf"^\s*{VAR}:.*\n", "", before, count=1, flags=re.M)
        if after == before:
            bad.append(f"M1 changed nothing -- ci.yml carries no `{VAR}:` line to remove")
        else:
            ci.write_text(after)
            found, _ = check(mirror)
            unset = [f for f in found if "UNSET" in f and "ci.yml" in f]
            if not unset:
                bad.append(f"M1: removing ci.yml's arming did not go RED (findings={found})")
            ci.write_text(before)

        # M2 -- arm a LOCAL caller. The hooks are fail-open by design and this
        # is the direction a one-way gate would miss.
        #
        # The line to mutate is the one `local_callers` ITSELF reports, not the
        # first textual match: `.githooks/pre-push` names `scripts/run-ci.sh`
        # in a comment forty lines above its first real call, and the first
        # draft of this probe edited THAT. The text changed, the "changed
        # nothing" guard passed, and the gate stayed green on a mutation that
        # had not touched anything it reads.
        sites = [row for row in local_callers(mirror) if row[0].endswith("pre-push")]
        if not sites:
            bad.append("M2 has no subject -- no local call site in .githooks/pre-push")
        else:
            hook = mirror / sites[0][0]
            before = hook.read_text()
            lines = before.split("\n")
            n = sites[0][1] - 1
            lines[n] = re.sub(
                r"(bash\s+\S*run-ci\.sh)", rf"{VAR}= \1", lines[n], count=1
            )
            after = "\n".join(lines)
            if after == before:
                bad.append("M2 changed nothing -- it is not a probe")
            else:
                hook.write_text(after)
                found, _ = check(mirror)
                if not any("LOCAL caller arms" in f for f in found):
                    bad.append(f"M2: arming a hook did not go RED (findings={found})")
                hook.write_text(before)

        # M3 -- the consumer. An arming nothing reads is decoration.
        runci = mirror / "scripts" / RUNCI
        before = runci.read_text()
        runci.write_text(before.replace(VAR, "WZ_GONE"))
        found, _ = check(mirror)
        if not any("decoration" in f for f in found):
            bad.append(f"M3: removing the consumer did not go RED (findings={found})")
        runci.write_text(before)
    return bad


def selftest(root: Path) -> int:
    bad: list[str] = []
    cases = [
        # (label, fixture kwargs, needle in the finding; None = must be clean)
        ("workflow env arms every step", {}, None),
        ("job env arms its steps", {"wf": False, "job": True}, None),
        ("step env arms itself", {"wf": False, "step": True}, None),
        ("nothing arms -> RED", {"wf": False}, "UNSET"),
        ("a LOCAL caller that arms -> RED", {"hook_armed": True}, "LOCAL caller arms"),
        ("consumer gone -> RED", {"consumer": False}, "decoration"),
        ("no hosted call site -> RED", {"with_step": False}, "lost its subject"),
        ("a caller outside both dirs that never names it -> RED",
         {"stray": "silent"}, "never names"),
        ("the same caller, having removed it deliberately", {"stray": "aware"}, None),
        ("a Markdown code fence is not a caller", {}, None),
        # The CONTROL for the line above: the same Markdown file, byte for
        # byte, with the execute bit set. It goes RED -- which is what proves
        # the previous case passes because the file cannot be RUN and not
        # because the scanner is failing to see the command inside it.
        ("...but an EXECUTABLE one is", {"md_executable": True}, "never names"),
    ]
    for label, kw, needle in cases:
        with tempfile.TemporaryDirectory() as td:
            fix = _fixture(Path(td), **kw)
            try:
                found, _ = check(fix)
            except GateError as exc:
                found = [f"GateError: {exc}"]
            if needle is None:
                if found:
                    bad.append(f"{label}: expected clean, got {found}")
            elif not any(needle in f for f in found):
                bad.append(f"{label}: expected a finding matching {needle!r}, got {found}")
    # A comment that merely NAMES run-ci.sh must not be read as a call -- the
    # fixture hook carries one, and if it were counted the LOCAL arm would
    # report two call sites where the file has one.
    with tempfile.TemporaryDirectory() as td:
        fix = _fixture(Path(td))
        if len(local_callers(fix)) != 1:
            bad.append(
                "a comment naming run-ci.sh was counted as a call site: "
                f"{local_callers(fix)}"
            )
    bad += _selftest_live(root)
    if bad:
        print("  decline arming SELFTEST FAIL:", file=sys.stderr)
        for b in bad:
            print(f"    - {b}", file=sys.stderr)
        return 1
    print(
        f"  decline arming: selftest OK ({len(cases)} fixture(s) -- three "
        "arming scopes, all three RED directions, the missing consumer, an "
        "empty population, a comment that is not a call, and a Markdown file "
        "that becomes one when it is made executable -- plus 3 mutation(s) of "
        "this repository's own workflows and hooks)"
    )
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--check", action="store_true")
    g.add_argument("--selftest", action="store_true")
    ap.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[2])
    args = ap.parse_args()

    if args.selftest:
        return selftest(args.root)
    try:
        bad, report = check(args.root)
    except GateError as exc:
        print(f"  decline arming FAIL: {exc}", file=sys.stderr)
        return 2
    if bad:
        print("  decline arming FAIL:", file=sys.stderr)
        for b in bad:
            print(f"    - {b}", file=sys.stderr)
        return 1
    for line in report:
        print(line)
    return 0


if __name__ == "__main__":
    sys.exit(main())
