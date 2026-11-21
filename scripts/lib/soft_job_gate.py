#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
"""R4582 (no register item) -- every soft job of a workflow carries a promise, and keeps it.

## The defect this closes

A job or step with `continue-on-error` reads as a pass whatever it did: the run
concludes `success`, so the previous-run gate (pre-push gate 2c) never sees it. The
Windows package jobs of `platform.yml` failed on every hosted run from the day they
were added (the packager decoded `cargo metadata` in the runner's ANSI code page),
and every one of those runs concluded `success`. Each soft site's own comment
promises that it becomes a gate once two consecutive hosted runs read it green;
nothing held that promise, and nothing read whether the site was red.

A soft STEP hides better than a soft job: the jobs API reports its conclusion as
`success` too. Measured 2026-11-21 on Platform run 44869972603: the macOS
multicast step's log ends `Process completed with exit code 1.` while the API says
`success`, and both steps of the cooperative-engine job's Windows row had failed to
link on each of the six main runs read, behind a job that concluded `success`.
Only the job log carries a soft step's verdict, so that is what the hosted half
reads.

## What is a soft site

  * `continue-on-error` on a job or a step, with any value but `false` (an expression
    can be true);
  * a step whose run script turns its command's failure into a warning
    (`|| echo "::warning...`): the step concludes `success` whatever the command did.

The other `|| true` lines of the workflows were read when this gate was written:
they are diagnostic listings, a cgroup read and the disk-headroom prune, whose
failure is no verdict anyone relies on. No workflow uses `set +e`.

## The declaration (deploy/soft_jobs.json)

One entry per site: `workflow`, `job` (its key under `jobs:`), `step` (its `name:`,
null for a job-level site), `kind`, `why_soft`, `gate_when` (the promise),
`promote_after_green` (consecutive green main runs on every instance of the job
that make it a gate), `allowed_consecutive_red` (consecutive red main runs the
hosted reading tolerates), `declared` and `expires` (ISO dates, at most
MAX_TERM_DAYS apart). Optional: `observe_only` (an instance name mapped to why that
instance is an observation with no gate promise; its readings never fail and it
holds the promotion), `note`, and `renewals` (`{on, until, why}`, each extending the
expiry by at most MAX_TERM_DAYS from the day it was made, with a reason).

## Static (--check, Layer C0): each a FAIL

  UNDECLARED  a soft site with no declaration
  ORPHAN      a declaration whose site is gone (promoted, renamed or removed)
  DUPLICATE   two declarations of one site
  FIELD       a declaration missing a field, with one of the wrong shape, or with
              a field this file does not know
  KIND        a declaration whose kind is not its site's
  EXPIRED     today is past the expiry (the last renewal's `until`)
  TERM        an expiry or a renewal more than MAX_TERM_DAYS ahead of its date, a
              renewal that does not extend the expiry, or one with no reason
  NAMELESS    a soft step with no `name:` (a declaration keys on it)
  UNREADABLE  a site the hosted half could not find: a job name that does not
              render, a step name with an expression in it, a step log anchor
              another step of the job shares, two soft steps of one job with one
              name, an observe-only key that is not an instance of the job
  READERS     the text scan and the YAML parse disagree on the soft sites
  EMPTY       no workflow was read

The expiry makes the check depend on the calendar on purpose: a soft site that
nobody revisits turns Layer C0 red on its own date.

## Hosted (--hosted <run-id>... | --hosted-last [N])

Reads each named run, or the last N completed push runs on main of every
workflow with a declared site (N defaults to the largest window a declaration
needs), through `gh api repos/<owner>/<repo>/actions/...` with the owner and repo
read from `git remote get-url origin`. A job-level site is read from its job's
conclusion; a step-level one from its section of the job log, from
`##[group]Run <first line of its script>` to the next step: any `##[error]` line in
it is red, and for a warning-swallow step any `##[warning]` line too.

Per instance of the job (a matrix row), newest run first, leaving out the runs
it did not run in: FAIL when the newest red streak is longer than
`allowed_consecutive_red`, and also while the instance is recovering from such a
breach with fewer than `promote_after_green` greens since; a breach is cleared by
the evidence that would promote the site. `promote` is printed, with the edit,
when every instance has read green on `promote_after_green` consecutive runs and
none is observe-only; a job-level site waits for the soft steps of its job, since
its job concludes success while they fail.

Exit codes: 0 every site within its promise; 1 a site broke it (or, for
--check, a rule failed); 2 usage; 3 NOT-MEASURED (no gh, no network, an
unreadable answer or log, or nothing read at all), never a pass.

Modes (one required): --check [--today YYYY-MM-DD], --selftest,
--hosted <run-id>..., --hosted-last [N].
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
from collections import Counter
from dataclasses import dataclass, field
from datetime import date
from itertools import product
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import hosted_cancelled_kind  # noqa: E402

ROOT = Path(__file__).resolve().parents[2]
WORKFLOWS_DIR = ".github/workflows"
DECLARATIONS = "deploy/soft_jobs.json"

MAX_TERM_DAYS = 90
SOON_DAYS = 14
MIN_PROSE = 20
GH_TIMEOUT_S = 120

EXIT_OK = 0
EXIT_FAIL = 1
EXIT_USAGE = 2
EXIT_NOT_MEASURED = 3

KIND_COE = "continue-on-error"
KIND_SWALLOW = "warning-swallow"
KINDS = (KIND_COE, KIND_SWALLOW)

REQUIRED = {
    "workflow": "str",
    "job": "str",
    "step": "str-or-null",
    "kind": "str",
    "why_soft": "prose",
    "gate_when": "prose",
    "promote_after_green": "int>=1",
    "allowed_consecutive_red": "int>=0",
    "declared": "date",
    "expires": "date",
}
OPTIONAL = ("observe_only", "note", "renewals")
RENEWAL_KEYS = ("on", "until", "why")

GREEN = "G"
RED = "R"
NOT_RUN = "-"
UNREAD = "?"

# The text reader marks a soft step that has no name with this, so that the YAML
# side, which reports it as NAMELESS, is not also told the two readers disagree.
NAMELESS_STEP = ""

SWALLOW = re.compile(r"""\|\|\s*echo\s+["']?::warning""")
COE_LINE = re.compile(r"^(\s*)(?:-\s+)?continue-on-error:\s*(.*?)\s*(?:#.*)?$")
JOB_KEY = re.compile(r"^  ([A-Za-z_][A-Za-z0-9_-]*):\s*(?:#.*)?$")
ITEM = re.compile(r"^(\s*)-(?:\s|$)")
ITEM_NAME = re.compile(r"^\s*-\s+name:\s*(.*)$")
MATRIX_EXPR = re.compile(r"\$\{\{\s*matrix\.([A-Za-z0-9_-]+)\s*\}\}")
ANY_EXPR = re.compile(r"\$\{\{.*?\}\}")
DATE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
LOG_STAMP = re.compile(r"^\ufeff?\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z ?")
GROUP_RUN = "##[group]Run "
SECTION_ENDS = ("Post job cleanup.", "Evaluate and set job outputs", "Cleaning up orphan processes")
FRAME_STEPS = ("Set up job", "Complete job")
REMOTE = re.compile(r"github\.com[:/]+([^/\s]+)/([^/\s]+?)(?:\.git)?/?$")


class Unreadable(RuntimeError):
    """An input could not be read. Never a pass."""


@dataclass
class Site:
    workflow: str
    job: str
    step: str | None
    kind: str
    line: int = 0
    instances: list[str] | None = None
    anchor: str | None = None

    @property
    def key(self) -> tuple:
        return (self.workflow, self.job, self.step, self.kind)

    def label(self) -> str:
        where = f"{self.workflow}:{self.line}" if self.line else self.workflow
        what = f"job {self.job}" + (f" / step {self.step!r}" if self.step is not None else "")
        return f"{where} {what} ({self.kind})"


@dataclass
class Scan:
    sites: dict = field(default_factory=dict)
    problems: list = field(default_factory=list)
    workflows: int = 0


# -- reading the workflows -------------------------------------------------------


def _yaml_load(text: str, rel: str):
    try:
        import yaml
    except ImportError as exc:
        raise Unreadable("PyYAML is not importable, so no workflow can be parsed") from exc
    try:
        return yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise Unreadable(f"{rel} is not YAML: {exc}") from exc


def _is_soft(value) -> bool:
    if value is None or value is False:
        return False
    return not (isinstance(value, str) and value.strip().lower() in ("", "false"))


def _unquote(raw: str) -> str:
    s = raw.strip()
    if len(s) >= 2 and s[0] == s[-1] == "'":
        return s[1:-1].replace("''", "'")
    if len(s) >= 2 and s[0] == s[-1] == '"':
        try:
            return json.loads(s)
        except ValueError:
            return s[1:-1]
    return re.sub(r"\s+#.*$", "", s)


def _indent(line: str) -> int:
    return len(line) - len(line.lstrip(" "))


def _meaningful(line: str) -> bool:
    stripped = line.strip()
    return bool(stripped) and not stripped.startswith("#")


def text_sites(rel: str, text: str) -> tuple[list, list]:
    """(job, step name or None, kind, line) for every soft line of the text, and problems.

    The YAML parse is the reading the sites are taken from; this one is the
    independent count it is held to, and the source of the line numbers.
    """
    lines = text.splitlines()
    in_jobs = []
    inside = False
    for line in lines:
        if re.match(r"^jobs:\s*(?:#.*)?$", line):
            inside = True
        elif line[:1] not in ("", " ", "#"):
            inside = False
        in_jobs.append(inside)

    def job_of(i: int):
        for j in range(i, -1, -1):
            m = JOB_KEY.match(lines[j])
            if m and in_jobs[j]:
                return m.group(1)
        return None

    def step_name(start: int) -> str:
        m = ITEM_NAME.match(lines[start])
        if m:
            return _unquote(m.group(1))
        base = _indent(lines[start])
        for j in range(start + 1, len(lines)):
            if not _meaningful(lines[j]):
                continue
            if _indent(lines[j]) <= base:
                break
            m = re.match(r"^\s*name:\s*(.*)$", lines[j])
            if m and _indent(lines[j]) == base + 2:
                return _unquote(m.group(1))
        return NAMELESS_STEP

    def owner(i: int, through: bool):
        """('step', start line) or ('job', key) for the line at i, or None."""
        if ITEM.match(lines[i]):
            return ("step", i)
        threshold = _indent(lines[i])
        for j in range(i - 1, -1, -1):
            if not _meaningful(lines[j]) or _indent(lines[j]) >= threshold:
                continue
            if ITEM.match(lines[j]):
                return ("step", j)
            m = JOB_KEY.match(lines[j])
            if m and in_jobs[j]:
                return ("job", m.group(1))
            if not through:
                return None
            threshold = _indent(lines[j])
        return None

    found: list = []
    problems: list = []
    for i, line in enumerate(lines):
        if not in_jobs[i] or line.lstrip().startswith("#"):
            continue
        hits = []
        m = COE_LINE.match(line)
        if m and _is_soft(_unquote(m.group(2))):
            hits.append((KIND_COE, False))
        if SWALLOW.search(line):
            hits.append((KIND_SWALLOW, True))
        for kind, through in hits:
            own = owner(i, through)
            if own is None or (own[0] == "job" and kind == KIND_SWALLOW):
                problems.append(
                    f"READERS {rel}:{i + 1}: a {kind} line the text reader cannot place on "
                    "a job or a step, so the YAML parse may not see it either"
                )
                continue
            if own[0] == "job":
                found.append((own[1], None, kind, i + 1))
            else:
                found.append((job_of(own[1]), step_name(own[1]), kind, i + 1))
    return found, problems


def render_instances(job_key: str, job: dict):
    """The job's run names, one per matrix row, or None when one cannot be rendered."""
    strategy = job.get("strategy")
    matrix = strategy.get("matrix") if isinstance(strategy, dict) else None
    combos: list = [{}]
    if matrix is not None:
        if not isinstance(matrix, dict):
            return None
        axes = {k: v for k, v in matrix.items() if k not in ("include", "exclude")}
        if any(not isinstance(v, list) for v in axes.values()):
            return None
        combos = [dict(zip(axes, vals)) for vals in product(*axes.values())] if axes else []
        for exc in matrix.get("exclude") or []:
            if not isinstance(exc, dict):
                return None
            combos = [c for c in combos if not all(c.get(k) == v for k, v in exc.items())]
        base = list(combos)
        for inc in matrix.get("include") or []:
            if not isinstance(inc, dict):
                return None
            matched = False
            for c in base:
                if all(c.get(k) == v for k, v in inc.items() if k in axes):
                    c.update({k: v for k, v in inc.items() if k not in axes})
                    matched = True
            if not matched:
                combos.append(dict(inc))
    template = job.get("name")
    names = []
    for c in combos:
        if isinstance(template, str):
            rendered = MATRIX_EXPR.sub(
                lambda m, c=c: str(c[m.group(1)]) if m.group(1) in c else m.group(0), template
            )
        elif c:
            rendered = f"{job_key} ({', '.join(str(v) for v in c.values())})"
        else:
            rendered = job_key
        if ANY_EXPR.search(rendered):
            return None
        names.append(rendered)
    return names


def step_anchor(step: dict):
    """What the job log prints after `##[group]Run ` for this step."""
    run = step.get("run")
    if isinstance(run, str):
        for line in run.splitlines():
            if line.strip():
                return line.strip()
        return None
    uses = step.get("uses")
    return uses.strip() if isinstance(uses, str) else None


def anchor_regex(anchor: str):
    return re.compile(".*?".join(re.escape(p) for p in ANY_EXPR.split(anchor)))


def scan_workflow(rel: str, text: str, scan: Scan) -> None:
    doc = _yaml_load(text, rel)
    scan.workflows += 1
    jobs = doc.get("jobs") if isinstance(doc, dict) else None
    parsed: list = []
    if isinstance(jobs, dict):
        for job_key, job in jobs.items():
            if not isinstance(job, dict):
                continue
            instances = render_instances(job_key, job)
            steps = [s for s in job.get("steps") or [] if isinstance(s, dict)]
            anchors = [step_anchor(s) for s in steps]
            job_sites: list = []
            if _is_soft(job.get("continue-on-error")):
                job_sites.append(Site(rel, job_key, None, KIND_COE, instances=instances))
            for idx, step in enumerate(steps):
                kinds = []
                if _is_soft(step.get("continue-on-error")):
                    kinds.append(KIND_COE)
                if isinstance(step.get("run"), str) and SWALLOW.search(step["run"]):
                    kinds.append(KIND_SWALLOW)
                if not kinds:
                    continue
                name = step.get("name")
                if not isinstance(name, str) or not name.strip():
                    scan.problems.append(
                        f"NAMELESS {rel}: job {job_key}, step #{idx + 1} is soft and has no "
                        "`name:`; a declaration keys on the name, so give it one"
                    )
                    continue
                if ANY_EXPR.search(name):
                    scan.problems.append(
                        f"UNREADABLE {rel}: job {job_key}, step {name!r}: the jobs API names a "
                        "step by its rendered name, which a declaration cannot spell"
                    )
                anchor = anchors[idx]
                if anchor is None or anchors.count(anchor) > 1:
                    why = "missing" if anchor is None else "shared by another step of the job"
                    scan.problems.append(
                        f"UNREADABLE {rel}: job {job_key}, step {name!r}: its log anchor "
                        f"{anchor!r} is {why}, so the hosted reading cannot find its section"
                    )
                for kind in kinds:
                    job_sites.append(
                        Site(rel, job_key, name, kind, instances=instances, anchor=anchor)
                    )
            if job_sites and instances is None:
                scan.problems.append(
                    f"UNREADABLE {rel}: job {job_key} has soft sites and a run name this "
                    "reader cannot render from its matrix, so no hosted job matches it"
                )
            parsed.extend(job_sites)

    text_found, text_problems = text_sites(rel, text)
    scan.problems.extend(text_problems)
    text_keys = Counter((j, s, k) for j, s, k, _ in text_found if s != NAMELESS_STEP)
    yaml_keys = Counter((s.job, s.step, s.kind) for s in parsed)
    if text_keys != yaml_keys:
        scan.problems.append(
            f"READERS {rel}: the text scan and the YAML parse disagree on the soft sites "
            f"(text only: {list((text_keys - yaml_keys).elements())}; "
            f"YAML only: {list((yaml_keys - text_keys).elements())})"
        )
    lines: dict = {}
    for j, s, k, ln in text_found:
        lines.setdefault((j, s, k), []).append(ln)
    for site in parsed:
        if site.key in scan.sites:
            scan.problems.append(
                f"UNREADABLE {rel}: two soft steps of job {site.job} are named {site.step!r}; "
                "a declaration cannot tell them apart"
            )
            continue
        got = lines.get((site.job, site.step, site.kind)) or []
        site.line = got[0] if got else 0
        scan.sites[site.key] = site


def scan_tree(texts: dict) -> Scan:
    scan = Scan()
    for rel in sorted(texts):
        try:
            scan_workflow(rel, texts[rel], scan)
        except Unreadable as exc:
            scan.problems.append(f"EMPTY {exc}")
    if scan.workflows == 0:
        scan.problems.append(
            f"EMPTY no workflow under {WORKFLOWS_DIR} was read; a gate that cannot see its "
            "subject must not pass"
        )
    return scan


# -- the declarations -------------------------------------------------------------


def _date(value):
    if not isinstance(value, str) or not DATE.match(value):
        return None
    try:
        return date.fromisoformat(value)
    except ValueError:
        return None


def _shape_ok(kind: str, value) -> bool:
    if kind == "str":
        return isinstance(value, str) and bool(value.strip())
    if kind == "str-or-null":
        return value is None or (isinstance(value, str) and bool(value.strip()))
    if kind == "prose":
        return isinstance(value, str) and len(value.strip()) >= MIN_PROSE
    if kind == "date":
        return _date(value) is not None
    if kind.startswith("int>="):
        floor = int(kind[len("int>="):])
        return isinstance(value, int) and not isinstance(value, bool) and value >= floor
    raise ValueError(kind)


def expiry_of(decl: dict):
    """The date the declaration lapses on: its last renewal's, else its own."""
    renewals = decl.get("renewals")
    if isinstance(renewals, list) and renewals and isinstance(renewals[-1], dict):
        return _date(renewals[-1].get("until"))
    return _date(decl.get("expires"))


def check_declaration(i: int, decl, today: date) -> list:
    if not isinstance(decl, dict):
        return [f"FIELD declaration #{i + 1}: not an object"]
    tag = f"declaration #{i + 1} ({decl.get('job')} / {decl.get('step')!r})"
    out = []
    for key, kind in REQUIRED.items():
        if key not in decl:
            out.append(f"FIELD {tag}: `{key}` is missing")
        elif not _shape_ok(kind, decl[key]):
            out.append(f"FIELD {tag}: `{key}` is not {kind} (read {decl[key]!r})")
    for key in decl:
        if key not in REQUIRED and key not in OPTIONAL:
            out.append(f"FIELD {tag}: `{key}` is not a field this file knows")
    if decl.get("kind") not in KINDS:
        out.append(f"FIELD {tag}: `kind` is one of {list(KINDS)}")
    if decl.get("kind") == KIND_SWALLOW and decl.get("step") is None:
        out.append(f"FIELD {tag}: a warning-swallow is a step, so `step` names it")
    if "note" in decl and not _shape_ok("str", decl["note"]):
        out.append(f"FIELD {tag}: `note` is empty")
    obs = decl.get("observe_only")
    if "observe_only" in decl and (
        not isinstance(obs, dict)
        or not obs
        or not all(isinstance(k, str) and _shape_ok("prose", v) for k, v in obs.items())
    ):
        out.append(f"FIELD {tag}: `observe_only` maps an instance name to why it is only observed")
    declared, expires = _date(decl.get("declared")), _date(decl.get("expires"))
    if declared and expires:
        if expires < declared:
            out.append(f"TERM {tag}: expires {expires}, before it was declared ({declared})")
        elif (expires - declared).days > MAX_TERM_DAYS:
            out.append(
                f"TERM {tag}: expires {(expires - declared).days} days after it was declared; "
                f"a term is at most {MAX_TERM_DAYS} days"
            )
    if "renewals" in decl:
        renewals = decl["renewals"]
        if not isinstance(renewals, list) or not renewals:
            out.append(f"FIELD {tag}: `renewals` is a non-empty list of {{on, until, why}}")
            renewals = []
        current = expires
        for n, ren in enumerate(renewals):
            rtag = f"{tag}, renewal #{n + 1}"
            if not isinstance(ren, dict) or set(ren) != set(RENEWAL_KEYS):
                out.append(f"FIELD {rtag}: a renewal is exactly {{on, until, why}}")
                current = None
                continue
            on, until = _date(ren.get("on")), _date(ren.get("until"))
            if on is None or until is None:
                out.append(f"FIELD {rtag}: `on` and `until` are ISO dates")
                current = None
                continue
            if not _shape_ok("prose", ren.get("why")):
                out.append(f"TERM {rtag}: a renewal says why the site is still soft")
            if current is not None and until <= current:
                out.append(f"TERM {rtag}: until {until} does not extend the expiry {current}")
            if declared is not None and on < declared:
                out.append(f"TERM {rtag}: made on {on}, before the site was declared")
            if (until - on).days > MAX_TERM_DAYS:
                out.append(
                    f"TERM {rtag}: reaches {(until - on).days} days past the day it was made; "
                    f"a term is at most {MAX_TERM_DAYS} days"
                )
            current = until
    lapse = expiry_of(decl)
    if lapse is not None and today > lapse:
        out.append(
            f"EXPIRED {tag}: lapsed on {lapse}. Make it a gate (remove the soft marker and "
            "this declaration), or renew it with a reason under `renewals`"
        )
    return out


def decl_key(decl: dict) -> tuple:
    return tuple(
        v if isinstance(v, (str, type(None))) else repr(v)
        for v in (decl.get("workflow"), decl.get("job"), decl.get("step"), decl.get("kind"))
    )


def check(texts: dict, doc, today: date):
    """(problems, scan, declarations) for the workflows' texts and the parsed declaration file."""
    scan = scan_tree(texts)
    problems = list(scan.problems)
    decls: list = []
    if not isinstance(doc, dict) or not isinstance(doc.get("sites"), list):
        problems.append(f"FIELD {DECLARATIONS}: an object with a `sites` list")
        return problems, scan, decls
    for key in doc:
        if key not in ("about", "sites"):
            problems.append(f"FIELD {DECLARATIONS}: top-level `{key}` is not a field this file knows")
    by_key: dict = {}
    for i, decl in enumerate(doc["sites"]):
        problems.extend(check_declaration(i, decl, today))
        if isinstance(decl, dict):
            decls.append(decl)
            by_key.setdefault(decl_key(decl), []).append(i)
    for key, idxs in by_key.items():
        if len(idxs) > 1:
            problems.append(f"DUPLICATE {key}: declared by entries {[i + 1 for i in idxs]}")
    loose = {k[:3]: k for k in by_key}
    for key, site in scan.sites.items():
        if key in by_key:
            continue
        if key[:3] in loose:
            problems.append(
                f"KIND {site.label()}: declared as {loose[key[:3]][3]}, but the site is {site.kind}"
            )
        else:
            problems.append(
                f"UNDECLARED {site.label()}: a soft site with no entry in {DECLARATIONS}; say why "
                "it is soft, when it becomes a gate and when the declaration expires"
            )
    site_loose = {k[:3] for k in scan.sites}
    for key in by_key:
        if key in scan.sites or key[:3] in site_loose:
            continue
        problems.append(
            f"ORPHAN {key}: declared, but no such soft site is in the workflows (promoted, "
            "renamed or removed); delete the declaration or correct it"
        )
    for decl in decls:
        site = scan.sites.get(decl_key(decl))
        obs = decl.get("observe_only")
        if site is None or not isinstance(obs, dict) or site.instances is None:
            continue
        for name in obs:
            if name not in site.instances:
                problems.append(
                    f"UNREADABLE {site.label()}: observe-only {name!r} is not one of the "
                    f"job's instances {site.instances}"
                )
    return problems, scan, decls


def read_tree():
    wf_dir = ROOT / WORKFLOWS_DIR
    texts = {}
    if wf_dir.is_dir():
        for p in sorted(list(wf_dir.glob("*.yml")) + list(wf_dir.glob("*.yaml"))):
            texts[f"{WORKFLOWS_DIR}/{p.name}"] = p.read_text(encoding="utf-8")
    path = ROOT / DECLARATIONS
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        doc = None
    except ValueError as exc:
        raise Unreadable(f"{DECLARATIONS} is not JSON: {exc}") from exc
    return texts, doc


def run_check(today: date) -> int:
    try:
        texts, doc = read_tree()
    except Unreadable as exc:
        print(f"soft-job gate FAIL: {exc}", file=sys.stderr)
        return EXIT_FAIL
    if doc is None:
        print(f"soft-job gate FAIL: {DECLARATIONS} is missing", file=sys.stderr)
        return EXIT_FAIL
    problems, scan, decls = check(texts, doc, today)
    if problems:
        print(f"soft-job gate FAIL: {len(problems)} problem(s)", file=sys.stderr)
        for p in problems:
            print(f"    {p}", file=sys.stderr)
        return EXIT_FAIL
    lapses = [(expiry_of(d), d) for d in decls]
    for lapse, decl in lapses:
        if lapse is not None and (lapse - today).days <= SOON_DAYS:
            print(
                f"  soft-job gate: {decl.get('job')} / {decl.get('step')!r} lapses on {lapse}, "
                f"{(lapse - today).days} day(s) from now"
            )
    nearest = min((lapse for lapse, _ in lapses if lapse is not None), default=None)
    print(
        f"  soft-job gate: {len(scan.sites)} soft site(s) in {scan.workflows} workflow(s), each "
        f"declared; nearest expiry {nearest or 'none'}"
    )
    return EXIT_OK


# -- the hosted reading -----------------------------------------------------------


def normalize_log(raw: bytes) -> list:
    text = raw.decode("utf-8", errors="replace")
    return [LOG_STAMP.sub("", line.rstrip("\r")) for line in text.split("\n")]


def step_section(lines: list, anchor: str):
    """The lines of the one step whose group opens with `Run <anchor>`, or None."""
    rx = anchor_regex(anchor)
    starts = [
        i
        for i, line in enumerate(lines)
        if line.startswith(GROUP_RUN) and rx.fullmatch(line[len(GROUP_RUN):].strip())
    ]
    if len(starts) != 1:
        return None
    end = starts[0] + 1
    while end < len(lines) and not lines[end].startswith(GROUP_RUN) and lines[end] not in SECTION_ENDS:
        end += 1
    return lines[starts[0]:end]


def _ran_a_step(job: dict) -> bool:
    for s in job.get("steps") or []:
        name = str(s.get("name") or "")
        if name in FRAME_STEPS or name.startswith("Post "):
            continue
        if s.get("conclusion") not in (None, "skipped"):
            return True
    return False


def read_site(site: Site, job, log) -> tuple:
    """(reading, detail) of one site in one job of one run; `log(job_id)` gives its lines."""
    if job is None:
        return NOT_RUN, "no such job in this run"
    if job.get("status") != "completed":
        return UNREAD, f"the job is {job.get('status')!r}"
    c = job.get("conclusion")
    if c == "skipped" or (c == "cancelled" and not hosted_cancelled_kind.job_started(job)):
        return NOT_RUN, f"job {c}"
    if site.step is None:
        if c in hosted_cancelled_kind.JOB_PASS:
            # A dispatch that did not select this row skips every step and still
            # concludes success; that row graded nothing.
            if job.get("steps") and not _ran_a_step(job):
                return NOT_RUN, "every step of the job was skipped"
            return GREEN, f"job {c}"
        if c in hosted_cancelled_kind.JOB_FAIL or c == "cancelled":
            return RED, f"job {c}"
        return UNREAD, f"job concluded {c!r}, which this reader does not know"
    steps = [s for s in job.get("steps") or [] if isinstance(s, dict) and s.get("name") == site.step]
    if len(steps) != 1:
        return UNREAD, f"the jobs API lists {len(steps)} step(s) named {site.step!r}"
    sc = steps[0].get("conclusion")
    if sc == "skipped":
        return NOT_RUN, "step skipped"
    if sc is None:
        return UNREAD, "the step has no conclusion"
    if sc in ("failure", "cancelled", "timed_out"):
        return RED, f"step {sc}"
    if site.anchor is None:
        return UNREAD, "the step has no log anchor"
    try:
        lines = log(job["id"])
    except Unreadable as exc:
        return UNREAD, str(exc)
    section = step_section(lines, site.anchor)
    if section is None:
        return UNREAD, f"no single log group `Run {site.anchor}`"
    marks = ("##[error]",) if site.kind == KIND_COE else ("##[error]", "##[warning]")
    hits = [line for line in section if line.startswith(marks)]
    if hits:
        return RED, hits[0][:160]
    return GREEN, f"step {sc}, and its log section carries no error"


def judge(readings: list, allowance: int, promote: int) -> tuple:
    """(state, detail, leading greens) of one instance; readings newest first, NOT_RUN left out."""
    g = 0
    while g < len(readings) and readings[g] == GREEN:
        g += 1
    i, r = g, 0
    while i < len(readings) and readings[i] == RED:
        r += 1
        i += 1
    unknown = i < len(readings) and readings[i] == UNREAD
    if g >= promote:
        return "OK", f"{g} consecutive green", g
    if r > allowance:
        more = "+" if unknown else ""
        if g == 0:
            return "FAIL", f"red on {r}{more} consecutive run(s); allows {allowance}", g
        return (
            "FAIL",
            f"recovering: {g} of {promote} green run(s) since {r}{more} consecutive red; "
            f"allows {allowance}",
            g,
        )
    if unknown:
        return "UNREAD", "an unread run hides whether the red streak is within the allowance", g
    if not readings:
        return "NOT-READ", "no run read this instance", g
    if r:
        return "OK", f"{r} consecutive red, within the allowance of {allowance}", g
    return "OK", f"{g} consecutive green", g


def promote_edit(site: Site) -> str:
    if site.kind == KIND_SWALLOW:
        return (
            f"drop the `|| echo \"::warning...\"` of the step's run line ({site.workflow}:"
            f"{site.line}) so the command's failure fails the step, and delete its declaration "
            f"in {DECLARATIONS}"
        )
    return (
        f"delete `continue-on-error: true` at {site.workflow}:{site.line}, say in the comment "
        f"above it that it is gated, and delete its declaration in {DECLARATIONS}"
    )


def hosted_report(entries, runs_by_wf, fetch_jobs, fetch_log) -> int:
    """Print the reading of every declared site and return the exit code.

    `entries` is [(Site, declaration)], `runs_by_wf` {workflow: [run, newest first]};
    `fetch_jobs(run_id)` gives the run's jobs and `fetch_log(job_id)` a job's log lines,
    and both raise Unreadable.
    """
    jobs_cache: dict = {}
    log_cache: dict = {}

    def jobs_of(run_id):
        if run_id not in jobs_cache:
            try:
                jobs_cache[run_id] = fetch_jobs(run_id)
            except Unreadable as exc:
                jobs_cache[run_id] = exc
        return jobs_cache[run_id]

    def log_of(job_id):
        if job_id not in log_cache:
            try:
                log_cache[job_id] = fetch_log(job_id)
            except Unreadable as exc:
                log_cache[job_id] = exc
        got = log_cache[job_id]
        if isinstance(got, Unreadable):
            raise got
        return got

    # A job-level site's job concludes success while a soft step of it fails, so
    # its greens say nothing about those steps; it is promoted after them.
    with_soft_steps = {(s.workflow, s.job) for s, _ in entries if s.step is not None}
    failed = unread = read_any = 0
    for site, decl in entries:
        runs = runs_by_wf.get(site.workflow) or []
        allowance = decl["allowed_consecutive_red"]
        promote = decl["promote_after_green"]
        observe = decl.get("observe_only") or {}
        print(f"soft-job {site.label()}: allows {allowance} red, a gate after {promote} green")
        states = []
        greens = []
        for inst in site.instances or []:
            readings = []
            for run in runs:
                jobs = jobs_of(run["id"])
                if isinstance(jobs, Unreadable):
                    readings.append(UNREAD)
                    continue
                match = [j for j in jobs if j.get("name") == inst]
                if len(match) > 1:
                    readings.append(UNREAD)
                    continue
                reading, _ = read_site(site, match[0] if match else None, log_of)
                if reading != NOT_RUN:
                    readings.append(reading)
            state, detail, g = judge(readings, allowance, promote)
            if inst in observe:
                state, detail = "OBSERVED", f"observe-only: {observe[inst]}"
            else:
                states.append(state)
                greens.append(g)
            if any(x in (GREEN, RED) for x in readings):
                read_any += 1
            print(f"    {inst}: {''.join(readings) or '(none)'}  {state}: {detail}")
        if "FAIL" in states:
            failed += 1
        elif "UNREAD" in states:
            unread += 1
        if observe:
            print(f"    promotion held: observe-only instance(s) {sorted(observe)}")
        elif site.step is None and (site.workflow, site.job) in with_soft_steps:
            print("    promotion held: the job still has soft steps; they are promoted first")
        elif greens and all(g >= promote for g in greens):
            print(
                f"    promote: {promote} consecutive green main run(s) on every instance; "
                f"{promote_edit(site)}"
            )
    fetch_failures = [rid for rid, got in jobs_cache.items() if isinstance(got, Unreadable)]
    for rid in fetch_failures:
        print(f"soft-job hosted: run {rid} NOT-MEASURED: {jobs_cache[rid]}", file=sys.stderr)
    if failed:
        print(f"soft-job hosted FAIL: {failed} soft site(s) broke their promise", file=sys.stderr)
        return EXIT_FAIL
    if unread or fetch_failures or not read_any:
        what = "nothing was read" if not read_any else f"{unread} site(s) could not be read"
        print(f"soft-job hosted NOT-MEASURED: {what}", file=sys.stderr)
        return EXIT_NOT_MEASURED
    print("soft-job hosted: every declared site within its promise")
    return EXIT_OK


def _gh(path: str) -> bytes:
    try:
        r = subprocess.run(["gh", "api", path], capture_output=True, timeout=GH_TIMEOUT_S)
    except FileNotFoundError as exc:
        raise Unreadable("gh is not on PATH") from exc
    except subprocess.TimeoutExpired as exc:
        raise Unreadable(f"gh api {path}: no answer in {GH_TIMEOUT_S}s") from exc
    if r.returncode != 0:
        err = r.stderr.decode("utf-8", errors="replace").strip()[:200]
        raise Unreadable(f"gh api {path}: {err or 'failed'}")
    return r.stdout


def _gh_json(path: str):
    try:
        return json.loads(_gh(path).decode("utf-8"))
    except ValueError as exc:
        raise Unreadable(f"gh api {path}: not JSON ({exc})") from exc


def origin_repo() -> tuple:
    try:
        r = subprocess.run(
            ["git", "-C", str(ROOT), "remote", "get-url", "origin"], capture_output=True
        )
    except FileNotFoundError as exc:
        raise Unreadable("git is not on PATH") from exc
    if r.returncode != 0:
        raise Unreadable("`git remote get-url origin` failed")
    url = r.stdout.decode("utf-8", errors="replace").strip()
    m = REMOTE.search(url)
    if not m:
        raise Unreadable(f"origin {url!r} names no GitHub repository")
    return m.group(1), m.group(2)


class Api:
    def __init__(self, owner: str, repo: str):
        self.base = f"repos/{owner}/{repo}/actions"

    def run(self, run_id: str) -> dict:
        doc = _gh_json(f"{self.base}/runs/{run_id}")
        if not isinstance(doc, dict) or "id" not in doc:
            raise Unreadable(f"run {run_id}: the answer carries no run")
        return doc

    def main_runs(self, workflow: str, n: int) -> list:
        name = workflow.rsplit("/", 1)[-1]
        doc = _gh_json(
            f"{self.base}/workflows/{name}/runs?branch=main&event=push&status=completed&per_page={n}"
        )
        if not isinstance(doc, dict) or not isinstance(doc.get("workflow_runs"), list):
            raise Unreadable(f"{workflow}: the answer carries no `workflow_runs` list")
        return doc["workflow_runs"]

    def jobs(self, run_id) -> list:
        out: list = []
        page = 1
        while True:
            doc = _gh_json(f"{self.base}/runs/{run_id}/jobs?per_page=100&page={page}")
            if not isinstance(doc, dict) or not isinstance(doc.get("jobs"), list):
                raise Unreadable(f"run {run_id}: the jobs answer has no `jobs` list")
            out.extend(doc["jobs"])
            total = doc.get("total_count")
            if not isinstance(total, int):
                raise Unreadable(f"run {run_id}: the jobs answer has no `total_count`")
            if len(out) >= total or not doc["jobs"]:
                break
            page += 1
        if len(out) < total:
            raise Unreadable(f"run {run_id}: read {len(out)} of {total} job(s)")
        return out

    def log(self, job_id) -> list:
        return normalize_log(_gh(f"{self.base}/jobs/{job_id}/logs"))


def run_hosted(argv: list) -> int:
    try:
        texts, doc = read_tree()
    except Unreadable as exc:
        print(f"soft-job hosted: {exc}", file=sys.stderr)
        return EXIT_FAIL
    problems, scan, decls = check(texts, doc, date.today())
    if doc is None or any(p.startswith(("FIELD", "EMPTY", "READERS")) for p in problems):
        print("soft-job hosted: the declarations or the workflows do not read; run --check", file=sys.stderr)
        return EXIT_FAIL
    entries = [(scan.sites[decl_key(d)], d) for d in decls if decl_key(d) in scan.sites]
    window = max(
        [5] + [d["allowed_consecutive_red"] + 1 + d["promote_after_green"] for _, d in entries]
    )
    try:
        api = Api(*origin_repo())
        runs_by_wf: dict = {}
        if argv[0] == "--hosted":
            for rid in argv[1:]:
                run = api.run(rid)
                wf = str(run.get("path") or "").split("@", 1)[0]
                if run.get("head_branch") != "main" or run.get("event") != "push":
                    print(
                        f"soft-job hosted: run {rid} is a {run.get('event')} run on "
                        f"{run.get('head_branch')}; read as given"
                    )
                runs_by_wf.setdefault(wf, []).append(run)
            for runs in runs_by_wf.values():
                runs.sort(key=lambda r: str(r.get("created_at") or ""), reverse=True)
        else:
            n = int(argv[1]) if len(argv) == 2 else window
            for wf in sorted({s.workflow for s, _ in entries}):
                runs_by_wf[wf] = api.main_runs(wf, n)
                print(f"soft-job hosted: {wf}: {len(runs_by_wf[wf])} completed main push run(s)")
    except Unreadable as exc:
        print(f"soft-job hosted NOT-MEASURED: {exc}", file=sys.stderr)
        return EXIT_NOT_MEASURED
    return hosted_report(entries, runs_by_wf, api.jobs, api.log)


# -- selftest ---------------------------------------------------------------------

FX = ".github/workflows/fx.yml"
FIXTURE_WF = """\
name: Fixture
on:
  push:
    branches: [main]
jobs:
  plain:
    name: plain (${{ matrix.os }})
    runs-on: ${{ matrix.os }}
    continue-on-error: true
    strategy:
      matrix:
        include:
          - os: ubuntu-22.04
          - os: windows-latest
    steps:
      - name: build
        run: cargo build
      - name: observed probe
        continue-on-error: true
        run: |
          # what the probe asks
          bash probe.sh
      - name: settled
        continue-on-error: false
        run: bash settled.sh
  packed:
    runs-on: ubuntu-22.04
    strategy:
      matrix:
        arch: [x64, x86]
    steps:
      - name: dry run
        run: cargo publish --dry-run || echo "::warning::dry run failed"
"""


def _fixture_decls() -> dict:
    def d(job, step, kind, **extra):
        base = {
            "workflow": FX,
            "job": job,
            "step": step,
            "kind": kind,
            "why_soft": "a fixture site, soft while it is brought up",
            "gate_when": "two consecutive green main runs on every row",
            "promote_after_green": 2,
            "allowed_consecutive_red": 1,
            "declared": "2026-11-21",
            "expires": "2026-12-21",
        }
        base.update(extra)
        return base

    return {
        "about": "fixture",
        "sites": [
            d("plain", None, KIND_COE),
            d(
                "plain",
                "observed probe",
                KIND_COE,
                observe_only={"plain (windows-latest)": "a fixture row observed only, for the arm"},
            ),
            d("packed", "dry run", KIND_SWALLOW),
        ],
    }


def _selftest_static(say) -> None:
    today = date(2026, 11, 21)

    def run(doc, wf=FIXTURE_WF, when=today, texts=None):
        return check({FX: wf} if texts is None else texts, doc, when)[0]

    def has(problems, word):
        return any(p.startswith(word) for p in problems)

    got = run(_fixture_decls())
    say("control: a declared tree is clean", not got, got)
    scan = scan_tree({FX: FIXTURE_WF})
    site = scan.sites.get((FX, "plain", None, KIND_COE))
    say("a job-level site carries its line", site is not None and site.line == 9, site)
    say(
        "a matrix of include rows renders the job's names",
        site is not None and site.instances == ["plain (ubuntu-22.04)", "plain (windows-latest)"],
        site,
    )
    packed = scan.sites.get((FX, "packed", "dry run", KIND_SWALLOW))
    say(
        "an axis matrix and no name render as key (value)",
        packed is not None and packed.instances == ["packed (x64)", "packed (x86)"],
        packed,
    )
    probe = scan.sites.get((FX, "plain", "observed probe", KIND_COE))
    say(
        "a step's anchor is its script's first line",
        probe is not None and probe.anchor == "# what the probe asks",
        probe,
    )
    say("continue-on-error: false is no site", len(scan.sites) == 3, list(scan.sites))

    doc = _fixture_decls()
    doc["sites"].pop(2)
    say("UNDECLARED: a soft site with no entry", has(run(doc), "UNDECLARED"), run(doc))

    doc = _fixture_decls()
    doc["sites"].append(dict(doc["sites"][0], job="settled-job"))
    say("ORPHAN: an entry with no site", has(run(doc), "ORPHAN"), run(doc))

    doc = _fixture_decls()
    doc["sites"].append(dict(doc["sites"][0]))
    say("DUPLICATE: two entries of one site", has(run(doc), "DUPLICATE"), run(doc))

    doc = _fixture_decls()
    del doc["sites"][0]["gate_when"]
    say("FIELD: a missing field", has(run(doc), "FIELD"), run(doc))
    doc = _fixture_decls()
    doc["sites"][0]["allowed_consecutive_red"] = True
    say("FIELD: a bool is not a count", has(run(doc), "FIELD"), run(doc))
    doc = _fixture_decls()
    doc["sites"][0]["expire"] = "2026-12-01"
    say("FIELD: a field this file does not know", has(run(doc), "FIELD"), run(doc))
    doc = _fixture_decls()
    doc["sites"][0]["why_soft"] = "soft"
    say("FIELD: prose too short to be a reason", has(run(doc), "FIELD"), run(doc))

    doc = _fixture_decls()
    doc["sites"][2]["kind"] = KIND_COE
    say("KIND: the swallow declared as continue-on-error", has(run(doc), "KIND"), run(doc))

    after = date(2026, 12, 22)
    got = run(_fixture_decls(), when=after)
    say("EXPIRED: past the expiry", has(got, "EXPIRED"), got)
    doc = _fixture_decls()
    for decl in doc["sites"]:
        decl["renewals"] = [
            {"on": "2026-12-20", "until": "2027-01-20", "why": "the fix is under review, two runs pending"}
        ]
    got = run(doc, when=after)
    say("a renewal with a reason extends the term", not got, got)
    doc["sites"][0]["renewals"][0]["why"] = ""
    got = run(doc, when=after)
    say("TERM: a renewal with no reason", has(got, "TERM"), got)
    doc = _fixture_decls()
    doc["sites"][0]["renewals"] = [
        {"on": "2026-12-20", "until": "2026-12-01", "why": "a renewal that shortens the term"}
    ]
    say("TERM: a renewal that does not extend", has(run(doc), "TERM"), run(doc))
    doc = _fixture_decls()
    doc["sites"][0]["expires"] = "2027-03-01"
    say("TERM: a term past the maximum", has(run(doc), "TERM"), run(doc))

    nameless = FIXTURE_WF.replace(
        "      - name: observed probe\n        continue-on-error: true\n",
        "      - continue-on-error: true\n",
    )
    got = run(_fixture_decls(), nameless)
    say("NAMELESS: a soft step with no name", has(got, "NAMELESS") and not has(got, "READERS"), got)

    shared = FIXTURE_WF.replace(
        "      - name: settled\n        continue-on-error: false\n        run: bash settled.sh\n",
        "      - name: settled\n        run: |\n          # what the probe asks\n          true\n",
    )
    got = run(_fixture_decls(), shared)
    say("UNREADABLE: two steps of a job share a log anchor", has(got, "UNREADABLE"), got)
    doc = _fixture_decls()
    doc["sites"][1]["observe_only"] = {"plain (macos-latest)": "a row the job does not have, for the arm"}
    say("UNREADABLE: an observe-only key that is no instance", has(run(doc), "UNREADABLE"), run(doc))

    hidden = FIXTURE_WF.replace(
        "          bash probe.sh\n",
        "          bash probe.sh\n          cat <<EOF\n          continue-on-error: true\n          EOF\n",
    )
    got = run(_fixture_decls(), hidden)
    say("READERS: a soft line the parse does not see", has(got, "READERS"), got)

    expr = FIXTURE_WF.replace(
        "        continue-on-error: false\n",
        "        continue-on-error: ${{ matrix.os == 'x' }}\n",
    )
    got = run(_fixture_decls(), expr)
    say("an expression value is a site", has(got, "UNDECLARED") and not has(got, "READERS"), got)

    got = run(_fixture_decls(), texts={})
    say("EMPTY: no workflow read", has(got, "EMPTY"), got)


def _api_job(jid, name, conclusion, steps=(), started=True):
    return {
        "id": jid,
        "name": name,
        "status": "completed",
        "conclusion": conclusion,
        "runner_name": "GitHub Actions 1" if started else None,
        "steps": [{"name": n, "status": "completed", "conclusion": c} for n, c in steps],
        "started_at": "2026-11-21T00:00:00Z",
        "completed_at": "2026-11-21T00:10:00Z",
    }


def _log(*body: str) -> list:
    raw = "".join(f"2026-11-21T05:20:{n:02d}.0000000Z {line}\r\n" for n, line in enumerate(body))
    return normalize_log(("\ufeff" + raw).encode("utf-8"))


def _selftest_hosted(say) -> None:
    import io
    from contextlib import redirect_stderr, redirect_stdout

    scan = scan_tree({FX: FIXTURE_WF})
    job_site = scan.sites[(FX, "plain", None, KIND_COE)]
    step_site = scan.sites[(FX, "plain", "observed probe", KIND_COE)]
    swallow = scan.sites[(FX, "packed", "dry run", KIND_SWALLOW)]

    def no_log(_):
        raise Unreadable("no log in this arm")

    def reading(site, job, log=no_log):
        return read_site(site, job, log)[0]

    say("job-level: failure is red", reading(job_site, _api_job(1, "x", "failure")) == RED)
    say("job-level: success is green", reading(job_site, _api_job(1, "x", "success")) == GREEN)
    say("job-level: skipped did not run", reading(job_site, _api_job(1, "x", "skipped")) == NOT_RUN)
    say(
        "job-level: cancelled before it started did not run",
        reading(job_site, _api_job(1, "x", "cancelled", started=False)) == NOT_RUN,
    )
    say(
        "job-level: a row whose every step was skipped did not run",
        reading(job_site, _api_job(1, "x", "success", [("Set up job", "success"), ("build", "skipped")]))
        == NOT_RUN,
    )
    say("job-level: an unknown conclusion is unread", reading(job_site, _api_job(1, "x", "stale")) == UNREAD)

    masked = _log(
        "##[group]Run cargo build",
        "ok",
        "##[endgroup]",
        "##[group]Run # what the probe asks",
        "probe: FAIL",
        "##[error]Process completed with exit code 1.",
        "Post job cleanup.",
        "##[warning]Node.js 20 is deprecated.",
    )
    job = _api_job(2, "plain (ubuntu-22.04)", "success", [("build", "success"), ("observed probe", "success")])
    got = read_site(step_site, job, lambda _: masked)
    say("step-level: a step the API calls success is red by its log", got[0] == RED, got)
    clean = _log(
        "##[group]Run # what the probe asks", "probe: PASS", "Post job cleanup.", "##[error]a post step"
    )
    got = read_site(step_site, job, lambda _: clean)
    say("step-level: the section ends before the post steps", got[0] == GREEN, got)
    got = read_site(step_site, job, lambda _: _log("##[group]Run something else"))
    say("step-level: a missing anchor is unread, never green", got[0] == UNREAD, got)
    say("step-level: a log that cannot be fetched is unread", reading(step_site, job) == UNREAD)
    skipped = _api_job(2, "plain (ubuntu-22.04)", "success", [("observed probe", "skipped")])
    say("step-level: a skipped step did not run", reading(step_site, skipped) == NOT_RUN)
    pjob = _api_job(3, "packed (x64)", "success", [("dry run", "success")])
    warned = _log(
        '##[group]Run cargo publish --dry-run || echo "::warning::dry run failed"',
        "##[warning]dry run failed",
    )
    got = read_site(swallow, pjob, lambda _: warned)
    say("swallow: a warning in its section is red", got[0] == RED, got)

    for readings, allowance, want in (
        ([RED, GREEN], 1, "OK"),
        ([RED, RED, GREEN], 1, "FAIL"),
        ([GREEN, RED, RED], 0, "FAIL"),
        ([GREEN, GREEN, RED, RED], 0, "OK"),
        ([RED, UNREAD, RED], 2, "UNREAD"),
        ([RED, RED, UNREAD], 1, "FAIL"),
        ([], 1, "NOT-READ"),
    ):
        got = judge(readings, allowance, 2)
        say(f"judge {''.join(readings) or '(none)'} allowing {allowance}: {want}", got[0] == want, got)

    entries = [
        (job_site, {"allowed_consecutive_red": 0, "promote_after_green": 2}),
        (
            step_site,
            {
                "allowed_consecutive_red": 0,
                "promote_after_green": 2,
                "observe_only": {"plain (windows-latest)": "observed only in this arm"},
            },
        ),
    ]
    runs = {FX: [{"id": 11}, {"id": 10}]}

    def jobs(prefix, windows):
        return [
            _api_job(prefix, "plain (ubuntu-22.04)", "success", [("observed probe", "success")]),
            _api_job(prefix + 1, "plain (windows-latest)", windows, [("observed probe", "success")]),
        ]

    logs = {
        jid: _log("##[group]Run # what the probe asks", "PASS" if jid % 2 == 0 else "##[error]exit 1")
        for jid in (100, 101, 200, 201)
    }

    def report(jobs_by_run, ents=entries):
        out = io.StringIO()

        def fetch_jobs(rid):
            got = jobs_by_run[rid]
            if isinstance(got, Unreadable):
                raise got
            return got

        def fetch_log(jid):
            if jid not in logs:
                raise Unreadable(f"job {jid}: no log")
            return logs[jid]

        with redirect_stdout(out), redirect_stderr(out):
            rc = hosted_report(ents, runs, fetch_jobs, fetch_log)
        return rc, out.getvalue()

    green = {11: jobs(100, "success"), 10: jobs(100, "success")}
    rc, text = report(green, entries[:1])
    say("hosted: two green runs promote a site", rc == EXIT_OK and "promote:" in text, text)
    rc, text = report(green)
    say(
        "hosted: an observe-only row is shown, never fails, and holds the promotion",
        rc == EXIT_OK and "OBSERVED" in text and "observe-only instance" in text,
        text,
    )
    say(
        "hosted: a job with a soft step holds the job's own promotion",
        "still has soft steps" in text and "promote:" not in text,
        text,
    )
    rc, text = report({11: jobs(200, "failure"), 10: jobs(100, "success")})
    say("hosted: a red past the allowance fails", rc == EXIT_FAIL and "FAIL" in text, text)
    down = Unreadable("network down")
    rc, text = report({11: down, 10: down})
    say("hosted: an unreadable run is NOT-MEASURED, never a pass", rc == EXIT_NOT_MEASURED, text)
    rc, text = report({11: [], 10: []})
    say("hosted: a reading of nothing is NOT-MEASURED", rc == EXIT_NOT_MEASURED, text)


def selftest() -> int:
    results: list = []

    def say(name: str, ok: bool, detail=None) -> None:
        results.append(bool(ok))
        print(f"  {'ok ' if ok else 'BAD'}  {name}")
        if not ok and detail is not None:
            print(f"        read: {detail}")

    try:
        _selftest_static(say)
        _selftest_hosted(say)
    except (Unreadable, KeyError) as exc:
        print(f"soft-job gate selftest FAIL: an arm could not run ({exc!r})")
        return EXIT_FAIL
    bad = results.count(False)
    print(f"soft-job gate selftest: {len(results) - bad}/{len(results)} arm(s) behaved as claimed")
    return EXIT_FAIL if bad or not results else EXIT_OK


def main(argv: list) -> int:
    if argv == ["--selftest"]:
        return selftest()
    if argv[:1] == ["--check"]:
        if argv == ["--check"]:
            return run_check(date.today())
        if len(argv) == 3 and argv[1] == "--today" and _date(argv[2]):
            return run_check(_date(argv[2]))
    elif argv[:1] == ["--hosted"] and len(argv) >= 2 and all(a.isdigit() for a in argv[1:]):
        return run_hosted(argv)
    elif argv[:1] == ["--hosted-last"] and (
        len(argv) == 1 or (len(argv) == 2 and argv[1].isdigit() and int(argv[1]) > 0)
    ):
        return run_hosted(argv)
    print(
        "usage: soft_job_gate.py --check [--today YYYY-MM-DD] | --selftest "
        "| --hosted <run-id>... | --hosted-last [N]",
        file=sys.stderr,
    )
    return EXIT_USAGE


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
