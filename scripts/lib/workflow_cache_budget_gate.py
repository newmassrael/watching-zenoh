#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
"""R3158 (no register item) -- every hosted cache key class is DECLARED, owned and budgeted.

The debt it answers for, open-debt item 899, lives in the operator's agent-memory
register, which has no store `debt-` id for `gate_provenance_lint.py` to resolve; the
honest pair is this sentence and `no register item` in the citation.

## The defect, measured

GitHub caps a repository's Actions cache at 10 GB and, past it, evicts the least
recently used entries. It has no idea which entry is dear. On 2026-10-09 the
repository held 10.78 GB in 46 entries, and the RocksDB native engine (5 MB, about
290 s to rebuild) was among those that fell out: its step took 3 s, then 7 s, then
293 s across three runs, and the 293 s one tripped the job-budget margin of the
`ci` job. Six more rust-cache entries were already gone, so the real demand was
nearer 14 GB than 10.

The demand was not an accident of one commit. Every one of 21 jobs owned a private
rust-cache entry (400-830 MB each), and rust-cache puts the hash of every
`Cargo.toml` and `Cargo.lock` of the workspace into the key, so each manifest change
(27 commits in seven days) wrote a fresh generation of all of them. `actions/cache`
cannot be told that an entry is precious; the only lever is to stay under the cap so
that eviction never starts.

## What this gate holds

`.github/cache-classes.json` is the register. Over every cache use in
`.github/workflows/*.yml` and in the local composite actions those jobs call:

  1. every use falls in exactly one declared class (by the literal key prefix), and
     every declared class has at least one use: a cache nobody declared, or a class
     whose last user left, is a FAIL
  2. the jobs that SAVE a class are exactly its declared `owners`, and for rust-cache
     the jobs that only READ it are exactly its declared `readers`: a job cannot
     become a second saver of a shared key, or drop out of one, unnoticed
  3. a key that names a commit or a run (`github.sha`, `github.run_id`,
     `github.run_number`, `github.run_attempt` and the event spellings of the head
     sha) is refused unless its class declares `allow_run_scoped` (today only the apt
     archives, whose key must move with the package list). A commit-scoped key writes
     a new entry per push and is the shape that fills the cap
  4. every save is limited to the default branch: a branch run cannot write a cache
     other refs can read, so a save there is cost with no reader. A rust-cache use
     must state `save-if`, either that condition or `false` (a reader)
  5. a rust-cache reader names the key of a saver in its class: restoring from a key
     nobody saves is the cache that never warms
  6. the class budgets sum to at most `target_mb`, which is at most 85 percent of
     `cap_mb`, and no measured size exceeds its budget. The headroom is what keeps
     GitHub's eviction from ever running
  7. `.github/workflows/cache-prune.yml` exists and holds only what it needs: a
     schedule, a manual dispatch and a `workflow_run` on the default branch (never
     `push` or `pull_request`), and a single job whose token is `actions: write` +
     `contents: read` and nothing else

Rules 1-2 of `workflow_cache_save_gate.py` (no combined `actions/cache`, every restore
has its save) are unchanged and still run beside this one.

## The population is derived, and zero is a failure

The uses are read by parsing the workflows; a parse that yields no cache use FAILS,
because this repository has dozens and zero means the reader stopped reading.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]
REGISTRY = ".github/cache-classes.json"
PRUNE_WORKFLOW = ".github/workflows/cache-prune.yml"

MAIN_ONLY = "github.ref == 'refs/heads/main'"
# Every spelling that makes a key move with a commit or a run.
RUN_SCOPED = (
    "github.sha",
    "github.run_id",
    "github.run_number",
    "github.run_attempt",
    "github.event.after",
    "github.event.head_commit",
    "github.event.pull_request.head.sha",
    "github.head_ref",
    "GITHUB_SHA",
    "GITHUB_RUN_ID",
)
EXPR = re.compile(r"\$\{\{(.*?)\}\}")
CLASS_FIELDS = (
    "id",
    "kind",
    "prefixes",
    "owners",
    "budget_mb",
    "churn",
    "generation_suffix",
    "keep",
    "protect",
    "evict_priority",
    "allow_run_scoped",
)
KINDS = ("actions-cache", "rust-cache")
CHURN = ("pinned", "manifest", "run")
TARGET_FRACTION = 0.85


def literal_prefix(template: str) -> str:
    cut = template.find("${{")
    return template if cut < 0 else template[:cut]


def _is_false(value: object) -> bool:
    return str(value).strip().lower() == "false"


def _job_steps(doc: dict, docs: dict[str, dict]) -> dict[str, list[dict]]:
    """Job name -> its steps, with local composite actions expanded in place."""

    def expand(steps: list[dict]) -> list[dict]:
        out: list[dict] = []
        for step in steps:
            uses = str(step.get("uses") or "")
            if uses.startswith("./.github/actions/"):
                comp = docs.get(uses[2:].rstrip("/") + "/action.yml", {})
                out.extend(expand(list((comp.get("runs") or {}).get("steps") or [])))
            else:
                out.append(step)
        return out

    if not isinstance(doc.get("jobs"), dict):
        return {}
    return {
        name: expand(list(job.get("steps") or []))
        for name, job in doc["jobs"].items()
        if isinstance(job, dict)
    }


def derive_uses(docs: dict[str, dict]) -> list[dict]:
    """One row per cache use: path, job, role (save|read), key template, condition."""
    rows: list[dict] = []
    for path, doc in sorted(docs.items()):
        if not path.startswith(".github/workflows/"):
            continue
        base = path.rsplit("/", 1)[-1]
        for job, steps in _job_steps(doc, docs).items():
            keys_by_id: dict[str, str] = {}
            for step in steps:
                uses = str(step.get("uses") or "")
                w = step.get("with") or {}
                if uses.startswith("actions/cache/restore@") and step.get("id"):
                    keys_by_id[step["id"]] = str(w.get("key") or "")

            def resolve(template: str) -> str:
                def sub(m: re.Match) -> str:
                    mm = re.fullmatch(r"\s*steps\.([\w-]+)\.outputs\.cache-primary-key\s*", m.group(1))
                    return keys_by_id.get(mm.group(1), m.group(0)) if mm else m.group(0)

                return EXPR.sub(sub, template)

            for step in steps:
                uses = str(step.get("uses") or "")
                w = step.get("with") or {}
                name = str(step.get("name") or step.get("id") or uses)
                row = dict(file=base, job=job, step=name, owner=f"{base}:{job}")
                if uses.startswith("Swatinem/rust-cache@"):
                    shared, key = w.get("shared-key"), w.get("key")
                    if shared:
                        template = f"v0-rust-{shared}-"
                    elif key:
                        template = f"v0-rust-{key}-{job}-"
                    else:
                        template = f"v0-rust-{job}-"
                    save_if = w.get("save-if")
                    cond = "" if save_if is None else str(save_if)
                    row.update(
                        kind="rust-cache",
                        template=template,
                        cond=cond,
                        role="read" if _is_false(save_if) else "save",
                        explicit=save_if is not None,
                    )
                elif uses.startswith("actions/cache/save@"):
                    row.update(
                        kind="actions-cache",
                        template=resolve(str(w.get("key") or "")),
                        cond=str(step.get("if") or ""),
                        role="save",
                        explicit=True,
                    )
                elif uses.startswith("actions/cache/restore@"):
                    row.update(
                        kind="actions-cache",
                        template=str(w.get("key") or ""),
                        cond="",
                        role="read",
                        explicit=True,
                    )
                else:
                    continue
                rows.append(row)
    return rows


def classify(template: str, classes: list[dict]) -> tuple[dict | None, str]:
    """The class whose longest prefix starts the key; (None, why) if none or ambiguous."""
    lit = literal_prefix(template)
    best: list[tuple[int, dict]] = []
    for cls in classes:
        for p in cls.get("prefixes", []):
            if lit.startswith(p):
                best.append((len(p), cls))
    if not best:
        return None, "matches no declared class"
    top = max(n for n, _ in best)
    winners = {c["id"] for n, c in best if n == top}
    if len(winners) > 1:
        return None, f"matches several classes at the same depth: {sorted(winners)}"
    return next(c for n, c in best if n == top and c["id"] in winners), ""


def check_registry(reg: dict) -> list[str]:
    fails: list[str] = []
    classes = reg.get("classes")
    if not isinstance(classes, list) or not classes:
        return [f"{REGISTRY}: no classes"]
    for key in ("cap_mb", "target_mb"):
        if not isinstance(reg.get(key), (int, float)):
            fails.append(f"{REGISTRY}: `{key}` must be a number")
    if fails:
        return fails
    ids: set[str] = set()
    total = 0.0
    for cls in classes:
        cid = cls.get("id", "<no id>")
        for field in CLASS_FIELDS:
            if field not in cls:
                fails.append(f"{REGISTRY}: class `{cid}` lacks `{field}`")
        if cid in ids:
            fails.append(f"{REGISTRY}: class id `{cid}` is declared twice")
        ids.add(cid)
        if cls.get("kind") not in KINDS:
            fails.append(f"{REGISTRY}: class `{cid}` kind must be one of {KINDS}")
        if cls.get("churn") not in CHURN:
            fails.append(f"{REGISTRY}: class `{cid}` churn must be one of {CHURN}")
        if not cls.get("prefixes"):
            fails.append(f"{REGISTRY}: class `{cid}` declares no key prefix")
        if not isinstance(cls.get("budget_mb"), (int, float)) or cls["budget_mb"] <= 0:
            fails.append(f"{REGISTRY}: class `{cid}` budget_mb must be a positive number")
            continue
        total += cls["budget_mb"]
        meas = cls.get("measured_mb")
        if meas is not None and meas > cls["budget_mb"]:
            fails.append(
                f"{REGISTRY}: class `{cid}` measured {meas} MB exceeds its {cls['budget_mb']} MB budget"
            )
        if not isinstance(cls.get("keep"), int) or cls["keep"] < 1:
            fails.append(f"{REGISTRY}: class `{cid}` keep must be an integer >= 1")
        gs = cls.get("generation_suffix")
        if gs is not None:
            try:
                re.compile(gs)
            except re.error as e:
                fails.append(f"{REGISTRY}: class `{cid}` generation_suffix is not a regex: {e}")
        if cls.get("protect") and cls.get("evict_priority") != 100:
            fails.append(f"{REGISTRY}: protected class `{cid}` must carry evict_priority 100")
        if not cls.get("protect") and cls.get("evict_priority") == 100:
            fails.append(f"{REGISTRY}: class `{cid}` has evict_priority 100 but is not protected")
        for pat in cls.get("stale_patterns", []):
            try:
                re.compile(pat)
            except re.error as e:
                fails.append(f"{REGISTRY}: class `{cid}` stale_patterns entry {pat!r} is not a regex: {e}")
        if cls.get("churn") == "run" and not cls.get("allow_run_scoped"):
            fails.append(f"{REGISTRY}: class `{cid}` churns per run but does not allow a run-scoped key")
        if cls.get("kind") == "actions-cache" and cls.get("readers"):
            fails.append(f"{REGISTRY}: class `{cid}` is actions-cache; `readers` applies to rust-cache only")
    for a in classes:
        for b in classes:
            if a is b:
                continue
            for pa in a.get("prefixes", []):
                for pb in b.get("prefixes", []):
                    if pa.startswith(pb):
                        fails.append(
                            f"{REGISTRY}: prefix `{pa}` of `{a.get('id')}` sits inside `{pb}` of `{b.get('id')}`"
                        )
    if reg["target_mb"] > reg["cap_mb"] * TARGET_FRACTION:
        fails.append(
            f"{REGISTRY}: target_mb {reg['target_mb']} is over {int(TARGET_FRACTION * 100)} percent "
            f"of cap_mb {reg['cap_mb']}; with no headroom GitHub's LRU eviction runs and it cannot "
            "tell the RocksDB engine from a target directory"
        )
    if total > reg["target_mb"]:
        fails.append(
            f"{REGISTRY}: the class budgets sum to {total:g} MB, over target_mb {reg['target_mb']}"
        )
    return fails


def check_uses(rows: list[dict], reg: dict) -> list[str]:
    fails: list[str] = []
    classes = reg["classes"]
    savers: dict[str, set[str]] = {c["id"]: set() for c in classes}
    readers: dict[str, set[str]] = {c["id"]: set() for c in classes}
    saver_prefix: dict[str, set[str]] = {c["id"]: set() for c in classes}
    used: set[str] = set()
    for r in rows:
        where = f"{r['file']} [{r['job']}] `{r['step']}`"
        cls, why = classify(r["template"], classes)
        if cls is None:
            fails.append(
                f"{where}: cache key `{r['template']}` {why}. Declare its class in {REGISTRY} "
                "with an owner, a size budget and its churn."
            )
            continue
        cid = cls["id"]
        used.add(cid)
        if cls["kind"] != r["kind"]:
            fails.append(f"{where}: a {r['kind']} use in class `{cid}`, which is {cls['kind']}")
        text = r["template"]
        hit = [t for t in RUN_SCOPED if t in text]
        if hit and not cls.get("allow_run_scoped"):
            fails.append(
                f"{where}: the key names {hit}, which makes it move with a commit or a run; "
                f"class `{cid}` does not allow that. A key per push writes a new entry per push."
            )
        if r["role"] == "save":
            savers[cid].add(r["owner"])
            saver_prefix[cid].add(literal_prefix(r["template"]))
            if r["kind"] == "rust-cache" and not r["explicit"]:
                fails.append(
                    f"{where}: rust-cache without `save-if`; state `{MAIN_ONLY}` for a saver or "
                    "`false` for a reader"
                )
            elif MAIN_ONLY not in r["cond"]:
                fails.append(
                    f"{where}: a save that is not limited to the default branch (`{MAIN_ONLY}`); "
                    "a branch run writes an entry no other ref can read"
                )
        elif r["kind"] == "rust-cache":
            readers[cid].add(r["owner"])
    for cls in classes:
        cid = cls["id"]
        if cid not in used:
            fails.append(f"{REGISTRY}: class `{cid}` has no cache use in any workflow; remove it")
            continue
        want = set(cls["owners"])
        if savers[cid] != want:
            fails.append(
                f"class `{cid}` owners: declared {sorted(want)}, workflows save with "
                f"{sorted(savers[cid])} (extra {sorted(savers[cid] - want)}, "
                f"missing {sorted(want - savers[cid])})"
            )
        if cls["kind"] == "rust-cache":
            want_r = set(cls.get("readers", []))
            if readers[cid] != want_r:
                fails.append(
                    f"class `{cid}` readers: declared {sorted(want_r)}, workflows read with "
                    f"{sorted(readers[cid])} (extra {sorted(readers[cid] - want_r)}, "
                    f"missing {sorted(want_r - readers[cid])})"
                )
    for r in rows:
        if r["kind"] == "rust-cache" and r["role"] == "read":
            cls, _ = classify(r["template"], classes)
            if cls is not None and literal_prefix(r["template"]) not in saver_prefix[cls["id"]]:
                fails.append(
                    f"{r['file']} [{r['job']}] `{r['step']}`: reads `{r['template']}`, which no saver "
                    f"of class `{cls['id']}` writes (savers write {sorted(saver_prefix[cls['id']])}); "
                    "a restore from a key nobody saves never warms"
                )
    return fails


def check_prune(doc: dict | None) -> list[str]:
    if doc is None:
        return [
            f"{PRUNE_WORKFLOW} is missing: with the budgets in {REGISTRY} nothing removes a "
            "superseded generation, an orphan key or an entry on a dead ref"
        ]
    fails: list[str] = []
    on = doc.get(True, doc.get("on")) or {}
    triggers = set(on) if isinstance(on, dict) else {on} if isinstance(on, str) else set(on or [])
    allowed = {"schedule", "workflow_dispatch", "workflow_run"}
    if triggers - allowed:
        fails.append(
            f"{PRUNE_WORKFLOW}: triggers {sorted(triggers - allowed)}; a token that can delete "
            "caches runs only from schedule, workflow_dispatch and workflow_run"
        )
    if not triggers & allowed:
        fails.append(f"{PRUNE_WORKFLOW}: no trigger, so it never runs")
    wr = on.get("workflow_run") if isinstance(on, dict) else None
    if isinstance(wr, dict) and wr.get("branches") != ["main"]:
        fails.append(f"{PRUNE_WORKFLOW}: workflow_run must be limited to `branches: [main]`")
    top = doc.get("permissions")
    if top not in ({}, {"contents": "read"}):
        fails.append(
            f"{PRUNE_WORKFLOW}: workflow-level permissions must be `{{}}` or contents: read, "
            f"found {top!r}; the write scope belongs to the one job that needs it"
        )
    jobs = doc.get("jobs") or {}
    if len(jobs) != 1:
        fails.append(f"{PRUNE_WORKFLOW}: expected exactly one job, found {sorted(jobs)}")
    for name, job in jobs.items():
        perms = job.get("permissions")
        if perms != {"actions": "write", "contents": "read"}:
            fails.append(
                f"{PRUNE_WORKFLOW} [{name}]: job permissions must be exactly "
                f"`actions: write` + `contents: read`, found {perms!r}"
            )
        if not job.get("timeout-minutes"):
            fails.append(f"{PRUNE_WORKFLOW} [{name}]: no timeout-minutes")
        runs = "\n".join(str(s.get("run") or "") for s in job.get("steps") or [])
        if "cache_prune.py" not in runs:
            fails.append(f"{PRUNE_WORKFLOW} [{name}]: no step runs scripts/lib/cache_prune.py")
    return fails


def check(docs: dict[str, dict], reg: dict, prune: dict | None) -> tuple[list[str], int]:
    fails = check_registry(reg)
    rows = derive_uses(docs)
    if not fails:
        fails.extend(check_uses(rows, reg))
    fails.extend(check_prune(prune))
    return fails, len(rows)


def load_tree() -> tuple[dict[str, dict], dict, dict | None]:
    files = sorted((REPO_ROOT / ".github" / "workflows").glob("*.yml"))
    files += sorted((REPO_ROOT / ".github" / "actions").glob("**/action.yml"))
    docs = {
        str(f.relative_to(REPO_ROOT)): yaml.safe_load(f.read_text(encoding="utf-8")) or {}
        for f in files
    }
    reg = json.loads((REPO_ROOT / REGISTRY).read_text(encoding="utf-8"))
    return docs, reg, docs.get(PRUNE_WORKFLOW)


def main() -> int:
    docs, reg, prune = load_tree()
    fails, seen = check(docs, reg, prune)
    classes = reg.get("classes", [])
    total = sum(c.get("budget_mb", 0) for c in classes)
    print(
        f"workflow-cache-budget: {seen} cache use(s), {len(classes)} class(es), budgets "
        f"{total:g} MB of target {reg.get('target_mb')} MB (cap {reg.get('cap_mb')} MB)"
    )
    if seen == 0:
        print(
            "workflow-cache-budget FAIL: parsed ZERO cache uses. This repository has dozens, so "
            "the reader stopped reading; a green here would grade nothing.",
            file=sys.stderr,
        )
        return 1
    if fails:
        print("workflow-cache-budget FAIL:", file=sys.stderr)
        for f in fails:
            print(f"  - {f}", file=sys.stderr)
        return 1
    print(
        "workflow-cache-budget: OK -- every key class is declared and owned, no commit-scoped key "
        "outside its allow-list, every save is main-only, budgets fit the target, pruner is scoped"
    )
    return 0


def _fixture() -> tuple[dict[str, dict], dict, dict]:
    def reg_class(cid, kind, prefixes, owners, **kw):
        c = dict(
            id=cid,
            kind=kind,
            prefixes=prefixes,
            owners=owners,
            budget_mb=100,
            churn="pinned",
            generation_suffix=None,
            keep=1,
            protect=False,
            evict_priority=10,
            allow_run_scoped=False,
        )
        c.update(kw)
        return c

    reg = dict(
        cap_mb=1000,
        target_mb=800,
        classes=[
            reg_class("engine", "actions-cache", ["eng-"], ["a.yml:j"], protect=True, evict_priority=100),
            reg_class("apt", "actions-cache", ["apt-"], ["a.yml:j"], churn="run", allow_run_scoped=True),
            reg_class("rust-main", "rust-cache", ["v0-rust-main-"], ["a.yml:j"], readers=["a.yml:r"]),
        ],
    )
    steps = [
        dict(id="e", uses="actions/cache/restore@v4", name="re", **{"with": {"path": "p", "key": "eng-${{ x }}"}}),
        {
            "uses": "actions/cache/save@v4",
            "name": "se",
            "if": "github.ref == 'refs/heads/main'",
            "with": {"path": "p", "key": "${{ steps.e.outputs.cache-primary-key }}"},
        },
        dict(id="a", uses="actions/cache/restore@v4", name="ra", **{"with": {"path": "p", "key": "apt-${{ runner.os }}"}}),
        {
            "uses": "actions/cache/save@v4",
            "name": "sa",
            "if": "always() && github.ref == 'refs/heads/main'",
            "with": {"path": "p", "key": "${{ steps.a.outputs.cache-primary-key }}-${{ github.run_id }}"},
        },
        {
            "uses": "Swatinem/rust-cache@v2",
            "name": "rs",
            "with": {"shared-key": "main", "save-if": "${{ github.ref == 'refs/heads/main' }}"},
        },
    ]
    reader = {
        "steps": [{"uses": "Swatinem/rust-cache@v2", "name": "rr", "with": {"shared-key": "main", "save-if": "false"}}]
    }
    wf = {"jobs": {"j": {"steps": steps}, "r": reader}}
    prune = {
        True: {"schedule": [{"cron": "0 3 * * *"}], "workflow_dispatch": None},
        "permissions": {},
        "jobs": {
            "prune": {
                "timeout-minutes": 10,
                "permissions": {"actions": "write", "contents": "read"},
                "steps": [{"run": "python3 scripts/lib/cache_prune.py --apply"}],
            }
        },
    }
    return {".github/workflows/a.yml": wf}, reg, prune


def selftest() -> int:
    import copy

    cases: list[tuple[str, callable, str | None]] = []

    def case(label, mutate, want):
        cases.append((label, mutate, want))

    case("a coherent fixture is clean", lambda d, r, p: None, None)

    def undeclared(d, r, p):
        d[".github/workflows/a.yml"]["jobs"]["j"]["steps"].append(
            {"uses": "actions/cache/restore@v4", "name": "x", "with": {"key": "mystery-${{ x }}"}}
        )

    case("a cache key in no declared class", undeclared, "matches no declared class")

    def sha_key(d, r, p):
        d[".github/workflows/a.yml"]["jobs"]["j"]["steps"][1]["with"]["key"] = "eng-${{ github.sha }}"

    case("a commit-scoped key outside its allow-list", sha_key, "move with a commit or a run")

    def run_id_ok(d, r, p):
        pass

    case("a run-scoped key IN the allow-listed class stays clean", run_id_ok, None)

    def unscoped_save(d, r, p):
        del d[".github/workflows/a.yml"]["jobs"]["j"]["steps"][1]["if"]

    case("a save not limited to the default branch", unscoped_save, "not limited to the default branch")

    def rust_no_save_if(d, r, p):
        del d[".github/workflows/a.yml"]["jobs"]["j"]["steps"][4]["with"]["save-if"]

    case("rust-cache with no save-if", rust_no_save_if, "rust-cache without `save-if`")

    def extra_saver(d, r, p):
        d[".github/workflows/a.yml"]["jobs"]["r"]["steps"][0]["with"]["save-if"] = (
            "${{ github.ref == 'refs/heads/main' }}"
        )

    case("a reader that became a second saver", extra_saver, "owners: declared")

    def dropped_reader(d, r, p):
        del d[".github/workflows/a.yml"]["jobs"]["r"]

    case("a declared reader that left", dropped_reader, "readers: declared")

    def reader_nowhere(d, r, p):
        d[".github/workflows/a.yml"]["jobs"]["r"]["steps"][0]["with"]["shared-key"] = "other"
        r["classes"][2]["prefixes"].append("v0-rust-other-")

    case("a reader of a key nobody saves", reader_nowhere, "no saver")

    def stale_class(d, r, p):
        r["classes"].append(
            dict(r["classes"][0], id="ghost", prefixes=["ghost-"], protect=False, evict_priority=10)
        )

    case("a declared class with no use", stale_class, "has no cache use")

    def over_target(d, r, p):
        r["classes"][0]["budget_mb"] = 700

    case("budgets over the target", over_target, "sum to")

    def target_high(d, r, p):
        r["target_mb"] = 950

    case("a target with no headroom under the cap", target_high, "no headroom")

    def over_measured(d, r, p):
        r["classes"][0]["measured_mb"] = 150

    case("a measured size over its budget", over_measured, "exceeds its")

    case("no prune workflow", None, "is missing")

    def prune_pr(d, r, p):
        p[True]["pull_request"] = None

    case("prune triggered by pull_request", prune_pr, "triggers")

    def prune_write_all(d, r, p):
        p["jobs"]["prune"]["permissions"] = {"actions": "write", "contents": "write"}

    case("prune with a wider token", prune_write_all, "job permissions must be exactly")

    def prune_top_write(d, r, p):
        p["permissions"] = {"actions": "write"}

    case("prune with workflow-level write", prune_top_write, "workflow-level permissions")

    def composite(d, r, p):
        d[".github/workflows/a.yml"]["jobs"]["j"]["steps"].append({"uses": "./.github/actions/c"})
        d[".github/actions/c/action.yml"] = {
            "runs": {"steps": [{"uses": "actions/cache/save@v4", "name": "cs", "with": {"key": "zzz-1"}}]}
        }

    case("a composite action's cache is read too", composite, "matches no declared class")

    bad = 0
    for label, mutate, want in cases:
        docs, reg, prune = _fixture()
        docs, reg, prune = copy.deepcopy(docs), copy.deepcopy(reg), copy.deepcopy(prune)
        prune_arg: dict | None = prune
        if label == "no prune workflow":
            prune_arg = None
        elif mutate is not None:
            mutate(docs, reg, prune)
        fails, _ = check(docs, reg, prune_arg)
        got = "\n".join(fails)
        ok = (want is None and not fails) or (want is not None and want in got)
        print(f"  {'ok ' if ok else 'BAD'}  {label}: expected {want or 'clean'}")
        if not ok:
            print(f"        got: {got or 'clean'}")
        bad += not ok
    docs, reg, prune = _fixture()
    _, seen = check({".github/workflows/a.yml": {"jobs": {"j": {"steps": [{"run": "true"}]}}}}, reg, prune)
    if seen != 0:
        print("  BAD  a workflow with no cache use counted one")
        bad += 1
    else:
        print("  ok   an empty population is seen as zero (main() FAILs on it)")
    total = len(cases) + 1
    print(f"  {total - bad}/{total} arm(s) behaved as claimed")
    return 1 if bad else 0


if __name__ == "__main__":
    if sys.argv[1:] == ["--selftest"]:
        sys.exit(selftest())
    if sys.argv[1:]:
        print(f"usage: {sys.argv[0]} [--selftest]", file=sys.stderr)
        sys.exit(2)
    sys.exit(main())
