#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
"""R3353 (no register item) -- the author receipt store, and the plan it answers.

The citation is the round that first kept verification receipts (the table of
which lanes a change needs and `scripts/verify-once.sh`); its register item lives
in the operator's notes, which have no store id for `gate_provenance_lint.py` to
resolve.

## The defect, measured twice

On 2026-10-19 the first receipts were removed: they lived one file per lane in a
directory every worktree of the clone shares, so one session's run overwrote
another's and a push that had passed every lane was refused. Without receipts, on
2026-11-26 one integration ran its layer lanes for the first time on the merged
branch and re-ran a hand-chained whole gate from its first step at every repair,
50 to 80 minutes a time.

## What this holds (stage M2 of the landing RFC)

A verdict is keyed by the DIGEST of what its lane read, D(L, t), which
`scripts/lib/lane_digest.py` (stage M1) computes from a commit's tree together
with the lane set G(t) and each lane's class (D, E or S). This module does not
compute either; it reads them through `LaneDigest`, the one adapter.

The store is `<git common dir>/wz-receipts/`, shared by every worktree of the
clone, never tracked, never pushed:

    <lane>/<digest[0:2]>/<digest>/<receipt-id>.json

where receipt-id is the SHA-256 of the record's bytes. A record is written to a
temporary name in the same directory and published with link(2), which fails when
the name exists: nothing renames over a receipt or edits one. Two sessions that
judged different trees write different keys; two that judged the same inputs write
two receipts of one key. A receipt whose bytes do not hash to its name, or whose
digest or lane is not its directory's, is ignored and reported.

Author receipts are advisory: they let an author skip a run whose inputs were
already judged here, and nothing that admits a candidate to main reads them.

## The plans (what `scripts/verify-once.sh` passes)

  changed    the lanes of G(tip) whose digest differs from their digest on the
             merge base with the target (a lane the change did not move was judged
             when the base was admitted), minus those with a pass at their
             digest here, which are INHERITED and printed with the commit they
             were judged on. The default. The base is read with the tip's
             declaration for every lane the base does not declare itself
             (`lane_digest.py`, "Comparing two trees"), so a base older than a
             lane's entry is compared by that lane's inputs.
  only-red   the lanes whose latest measured receipt at their current digest is a
             failure.
  all        every lane of G(tip); refused when this store already holds a verdict
             at any of their digests, unless a reason is given, which every
             receipt of the run keeps.

An S lane (a statistic) is never run or reused here; it is printed as deferred to
its post-merge sample. A failure is never reused: a lane whose latest receipt at its
digest failed runs again.

## What this does NOT claim

That a receipt says how many tests ran (bx's result file does not carry it), or
where the lane's log is kept: those fields are written null until the runner
reports them. Receipts are not deleted; removal by age is left to a later stage.

Usage:
    python3 scripts/lib/gate_ledger.py plan --mode changed --base origin/main --head HEAD
    python3 scripts/lib/gate_ledger.py units --head HEAD --ids C1nh,C1co
    python3 scripts/lib/gate_ledger.py record --mode changed --head H \\
        --results results.jsonl --ids C1nh,C1co --started T
    python3 scripts/lib/gate_ledger.py summary --base origin/main --head HEAD
    python3 scripts/lib/gate_ledger.py --selftest
"""

from __future__ import annotations

import argparse
import contextlib
import datetime
import hashlib
import io
import itertools
import json
import os
import re
import secrets
import subprocess
import sys
import tempfile
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
STORE_DIR = "wz-receipts"
CLONE_ID = "clone-id"
SCHEMA = 1
MODES = ("changed", "only-red", "all")
CLASSES = ("D", "E", "S")
#: Variables that pin git to one repository. Every call here names its repository
#: with `-C`, and a hook (or the selftest under a hook) must not be redirected.
GIT_PINS = (
    "GIT_DIR",
    "GIT_WORK_TREE",
    "GIT_INDEX_FILE",
    "GIT_OBJECT_DIRECTORY",
    "GIT_ALTERNATE_OBJECT_DIRECTORIES",
    "GIT_COMMON_DIR",
    "GIT_PREFIX",
)
REFUSAL_HEAD = "verify-once: REFUSED --all:"
_SEQ = itertools.count()
_LAST_NS = [0]


class LedgerError(Exception):
    """A plan, a store or a lane set that cannot be read: exit 2, never a pass."""


# ---------------------------------------------------------------------------
# git
# ---------------------------------------------------------------------------


def git_env() -> dict[str, str]:
    return {k: v for k, v in os.environ.items() if k not in GIT_PINS}


def git(root: Path, *args: str, check: bool = True) -> str:
    run = subprocess.run(
        ["git", "-C", str(root), *args], capture_output=True, text=True, env=git_env()
    )
    if check and run.returncode != 0:
        said = (run.stderr or run.stdout).strip() or f"exit {run.returncode}"
        raise LedgerError(f"git {' '.join(args)} failed: {said}")
    return run.stdout


def resolve(root: Path, rev: str) -> str:
    sha = git(root, "rev-parse", "--verify", "--quiet", f"{rev}^{{commit}}", check=False).strip()
    if not sha:
        raise LedgerError(f"{rev!r} names no commit")
    return sha


def merge_base(root: Path, base: str, head: str) -> str:
    sha = git(root, "merge-base", base, head, check=False).strip()
    if not sha:
        raise LedgerError(f"{base} and {head} have no merge base")
    return sha


def common_dir(root: Path) -> Path:
    return Path(git(root, "rev-parse", "--path-format=absolute", "--git-common-dir").strip())


def tree_is_clean(root: Path) -> bool:
    return not git(root, "status", "--porcelain").strip()


# ---------------------------------------------------------------------------
# the lane set and the digest: stage M1's, read through one adapter
# ---------------------------------------------------------------------------


class LaneDigest:
    """The lane set G(t), each lane's class and unit, and D(L, t), from
    `scripts/lib/lane_digest.py`. Every read of that module is here."""

    def __init__(self, root: Path) -> None:
        here = str(Path(__file__).resolve().parent)
        if here not in sys.path:
            sys.path.insert(0, here)
        try:
            import lane_digest  # noqa: PLC0415 -- the module is stage M1's, read on use
        except ImportError as exc:
            raise LedgerError(f"scripts/lib/lane_digest.py cannot be imported: {exc}") from exc
        self.root = root
        self.module = lane_digest

    def _read(self, call):
        """A tree the module cannot read is a plan that cannot be made (exit 2), with
        the module's sentence; never a traceback."""
        try:
            return call()
        except (self.module.DigestError, self.module.lane_graph.GraphError,
                self.module.GitError) as exc:
            raise LedgerError(str(exc)) from exc

    def lanes(self, rev: str, *, decls_from: str | None = None) -> list[dict]:
        return list(self._read(lambda: self.module.lanes(self.root, rev, decls_from=decls_from)))

    def digest(self, rev: str, lane_id: str, *, decls_from: str | None = None) -> str:
        return str(self._read(
            lambda: self.module.digest(self.root, rev, lane_id, decls_from=decls_from)))

    def explain(self, base: str, head: str, lane_id: str) -> str | None:
        explain = getattr(self.module, "explain", None)
        if explain is None:
            return None
        return str(self._read(lambda: explain(self.root, base, head, lane_id)))


def lane_table(provider, rev: str, decls_from: str | None = None) -> dict[str, dict]:
    """G(rev) by lane id, each entry checked for the fields this module reads; with
    `decls_from`, read with that tree's entry for a lane `rev` does not declare."""
    out: dict[str, dict] = {}
    for lane in provider.lanes(rev, decls_from=decls_from):
        lane_id = lane.get("id") if isinstance(lane, dict) else None
        if not isinstance(lane_id, str) or not lane_id:
            raise LedgerError(f"the lane set at {rev[:12]} holds an entry with no id: {lane!r}")
        if lane.get("class") not in CLASSES:
            raise LedgerError(f"lane {lane_id}: class {lane.get('class')!r} is none of {CLASSES}")
        unit = lane.get("unit")
        if lane["class"] != "S" and (not isinstance(unit, dict) or unit.get("name") != lane_id):
            raise LedgerError(f"lane {lane_id}: its unit is not a plan line named {lane_id}")
        if lane_id in out:
            raise LedgerError(f"lane {lane_id} is in the lane set twice")
        out[lane_id] = lane
    return out


def split_id(lane_id: str) -> tuple[str, str | None]:
    lane, _, part = lane_id.partition(":")
    return lane, (part or None)


# ---------------------------------------------------------------------------
# the store
# ---------------------------------------------------------------------------


def store_root(root: Path) -> Path:
    return common_dir(root) / STORE_DIR


def safe(name: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]", "_", name)


def digest_dir(root: Path, lane_id: str, digest: str) -> Path:
    lane, _ = split_id(lane_id)
    return store_root(root) / safe(lane) / digest[:2] / digest


def publish(path: Path, data: bytes) -> bool:
    """Write `data` at `path` by link(2) from a temporary name beside it.

    True when this call published it, False when the name already existed; an
    existing file is never replaced."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.{os.getpid()}.{secrets.token_hex(4)}.tmp")
    tmp.write_bytes(data)
    try:
        os.link(tmp, path)
        return True
    except FileExistsError:
        return False
    finally:
        tmp.unlink()


def encode(record: dict) -> bytes:
    return (json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n").encode()


def write_receipt(root: Path, record: dict) -> Path:
    data = encode(record)
    path = digest_dir(root, record["lane_id"], record["digest"]) / (
        hashlib.sha256(data).hexdigest() + ".json"
    )
    publish(path, data)
    return path


def receipts(root: Path, lane_id: str, digest: str) -> list[dict]:
    """The sound receipts of one lane at one digest, oldest first. One whose bytes do
    not hash to its name, or that names another lane or digest, is reported and left
    out: it answers no question this key asks."""
    here = digest_dir(root, lane_id, digest)
    if not here.is_dir():
        return []
    out = []
    for path in sorted(here.glob("*.json")):
        data = path.read_bytes()
        try:
            record = json.loads(data)
        except ValueError:
            record = None
        sound = (
            isinstance(record, dict)
            and hashlib.sha256(data).hexdigest() == path.stem
            and record.get("digest") == digest
            and record.get("lane_id") == lane_id
        )
        if not sound:
            print(f"gate-ledger: ignored receipt {path}: its bytes, digest or lane are not its key",
                  file=sys.stderr)
            continue
        out.append(record)
    out.sort(key=lambda r: (int(r.get("recorded_ns") or 0), str(r.get("ended"))))
    return out


def latest_verdict(root: Path, lane_id: str, digest: str) -> dict | None:
    """The newest receipt with a verdict (pass or fail); an unmeasured run is none."""
    measured = [r for r in receipts(root, lane_id, digest) if r.get("verdict") in ("pass", "fail")]
    return measured[-1] if measured else None


def clone_id(root: Path) -> str:
    """A random id for this clone, made once; it names no host, path or person."""
    path = store_root(root) / CLONE_ID
    if not path.is_file():
        publish(path, (secrets.token_hex(8) + "\n").encode())
    return path.read_text(encoding="utf-8").strip()


def recorded_ns() -> int:
    """The order of receipts at one key: nanoseconds, strictly increasing within a
    process, since two runs of one lane can end in the same second."""
    _LAST_NS[0] = max(time.time_ns(), _LAST_NS[0] + 1)
    return _LAST_NS[0]


def now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# ---------------------------------------------------------------------------
# the plan
# ---------------------------------------------------------------------------


class Row:
    def __init__(self, lane: dict, state: str, digest: str = "", last: dict | None = None) -> None:
        self.lane = lane
        self.id = lane["id"]
        self.state = state  # run | inherited | unchanged | deferred
        self.digest = digest
        self.last = last


class Plan:
    def __init__(self, mode: str, base: str, head: str, rows: list[Row], refused: bool) -> None:
        self.mode = mode
        self.base = base
        self.head = head
        self.rows = rows
        self.refused = refused

    def to_run(self) -> list[str]:
        return [r.id for r in self.rows if r.state == "run"]


def make_plan(root: Path, provider, mode: str, base: str, head: str,
              reason: str | None = None) -> Plan:
    if mode not in MODES:
        raise LedgerError(f"mode {mode!r} is none of {', '.join(MODES)}")
    head_sha = resolve(root, head)
    lanes = lane_table(provider, head_sha)
    base_sha = merge_base(root, base, head_sha) if mode == "changed" else ""
    base_lanes = lane_table(provider, base_sha, decls_from=head_sha) if base_sha else {}
    rows: list[Row] = []
    for lane_id in sorted(lanes):
        lane = lanes[lane_id]
        if lane["class"] == "S":
            if mode != "only-red":
                rows.append(Row(lane, "deferred"))
            continue
        digest = provider.digest(head_sha, lane_id)
        last = latest_verdict(root, lane_id, digest)
        if mode == "all":
            rows.append(Row(lane, "run", digest, last))
        elif mode == "only-red":
            if last is not None and last.get("verdict") == "fail":
                rows.append(Row(lane, "run", digest, last))
        elif lane_id in base_lanes and provider.digest(base_sha, lane_id, decls_from=head_sha) == digest:
            rows.append(Row(lane, "unchanged", digest, last))
        elif last is not None and last.get("verdict") == "pass":
            rows.append(Row(lane, "inherited", digest, last))
        else:
            rows.append(Row(lane, "run", digest, last))
    refused = mode == "all" and not reason and any(
        receipts(root, r.id, r.digest) for r in rows if r.state == "run"
    )
    return Plan(mode, base, head_sha, rows, refused)


def describe(row: Row) -> str:
    last = row.last
    if row.state == "deferred":
        return f"  deferred   {row.id}  class S: judged by its sample after the merge, not here"
    if row.state == "unchanged":
        return f"  unchanged  {row.id}  same inputs as the base; judged when the base was admitted"
    if row.state == "inherited" and last is not None:
        said = f", reason: {last['reason']}" if last.get("reason") else ""
        return (f"  inherited  {row.id}  pass on {str(last.get('commit'))[:12]} "
                f"(digest {row.digest[:12]}, {last.get('ended')}{said})")
    if last is None:
        why = f"no verdict at digest {row.digest[:12]}"
    elif last.get("verdict") == "pass":
        why = f"pass on {str(last.get('commit'))[:12]} already; run again by --all --reason"
    else:
        why = f"fail on {str(last.get('commit'))[:12]} at {last.get('ended')} (exit {last.get('exit')})"
    return f"  run        {row.id}  {why}"


def print_plan(plan: Plan, provider=None) -> None:
    counts: dict[str, int] = {}
    for r in plan.rows:
        counts[r.state] = counts.get(r.state, 0) + 1
    summary = ", ".join(f"{n} {s}" for s, n in sorted(counts.items())) or "no lane"
    print(f"verify-once: {plan.mode} {plan.base or '-'}..{plan.head[:12]}: {summary}")
    for r in plan.rows:
        if r.state == "unchanged":
            continue
        print(describe(r))
        if provider is not None and r.state == "run" and plan.base:
            said = provider.explain(plan.base, plan.head, r.id)
            if said:
                print("             " + said.replace("\n", "\n             "))
    if plan.refused:
        judged = sum(1 for r in plan.rows if r.state == "run" and r.last is not None)
        print(f"{REFUSAL_HEAD} the receipt store already holds a verdict for {judged} of "
              f"{len(plan.to_run())} lane(s) at these exact inputs.", file=sys.stderr)
        print("verify-once: run `bash scripts/verify-once.sh` (the lanes whose inputs changed "
              "or failed) or `bash scripts/verify-once.sh --only-red`; a whole run is "
              "`bash scripts/verify-once.sh --all --reason '<why>'`, and every receipt keeps the "
              "reason.", file=sys.stderr)


# ---------------------------------------------------------------------------
# units (the plan bx reads), the record of their results, the round's summary
# ---------------------------------------------------------------------------


def is_exit(value) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def record(root: Path, provider, mode: str, head: str, results: Path, ids: list[str],
           reason: str | None, started: str) -> int:
    """A receipt per lane the results name. A unit with no exit status is written
    unmeasured, which is no verdict."""
    head_sha = resolve(root, head)
    if resolve(root, "HEAD") != head_sha or not tree_is_clean(root):
        print("verify-once: the checkout changed while the lanes ran (dirty, untracked or HEAD "
              "moved); no receipt is written for bytes that were not the ones judged",
              file=sys.stderr)
        return 1
    rows: dict[str, dict] = {}
    if results.is_file():
        for line in results.read_text(encoding="utf-8").splitlines():
            if line.strip():
                row = json.loads(line)
                rows[str(row.get("name"))] = row
    lanes = lane_table(provider, head_sha)
    executor = {"kind": "author", "clone": clone_id(root)}
    ended = now()
    failed = 0
    for lane_id in ids:
        lane = lanes.get(lane_id)
        row = rows.get(lane_id)
        if lane is None or row is None:
            print(f"  NO RESULT  {lane_id}: {'not in the lane set' if lane is None else 'bx reported no unit of it'}")
            failed += 1
            continue
        exit_status = row.get("exit")
        verdict = ("pass" if exit_status == 0 else "fail") if is_exit(exit_status) else "unmeasured"
        name, part = split_id(lane_id)
        receipt = {
            "schema": SCHEMA,
            "lane": name,
            "lane_id": lane_id,
            "part_or_leg": part,
            "class": lane["class"],
            "digest": provider.digest(head_sha, lane_id),
            "manifest": lane.get("manifest"),
            "argv": list(lane["unit"].get("argv", [])),
            "verdict": verdict,
            "exit": exit_status if is_exit(exit_status) else None,
            "ran": None,
            "log_sha256": None,
            "log_ref": None,
            "executor": executor,
            "tools": lane.get("tools"),
            "started": started,
            "ended": ended,
            "commit": head_sha,
            "recorded_ns": recorded_ns(),
            "mode": mode,
            "reason": reason or None,
        }
        write_receipt(root, receipt)
        print(f"  {verdict:10} {lane_id}" + (f" (exit {exit_status})" if is_exit(exit_status) else ""))
        if verdict != "pass":
            failed += 1
    return 1 if failed else 0


def summary_lines(root: Path, provider, base: str, head: str) -> list[str]:
    """The round's verification, one line per lane the change moved: what an auditor
    can recompute (lane, digest, verdict, executor class) instead of a sentence."""
    plan = make_plan(root, provider, "changed", base, head)
    out = []
    for r in plan.rows:
        if r.state in ("unchanged", "deferred"):
            continue
        last = r.last
        verdict = last.get("verdict") if last else "none"
        executor = (last.get("executor") or {}).get("kind") if last else "-"
        out.append(f"{r.id} {r.digest} {verdict} {executor}")
    return out


# ---------------------------------------------------------------------------
# self test
# ---------------------------------------------------------------------------


class FakeDigest:
    """A lane set for the selftest: each lane reads one path, and its digest is the
    hash of its id and that path's blob in the commit."""

    def __init__(self, root: Path, lanes: dict[str, tuple[str, str]]) -> None:
        self.root = root
        self.spec = lanes  # id -> (class, path it reads)
        # (rev, decls_from) of every read: the fake's lanes have no declaration to
        # borrow, so the selftest asks which tree each read was told to borrow from.
        self.reads: list[tuple[str, str | None]] = []

    def lanes(self, rev: str, *, decls_from: str | None = None) -> list[dict]:
        self.reads.append((rev, decls_from))
        return [{"id": i, "class": c, "unit": {"name": i, "argv": ["run", i]}}
                for i, (c, _) in self.spec.items()]

    def digest(self, rev: str, lane_id: str, *, decls_from: str | None = None) -> str:
        self.reads.append((rev, decls_from))
        path = self.spec[lane_id][1]
        blob = git(self.root, "rev-parse", f"{rev}:{path}", check=False).strip()
        return hashlib.sha256(f"{lane_id}\0{blob}".encode()).hexdigest()

    def explain(self, base: str, head: str, lane_id: str) -> str | None:
        return f"reads {self.spec[lane_id][1]}"


def selftest() -> int:
    failures: list[str] = []

    def expect(name: str, ok: bool, detail: str = "") -> None:
        print(f"  selftest -- {name}: {'ok' if ok else 'FAIL ' + detail}")
        if not ok:
            failures.append(name)

    def quiet(fn):
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            return fn()

    with tempfile.TemporaryDirectory() as tmp, tempfile.TemporaryDirectory() as scratch:
        root = Path(tmp)

        def sh(*args: str) -> str:
            return git(root, "-c", "user.name=t", "-c", "user.email=t@t", "-c",
                       "commit.gpgsign=false", "-c", "core.hooksPath=/dev/null", *args)

        def put(path: str, text: str) -> None:
            target = root / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(text, encoding="utf-8")

        def commit(msg: str) -> str:
            sh("add", "-A")
            sh("commit", "-q", "-m", msg)
            return resolve(root, "HEAD")

        lanes = FakeDigest(root, {"A": ("D", "a.txt"), "B": ("E", "b.txt"),
                                  "C1:p": ("D", "c.txt"), "M": ("S", "a.txt")})

        def judge(mode: str, head: str, results: list[tuple[str, object]],
                  reason: str | None = None) -> int:
            path = Path(scratch) / f"results-{next(_SEQ)}.jsonl"
            path.write_text("".join(json.dumps({"name": n, "exit": e}) + "\n" for n, e in results),
                            encoding="utf-8")
            ids = [n for n, _ in results]
            return quiet(lambda: record(root, lanes, mode, head, path, ids, reason, now()))

        def states(plan: Plan) -> dict[str, str]:
            return {r.id: r.state for r in plan.rows}

        git(root, "init", "-q", "-b", "main")
        for name in ("a.txt", "b.txt", "c.txt", "d.txt"):
            put(name, "0\n")
        base = commit("base")

        # Red when --all is refused on inputs nobody judged.
        plan = make_plan(root, lanes, "all", base, base)
        expect("--all runs without a reason when the store judged none of its inputs",
               not plan.refused and sorted(plan.to_run()) == ["A", "B", "C1:p"], str(plan.to_run()))

        # Red when the base comparison is dropped: every lane would run on every change.
        put("a.txt", "1\n")
        c1 = commit("a moves")
        lanes.reads.clear()
        got = states(make_plan(root, lanes, "changed", base, c1))
        expect("a change owes the lanes whose digest it moved, and no other",
               got == {"A": "run", "B": "unchanged", "C1:p": "unchanged", "M": "deferred"}, str(got))
        # Red when the base is read with its own declaration alone: a base older than a
        # lane's entry would refuse the plan instead of comparing the lane's inputs.
        expect("the base is read with the tip's declaration, the tip with its own",
               (base, c1) in lanes.reads and (c1, None) in lanes.reads
               and all(d in (None, c1) for _, d in lanes.reads)
               and all(r != c1 or d is None for r, d in lanes.reads), str(lanes.reads))

        # Red when an S lane is planned to run, or a D lane's pass is not reused.
        expect("a pass is recorded", judge("changed", c1, [("A", 0)]) == 0)
        plan = make_plan(root, lanes, "changed", base, c1)
        got = states(plan)
        expect("a lane with a pass at its digest is inherited", got.get("A") == "inherited", str(got))
        line = describe(next(r for r in plan.rows if r.id == "A"))
        expect("an inherited pass names the commit it was judged on", c1[:12] in line, line)

        # Red when the store is keyed by lane or by commit: a verdict on other bytes must
        # not displace this one, and a rebase with equal inputs must find it.
        put("a.txt", "2\n")
        c2 = commit("a moves again")
        expect("a fail at other inputs is recorded and reported", judge("changed", c2, [("A", 1)]) == 1)
        sh("checkout", "-q", "-b", "rebased", base)
        put("d.txt", "unrelated\n")
        commit("an unrelated base change")
        put("a.txt", "1\n")
        c1r = commit("the same a on another base")
        got = states(make_plan(root, lanes, "changed", base, c1r))
        expect("a pass survives a verdict on other bytes and a rebase with equal inputs",
               got.get("A") == "inherited", str(got))

        # Red when a failure is reused, or --only-red reads anything but the current digest.
        sh("checkout", "-q", "main")
        got = states(make_plan(root, lanes, "changed", base, c2))
        expect("a fail at the same digest runs again", got.get("A") == "run", str(got))
        got = states(make_plan(root, lanes, "only-red", base, c2))
        expect("--only-red picks the lane whose latest verdict here failed, and only it",
               got == {"A": "run"}, str(got))
        expect("an unmeasured run is recorded", judge("changed", c2, [("A", None)]) == 1)
        got = states(make_plan(root, lanes, "only-red", base, c2))
        expect("an unmeasured run is no verdict: the fail still stands", got == {"A": "run"}, str(got))
        judge("changed", c2, [("A", 0)])
        expect("--only-red has nothing once that lane passed",
               make_plan(root, lanes, "only-red", base, c2).rows == [])

        # Red when two writers of one digest overwrite each other, or publication replaces.
        digest = lanes.digest(c2, "A")
        before = len(receipts(root, "A", digest))
        rec = {"schema": SCHEMA, "lane": "A", "lane_id": "A", "digest": digest, "verdict": "pass",
               "ended": "z1", "started": "z0", "commit": c2}
        write_receipt(root, rec)
        write_receipt(root, {**rec, "ended": "z2"})
        write_receipt(root, rec)
        expect("two writers of one digest leave two receipts, and a repeat adds none",
               len(receipts(root, "A", digest)) == before + 2, str(len(receipts(root, "A", digest))))
        target = Path(scratch) / "taken.json"
        target.write_bytes(b"first\n")
        expect("publication never replaces an existing name",
               publish(target, b"second\n") is False and target.read_bytes() == b"first\n")

        # Red when a receipt is trusted without its key: bytes, digest and lane.
        forged = digest_dir(root, "A", digest) / ("0" * 64 + ".json")
        forged.write_bytes(encode({**rec, "verdict": "fail", "ended": "z9"}))
        expect("a receipt whose bytes do not hash to its name is ignored",
               all(r.get("ended") != "z9" for r in quiet(lambda: receipts(root, "A", digest))))
        moved = {**rec, "digest": "f" * 64, "ended": "z8"}
        data = encode(moved)
        (digest_dir(root, "A", digest) / (hashlib.sha256(data).hexdigest() + ".json")).write_bytes(data)
        expect("a receipt filed under another digest is ignored",
               all(r.get("ended") != "z8" for r in quiet(lambda: receipts(root, "A", digest))))
        forged.unlink()
        (digest_dir(root, "A", digest) / (hashlib.sha256(data).hexdigest() + ".json")).unlink()

        # Red when a dirty or untracked checkout gets a receipt.
        put("untracked.txt", "x\n")
        expect("an untracked file in the checkout writes no receipt",
               judge("changed", c2, [("B", 0)]) == 1 and latest_verdict(root, "B", lanes.digest(c2, "B")) is None)
        (root / "untracked.txt").unlink()

        # Red when --all is not refused on judged inputs, or the reason is not kept.
        plan = make_plan(root, lanes, "all", base, c2)
        err = io.StringIO()
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(err):
            print_plan(plan)
        expect("--all is refused when the store already judged these inputs",
               plan.refused and err.getvalue().startswith(REFUSAL_HEAD), err.getvalue())
        plan = make_plan(root, lanes, "all", base, c2, reason="a new toolchain")
        expect("--all with a reason runs every lane but the S lane",
               not plan.refused and sorted(plan.to_run()) == ["A", "B", "C1:p"], str(plan.to_run()))
        judge("all", c2, [("C1:p", 0)], reason="a new toolchain")
        last = latest_verdict(root, "C1:p", lanes.digest(c2, "C1:p"))
        expect("every receipt of a whole run keeps its reason, and its part",
               last is not None and last.get("reason") == "a new toolchain"
               and last.get("lane") == "C1" and last.get("part_or_leg") == "p", str(last))
        sh("checkout", "-q", "-b", "fresh", base)
        put("b.txt", "fresh\n")
        fresh = commit("b moves")

        # Red when the units carry a lane not asked for, or an S lane.
        units = quiet(lambda: units_for_root(root, lanes, fresh, ["B"]))
        expect("the units are the lanes asked for, by their plan lines",
               units == [{"name": "B", "argv": ["run", "B"]}], str(units))
        try:
            units_for_root(root, lanes, fresh, ["M"])
            refused_s = False
        except LedgerError:
            refused_s = True
        expect("an S lane has no unit here", refused_s)

        # Red when the round's verification is not read from the receipts.
        judge("changed", fresh, [("B", 0)])
        lines = summary_lines(root, lanes, base, fresh)
        expect("the round's verification names lane, digest, verdict and executor class",
               lines == [f"B {lanes.digest(fresh, 'B')} pass author"], str(lines))

        # Red when the adapter lets the module's error through: the plan command would
        # die with a traceback instead of exit 2 and the module's sentence.
        try:
            LaneDigest(root).lanes(base)
            unreadable = "read"
        except LedgerError as exc:
            unreadable = str(exc)
        expect("a tree the lane module cannot read is a LedgerError",
               "run-ci.sh" in unreadable, unreadable)

    print(f"gate-ledger selftest: {'OK' if not failures else 'FAILED: ' + ', '.join(failures)}")
    return 1 if failures else 0


def units_for_root(root: Path, provider, head: str, ids: list[str]) -> list[dict]:
    lanes = lane_table(provider, resolve(root, head))
    out = []
    for lane_id in ids:
        lane = lanes.get(lane_id)
        if lane is None:
            raise LedgerError(f"no lane {lane_id} in the lane set at {head}")
        if lane["class"] == "S":
            raise LedgerError(f"lane {lane_id} is class S: it is never judged here")
        out.append(dict(lane["unit"]))
    return out


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--selftest", action="store_true")
    sub = parser.add_subparsers(dest="cmd")
    p = sub.add_parser("plan")
    p.add_argument("--mode", choices=MODES, default="changed")
    p.add_argument("--base", default="origin/main")
    p.add_argument("--head", default="HEAD")
    p.add_argument("--reason")
    p.add_argument("--ids-out", help="write the ids of the lanes to run here, comma-separated")
    p = sub.add_parser("units")
    p.add_argument("--head", default="HEAD")
    p.add_argument("--ids", required=True)
    p = sub.add_parser("record")
    p.add_argument("--mode", choices=MODES, required=True)
    p.add_argument("--head", default="HEAD")
    p.add_argument("--results", required=True)
    p.add_argument("--ids", required=True)
    p.add_argument("--reason")
    p.add_argument("--started", default="")
    p = sub.add_parser("summary")
    p.add_argument("--base", default="origin/main")
    p.add_argument("--head", default="HEAD")
    args = parser.parse_args()
    if args.selftest:
        return selftest()
    try:
        if args.cmd is None:
            parser.print_help()
            return 2
        provider = LaneDigest(REPO_ROOT)
        if args.cmd == "plan":
            if args.reason and args.mode != "all":
                raise LedgerError("--reason is the reason of a whole run, given with --mode all")
            plan = make_plan(REPO_ROOT, provider, args.mode, args.base, args.head, args.reason)
            print_plan(plan, provider)
            if plan.refused:
                return 3
            if args.ids_out:
                Path(args.ids_out).write_text(",".join(plan.to_run()), encoding="utf-8")
            return 1 if plan.to_run() else 0
        if args.cmd == "units":
            ids = [i for i in args.ids.split(",") if i]
            for unit in units_for_root(REPO_ROOT, provider, args.head, ids):
                print(json.dumps(unit, separators=(",", ":")))
            return 0
        if args.cmd == "record":
            ids = [i for i in args.ids.split(",") if i]
            return record(REPO_ROOT, provider, args.mode, args.head, Path(args.results), ids,
                          args.reason, args.started or now())
        lines = summary_lines(REPO_ROOT, provider, args.base, args.head)
        for line in lines:
            print(line)
        return 0
    except LedgerError as exc:
        print(f"gate-ledger: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    os.environ.setdefault("LC_ALL", "C")
    sys.exit(main())
