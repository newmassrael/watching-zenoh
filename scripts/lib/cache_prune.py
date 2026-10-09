#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
"""R3160 (no register item) -- decide WHICH hosted caches to drop, instead of letting LRU.

The debt it answers for, open-debt item 899, lives in the operator's agent-memory
register, which has no store `debt-` id for `gate_provenance_lint.py` to resolve; the
honest pair is this sentence and `no register item` in the citation.

GitHub evicts the least recently used cache entry once a repository passes 10 GB and
cannot tell a 5 MB RocksDB engine that costs 290 s to rebuild from a 600 MB target
directory that costs two minutes. This program is the evictor that can: it reads
`.github/cache-classes.json` and removes entries in four passes, each with a stated
reason, stopping as soon as the repository is back under the registry's `target_mb`.

  1. orphan      the key belongs to no declared class (a job that was removed or
                 renamed, a key moved by a pin bump). Younger than 15 minutes is left
                 alone: a job may still be using what it has just saved.
  2. dead ref    the entry lives on a ref other than the default branch and has not
                 been read for two days. The default branch cannot read it and the
                 ref that wrote it has moved on.
  3. superseded  inside one series of a class (the key with its generation suffix
                 removed), everything beyond the newest `keep` entries. A manifest
                 change writes a new rust-cache generation and the previous one is
                 dead weight from that moment.
  4. over target if the repository is still over `target_mb`, drop the least dear
                 entries first: lower `evict_priority`, then least recently read.
                 A class with `protect: true` is never touched by this pass. That is
                 the point of the whole program: the RocksDB engine, the Zephyr SDK
                 and the oracle builds are the entries LRU gets wrong.

It defaults to a DRY RUN and prints what it would delete. `--apply` deletes, through
`gh api -X DELETE`, which needs a token with `actions: write` and nothing more.

`--selftest` drives every pass on fixtures. `--listing FILE` reads a saved listing
(one JSON object per line, or the API's `{"actions_caches": [...]}`) instead of the
API, so a policy change can be read against the real repository without touching it.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
REGISTRY = ROOT / ".github" / "cache-classes.json"
MAIN_REF = "refs/heads/main"
MIN_AGE_S = 15 * 60
DEAD_REF_GRACE_S = 2 * 24 * 3600
MB = 1_000_000


def epoch(ts: str) -> float:
    return datetime.fromisoformat(ts.replace("Z", "+00:00")).timestamp()


def class_of(key: str, classes: list[dict]) -> dict | None:
    """The declared class owning `key`; None for an orphan.

    A class may also list `stale_patterns`: key shapes it USED to write under the same
    prefix before a key moved. They are orphans by declaration, which is what lets a
    renamed key be cleaned without waiting for LRU to find the old copy.
    """
    best, best_len = None, -1
    for cls in classes:
        if any(re.search(p, key) for p in cls.get("stale_patterns", [])):
            return None
        for p in cls["prefixes"]:
            if key.startswith(p) and len(p) > best_len:
                best, best_len = cls, len(p)
    return best


def series_of(cls: dict, key: str) -> str:
    suffix = cls.get("generation_suffix")
    if not suffix:
        return cls["id"]
    return re.sub(suffix, "", key)


def plan(entries: list[dict], reg: dict, now: float) -> tuple[list[tuple[dict, str]], dict]:
    """Deletions (entry, reason) in the order they apply, and a summary."""
    classes = reg["classes"]
    target = reg["target_mb"] * MB
    gone: dict[int, str] = {}
    order: list[int] = []

    def drop(e: dict, why: str) -> None:
        if e["id"] not in gone:
            gone[e["id"]] = why
            order.append(e["id"])

    def age(e: dict) -> float:
        return now - epoch(e["created_at"])

    for e in entries:
        if class_of(e["key"], classes) is None and age(e) >= MIN_AGE_S:
            drop(e, "orphan: the key belongs to no declared class")

    for e in entries:
        if e["id"] in gone or e["ref"] == MAIN_REF:
            continue
        if now - epoch(e["last_accessed_at"]) >= DEAD_REF_GRACE_S:
            drop(e, f"dead ref: {e['ref']} unread for 2 days, and the default branch cannot read it")

    groups: dict[tuple[str, str], list[dict]] = {}
    for e in entries:
        cls = class_of(e["key"], classes)
        if cls is None or e["id"] in gone or e["ref"] != MAIN_REF:
            continue
        groups.setdefault((cls["id"], series_of(cls, e["key"])), []).append(e)
    by_id = {c["id"]: c for c in classes}
    for (cid, series), members in groups.items():
        members.sort(key=lambda x: (x["created_at"], x["id"]), reverse=True)
        for old in members[by_id[cid]["keep"] :]:
            drop(old, f"superseded: `{members[0]['key'][-24:]}` is newer in series `{series[:48]}`")

    live = [e for e in entries if e["id"] not in gone]
    total = sum(e["size_in_bytes"] for e in live)
    if total > target:
        pool = []
        for e in live:
            cls = class_of(e["key"], classes)
            if cls is None or cls["protect"] or age(e) < MIN_AGE_S:
                continue
            pool.append((cls["evict_priority"], epoch(e["last_accessed_at"]), e))
        pool.sort(key=lambda t: (t[0], t[1]))
        for _, _, e in pool:
            if total <= target:
                break
            drop(e, f"over target: {total / MB:.0f} MB against {reg['target_mb']} MB; least dear first")
            total -= e["size_in_bytes"]
    live = [e for e in entries if e["id"] not in gone]
    summary = dict(
        before_mb=sum(e["size_in_bytes"] for e in entries) / MB,
        after_mb=sum(e["size_in_bytes"] for e in live) / MB,
        target_mb=reg["target_mb"],
        cap_mb=reg["cap_mb"],
        still_over_target=sum(e["size_in_bytes"] for e in live) > target,
    )
    by_entry = {e["id"]: e for e in entries}
    return [(by_entry[i], gone[i]) for i in order], summary


def class_table(entries: list[dict], reg: dict) -> list[str]:
    rows = [f"{'class':24s} {'entries':>7s} {'MB':>8s} {'budget MB':>10s}  note"]
    seen: dict[str, list[dict]] = {}
    orphans: list[dict] = []
    for e in entries:
        cls = class_of(e["key"], reg["classes"])
        (seen.setdefault(cls["id"], []) if cls else orphans).append(e)
    for cls in reg["classes"]:
        es = seen.get(cls["id"], [])
        mb = sum(e["size_in_bytes"] for e in es) / MB
        flag = "OVER BUDGET" if mb > cls["budget_mb"] else ""
        rows.append(f"{cls['id']:24s} {len(es):7d} {mb:8.1f} {cls['budget_mb']:10g}  {flag}")
    if orphans:
        rows.append(
            f"{'(no class)':24s} {len(orphans):7d} {sum(e['size_in_bytes'] for e in orphans) / MB:8.1f} "
            f"{'-':>10s}  ORPHAN"
        )
    return rows


def read_listing(path: str) -> list[dict]:
    text = Path(path).read_text(encoding="utf-8").strip()
    try:
        whole = json.loads(text)
    except json.JSONDecodeError:
        return [json.loads(line) for line in text.splitlines() if line.strip()]
    return list(whole["actions_caches"]) if isinstance(whole, dict) else list(whole)


def fetch_listing(repo: str) -> list[dict]:
    out = subprocess.run(
        ["gh", "api", "--paginate", f"repos/{repo}/actions/caches?per_page=100", "--jq", ".actions_caches[]"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    return [json.loads(line) for line in out.splitlines() if line.strip()]


def delete(repo: str, entry: dict) -> bool:
    r = subprocess.run(
        ["gh", "api", "-X", "DELETE", f"repos/{repo}/actions/caches/{entry['id']}"],
        capture_output=True,
        text=True,
    )
    if r.returncode != 0:
        print(f"  could not delete {entry['id']} ({entry['key'][:60]}): {r.stderr.strip()[:160]}", file=sys.stderr)
    return r.returncode == 0


def run(entries: list[dict], reg: dict, now: float, apply: bool, repo: str | None) -> int:
    deletions, summary = plan(entries, reg, now)
    lines = ["cache-prune: " + ("APPLY" if apply else "dry run")]
    lines.append("")
    lines.extend(class_table(entries, reg))
    lines.append("")
    freed = sum(e["size_in_bytes"] for e, _ in deletions) / MB
    lines.append(
        f"{len(deletions)} deletion(s) free {freed:.0f} MB: {summary['before_mb']:.0f} MB -> "
        f"{summary['after_mb']:.0f} MB (target {summary['target_mb']} MB, cap {summary['cap_mb']} MB)"
    )
    for e, why in deletions:
        lines.append(f"  - {e['id']:>10} {e['size_in_bytes'] / MB:8.1f} MB  {e['key'][:70]}  [{why}]")
    if summary["still_over_target"]:
        lines.append(
            "WARNING: still over target with only protected entries left to drop. Raise cap_mb, "
            "lower a budget, or drop a class."
        )
    report = "\n".join(lines)
    print(report)
    step_summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if step_summary:
        with open(step_summary, "a", encoding="utf-8") as fh:
            fh.write("```\n" + report + "\n```\n")
    if not apply:
        return 0
    failed = sum(not delete(repo, e) for e, _ in deletions)
    if failed:
        print(f"cache-prune: {failed} deletion(s) failed", file=sys.stderr)
        return 1
    return 0


def selftest() -> int:
    now = epoch("2026-10-09T12:00:00Z")
    nid = iter(range(1, 1000))

    def ent(key, mb, ref=MAIN_REF, created="2026-10-09T06:00:00Z", accessed="2026-10-09T11:00:00Z"):
        return dict(
            id=next(nid),
            key=key,
            ref=ref,
            size_in_bytes=int(mb * MB),
            created_at=created,
            last_accessed_at=accessed,
        )

    def cls(cid, prefix, suffix=None, keep=1, protect=False, prio=10):
        return dict(
            id=cid,
            prefixes=[prefix],
            generation_suffix=suffix,
            keep=keep,
            protect=protect,
            evict_priority=100 if protect else prio,
            budget_mb=1000,
        )

    reg = dict(
        cap_mb=1000,
        target_mb=500,
        classes=[
            cls("engine", "eng-", "-[0-9a-f]{4}$", keep=2, protect=True),
            cls("rust", "v0-rust-a-", "-[0-9a-f]{2}-[0-9a-f]{2}$", prio=30),
            cls("host", "v0-rust-h-", "-[0-9a-f]{2}-[0-9a-f]{2}$", prio=10),
        ],
    )

    def reasons(entries):
        d, s = plan(entries, reg, now)
        return {e["key"]: why.split(":")[0] for e, why in d}, s

    failures = 0

    def expect(label, got, want):
        nonlocal failures
        ok = got == want
        failures += not ok
        print(f"  {'ok ' if ok else 'BAD'}  {label}" + ("" if ok else f": got {got!r}, want {want!r}"))

    r, _ = reasons([ent("mystery-1", 10)])
    expect("an undeclared key is an orphan", r, {"mystery-1": "orphan"})

    r, _ = reasons([ent("mystery-1", 10, created="2026-10-09T11:55:00Z")])
    expect("a fresh orphan is left alone", r, {})

    reg["classes"][1]["stale_patterns"] = ["^v0-rust-a-old-"]
    r, _ = reasons([ent("v0-rust-a-old-Linux-aa-01", 10), ent("v0-rust-a-Linux-aa-01", 10)])
    expect("a stale pattern turns a renamed key into an orphan", r, {"v0-rust-a-old-Linux-aa-01": "orphan"})
    del reg["classes"][1]["stale_patterns"]

    r, _ = reasons([ent("v0-rust-a-Linux-aa-01", 100, ref="refs/pull/7/merge", accessed="2026-10-06T00:00:00Z")])
    expect("a stale entry on a pull ref is dropped", r, {"v0-rust-a-Linux-aa-01": "dead ref"})

    r, _ = reasons([ent("v0-rust-a-Linux-aa-01", 100, ref="refs/pull/7/merge")])
    expect("a recently read pull-ref entry is kept", r, {})

    old = ent("v0-rust-a-Linux-aa-01", 100, created="2026-10-08T01:00:00Z")
    new = ent("v0-rust-a-Linux-aa-02", 100, created="2026-10-09T01:00:00Z")
    r, _ = reasons([old, new])
    expect("the older generation of a series is superseded", r, {"v0-rust-a-Linux-aa-01": "superseded"})

    other_env = ent("v0-rust-a-Linux-bb-03", 100, created="2026-10-07T01:00:00Z")
    r, _ = reasons([other_env, new])
    expect("an older ENVIRONMENT hash in the same series is superseded too", r, {"v0-rust-a-Linux-bb-03": "superseded"})

    win = ent("v0-rust-a-Windows-aa-01", 100)
    r, _ = reasons([new, win])
    expect("two hosts are two series, so both stay", r, {})

    e1 = ent("eng-0001", 5, created="2026-10-01T00:00:00Z")
    e2 = ent("eng-0002", 5, created="2026-10-05T00:00:00Z")
    e3 = ent("eng-0003", 5, created="2026-10-09T00:00:00Z")
    r, _ = reasons([e1, e2, e3])
    expect("keep=2 retains the engine's previous generation", r, {"eng-0001": "superseded"})

    big = [
        ent("v0-rust-h-Windows-aa-01", 200, accessed="2026-10-09T01:00:00Z"),
        ent("v0-rust-a-Linux-aa-01", 200, accessed="2026-10-09T02:00:00Z"),
        ent("v0-rust-a-Linux2-aa-01", 200, accessed="2026-10-09T03:00:00Z"),
        ent("eng-0001", 400, accessed="2026-10-01T00:00:00Z"),
    ]
    d, s = plan(big, reg, now)
    names = [e["key"] for e, _ in d]
    expect(
        "over target: lowest priority then least recently read goes first, the protected engine never",
        names,
        ["v0-rust-h-Windows-aa-01", "v0-rust-a-Linux-aa-01", "v0-rust-a-Linux2-aa-01"],
    )
    expect("the plan lands under the target", s["after_mb"] <= reg["target_mb"], True)

    d, s = plan([ent("eng-0001", 700, accessed="2026-10-01T00:00:00Z")], reg, now)
    expect("only protected entries left: nothing deleted, and the warning flag is raised", (d, s["still_over_target"]), ([], True))

    young = [ent("v0-rust-a-Linux-aa-01", 900, created="2026-10-09T11:55:00Z")]
    d, s = plan(young, reg, now)
    expect("an entry younger than 15 minutes is not evicted for size", d, [])

    print(f"  {'FAIL' if failures else 'all arms behaved as claimed'}")
    return 1 if failures else 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n", 2)[1])
    ap.add_argument("--repo", default=os.environ.get("GITHUB_REPOSITORY"))
    ap.add_argument("--listing", help="read a saved listing instead of the API")
    ap.add_argument("--apply", action="store_true", help="delete (default is a dry run)")
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args()
    if args.selftest:
        return selftest()
    reg = json.loads(REGISTRY.read_text(encoding="utf-8"))
    if args.listing:
        entries = read_listing(args.listing)
    else:
        if not args.repo:
            print("cache-prune: no --repo and no GITHUB_REPOSITORY", file=sys.stderr)
            return 2
        entries = fetch_listing(args.repo)
    if args.apply and not args.repo:
        print("cache-prune: --apply needs --repo", file=sys.stderr)
        return 2
    if not entries:
        print("cache-prune: the listing is empty; nothing to judge, nothing deleted")
        return 0
    return run(entries, reg, datetime.now().timestamp(), args.apply, args.repo)


if __name__ == "__main__":
    sys.exit(main())
