#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
"""R3353 (no register item) -- VERIFY ONCE, AND PROVE IT AT THE PUSH.

## The defect

A round's verification was chosen by the person running it, lane by lane, from
memory. Measured over one wave of work: nine separate build-host runs for one
batch, and a push that went out with three lanes it required never run (the ABI
pin, a count guard and the static gates, each found by a hosted red). Nothing
connected "these files changed" to "these lanes must pass", so both the repeats
and the omissions were unobservable until a hosted run said so.

## What this holds

One table, `scripts/lib/verify_lanes.json`, says which lane a changed file
requires. Two callers read it, so they cannot disagree:

  scripts/verify-once.sh   `plan` and `script`: every lane the push requires and
                           has no current receipt for, as ONE remote script, run
                           in ONE build-host invocation; then `record`.
  .githooks/pre-push       gate 2c4, `check`: refuses a push whose required lane
                           has no passing receipt for the bytes that trigger it.

A RECEIPT is bound to the trigger files and nothing else: its digest is the git
blob of every changed file the lane's triggers match, plus the lane's own
definition. So a ledger or ack commit, which changes no trigger, leaves every
receipt valid; fixing one test file invalidates exactly the lanes that file
triggers, and `verify-once` re-runs only those. That is what makes a second run
cheap and a repeated run of unchanged bytes impossible: with every receipt
current there is nothing to run.

A lane the build host cannot run (Layer M needs zenohd and the pico CLI) is
`hosted_only`: it is printed as deferred, never counted as passed, and never
blocks a push, as the pre-push hook has always printed a deferral.

## What this does NOT claim

That the table is complete. It is the lanes whose absence cost a hosted run,
written down once; a new miss is repaired by adding its trigger here, in the
commit that repairs the miss. Nor does a receipt say the lane would pass on the
merged tip: a lane reads files its triggers do not name, and the hosted run stays
the authority. It says the lane passed on the bytes this push changes.

Receipts live in the git common directory (`wz-verify/`), shared by every
worktree of the clone and never committed. No waiver exists: the way past a lane
is to run it, or to edit the table where the diff shows it, or `--no-verify`
which the owner's rules leave to an explicit request.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shlex
import subprocess
import sys
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
TABLE = "scripts/lib/verify_lanes.json"
REMOTE_ZC = "/home/developer/zc"


# ---------------------------------------------------------------------------
# git
# ---------------------------------------------------------------------------


def git(root: Path, *args: str, check: bool = True) -> str:
    run = subprocess.run(
        ["git", "-C", str(root), *args], capture_output=True, text=True
    )
    if check and run.returncode != 0:
        raise SystemExit(f"verify-plan: git {' '.join(args)} failed: {run.stderr.strip()}")
    return run.stdout


def changed_files(root: Path, base: str, head: str) -> list[str]:
    out = git(root, "diff", "--name-only", "--no-renames", "-z", f"{base}..{head}")
    return sorted(p for p in out.split("\0") if p)


def tree_blobs(root: Path, head: str) -> dict[str, str]:
    out = git(root, "ls-tree", "-r", "-z", head)
    blobs: dict[str, str] = {}
    for entry in out.split("\0"):
        if not entry:
            continue
        meta, _, path = entry.partition("\t")
        blobs[path] = meta.split()[2]
    return blobs


def receipt_dir(root: Path) -> Path:
    common = git(root, "rev-parse", "--git-common-dir").strip()
    path = Path(common)
    if not path.is_absolute():
        path = (root / path).resolve()
    return path / "wz-verify"


# ---------------------------------------------------------------------------
# the table
# ---------------------------------------------------------------------------


def glob_re(pattern: str) -> re.Pattern[str]:
    out: list[str] = []
    i = 0
    while i < len(pattern):
        if pattern.startswith("**/", i):
            out.append("(?:.*/)?")
            i += 3
        elif pattern.startswith("**", i):
            out.append(".*")
            i += 2
        elif pattern[i] == "*":
            out.append("[^/]*")
            i += 1
        elif pattern[i] == "?":
            out.append("[^/]")
            i += 1
        else:
            out.append(re.escape(pattern[i]))
            i += 1
    return re.compile("^" + "".join(out) + "$")


def load_table(root: Path) -> dict:
    path = root / TABLE
    try:
        table = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise SystemExit(f"verify-plan: cannot read {TABLE}: {exc}")
    if table.get("schema") != 1:
        raise SystemExit(f"verify-plan: {TABLE} has schema {table.get('schema')!r}, want 1")
    return table


class Lane:
    def __init__(self, lane_id: str, cwd: str, cmds: list[str], files: list[str],
                 hosted_only: bool, why: str, definition: str) -> None:
        self.id = lane_id
        self.cwd = cwd
        self.cmds = cmds
        self.files = files
        self.hosted_only = hosted_only
        self.why = why
        self.definition = definition

    def digest(self, blobs: dict[str, str]) -> str:
        h = hashlib.sha256()
        h.update(self.definition.encode())
        for path in self.files:
            h.update(f"\n{path}\t{blobs.get(path, 'DELETED')}".encode())
        return h.hexdigest()


def package_dirs(root: Path, head: str, blobs: dict[str, str]) -> dict[str, str]:
    """`crates/<dir>` -> package name, for every directory with a manifest."""
    names: dict[str, str] = {}
    for path in blobs:
        m = re.fullmatch(r"crates/([^/]+)/Cargo\.toml", path)
        if not m:
            continue
        text = git(root, "show", f"{head}:{path}", check=False)
        pkg = re.search(r'(?ms)^\[package\].*?^name\s*=\s*"([^"]+)"', text)
        if pkg:
            names[m.group(1)] = pkg.group(1)
    return names


def required_lanes(root: Path, base: str, head: str) -> list[Lane]:
    table = load_table(root)
    files = changed_files(root, base, head)
    blobs = tree_blobs(root, head)
    lanes: list[Lane] = []

    def matching(triggers: list[str]) -> list[str]:
        regexes = [glob_re(t) for t in triggers]
        return [f for f in files if any(r.match(f) for r in regexes)]

    for entry in table["layers"]:
        hit = matching(entry["triggers"])
        if hit:
            lanes.append(Lane(
                entry["id"], ".", [f"bash scripts/run-ci.sh --layer {entry['layer']}"],
                hit, False, entry["why"], json.dumps(entry, sort_keys=True)))
    for entry in table["commands"]:
        hit = matching(entry["triggers"])
        if hit:
            cmd = entry["cmd"].replace("{base}", base)
            lanes.append(Lane(
                entry["id"], entry["cwd"], [cmd], hit, False, entry["why"],
                json.dumps({**entry, "cmd": entry["cmd"]}, sort_keys=True)))
    for entry in table["hosted_only"]:
        hit = matching(entry["triggers"])
        if hit:
            lanes.append(Lane(
                entry["id"], ".", [], hit, True, entry["why"],
                json.dumps(entry, sort_keys=True)))

    dirs = package_dirs(root, head, blobs)
    per = table["per_crate"]
    for dirname, pkg in sorted(dirs.items()):
        hit = [f for f in files if f.startswith(f"crates/{dirname}/")]
        if not hit:
            continue
        clippy = [c.replace("{crate}", pkg) for c in per["clippy"]["cmds"]]
        clippy += per["clippy"]["extra"].get(pkg, [])
        lanes.append(Lane(f"clippy:{pkg}", "crates", clippy, hit, False,
                          "clippy of a crate the push changes, every feature set the table names",
                          json.dumps(clippy)))
        if pkg not in per["test"]["skip"]:
            tests = per["test"]["override"].get(pkg) or [
                c.replace("{crate}", pkg) for c in per["test"]["cmds"]]
            lanes.append(Lane(f"test:{pkg}", "crates", tests, hit, False,
                              "the tests of a crate the push changes",
                              json.dumps(tests)))
    return lanes


# ---------------------------------------------------------------------------
# receipts
# ---------------------------------------------------------------------------


def receipt_path(root: Path, lane_id: str) -> Path:
    return receipt_dir(root) / (re.sub(r"[^A-Za-z0-9_.-]", "_", lane_id) + ".json")


def read_receipt(root: Path, lane_id: str) -> dict | None:
    try:
        return json.loads(receipt_path(root, lane_id).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def state_of(root: Path, lane: Lane, blobs: dict[str, str]) -> str:
    if lane.hosted_only:
        return "hosted-only"
    receipt = read_receipt(root, lane.id)
    if receipt is None:
        return "missing"
    if receipt.get("digest") != lane.digest(blobs):
        return "stale"
    return "current" if receipt.get("rc") == 0 else "failed"


# ---------------------------------------------------------------------------
# commands
# ---------------------------------------------------------------------------


def plan_report(root: Path, base: str, head: str) -> tuple[list[tuple[Lane, str]], bool]:
    blobs = tree_blobs(root, head)
    rows = [(lane, state_of(root, lane, blobs)) for lane in required_lanes(root, base, head)]
    pending = any(state in ("missing", "stale", "failed") for _, state in rows)
    return rows, pending


def print_plan(rows: list[tuple[Lane, str]]) -> None:
    if not rows:
        print("verify-plan: this change requires no lane (no trigger file changed)")
        return
    for lane, state in rows:
        print(f"  {state:11} {lane.id}  ({len(lane.files)} trigger file(s)) -- {lane.why}")


def cmd_plan(args: argparse.Namespace) -> int:
    rows, pending = plan_report(REPO_ROOT, args.base, args.head)
    print(f"verify-plan: {args.base}..{args.head}")
    print_plan(rows)
    return 1 if pending else 0


def cmd_check(args: argparse.Namespace) -> int:
    base, _, head = args.range.partition("..")
    if not base or not head:
        print(f"verify-plan: not a range: {args.range!r}", file=sys.stderr)
        return 2
    rows, pending = plan_report(REPO_ROOT, base, head)
    deferred = [lane.id for lane, state in rows if state == "hosted-only"]
    if deferred:
        print(f"pre-push: DEFERRED to the hosted run, not a local pass: {', '.join(deferred)}")
    if not pending:
        print(f"pre-push: verification receipts current for {len(rows) - len(deferred)} lane(s)")
        return 0
    print("verify-plan: lanes this push requires without a passing receipt for their bytes:",
          file=sys.stderr)
    for lane, state in rows:
        if state in ("missing", "stale", "failed"):
            print(f"  {state:8} {lane.id} -- {lane.why}", file=sys.stderr)
    print("  run, once: bash scripts/verify-once.sh   (it runs only these lanes)", file=sys.stderr)
    return 1


def remote_script(root: Path, lanes: list[Lane], tag: str) -> str:
    out = [
        "#!/bin/bash",
        f"# generated by verify_plan.py: {len(lanes)} lane(s), one invocation. Usage: <this> <tag>",
        "set -u",
        'tag="${1:-' + tag + '}"',
        "[ -f ~/.cargo/env ] && source ~/.cargo/env",
        'ROOT="$PWD"; [ -d "$ROOT/scripts" ] || ROOT="$(dirname "$PWD")"',
        f"mkdir -p {REMOTE_ZC}",
        "lane() { local id=\"$1\" cwd=\"$2\" cmd=\"$3\"; local f=\"" + REMOTE_ZC +
        "/$tag-$(printf %s \"$id\" | tr -c 'A-Za-z0-9_.-' _).log\";",
        "  ( cd \"$ROOT/$cwd\" && eval \"$cmd\" ) > \"$f\" 2>&1; local rc=$?;",
        "  echo \"LANE $id rc=$rc\"; }",
        "worst=0",
    ]
    for lane in lanes:
        cmd = " && ".join(lane.cmds)
        out.append(f"lane {shlex.quote(lane.id)} {shlex.quote(lane.cwd)} {shlex.quote(cmd)}")
    out.append("exit 0")
    return "\n".join(out) + "\n"


def cmd_script(args: argparse.Namespace) -> int:
    rows, _ = plan_report(REPO_ROOT, args.base, args.head)
    runnable = ("missing", "stale", "failed", "current") if args.force else (
        "missing", "stale", "failed")
    todo = [lane for lane, state in rows if state in runnable]
    if not todo:
        return 3
    sys.stdout.write(remote_script(REPO_ROOT, todo, args.tag))
    print(json.dumps([lane.id for lane in todo]), file=sys.stderr)
    return 0


LANE_LINE = re.compile(r"^LANE (\S+) rc=(\d+)\s*$", re.M)


def cmd_record(args: argparse.Namespace) -> int:
    root = REPO_ROOT
    dirty = git(root, "status", "--porcelain", "--untracked-files=no").strip()
    head_now = git(root, "rev-parse", "HEAD").strip()
    if dirty or head_now != git(root, "rev-parse", args.head).strip():
        print("verify-plan: the tree changed while the lanes ran (dirty or HEAD moved); "
              "no receipt is written for bytes that were not the ones verified", file=sys.stderr)
        return 1
    text = Path(args.log).read_text(encoding="utf-8", errors="replace")
    results = {m.group(1): int(m.group(2)) for m in LANE_LINE.finditer(text)}
    blobs = tree_blobs(root, args.head)
    lanes = {lane.id: lane for lane in required_lanes(root, args.base, args.head)}
    receipt_dir(root).mkdir(parents=True, exist_ok=True)
    failed = []
    for lane_id, rc in sorted(results.items()):
        lane = lanes.get(lane_id)
        if lane is None:
            continue
        payload = {"lane": lane_id, "digest": lane.digest(blobs), "rc": rc,
                   "head": args.head, "host": args.host}
        receipt_path(root, lane_id).write_text(json.dumps(payload) + "\n", encoding="utf-8")
        print(f"  {'passed' if rc == 0 else 'FAILED':7} {lane_id} (rc={rc})")
        if rc != 0:
            failed.append(lane_id)
    missing = [i for i in args.expect.split(",") if i and i not in results]
    for lane_id in missing:
        print(f"  NO RESULT {lane_id}: the host never printed its verdict line")
    return 1 if failed or missing else 0


# ---------------------------------------------------------------------------
# self test
# ---------------------------------------------------------------------------

SELFTEST_TABLE = {
    "schema": 1,
    "host": "pc2",
    "layers": [
        {"id": "L1", "layer": "L1", "triggers": ["crates/**/*.rs"], "why": "static"},
        {"id": "L2", "layer": "L2", "triggers": ["crates/alpha/**"], "why": "alpha only"},
    ],
    "commands": [
        {"id": "cg", "cwd": ".", "cmd": "echo {base}", "triggers": ["scripts/x.sh"], "why": "count"}
    ],
    "hosted_only": [{"id": "HM", "triggers": ["crates/alpha/**"], "why": "needs zenohd"}],
    "per_crate": {
        "clippy": {"cmds": ["clippy {crate}"], "extra": {"beta": ["clippy beta --x"]}},
        "test": {"cmds": ["test {crate}"], "override": {"beta": ["test beta --lib"]},
                 "skip": ["gamma"]},
    },
}


def selftest() -> int:
    failures: list[str] = []

    def expect(name: str, ok: bool, detail: str = "") -> None:
        print(f"  selftest -- {name}: {'ok' if ok else 'FAIL ' + detail}")
        if not ok:
            failures.append(name)

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)

        def sh(*args: str) -> None:
            subprocess.run(["git", "-C", tmp, *args], check=True, capture_output=True)

        def write(path: str, text: str) -> None:
            target = root / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(text, encoding="utf-8")

        def commit(msg: str) -> str:
            sh("add", "-A")
            sh("-c", "user.name=t", "-c", "user.email=t@t", "commit", "-q", "-m", msg)
            return git(root, "rev-parse", "HEAD").strip()

        sh("init", "-q", "-b", "main")
        for crate in ("alpha", "beta", "gamma"):
            write(f"crates/{crate}/Cargo.toml", f'[package]\nname = "{crate}"\nversion = "0"\n')
            write(f"crates/{crate}/src/lib.rs", "// 1\n")
        write("scripts/lib/verify_lanes.json", json.dumps(SELFTEST_TABLE))
        write("scripts/x.sh", "#\n")
        write("docs/ledger.md", "a\n")
        base = commit("base")

        def lane_ids(b: str, h: str) -> dict[str, str]:
            rows, _ = plan_report(root, b, h)
            return {lane.id: state for lane, state in rows}

        def with_root(fn):
            global REPO_ROOT
            saved = REPO_ROOT
            REPO_ROOT = root
            try:
                return fn()
            finally:
                REPO_ROOT = saved

        # a docs-only change requires nothing
        write("docs/ledger.md", "b\n")
        docs = commit("docs")
        expect("a ledger-only push requires no lane", lane_ids(base, docs) == {})

        # a change in alpha requires alpha's lanes and the shared static lane
        write("crates/alpha/src/lib.rs", "// 2\n")
        alpha = commit("alpha")
        got = lane_ids(base, alpha)
        expect("a change in alpha names L1, L2, its crate lanes and the hosted lane",
               set(got) == {"L1", "L2", "clippy:alpha", "test:alpha", "HM"}, str(got))
        expect("the hosted-only lane is reported hosted-only and nothing else is passed",
               got.get("HM") == "hosted-only"
               and all(s == "missing" for k, s in got.items() if k != "HM"), str(got))

        # a receipt makes a lane current; the check refuses until every lane has one
        def check(b: str, h: str) -> int:
            ns = argparse.Namespace(range=f"{b}..{h}")
            return with_root(lambda: cmd_check(ns))

        import contextlib
        import io

        def quiet(fn):
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                return fn()

        expect("the check refuses a push whose lanes have no receipt",
               quiet(lambda: check(base, alpha)) == 1)

        def record_all(b: str, h: str, rc: int = 0, only: set[str] | None = None) -> None:
            lines = []
            rows, _ = plan_report(root, b, h)
            for lane, state in rows:
                if state != "hosted-only" and (only is None or lane.id in only):
                    lines.append(f"LANE {lane.id} rc={rc}")
            log = root / ".lanes.log"
            log.write_text("\n".join(lines) + "\n", encoding="utf-8")
            ns = argparse.Namespace(log=str(log), base=b, head=h, host="t", expect="")
            quiet(lambda: with_root(lambda: cmd_record(ns)))
            log.unlink()

        record_all(base, alpha, rc=1)
        expect("a failed lane's receipt does not satisfy the check",
               quiet(lambda: check(base, alpha)) == 1)
        record_all(base, alpha)
        expect("with every non-hosted lane passed the check accepts the push",
               quiet(lambda: check(base, alpha)) == 0)

        # a docs commit on top does not disturb a receipt
        write("docs/ledger.md", "c\n")
        docs2 = commit("docs 2")
        expect("a ledger commit after verification keeps the receipts valid",
               quiet(lambda: check(base, docs2)) == 0)

        # extra clippy sets and the test override are part of the lane
        write("crates/beta/src/lib.rs", "// 2\n")
        beta = commit("beta")
        lanes = {l.id: l for l in required_lanes(root, docs2, beta)}
        expect("a crate's extra clippy sets and its test override are in its lanes",
               lanes["clippy:beta"].cmds == ["clippy beta", "clippy beta --x"]
               and lanes["test:beta"].cmds == ["test beta --lib"],
               str({k: v.cmds for k, v in lanes.items()}))

        # a change to a trigger file invalidates exactly the lanes it triggers
        write("crates/beta/src/lib.rs", "// 3\n")
        later = commit("beta again")
        got = lane_ids(base, later)
        expect("changing beta marks beta's lanes and the shared lane stale, not alpha's",
               got.get("clippy:beta") == "missing" and got.get("L1") == "stale"
               and got.get("clippy:alpha") == "current" and got.get("L2") == "current", str(got))
        rows_now, _ = plan_report(root, base, later)
        record_all(base, later, only={lane.id for lane, st in rows_now
                                      if st not in ("current", "hosted-only")})
        expect("after re-running only the stale and missing lanes the push is accepted",
               quiet(lambda: check(base, later)) == 0)

        # the table is part of every lane's definition
        write("scripts/lib/verify_lanes.json",
              json.dumps({**SELFTEST_TABLE, "layers": [
                  {"id": "L1", "layer": "L1x", "triggers": ["crates/**/*.rs"], "why": "static"},
                  SELFTEST_TABLE["layers"][1]]}))
        edited = commit("table edit")
        got = lane_ids(base, edited)
        expect("editing a lane's definition invalidates its receipt",
               got.get("L1") == "stale" and got.get("L2") == "current", str(got))

        # a tree that moved while the lanes ran gets no receipt
        write("crates/alpha/src/lib.rs", "// dirty\n")
        log = root / ".lanes.log"
        log.write_text("LANE L1 rc=0\n", encoding="utf-8")
        ns = argparse.Namespace(log=str(log), base=base, head=edited, host="t", expect="")
        expect("a dirty tree is refused a receipt",
               quiet(lambda: with_root(lambda: cmd_record(ns))) == 1)
        sh("checkout", "--", "crates/alpha/src/lib.rs")

        # the remote script is one invocation naming every stale lane
        rows, _ = plan_report(root, base, edited)
        todo = [lane for lane, state in rows if state in ("missing", "stale", "failed")]
        text = remote_script(root, todo, "t1")
        expect("the generated script carries one verdict line per stale lane",
               text.count("\nlane ") == len(todo) and "LANE $id rc=$rc" in text, text)
        ids = {m.group(1) for m in re.finditer(r"^lane '?([^' ]+)'?", text, re.M)}
        expect("and names exactly those lanes", ids == {lane.id for lane in todo}, str(ids))

        # a crate the table skips for tests still has its clippy lane
        write("crates/gamma/src/lib.rs", "// 2\n")
        gamma = commit("gamma")
        got = lane_ids(edited, gamma)
        expect("a skipped crate has a clippy lane and no test lane",
               "clippy:gamma" in got and "test:gamma" not in got, str(got))

    print(f"verify-plan selftest: {'OK' if not failures else 'FAILED: ' + ', '.join(failures)}")
    return 1 if failures else 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--selftest", action="store_true")
    sub = parser.add_subparsers(dest="cmd")
    for name in ("plan", "script"):
        p = sub.add_parser(name)
        p.add_argument("--base", default="origin/main")
        p.add_argument("--head", default="HEAD")
        if name == "script":
            p.add_argument("--tag", default="verify")
            p.add_argument("--force", action="store_true",
                           help="include lanes whose receipt is current")
    p = sub.add_parser("check")
    p.add_argument("range", help="<base>..<head>, as the pre-push hook has it")
    p = sub.add_parser("record")
    p.add_argument("--base", default="origin/main")
    p.add_argument("--head", default="HEAD")
    p.add_argument("--log", required=True)
    p.add_argument("--host", default="")
    p.add_argument("--expect", default="", help="comma-separated lane ids that must have a verdict")
    args = parser.parse_args()
    if args.selftest:
        return selftest()
    handler = {"plan": cmd_plan, "script": cmd_script, "check": cmd_check,
               "record": cmd_record}.get(args.cmd or "")
    if handler is None:
        parser.print_help()
        return 2
    return handler(args)


if __name__ == "__main__":
    os.environ.setdefault("LC_ALL", "C")
    sys.exit(main())
