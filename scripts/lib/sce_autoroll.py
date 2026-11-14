#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
"""R4167 (no register item) -- the autoroller SCE ADR 0078 section 4 asks of a
consumer: move the `vendor/sce` pin one landing at a time, in order, and treat
the first landing that does not build as the one to fix.

The citation is `no register item`: the carry this answers ("ADR 0078 section 4
wants an autoroller") is a ledger carry of the SCE crossing rounds, not an
inventory id `gate_provenance_lint.py` could resolve.

## Why one landing at a time

A move across several SCE landings mixes their errors into one set, in files
other work is editing, and leaves no way to say which change a failure belongs
to. Moved one landing at a time, every failure belongs to one change and is
fixed from the one guide section that change wrote
(`docs/SCE_CODEC_CONSUMER_MIGRATION.md` in the SCE tree). SCE keeps no branch
for an old pin, so a pin that is not on the target's first-parent line is
refused here rather than rolled.

## What a landing is, for wz

SCE's history is linear and carries no landing markers, so this reads two facts
off each commit after the pin, both of SCE's own making:

* the commit adds a section to the migration guide that applies to Rust or to
  every backend ("Landing: the commit that adds this section"). A section whose
  heading names only another backend (C++, C11, Kotlin, Swift, Go, Python,
  TTCN-3) changes nothing wz generates and is listed, not stopped at;
* the commit changes a package wz COMPILES: an SCE workspace package named in
  `crates/Cargo.lock` with no `source` (a path package), outside the
  `tests/`, `benches/` and `examples/` a dependent never builds, or SCE's root
  `Cargo.toml`, whose workspace keys those packages inherit.

Each such commit is a stop. A commit that changes only what wz GENERATES from
(a package only `xtask/Cargo.lock` names, such as the generator, or the
templates under `tools/codegen/templates/` outside another backend's subtree)
is crossed with the next stop: SCE's guide gate holds that such a change moves
no API a consumer calls, and the regeneration at the stop reads it anyway.
Every other path is inert. When no stop is left before the target, the target
itself is the last landing (the tail).

The packages are read from wz's two lock files and SCE's workspace manifest, at
the pin and at the target, so a package wz starts or stops depending on moves
the classification with no edit here.

## What it does not do

It plans and changes nothing: no fetch, checkout, regeneration, build or
commit. The plan names the branch, the commands and the checks, and the main
session runs them; a move whose build fails at a stop is bisected over the
generator commits that stop crossed, which the plan lists.

Usage:
  python3 scripts/lib/sce_autoroll.py plan [--sce DIR] [--target REF]
      [--pin SHA] [--base REF] [--worktrees DIR] [--json]
  python3 scripts/lib/sce_autoroll.py --selftest
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

GUIDE = "docs/SCE_CODEC_CONSUMER_MIGRATION.md"
COMPILE_LOCK = "crates/Cargo.lock"
GENERATE_LOCK = "xtask/Cargo.lock"
SUBMODULE = "vendor/sce"
TEMPLATES = "tools/codegen/templates/"
# The template subtrees of a backend wz does not generate, under `templates/`
# and under `templates/forge/`.
FOREIGN_TEMPLATE_DIRS = ("c", "cpp", "go", "kotlin", "python", "swift", "ttcn3")
# What cargo never builds of a package for a dependent.
NOT_BUILT_FOR_A_DEPENDENT = ("tests", "benches", "examples")
FOREIGN_BACKENDS = re.compile(r"C\+\+|\bC11\b|\bKotlin\b|\bSwift\b|\bGo\b|\bPython\b|\bTTCN-3\b")
RUST = re.compile(r"\bRust\b")

RUNTIME = "runtime"
GENERATOR = "generator"
GUIDE_CLASS = "guide"
INERT = "inert"


class Refused(Exception):
    """A plan this tool will not make, with the reason."""


# ── git, with the environment of a hook left out ─────────────────────────────


def _git_env() -> dict[str, str]:
    # A hook exports GIT_DIR and GIT_INDEX_FILE for the repository it runs in;
    # left in place they would point every `git -C <other repo>` back at it.
    return {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}


def git(repo: Path, *args: str, check: bool = True) -> subprocess.CompletedProcess:
    proc = subprocess.run(
        ["git", "-C", str(repo), *args],
        env=_git_env(),
        capture_output=True,
        text=True,
    )
    if check and proc.returncode != 0:
        raise Refused(f"git {' '.join(args)} in {repo} failed: {proc.stderr.strip()}")
    return proc


def show(repo: Path, rev: str, path: str) -> str | None:
    proc = git(repo, "show", f"{rev}:{path}", check=False)
    return proc.stdout if proc.returncode == 0 else None


# ── reading the manifests (no tomllib: the hosted python floor is 3.10) ──────


def path_packages(lock_text: str) -> set[str]:
    """The packages of a Cargo.lock that have no `source`: path packages."""
    names: set[str] = set()
    for block in lock_text.split("[[package]]")[1:]:
        name = None
        sourced = False
        for line in block.splitlines():
            line = line.strip()
            if line.startswith("["):
                break
            m = re.match(r'name\s*=\s*"([^"]+)"', line)
            if m:
                name = m.group(1)
            if re.match(r"source\s*=", line):
                sourced = True
        if name and not sourced:
            names.add(name)
    return names


def workspace_members(manifest: str) -> list[str]:
    """The `members` of a `[workspace]` table, comments and trailing commas allowed."""
    m = re.search(r"^\s*members\s*=\s*\[(.*?)\]", manifest, re.S | re.M)
    if not m:
        return []
    body = "\n".join(line.split("#", 1)[0] for line in m.group(1).splitlines())
    return re.findall(r'"([^"]+)"', body)


def package_name(manifest: str) -> str | None:
    in_package = False
    for line in manifest.splitlines():
        stripped = line.strip()
        if stripped.startswith("["):
            in_package = stripped == "[package]"
            continue
        if in_package:
            m = re.match(r'name\s*=\s*"([^"]+)"', stripped)
            if m:
                return m.group(1)
    return None


def package_dirs(sce: Path, revs: list[str]) -> dict[str, set[str]]:
    """SCE workspace package name -> the directories it has at any of `revs`."""
    dirs: dict[str, set[str]] = {}
    for rev in revs:
        root = show(sce, rev, "Cargo.toml")
        if root is None:
            raise Refused(f"SCE has no root Cargo.toml at {rev}")
        for member in workspace_members(root):
            candidates = [member]
            if member.endswith("/*"):
                prefix = member[:-2]
                listed = git(sce, "ls-tree", "--name-only", f"{rev}:{prefix}", check=False)
                candidates = [f"{prefix}/{d}" for d in listed.stdout.split()]
            for directory in candidates:
                manifest = show(sce, rev, f"{directory}/Cargo.toml")
                name = package_name(manifest) if manifest else None
                if name:
                    dirs.setdefault(name, set()).add(directory.rstrip("/"))
    return dirs


# ── classifying a path, a section, a commit ──────────────────────────────────


@dataclass
class Surface:
    """Where in the SCE tree a change reaches wz, and how."""

    compiled: set[str]  # package directories wz compiles
    generated: set[str]  # package directories only the generator builds

    def classify(self, path: str) -> str:
        if path == GUIDE:
            return GUIDE_CLASS
        if path == "Cargo.toml":
            return RUNTIME
        for directory in self.compiled:
            if _built_part_of(path, directory):
                return RUNTIME
        for directory in self.generated:
            if _built_part_of(path, directory):
                return GENERATOR
        if path.startswith(TEMPLATES) and not _foreign_template(path[len(TEMPLATES) :]):
            return GENERATOR
        return INERT


def _built_part_of(path: str, directory: str) -> bool:
    if not path.startswith(directory + "/"):
        return False
    first = path[len(directory) + 1 :].split("/", 1)[0]
    return first not in NOT_BUILT_FOR_A_DEPENDENT


def _foreign_template(rest: str) -> bool:
    parts = rest.split("/")
    if parts[0] == "forge" and len(parts) > 1:
        return parts[1] in FOREIGN_TEMPLATE_DIRS
    return parts[0] in FOREIGN_TEMPLATE_DIRS


def section_applies(heading: str) -> bool:
    """Whether a guide section is wz's: it names Rust, or no backend at all."""
    return bool(RUST.search(heading)) or not FOREIGN_BACKENDS.search(heading)


def guide_sections(text: str | None) -> dict[str, str]:
    """Heading -> body of each `## ` section of the guide.

    A body is compared without the blank lines around it: a section added after
    another gives that one a blank line it did not end on, which is no amendment.
    """
    sections: dict[str, str] = {}
    if not text:
        return sections
    heading = None
    body: list[str] = []
    for line in text.splitlines():
        if line.startswith("## "):
            if heading is not None:
                sections[heading] = "\n".join(body).strip()
            heading = line[3:].strip()
            body = []
        elif heading is not None:
            body.append(line)
    if heading is not None:
        sections[heading] = "\n".join(body).strip()
    return sections


@dataclass
class Commit:
    sha: str
    subject: str
    paths: list[str]
    classes: set[str] = field(default_factory=set)
    runtime_paths: list[str] = field(default_factory=list)
    added_sections: list[str] = field(default_factory=list)
    amended_sections: list[str] = field(default_factory=list)

    @property
    def applied_sections(self) -> list[str]:
        return [h for h in self.added_sections if section_applies(h)]

    @property
    def foreign_sections(self) -> list[str]:
        return [h for h in self.added_sections if not section_applies(h)]

    @property
    def is_stop(self) -> bool:
        return RUNTIME in self.classes or bool(self.applied_sections)

    def label(self) -> str:
        return ",".join(sorted(self.classes)) if self.classes else INERT


def read_commits(sce: Path, pin: str, target: str, surface: Surface) -> list[Commit]:
    """The first-parent commits of `pin..target`, oldest first, classified."""
    log = git(
        sce,
        "log",
        "--reverse",
        "--first-parent",
        "-m",
        "--no-renames",
        "--name-only",
        "--format=%x00%H%x09%s",
        f"{pin}..{target}",
    ).stdout
    commits: list[Commit] = []
    for record in log.split("\x00")[1:]:
        lines = record.splitlines()
        sha, _, subject = lines[0].partition("\t")
        paths = [p for p in lines[1:] if p.strip()]
        commit = Commit(sha=sha, subject=subject, paths=paths)
        for path in paths:
            cls = surface.classify(path)
            if cls != INERT:
                commit.classes.add(cls)
            if cls == RUNTIME:
                commit.runtime_paths.append(path)
        if GUIDE in paths:
            before = guide_sections(show(sce, f"{sha}^1", GUIDE))
            after = guide_sections(show(sce, sha, GUIDE))
            commit.added_sections = [h for h in after if h not in before]
            commit.amended_sections = [
                h for h in after if h in before and after[h] != before[h] and section_applies(h)
            ]
        commits.append(commit)
    return commits


# ── the plan ────────────────────────────────────────────────────────────────


@dataclass
class Plan:
    pin: str
    target: str
    target_ref: str
    landing: Commit
    tail: bool
    crossed: list[Commit]
    landings_left: int
    commits_ahead: int

    @property
    def short(self) -> str:
        return self.landing.sha[:10]

    def sections(self, kind: str) -> list[tuple[str, str]]:
        return [(h, c.sha[:10]) for c in self.crossed for h in getattr(c, kind)]

    def touches(self, cls: str) -> bool:
        return any(cls in c.classes for c in self.crossed)


def make_plan(
    sce: Path,
    pin: str,
    target_ref: str,
    compiled_packages: set[str],
    generator_packages: set[str],
) -> Plan | None:
    """The next landing after `pin` toward `target_ref`, or None at the target."""
    resolved_pin = git(sce, "rev-parse", "--verify", "--quiet", f"{pin}^{{commit}}", check=False)
    if resolved_pin.returncode != 0:
        raise Refused(f"the pin {pin} is not in the SCE checkout {sce}: fetch it first")
    pin = resolved_pin.stdout.strip()
    target = git(sce, "rev-parse", "--verify", f"{target_ref}^{{commit}}").stdout.strip()
    if pin == target:
        return None
    if git(sce, "merge-base", "--is-ancestor", pin, target, check=False).returncode != 0:
        raise Refused(
            f"the pin {pin[:10]} is not an ancestor of {target_ref} ({target[:10]}): SCE keeps "
            "no branch for an old pin (ADR 0078 section 4), so there is no line to roll along"
        )
    dirs = package_dirs(sce, [pin, target])
    compiled = {d for name in compiled_packages & dirs.keys() for d in dirs[name]}
    generated = {
        d for name in (generator_packages - compiled_packages) & dirs.keys() for d in dirs[name]
    }
    commits = read_commits(sce, pin, target, Surface(compiled=compiled, generated=generated))
    stops = [i for i, c in enumerate(commits) if c.is_stop]
    tail_after_last = (stops[-1] if stops else -1) < len(commits) - 1
    landings_left = len(stops) + (1 if tail_after_last else 0)
    end = stops[0] if stops else len(commits) - 1
    return Plan(
        pin=pin,
        target=target,
        target_ref=target_ref,
        landing=commits[end],
        tail=not stops,
        crossed=commits[: end + 1],
        landings_left=landings_left,
        commits_ahead=len(commits),
    )


def render(plan: Plan, sce: Path, base: str, worktrees: Path) -> str:
    wt = worktrees / f"sce-roll-{plan.short}"
    out: list[str] = []
    say = out.append
    say(
        f"sce-autoroll: pin {plan.pin[:10]}, target {plan.target_ref} = {plan.target[:10]} "
        f"({plan.commits_ahead} commits ahead, {plan.landings_left} landing(s) left)"
    )
    say(f"next landing: {plan.landing.sha} {plan.landing.subject}")
    if plan.tail:
        say("  why: no stop is left before the target, so the target is the last landing")
    else:
        for heading in plan.landing.applied_sections:
            say(f"  why: it adds the guide section \"{heading}\"")
        for path in plan.landing.runtime_paths[:5]:
            say(f"  why: it changes {path}, which wz compiles")
    counts = {cls: sum(1 for c in plan.crossed if cls in c.classes) for cls in (RUNTIME, GENERATOR, GUIDE_CLASS)}
    say(
        f"crosses {len(plan.crossed)} commit(s): {counts[RUNTIME]} runtime, "
        f"{counts[GENERATOR]} generator, {counts[GUIDE_CLASS]} guide"
    )
    for c in plan.crossed:
        say(f"  {c.sha[:10]} [{c.label()}] {c.subject}")
    applied = plan.sections("applied_sections")
    foreign = plan.sections("foreign_sections")
    amended = plan.sections("amended_sections")
    say("guide sections to apply (Rust, or every backend):")
    say("".join(f"  - {h} ({s})\n" for h, s in applied).rstrip("\n") or "  none")
    if foreign:
        say("guide sections of other backends, not applied:")
        say("\n".join(f"  - {h} ({s})" for h, s in foreign))
    if amended:
        say("guide sections amended (re-read what an earlier move applied):")
        say("\n".join(f"  - {h} ({s})" for h, s in amended))
    bisect = [c for c in plan.crossed[:-1] if GENERATOR in c.classes]
    say("commands:")
    say(f"  git -C {sce} fetch origin    # when the checkout is behind {plan.target_ref}")
    say(f"  git worktree add {wt} -b sce-roll/{plan.short} {base}")
    say(f"  cd {wt} && git submodule update --init {SUBMODULE}")
    say(f"  git -C {SUBMODULE} fetch origin && git -C {SUBMODULE} checkout {plan.landing.sha}")
    say(f"  git add {SUBMODULE}    # bx refuses a submodule checked out and not staged")
    say(f"  git -C {SUBMODULE} diff {plan.pin[:10]} {plan.short} -- {GUIDE}")
    say("  bash scripts/regen-codegen.sh --stage1    # every codec is validated before one is written")
    say("  (apply the guide sections above to the call sites)")
    say("  bx --action regen-codegen    # both stages, once wz-session-core compiles")
    say("  git add -- out && git status --porcelain -- out")
    say("checklist:")
    say("  [ ] stage 1 regenerates; a refused document is fixed as its guide section says")
    say("  [ ] out/** read file by file; a change no crossed section explains goes to SCE")
    if plan.touches(RUNTIME) or applied:
        say("  [ ] cargo check --workspace --all-targets through bx, then each touched crate's")
        say("      tests and clippy, and the reduced lanes a workspace check misses:")
        say("      C1h C1g C1m C1ax C1cf C1bnl")
    else:
        say("  [ ] out/** unchanged: the move is the pin alone, held by Layer B2 (regen-diff)")
        say("  [ ] out/** changed: cargo check --workspace --all-targets through bx and the")
        say("      tests of the crates that include the moved files")
    say("  [ ] out/** changed: C1cs size budgets (from a hosted reading), deploy/text_budget.json,")
    say("      stack_frame_gate.py peaks, the kit images (scripts/kit-lane.sh build <image>)")
    say("  [ ] Layer B2: the committed out/** is what the pin regenerates")
    say(f"  [ ] one commit: build(sce): Move the SCE pin to {plan.short}, with out/** and the call sites")
    if bisect:
        say(f"  [ ] a failure no section explains: bisect over the {len(bisect)} generator commit(s) crossed")
    say("  [ ] a section that did not describe what the move met: tell SCE which (ADR 0078 section 4)")
    say("  [ ] then plan again from the new pin")
    return "\n".join(out)


def as_json(plan: Plan) -> str:
    return json.dumps(
        {
            "pin": plan.pin,
            "target": plan.target,
            "target_ref": plan.target_ref,
            "landing": plan.landing.sha,
            "subject": plan.landing.subject,
            "tail": plan.tail,
            "branch": f"sce-roll/{plan.short}",
            "landings_left": plan.landings_left,
            "commits_ahead": plan.commits_ahead,
            "crossed": [
                {
                    "sha": c.sha,
                    "subject": c.subject,
                    "classes": sorted(c.classes),
                    "applied_sections": c.applied_sections,
                    "foreign_sections": c.foreign_sections,
                    "amended_sections": c.amended_sections,
                }
                for c in plan.crossed
            ],
        },
        indent=2,
    )


# ── the wz side ─────────────────────────────────────────────────────────────


def wz_root() -> Path:
    return Path(__file__).resolve().parents[2]


def wz_pin(root: Path) -> str:
    line = git(root, "ls-tree", "HEAD", SUBMODULE).stdout.split()
    if len(line) < 3 or line[1] != "commit":
        raise Refused(f"HEAD carries no gitlink at {SUBMODULE}")
    return line[2]


def wz_lock_packages(root: Path, lock: str) -> set[str]:
    path = root / lock
    if not path.is_file():
        raise Refused(f"{lock} is missing: the packages wz builds are read from it")
    return path_packages(path.read_text(encoding="utf-8"))


def default_worktrees(root: Path) -> Path:
    common = git(root, "rev-parse", "--path-format=absolute", "--git-common-dir").stdout.strip()
    return Path(common).parent.parent / "wz-wt"


def cmd_plan(argv: list[str]) -> int:
    opts = {"--sce": None, "--target": "origin/main", "--pin": None, "--base": "origin/main", "--worktrees": None}
    want_json = False
    i = 0
    while i < len(argv):
        arg = argv[i]
        if arg == "--json":
            want_json = True
            i += 1
            continue
        if arg not in opts or i + 1 >= len(argv):
            print(f"sce-autoroll: unknown or incomplete argument '{arg}'", file=sys.stderr)
            return 2
        opts[arg] = argv[i + 1]
        i += 2
    root = wz_root()
    sce = Path(opts["--sce"]) if opts["--sce"] else root / SUBMODULE
    try:
        pin = opts["--pin"] or wz_pin(root)
        compiled = wz_lock_packages(root, COMPILE_LOCK)
        generator = wz_lock_packages(root, GENERATE_LOCK)
        plan = make_plan(sce, pin, opts["--target"], compiled, generator)
        if plan is None:
            print(f"sce-autoroll: the pin {pin[:10]} is {opts['--target']}; nothing to roll")
            return 0
        worktrees = Path(opts["--worktrees"]) if opts["--worktrees"] else default_worktrees(root)
    except Refused as refusal:
        print(f"sce-autoroll: REFUSED -- {refusal}", file=sys.stderr)
        return 1
    print(as_json(plan) if want_json else render(plan, sce, opts["--base"], worktrees))
    return 0


# ── selftest ────────────────────────────────────────────────────────────────


def _commit(repo: Path, message: str, files: dict[str, str]) -> str:
    for rel, text in files.items():
        path = repo / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    git(repo, "add", "-A")
    git(
        repo,
        "-c",
        "user.name=selftest",
        "-c",
        "user.email=selftest@example.invalid",
        "-c",
        "commit.gpgsign=false",
        "-c",
        "core.hooksPath=/dev/null",
        "commit",
        "-q",
        "-m",
        message,
    )
    return git(repo, "rev-parse", "HEAD").stdout.strip()


GUIDE_HEAD = "# Codec API changes a downstream consumer makes\n\nPreamble.\n\n"


def _fixture(repo: Path) -> dict[str, str]:
    git(repo, "init", "-q")
    # Named outright: the machine's `init.defaultBranch` is not the fixture's to depend on.
    git(repo, "symbolic-ref", "HEAD", "refs/heads/main")
    shas: dict[str, str] = {}
    shas["c0"] = _commit(
        repo,
        "chore: the tree",
        {
            "Cargo.toml": (
                "[workspace]\nmembers = [\n"
                '    "backends/rust/forge-runtime", # the runtime\n'
                '    "backends/rust/lua",\n'
                '    "sce-build",\n]\n'
            ),
            "backends/rust/forge-runtime/Cargo.toml": '[package]\nname = "sce-forge-runtime"\n',
            "backends/rust/forge-runtime/src/lib.rs": "",
            "backends/rust/lua/Cargo.toml": '[package]\nname = "sce-rust-lua"\n',
            "backends/rust/lua/src/lib.rs": "",
            "sce-build/Cargo.toml": '[package]\nname = "sce-build"\n\n[dependencies]\nname = "x"\n',
            "sce-build/src/lib.rs": "",
            GUIDE: GUIDE_HEAD + "## Old section (ADR 1)\n\nBody.\n",
        },
    )
    shas["c1"] = _commit(repo, "docs: a note", {"docs/notes.md": "x\n"})
    shas["c2"] = _commit(repo, "feat: the generator", {"sce-build/src/lib.rs": "// 1\n"})
    shas["c3"] = _commit(
        repo,
        "feat: a C++ section",
        {
            GUIDE: GUIDE_HEAD
            + "## Old section (ADR 1)\n\nBody.\n\n## A printed C++ codec holds X (ADR 2)\n\nC++.\n",
            "tools/codegen/templates/forge/cpp/a.jinja2": "x\n",
            "sce-build/tests/t.rs": "",
        },
    )
    shas["c4"] = _commit(repo, "feat: the runtime", {"backends/rust/forge-runtime/src/lib.rs": "// 1\n"})
    shas["c5"] = _commit(
        repo,
        "test: what wz does not build",
        {"backends/rust/forge-runtime/tests/t.rs": "", "backends/rust/lua/src/lib.rs": "// 1\n"},
    )
    shas["c6"] = _commit(
        repo,
        "feat: a section for every backend",
        {
            GUIDE: GUIDE_HEAD
            + "## Old section (ADR 1)\n\nBody, corrected.\n\n"
            + "## A printed C++ codec holds X (ADR 2)\n\nC++.\n\n"
            + "## A list states its bound only where the protocol does (ADR 3)\n\nAll.\n",
            "tools/codegen/templates/forge/rust/a.jinja2": "x\n",
        },
    )
    shas["c7"] = _commit(repo, "feat: a Rust template", {"tools/codegen/templates/rust/b.jinja2": "x\n"})
    git(repo, "checkout", "-q", "-b", "side", shas["c2"])
    shas["s1"] = _commit(repo, "feat: off the line", {"docs/side.md": "x\n"})
    git(repo, "checkout", "-q", "main")
    return shas


def selftest() -> bool:
    failures: list[str] = []

    def check(ok: bool, what: str) -> None:
        if not ok:
            failures.append(what)

    # The readers.
    lock = (
        '[[package]]\nname = "sce-forge-runtime"\nversion = "0.1.0"\n\n'
        '[[package]]\nname = "heapless"\nversion = "0.8.0"\n'
        'source = "registry+https://github.com/rust-lang/crates.io-index"\n\n'
        '[[package]]\nname = "wz-codecs"\nversion = "0.1.0"\ndependencies = [\n "heapless",\n]\n'
    )
    check(path_packages(lock) == {"sce-forge-runtime", "wz-codecs"}, "a lock's path packages")
    check(
        workspace_members('[workspace]\nmembers = [\n  "a", # x "y"\n  "b",\n]\n') == ["a", "b"],
        "a workspace's members, a comment and a trailing comma aside",
    )
    check(
        package_name('[workspace]\nname = "no"\n[package]\nname = "yes"\n') == "yes",
        "the name of [package], not of another table",
    )
    for heading, applies in [
        ("A Rust machine holds a list's bound in its type (ADR 0086 §7.4)", True),
        ("A codec whose list states no bound has no eager form at the default profile", True),
        ("Make the standard date expression a union that resolve_date takes", True),
        ("A Good name is not a backend", True),
        ("A printed C++ codec presents its elements through accessors", False),
        ("A C11 statechart holds the storage of its calls", False),
        ("Say what a Kotlin Mesh host writes", False),
    ]:
        check(section_applies(heading) == applies, f"section_applies({heading!r})")
    surface = Surface(compiled={"backends/rust/forge-runtime"}, generated={"sce-build"})
    for path, cls in [
        ("backends/rust/forge-runtime/src/lib.rs", RUNTIME),
        ("backends/rust/forge-runtime/Cargo.toml", RUNTIME),
        ("backends/rust/forge-runtime/tests/t.rs", INERT),
        ("backends/rust/forge-runtimes/src/lib.rs", INERT),
        ("Cargo.toml", RUNTIME),
        ("sce-build/src/forge/generator.rs", GENERATOR),
        ("sce-build/examples/e.rs", INERT),
        ("tools/codegen/templates/forge/rust/codec.rs.jinja2", GENERATOR),
        ("tools/codegen/templates/state_machine.jinja2", GENERATOR),
        ("tools/codegen/templates/forge/cpp/codec.hpp.jinja2", INERT),
        ("tools/codegen/templates/kotlin/m.kt.jinja2", INERT),
        (GUIDE, GUIDE_CLASS),
        ("docs/adr/0078.md", INERT),
    ]:
        check(surface.classify(path) == cls, f"classify({path!r}) == {cls}")

    # A history, rolled.
    scratch = Path(tempfile.mkdtemp(prefix="sce-autoroll-selftest-"))
    try:
        repo = scratch / "sce"
        repo.mkdir()
        s = _fixture(repo)
        compiled = {"sce-forge-runtime", "wz-codecs"}
        generator = {"sce-build", "sce-forge-runtime", "xtask"}

        first = make_plan(repo, s["c0"], "main", compiled, generator)
        check(first is not None and first.landing.sha == s["c4"], "from c0 the runtime commit is the stop")
        if first is not None:
            check([c.sha for c in first.crossed] == [s[k] for k in ("c1", "c2", "c3", "c4")], "c1..c4 crossed")
            labels = [c.label() for c in first.crossed]
            check(labels == [INERT, GENERATOR, GUIDE_CLASS, RUNTIME], f"the classes of c1..c4: {labels}")
            check(first.sections("foreign_sections") == [("A printed C++ codec holds X (ADR 2)", s["c3"][:10])],
                  "the C++ section is listed and not a stop")
            check(first.sections("applied_sections") == [], "no section to apply from c0")
            check(first.landings_left == 3, f"three landings left from c0: {first.landings_left}")
            check(not first.tail, "a stop is no tail")
            text = render(first, repo, "origin/main", scratch / "wt")
            check(f"sce-roll/{s['c4'][:10]}" in text and "C1bnl" in text, "the plan names the branch and lanes")
            check("bisect over the 1 generator commit(s)" in text, "the plan offers the bisect of c2")
            check(json.loads(as_json(first))["landing"] == s["c4"], "the json names the landing")

        second = make_plan(repo, s["c4"], "main", compiled, generator)
        check(second is not None and second.landing.sha == s["c6"], "from c4 the section for every backend is the stop")
        if second is not None:
            check(second.crossed[0].label() == INERT, "what wz does not build is inert")
            check(second.sections("applied_sections")
                  == [("A list states its bound only where the protocol does (ADR 3)", s["c6"][:10])],
                  "the section to apply")
            check(second.sections("amended_sections") == [("Old section (ADR 1)", s["c6"][:10])],
                  "the amended section")
            check(second.landings_left == 2, "two landings left from c4")

        tail = make_plan(repo, s["c6"], "main", compiled, generator)
        check(tail is not None and tail.tail and tail.landing.sha == s["c7"], "from c6 the target is the tail")
        check(tail is not None and tail.landings_left == 1, "one landing left from c6")

        check(make_plan(repo, s["c7"], "main", compiled, generator) is None, "at the target nothing is rolled")

        # The control: the stop at c4 comes from wz's lock, not from the path alone. A wz that
        # compiles no SCE package crosses c4 as the generator's and stops at c6.
        control = make_plan(repo, s["c0"], "main", set(), generator)
        check(control is not None and control.landing.sha == s["c6"], "without the runtime in the lock, c6")
        if control is not None:
            check(GENERATOR in control.crossed[3].classes, "c4 is the generator's when only it builds the runtime")

        try:
            make_plan(repo, s["s1"], "main", compiled, generator)
            check(False, "a pin off the line is refused")
        except Refused as refusal:
            check("not an ancestor" in str(refusal), f"the refusal says why: {refusal}")
        try:
            make_plan(repo, "0" * 40, "main", compiled, generator)
            check(False, "a pin the checkout lacks is refused")
        except Refused as refusal:
            check("fetch it first" in str(refusal), f"the refusal says to fetch: {refusal}")
    finally:
        shutil.rmtree(scratch, ignore_errors=True)

    for what in failures:
        print(f"sce-autoroll selftest: FAIL -- {what}", file=sys.stderr)
    if not failures:
        print("sce-autoroll selftest: ok")
    return not failures


def main(argv: list[str]) -> int:
    if argv[:1] == ["--selftest"]:
        return 0 if selftest() else 1
    if argv[:1] == ["plan"]:
        return cmd_plan(argv[1:])
    print(__doc__.split("Usage:", 1)[1].rstrip(), file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
