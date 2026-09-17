#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
"""R2686 (no register item) — the ONE derivation of "which cargo packages does
this push touch".

The citation is `no register item` for the reason `changed_gate_selftests.py`
and `round_fed_gate_reach.py` both give for theirs: the class this closes is
recorded in the operator's agent-memory register
(`project_prepush_preflight_has_no_structure`), which carries no store `debt-`
id for `gate_provenance_lint` to resolve. Open-debt item 742 is a NEIGHBOUR,
not this: 742 says so itself -- "the same subject, but that record covers only
gate 3's changed-crate derivation, and re-measured that is one of 43".

`.githooks/pre-push` computes that set INLINE, in shell, for gate 3
(changed-crate tests) and again -- expanded through `doclink_dependents.py` --
for gate 4 (Layer C1bz doc links). Until this module there was no entry point
for it, so anyone preparing a push had to RE-DERIVE the set by hand, and the
hand derivation is what keeps being wrong.

## The measurements this is built on, in the order they were taken

R2682 pre-ran Layer C1bz, derived its crate set from a PREFIX of the push
rather than from the push's final range, checked 10 crates where the hook
checked 25, and lost the push to a doc-link finding in the 15 it never looked
at. `MEMORY.md` had already recorded the class ("you lose a push even KNOWING
the rule, so what is missing is structure, not care") AND this design, before
that round started.

R2686 then reproduced the same defect a SECOND way while paying that round's
ratchets, which is why this module resolves the range rather than only mapping
paths to packages. Told by R2682's carry to compute the count-guard selection
with `guarded_count_gate`'s own pure functions, it did -- substituting a
one-line reader for the gate's `_read_worktree`, which resolves `crates/<dir>/
<rel>` where the substitute resolved `<rel>` against the process CWD. Every
read came back empty, `select()` has no way to tell an unreadable file from one
with no matching tests, and the population came out 10 where the gate's own
`--range` reported 33. It printed no error. 70% under, silently, in the same
direction as R2682's 10-of-25.

⇒ The lesson is not "re-derive more carefully". A re-derivation IS a second
implementation of the population, and both of this repository's measured
attempts under-reported. The rule this module exists to make followable:

    call the gate's own entry point; never recompute its population.

`guarded_count_gate.py` already HAS one (`--range`). The hook's changed-crate
set did not, and that is the gap here.

## Why the RANGE is resolved here and not left to the caller

Substituting the mapping was R2686's error; substituting the range was R2682's.
A shared path-to-package function would have fixed neither, because the caller
still has to name the range, and the range a preflight wants is not one a human
picks -- it is the one git will hand the hook on stdin: `<remote sha>..<pushed
sha>`. So with no `--range`, this resolves it the way the hook will see it,
`git ls-remote` first because that is the authoritative remote tip and the
local `origin/<branch>` ref can be stale. A caller that supplies nothing cannot
supply a prefix.

`branch.main.remote` is empty in this clone, so `origin/<branch>` is the
fallback and there is no upstream to read.

## What emptiness means, which is not one thing

A push touching no `crates/` path yields an EMPTY package list, and that is a
fact about the push, not a failure -- the hook skips gate 3 on it. So this
exits 0 printing nothing there. But a NON-EMPTY package list whose `--doc-links`
expansion comes back empty is the zero-population failure the hook already
refuses to report clean on, and this refuses it too, at the place that computed
it. The hook keeps its own check: two cheap refusals for one class beats moving
one.
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
CRATES = REPO_ROOT / "crates"
DOCLINK = Path(__file__).resolve().parent / "doclink_dependents.py"

# `crates/<dir>/<anything>` -- the hook's own spelling, kept identical so the
# two cannot drift while both exist.
_CRATE_DIR_RE = re.compile(r"^crates/([^/]+)/")
# `name = "pkg"` at the start of a line, first match wins, as the hook's sed does.
_PKG_NAME_RE = re.compile(r'^name\s*=\s*"([^"]+)"', re.MULTILINE)


def _git(args, cwd=None):
    """Run git, returning stdout or None when it fails. Never raises."""
    try:
        out = subprocess.run(
            ["git", *args],
            cwd=str(cwd or REPO_ROOT),
            capture_output=True,
            text=True,
            check=False,
        )
    except OSError:
        return None
    if out.returncode != 0:
        return None
    return out.stdout


def current_branch(cwd=None):
    out = _git(["rev-parse", "--abbrev-ref", "HEAD"], cwd=cwd)
    return out.strip() if out else ""


def resolve_range(explicit=None, cwd=None, notes=None):
    """The diff range this push will be graded over.

    `explicit` wins -- that is the hook, which is HANDED the range by git and
    must not go asking the network for one. Otherwise resolve the same shape
    the hook will receive: the remote tip of this branch, then HEAD.

    Returns the range string, or None when the base cannot be established. It
    refuses rather than guessing: a wrong base is exactly the defect.
    """
    if explicit:
        return explicit
    say = notes.append if notes is not None else (lambda _m: None)
    branch = current_branch(cwd=cwd)
    if not branch or branch == "HEAD":
        say("cannot resolve a branch name (detached HEAD?); pass --range")
        return None
    ls = _git(["ls-remote", "origin", branch], cwd=cwd)
    if ls:
        sha = ls.split("\t", 1)[0].strip() if "\t" in ls else ls.split()[0].strip()
        if re.fullmatch(r"[0-9a-f]{40}", sha or ""):
            return f"{sha}..HEAD"
        say(f"`git ls-remote origin {branch}` returned no usable sha")
    else:
        say(f"`git ls-remote origin {branch}` failed; falling back to origin/{branch}")
    if _git(["rev-parse", "--verify", f"origin/{branch}"], cwd=cwd):
        say(f"using the local ref origin/{branch}, which may be STALE")
        return f"origin/{branch}..HEAD"
    say(f"no remote base for {branch}: neither ls-remote nor origin/{branch}")
    return None


def changed_crate_dirs(rng, cwd=None):
    """The `crates/<dir>` directories this range touches, sorted and unique."""
    out = _git(["diff", "--name-only", rng, "--", "crates/"], cwd=cwd)
    if out is None:
        return None
    dirs = set()
    for line in out.splitlines():
        m = _CRATE_DIR_RE.match(line.strip())
        if m:
            dirs.add(m.group(1))
    return sorted(dirs)


def packages_for_dirs(dirs, crates_root=None, notes=None):
    """Map crate DIRS to cargo PACKAGE names.

    dir != package is rare but allowed, so the manifest is what answers. A dir
    whose `Cargo.toml` is gone (renamed or deleted inside the range) is skipped
    with a note rather than failing -- the hook's behaviour, kept.
    """
    root = Path(crates_root) if crates_root else CRATES
    say = notes.append if notes is not None else (lambda _m: None)
    pkgs = []
    for d in dirs:
        manifest = root / d / "Cargo.toml"
        if not manifest.is_file():
            say(f"crates/{d} — Cargo.toml gone (renamed/deleted), skipping")
            continue
        try:
            text = manifest.read_text()
        except OSError:
            say(f"crates/{d} — Cargo.toml unreadable, skipping")
            continue
        m = _PKG_NAME_RE.search(text)
        if m:
            pkgs.append(m.group(1))
        else:
            say(f"crates/{d} — Cargo.toml names no package, skipping")
    return pkgs


def doc_link_expansion(pkgs):
    """Expand to every crate whose DOCS link into one of `pkgs`.

    Shells out to `doclink_dependents.py` rather than reimplementing it, for
    this module's own reason: a second implementation of a population is the
    defect. Returns None when that gate could not be run at all.
    """
    if not pkgs:
        return []
    try:
        out = subprocess.run(
            [sys.executable, str(DOCLINK), *pkgs],
            capture_output=True,
            text=True,
            check=False,
        )
    except OSError:
        return None
    if out.returncode != 0:
        return None
    return [p.strip() for p in out.stdout.splitlines() if p.strip()]


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="the cargo packages a push touches (and, with --doc-links, "
        "the Layer C1bz population over them)"
    )
    ap.add_argument(
        "--range",
        dest="rng",
        default=None,
        help="diff range; default is the range the pre-push hook will be given "
        "(`<remote tip of this branch>..HEAD`)",
    )
    ap.add_argument(
        "--doc-links",
        action="store_true",
        help="print the doc-link expansion instead: the value for WZ_C1BZ_ONLY",
    )
    ap.add_argument(
        "--print-range",
        action="store_true",
        help="print the resolved range and exit, so a caller can SEE what it got",
    )
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args(argv)

    if args.selftest:
        return selftest()

    notes = []
    rng = resolve_range(args.rng, notes=notes)
    for n in notes:
        print(f"changed-crate-packages: {n}", file=sys.stderr)
    if rng is None:
        return 2
    if args.print_range:
        print(rng)
        return 0

    dirs = changed_crate_dirs(rng)
    if dirs is None:
        print(
            f"changed-crate-packages: `git diff {rng}` failed — the range does "
            "not resolve in this clone, so nothing here measured anything.",
            file=sys.stderr,
        )
        return 2
    if not dirs:
        # A push touching no crate. A FACT about the push, not a failure: the
        # hook skips gate 3 on exactly this, and gate 4 never runs.
        return 0

    notes = []
    pkgs = packages_for_dirs(dirs, notes=notes)
    for n in notes:
        print(f"changed-crate-packages: {n}", file=sys.stderr)
    if not pkgs:
        return 0

    if not args.doc_links:
        for p in pkgs:
            print(p)
        return 0

    expanded = doc_link_expansion(pkgs)
    if expanded is None:
        print(
            "changed-crate-packages: doclink_dependents.py could not be run — "
            "refusing to print a doc-link population nothing computed.",
            file=sys.stderr,
        )
        return 2
    if not expanded:
        # Zero population out of a NON-empty input: the failure the hook's
        # gate 4 refuses to report clean on, refused here too.
        print(
            f"changed-crate-packages: {len(pkgs)} changed package(s) expanded to "
            "NO doc-link crate — refusing to report a clean surface over an "
            "empty population.",
            file=sys.stderr,
        )
        return 1
    for p in expanded:
        print(p)
    return 0


def selftest():
    import tempfile

    failures = []

    def check(name, cond, detail=""):
        if not cond:
            failures.append(f"{name}: {detail}")

    # ── the crates/<dir> match, including what it must NOT match ──
    sample = [
        "crates/wz-runtime-tokio/src/router_forward.rs",
        "crates/wz-ap-demo/Cargo.toml",
        "crates/wz-runtime-tokio/src/lib.rs",
        "crates/loose-file-at-top",  # no trailing slash: not a crate dir
        "docs/.atomic/workspace.atomic.json",
        "scripts/run-ci.sh",
    ]
    got = sorted({m.group(1) for m in (_CRATE_DIR_RE.match(s) for s in sample) if m})
    check(
        "dir-match",
        got == ["wz-ap-demo", "wz-runtime-tokio"],
        f"expected two crate dirs, got {got}",
    )

    # ── dir -> package, including dir != package and a vanished manifest ──
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        (root / "alpha-dir").mkdir()
        (root / "alpha-dir" / "Cargo.toml").write_text(
            '[package]\nname = "alpha-pkg"\nversion = "0.1.0"\n'
        )
        (root / "gone-dir").mkdir()  # no Cargo.toml: renamed/deleted in the range
        (root / "nameless-dir").mkdir()
        (root / "nameless-dir" / "Cargo.toml").write_text("[workspace]\n")
        notes = []
        pkgs = packages_for_dirs(
            ["alpha-dir", "gone-dir", "nameless-dir"], crates_root=root, notes=notes
        )
        check(
            "dir-ne-package",
            pkgs == ["alpha-pkg"],
            f"the manifest must answer, not the dir name; got {pkgs}",
        )
        check(
            "skips-are-said",
            len(notes) == 2,
            f"a skipped dir must produce a note; got {len(notes)}: {notes}",
        )

        # ANTI-VACUITY: a non-empty input yielding nothing must be visible as
        # nothing, never as a clean answer. This is the arm that fails if the
        # mapping ever silently swallows its input -- R2686's own defect shape.
        notes2 = []
        empty = packages_for_dirs(["gone-dir"], crates_root=root, notes=notes2)
        check(
            "anti-vacuity",
            empty == [] and len(notes2) == 1,
            f"a fully-skipped input must be empty AND noted; got {empty} / {notes2}",
        )

    # ── an explicit range is passed through untouched, never re-resolved ──
    check(
        "explicit-range-wins",
        resolve_range("abc123..def456") == "abc123..def456",
        "the hook is HANDED its range by git and this must not second-guess it",
    )

    # ── a resolved default range names HEAD, never a bare sha or a prefix ──
    notes3 = []
    auto = resolve_range(None, notes=notes3)
    check(
        "default-range-ends-at-HEAD",
        auto is None or auto.endswith("..HEAD"),
        f"the default range must end at HEAD, not at a prefix; got {auto!r}",
    )

    if failures:
        for f in failures:
            print(f"changed_crate_packages selftest FAIL — {f}", file=sys.stderr)
        return 1
    print("changed_crate_packages selftest: 5 check(s) OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
