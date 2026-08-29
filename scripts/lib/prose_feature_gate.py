#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

"""R2190 (no register item) — A CARGO COMMAND WRITTEN DOWN IN THIS TREE NAMES
FEATURES THAT EXIST.

## It closes no register item, and that is the honest citation

Open-debt item 530 is "prose that contradicts a DERIVED fact has no
instrument". This is AN instrument for ONE family of that class and not for
the class, so 530 stays open and this header does not claim it. The
provenance convention has a form for exactly this position and it is the one
used here.

## The class, and the one instrument this file is

Item 530 is "prose that contradicts a DERIVED fact has no instrument". Its two
measured cases:

1. R2105 — `run-ci.sh` and `xtask/src/main.rs` both said a plain `cargo build`
   "needs no libxml2/SCE toolchain" while `cargo tree -e normal,build -i
   libxml --workspace` said the opposite, and the `portability` job said the
   right thing. The tree contradicted itself and a downstream consumer
   believed the wrong half.
2. R2161 — a cargo FEATURE was renamed. Every LOADED site was caught by
   something: `#[cfg]` by rustc's `unexpected_cfgs`, the manifests by cargo's
   own resolve, the gate tables by `--census` / `--all-legs`. **The comments
   were caught by nothing.**

This file is an instrument for the second case and not the first. A cargo
invocation is a form prose ALREADY uses, so nothing has to be marked and there
is no escape hatch in the marking; the package is resolved and every feature
it names is adjudicated against `cargo metadata`.

## Why not a banned-phrase grep, which item 530 measured rather than argued

A gate banning the old name would have redded R2161's OWN commit: that round
quoted the retired spelling three times on purpose, to describe the rename.
Prose that describes a rename correctly and prose that failed to follow it are
indistinguishable to a phrase list — which is why the answer is to adjudicate
a FORM against a derivation rather than to forbid a string.

## What is out of the population, and why it is a rule rather than a taste

`docs/.atomic/**` is the frozen audit ledger. Retroactively rewriting an entry
is this workspace's own named anti-pattern, so an entry quoting a name that
has since been retired is CORRECT and must stay. A gate that made the store a
subject would demand exactly the edit the store forbids.

## What it does NOT cover, so the green is not read wider than it is

The first measured case above. "A plain `cargo build` needs no libxml2" is a
claim about the DEPENDENCY GRAPH written in free prose, with no form to
adjudicate. Item 530 stays open for it; this file narrows the item and does
not close it.

⚠ AND THIS FILE CANNOT CONTAIN A FALSE EXAMPLE. It is tracked, so the scan
reads it: writing `cargo test -p <pkg> --features <a-name-that-is-not-one>`
here to illustrate the defect would red the gate on its own explanation. The
selftest's fixture is therefore written to a temporary directory, and the
prose above describes the shape instead of spelling one.
"""

from __future__ import annotations

import json
import pathlib
import re
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[2]
CRATES = ROOT / "crates"

# `cargo <verb> ... --features <list>`, on one line. The verbs are the ones
# that take `--features`; `cargo metadata` and `cargo fmt` do not.
CMD = re.compile(
    r"cargo\s+(?:\+\S+\s+)?(?:test|build|check|clippy|run|doc|tree)\b([^\n]*)"
)
PKG = re.compile(r"(?:-p|--package)[= ]+([A-Za-z0-9_-]+)")
FEAT = re.compile(r"--features[= ]+([A-Za-z0-9_,./-]+)")

# A site whose package cannot be resolved, with WHY. Keyed by (path, token) so
# a line move does not invalidate it.
#
# BOTH DIRECTIONS ARE CHECKED. An undeclared unresolved site is a FAIL, so the
# population cannot grow in silence; a declared entry that no longer occurs is
# also a FAIL, so the list cannot rot into a permission slip. That is the
# `ext_name::DECLARED_EMPTY` shape, which this workspace already trusts.
UNRESOLVED_DECLARED: dict[tuple[str, str], str] = {
    ("scripts/build-sce.sh", "cli"): (
        "builds SCE's own `sce-codegen` after `cd \"$SCE_DIR\"`, so the package "
        "is a vendored foreign crate and this workspace's metadata cannot "
        "adjudicate its features"
    ),
    ("scripts/lib/guarded_count_gate.py", "zenoh-config"): (
        "a FIXTURE string naming an invented package (`demo-crate`), which is "
        "that gate's own test input rather than a command anyone runs"
    ),
    ("scripts/lib/guarded_count_gate.py", "x"): (
        "the same fixture, second invented package (`other-crate`)"
    ),
    ("scripts/run-ci.sh", "transport-link-vsock"): (
        "prose quoting the environment-gated vsock command; the quote carries "
        "no `-p` and `run-ci.sh` belongs to no crate, so the package is "
        "implied by the paragraph rather than written"
    ),
    ("scripts/run-ci.sh", "scouting-static"): (
        "a layer BANNER (`Layer C1k — cargo test ... --features "
        "scouting-static`), which names the lane rather than issuing it"
    ),
    ("scripts/run-ci.sh", "transport-multilink"): (
        "prose quoting the demo-cfg-site clippy step, again without a `-p`"
    ),
}


def metadata() -> tuple[dict[str, set[str]], dict[str, str]]:
    """(package -> its features, manifest dir -> package).

    `--no-deps`, because the subject is what THIS workspace declares; a
    dependency's features are adjudicated by cargo at build time and by the
    `<dep>/<feature>` form below.
    """
    out = subprocess.run(
        ["cargo", "metadata", "--no-deps", "--format-version", "1"],
        cwd=CRATES,
        capture_output=True,
        text=True,
    )
    if out.returncode != 0:
        raise RuntimeError(f"cargo metadata failed: {out.stderr[:400]}")
    meta = json.loads(out.stdout)
    feats = {p["name"]: set(p["features"]) for p in meta["packages"]}
    dirs = {}
    for p in meta["packages"]:
        d = pathlib.Path(p["manifest_path"]).parent
        try:
            dirs[str(d.relative_to(ROOT))] = p["name"]
        except ValueError:
            continue
    return feats, dirs


def tracked_files() -> list[str]:
    out = subprocess.run(
        ["git", "ls-files"], cwd=ROOT, capture_output=True, text=True
    )
    return out.stdout.split()


def owner(path: str, dirs: dict[str, str]) -> str | None:
    """The crate a file lives in, so a command with no `-p` still resolves."""
    best = None
    for d, name in dirs.items():
        if path.startswith(d + "/") and (best is None or len(d) > len(best[0])):
            best = (d, name)
    return best[1] if best else None


def scan(
    root: pathlib.Path, files: list[str], feats: dict[str, set[str]], dirs: dict[str, str]
) -> tuple[int, list[str], list[tuple[str, str, int]]]:
    """(sites adjudicated, findings, unresolved sites as (path, token, line))."""
    adjudicated = 0
    findings: list[str] = []
    unresolved: list[tuple[str, str, int]] = []
    for rel in files:
        path = root / rel
        # The frozen ledger is not a subject; see the module doc.
        if rel.startswith("docs/.atomic/") or not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        for m in CMD.finditer(text):
            fm = FEAT.search(m.group(1))
            if fm is None:
                continue
            line = text[: m.start()].count("\n") + 1
            pm = PKG.search(m.group(1))
            pkg = pm.group(1) if pm else owner(rel, dirs)
            tokens = [
                t.strip().rstrip(".,;:")
                for t in fm.group(1).split(",")
                if t.strip().rstrip(".,;:")
            ]
            if pkg is None or pkg not in feats:
                for t in tokens:
                    unresolved.append((rel, t, line))
                continue
            for t in tokens:
                # `<dep>/<feature>` is a dependency's feature; cargo itself
                # refuses an unknown one at build time, and this workspace's
                # metadata has no standing to judge it.
                if "/" in t:
                    continue
                adjudicated += 1
                if t not in feats[pkg]:
                    findings.append(
                        f"{rel}:{line}: `cargo ... -p {pkg} --features {t}` names a "
                        f"feature `{pkg}` does not have. A command written down and "
                        f"not run is prose, and this is the one shape of it a "
                        f"derivation can adjudicate -- item 530's second measured "
                        f"case, where a rename was caught everywhere except the "
                        f"comments."
                    )
    return adjudicated, findings, unresolved


def check() -> int:
    feats, dirs = metadata()
    adjudicated, findings, unresolved = scan(ROOT, tracked_files(), feats, dirs)
    if adjudicated == 0:
        print(
            "prose-features: FAIL -- no cargo command in this tree names a "
            "workspace feature, so the arms below would report clean over an "
            "empty population"
        )
        return 1
    seen = {(rel, tok) for rel, tok, _ in unresolved}
    for rel, tok, line in unresolved:
        if (rel, tok) not in UNRESOLVED_DECLARED:
            findings.append(
                f"{rel}:{line}: `--features {tok}` on a command whose package this "
                f"gate cannot resolve, and which is not declared. Unclassified is "
                f"not a pass: give it a `-p <package>`, or declare it in "
                f"`UNRESOLVED_DECLARED` with the reason it cannot be resolved."
            )
    for key, why in sorted(UNRESOLVED_DECLARED.items()):
        if key not in seen:
            findings.append(
                f"{key[0]}: `--features {key[1]}` is declared unresolvable ({why}) "
                f"and no longer occurs. A declaration that outlives its subject is "
                f"a permission slip nobody re-reads; delete the entry."
            )
    if findings:
        print(f"prose-features: FAIL -- {len(findings)} finding(s)")
        for f in findings:
            print(f"  {f}")
        return 1
    print(
        f"prose-features: {adjudicated} feature name(s) in written-down cargo "
        f"commands all exist, {len(UNRESOLVED_DECLARED)} site(s) declared "
        f"unresolvable and all still present"
    )
    return 0


# ⚠ ASSEMBLED, NEVER SPELLED, and this is the file's own rule met the hard
# way. Written out as literals these four lines are read by `--check`, because
# `git ls-files` lists this file the moment it is committed -- so the gate was
# green while UNTRACKED and red on its first commit, with its own fixtures as
# the findings. An untracked gate cannot see itself, and that is not the same
# green as a tracked one's.
_C, _P, _F = "car" "go test", "-p demo", "--fea" "tures"
FIXTURE_OK = f"{_C} {_P} {_F} alpha --quiet\n"
FIXTURE_BAD = f"{_C} {_P} {_F} nosuch --quiet\n"
FIXTURE_DEP = f"{_C} {_P} {_F} other/thing --quiet\n"
FIXTURE_UNRESOLVED = f"{_C} {_F} alpha --quiet\n"


def selftest() -> int:
    """Both directions, on a fixture the production scan never sees.

    ⚠ The fixture is written to a TEMPORARY directory rather than kept in this
    file, and that is not tidiness: this file is tracked, so a false command
    spelled here would be read by `--check` and red the gate on its own
    explanation. Which is also item 530's own lesson about phrase lists, met
    from the other side.
    """
    feats = {"demo": {"alpha", "beta"}}
    dirs: dict[str, str] = {}
    with tempfile.TemporaryDirectory() as tmp:
        home = pathlib.Path(tmp)
        (home / "ok.sh").write_text(FIXTURE_OK, encoding="utf-8")
        (home / "bad.sh").write_text(FIXTURE_BAD, encoding="utf-8")
        (home / "dep.sh").write_text(FIXTURE_DEP, encoding="utf-8")
        (home / "amb.sh").write_text(FIXTURE_UNRESOLVED, encoding="utf-8")
        files = ["ok.sh", "bad.sh", "dep.sh", "amb.sh"]
        adjudicated, findings, unresolved = scan(home, files, feats, dirs)
        if adjudicated != 2:
            print(
                f"prose-features: SELFTEST FAIL -- the fixture offers two "
                f"adjudicable names (`alpha` and `nosuch`) and the scan "
                f"adjudicated {adjudicated}; a dependency feature must be "
                f"skipped and an unresolvable one must not be counted"
            )
            return 1
        if len(findings) != 1 or "nosuch" not in findings[0]:
            print(
                f"prose-features: SELFTEST FAIL -- expected exactly the "
                f"`nosuch` finding and got {findings}"
            )
            return 1
        if [(f, t) for f, t, _ in unresolved] != [("amb.sh", "alpha")]:
            print(
                f"prose-features: SELFTEST FAIL -- a command with no `-p` in a "
                f"file belonging to no crate must be reported unresolved, and "
                f"the scan said {unresolved}"
            )
            return 1
    print(
        "prose-features: selftest OK -- catches an absent name, spares a real "
        "one, skips a dependency feature, and refuses to guess a package"
    )
    return 0


def main(argv: list[str]) -> int:
    if len(argv) != 1 or argv[0] not in {"--check", "--selftest"}:
        print("usage: prose_feature_gate.py --check | --selftest")
        return 2
    return selftest() if argv[0] == "--selftest" else check()


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
