#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

"""R2228 (no register item) — how far behind each pinned upstream this tree is,
as a number a command produces rather than one a person happens to ask for.

The citation is `no register item` for the reason `lane_reach_gate.py` gives for
its own: the item this answers — unregistered open-debt item 578 — lives in the
agent-memory register, which has no store `debt-` id for `gate_provenance_lint`
to resolve. Naming it in prose here and `no register item` in the citation is
the honest pair; inventing a store id would make the join it checks a fiction.

## Why this exists, measured

On 2026-08-31 a round judged what "a genuine zenoh does" from a checkout it
never version-checked, and the pin turned out to be five minors old. The
conclusion survived, but it survived because someone ASKED — the user's "isn't
that just because upstream is an old version?" — and nothing in the tree would
have raised it. That is the whole of item 578: this tree's discipline is "cite
file:line for any source claim", and NOBODY MEASURES WHICH RELEASE those lines
were read from.

## What it measures, and why each half is DERIVED rather than listed

Both halves come from somewhere that already exists, because a third list would
be the copy item 567 refused:

* the POPULATION — every repository this tree fetches — from
  `gate_reason_claims.upstream_urls`, which reads the `url` of every submodule
  and every `git clone` in a tracked script or workflow. Seven repositories,
  and note that item 578's own text named TWO (`ZENOHD_VERSION` and the
  vendored pico). Deriving found `zenoh-c` pinned at the same `1.5.0` as zenoh,
  an axis the item did not know it had. That gap is the argument for ②.
* the PIN — from the structure that does the pinning, three shapes, each of
  which this tree actually uses:
    1. a submodule, whose checked-out `git describe --tags` names its base tag;
    2. `git clone --branch "$VAR"` in a script that also writes
       `VAR="${VAR:-VALUE}"`;
    3. `git clone` followed by `checkout "$VAR"` in a workflow whose `env:`
       block writes `VAR: VALUE`.
* the UPSTREAM SIDE — the GitHub releases API. Not a table of known versions;
  the repository's own answer.

## ⛔ A GATE THAT CANNOT MEASURE MUST NOT REPORT GREEN

Item 578's condition ③, and it is the reason this is NOT wired into `pre-push`.
An unreachable API, a missing `gh`, an empty response: each FAILS. The cost is
stated rather than hidden — this lane depends on the network, which no other
lane in this tree does, so a GitHub outage reds a run. That is the trade item
578 asked for in as many words ("못 재는 게이트는 초록을 보고하면 안 된다"),
and the alternative — a SKIP that goes green — is the exact failure this gate
exists to prevent, one layer up.

⚠ `NO_RELEASES` is NOT that escape. It is an OBSERVATION: the API answered, and
its answer was an empty list. The two are told apart by whether the call
succeeded, and a repository classified `NO_RELEASES` must ALSO fail to yield a
pin — `vendor/sce` has no tags at all, so `git describe` and the releases API
agree about it. A repository that has releases but whose pin cannot be derived
is RED, which is the direction that keeps the classification from being a
declaration.

## The verdicts, and why they are pinned in BOTH directions

`DISTANCE` below is not a budget somebody chose; it is the measurement, frozen.
One more release upstream and the number rises and this reds — which is the
whole point, since item 578 exists so that "five minors behind" cannot happen
again unnoticed. One fewer and it reds too, so that a pin bump must move this
line rather than quietly leaving it high. R2217 pinned a count the same way and
for the same reason.

⚠ `PIN_NOT_A_RELEASE` would be an escape hatch if it were merely tolerated:
pin by SHA and the distance question goes away. So the set carrying it is
pinned too. Zephyr is in it because `ZEPHYR_REF` is a commit, and a second
repository joining it is a RED that asks why a tagged pin was abandoned.
"""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import re
import subprocess
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

import gate_reason_claims as grc  # noqa: E402

ROOT = pathlib.Path(__file__).resolve().parents[2]

# The measurement, frozen in both directions. `distance` is how many releases
# upstream has published since the pinned one; `verdict` is the classification
# whose alternatives are documented above.
#
# MEASURED 2026-08-31 (R2228). Read the module docstring before changing a row:
# a rising number is upstream moving and belongs to open-debt item 579, not to
# this table.
#
# R2229 (item 579) moved zenoh and zenoh-c from 9 to 0 by bumping the pins to
# 1.10.0, and this table RED-ed on the way through — in the falling direction,
# which is the half a one-sided budget would have missed. That is the round this
# gate was built one round early for.
PINNED: dict[str, tuple[str, int]] = {
    "FreeRTOS/FreeRTOS-Kernel": ("MEASURED", 3),
    "eclipse-zenoh/zenoh": ("MEASURED", 0),
    "eclipse-zenoh/zenoh-c": ("MEASURED", 0),
    "eclipse-zenoh/zenoh-pico": ("MEASURED", 1),
    "lwip-tcpip/lwip": ("NO_RELEASES", 0),
    "newmassrael/scxml-core-engine": ("NO_RELEASES", 0),
    "zephyrproject-rtos/zephyr": ("PIN_NOT_A_RELEASE", 0),
}


class Unmeasurable(RuntimeError):
    """The gate could not measure. Never a green."""


def tracked_paths() -> list[str]:
    out = subprocess.run(
        ["git", "-C", str(ROOT), "ls-files"], capture_output=True, text=True, check=True
    )
    return out.stdout.split()


def github_repos(urls: frozenset[str]) -> dict[str, str]:
    """`owner/repo` for every derived GitHub URL, mapped back to the URL.

    A non-GitHub URL is not silently dropped — it is returned by
    [`unroutable_urls`] and reds, because a pin this gate cannot reach is the
    same blind spot as a pin it never looked for.
    """
    repos: dict[str, str] = {}
    for url in urls:
        m = re.match(r"(?:https://|git@)github\.com[:/](?P<owner>[^/]+)/(?P<repo>[^/]+)$", url)
        if not m:
            continue
        repo = m.group("repo")
        if repo.endswith(".git"):
            repo = repo[: -len(".git")]
        repos[f"{m.group('owner')}/{repo}"] = url
    return repos


def unroutable_urls(urls: frozenset[str]) -> list[str]:
    routed = set(github_repos(urls).values())
    return sorted(u for u in urls if u not in routed)


def submodule_pins() -> dict[str, str]:
    """`url -> base tag`, for every submodule whose checkout carries a tag.

    `git describe --tags` yields either the tag itself (`V11.1.0`) or the tag
    plus a distance (`1.9.0-10-g3b3ab65c`); the base tag is what the releases
    API can be asked about, so the suffix is stripped. A submodule with NO tags
    raises nothing here and simply does not appear — the caller decides whether
    that is `NO_RELEASES` (upstream publishes none) or a RED.
    """
    text = (ROOT / ".gitmodules").read_text(errors="replace")
    pins: dict[str, str] = {}
    for block in re.split(r"^\[submodule ", text, flags=re.M)[1:]:
        path = re.search(r"path\s*=\s*(\S+)", block)
        url = re.search(r"url\s*=\s*(\S+)", block)
        if not path or not url:
            continue
        got = subprocess.run(
            ["git", "-C", str(ROOT / path.group(1)), "describe", "--tags"],
            capture_output=True,
            text=True,
        )
        if got.returncode != 0:
            continue
        described = got.stdout.strip()
        base = re.sub(r"-\d+-g[0-9a-f]+$", "", described)
        if base:
            pins[url.group(1).rstrip("/")] = base
    return pins


def script_pins(paths: list[str]) -> dict[str, str]:
    """`url -> pinned ref`, from a `git clone` whose ref is a shell/YAML variable.

    Two shapes, both of which this tree uses:
      * `git clone --branch "$VAR" URL` beside `VAR="${VAR:-VALUE}"`;
      * `git clone URL` followed by `checkout "$VAR"` beside a YAML `VAR: VALUE`.

    ⚠ LINE CONTINUATIONS ARE JOINED FIRST — `build-zenohd.sh` puts the URL on
    the line after `--branch "$V" \\`, and R2217 measured that a line-at-a-time
    scan misses exactly the repository this gate is most about.
    """
    pins: dict[str, str] = {}
    for path in paths:
        if not path.startswith(grc.UPSTREAM_SOURCES) or path == ".gitmodules":
            continue
        try:
            text = (ROOT / path).read_text(errors="replace")
        except OSError:
            continue
        joined = text.replace("\\\n", " ")
        defaults = dict(re.findall(r'(\w+)="\$\{\1:-([^}"]+)\}"', joined))
        defaults.update(dict(re.findall(r"^\s*(\w+):\s*([0-9a-zA-Z._-]+)\s*$", joined, re.M)))
        for clone in re.findall(r"git\s+clone[^\n]*", joined):
            urls = re.findall(r"(?:https://|git@)\S+", clone)
            if not urls:
                continue
            url = urls[0].strip("\"' \\").rstrip("/")
            branch = re.search(r'--branch\s+"?\$\{?(\w+)\}?"?', clone)
            names = [branch.group(1)] if branch else []
            if not names:
                after = joined.split(clone, 1)[1][:400]
                names = re.findall(r'checkout\s+"?\$\{?(\w+)\}?"?', after)
            for name in names:
                if name in defaults:
                    pins[url] = defaults[name]
                    break
    return pins


def releases(repo: str, fetch=None) -> list[str]:
    """Tag names newest-first, from the repository's own releases API.

    Raises [`Unmeasurable`] when the call fails. An EMPTY list is a result, not
    a failure, and the difference is the whole of item 578's condition ③.
    """
    if fetch is not None:
        return fetch(repo)
    got = subprocess.run(
        ["gh", "api", f"repos/{repo}/releases?per_page=100", "--jq",
         ".[] | [.tag_name, .published_at] | @tsv"],
        capture_output=True,
        text=True,
    )
    if got.returncode != 0:
        raise Unmeasurable(f"{repo}: releases API failed: {got.stderr.strip()[:200]}")
    rows = [line.split("\t") for line in got.stdout.strip().splitlines() if line.strip()]
    if any(len(r) != 2 for r in rows):
        raise Unmeasurable(f"{repo}: releases API returned a row this gate cannot read")
    rows.sort(key=lambda r: r[1], reverse=True)
    return [r[0] for r in rows]


def judge(pin: str | None, tags: list[str]) -> tuple[str, int]:
    if not tags:
        return ("NO_RELEASES", 0)
    if pin is None:
        return ("PIN_NOT_DERIVED", 0)
    if pin in tags:
        return ("MEASURED", tags.index(pin))
    return ("PIN_NOT_A_RELEASE", 0)


# ── R2229 (open-debt item 579): the SECOND question, inside the tree ────────
#
# The distance above is about upstream. This is about whether this tree agrees
# with ITSELF about which release it pins, and it was added because moving one
# pin turned out to touch SEVEN places: the script's default, a `rustup
# toolchain install` in the workflow, and five cache keys. A cache key naming
# the old release is the dangerous one — it restores an old binary under a new
# pin, and every lane then grades wz against a router nobody meant to run.
#
# ⚠ THE POPULATION IS STRUCTURAL, NOT A LIST OF PLACES SOMEBODY REMEMBERED.
# Two shapes, both of which are what the workflow actually writes:
#   * `rustup toolchain install <channel>` — must equal the channel the pinned
#     release itself declares in `rust-toolchain.toml`;
#   * `key: <name>-<version>-<os>-…` — the version must be one this tree pins
#     somewhere. Not "the zenoh one": ANY derived pin, so a key for a different
#     upstream is not forced to name zenoh's.
# Anything matching a shape and resolving to neither is RED. There is no
# exemption table, because a version literal that is allowed to mean nothing is
# how the workflow drifted from the script in the first place.
CACHE_KEY = re.compile(r"^\s*key:\s*[a-z0-9-]+?-(\d+\.\d+\.\d+)-[a-z]", re.M)
TOOLCHAIN_INSTALL = re.compile(r"rustup\s+toolchain\s+install\s+(\d+\.\d+\.\d+)")


def release_toolchain(repo: str, ref: str, fetch=None) -> str | None:
    """The channel `ref` of `repo` pins, read from its own `rust-toolchain.toml`."""
    if fetch is not None:
        return fetch(repo, ref)
    got = subprocess.run(
        ["gh", "api", f"repos/{repo}/contents/rust-toolchain.toml?ref={ref}", "--jq", ".content"],
        capture_output=True,
        text=True,
    )
    if got.returncode != 0:
        raise Unmeasurable(f"{repo}@{ref}: cannot read rust-toolchain.toml")
    import base64

    try:
        raw = base64.b64decode(got.stdout).decode("utf-8", "replace")
    except ValueError as exc:
        raise Unmeasurable(f"{repo}@{ref}: rust-toolchain.toml is not base64: {exc}") from None
    m = re.search(r'channel\s*=\s*"([^"]+)"', raw)
    return m.group(1) if m else None


def pin_consistency(workflow: str, pins: dict[str, str], toolchains: set[str]) -> list[str]:
    """Complaints about version literals in the workflow that no pin explains."""
    bad: list[str] = []
    known = set(pins.values())
    for version in set(CACHE_KEY.findall(workflow)):
        if version not in known:
            bad.append(
                f"cache key names {version}, which no pin in this tree derives "
                f"(derived: {sorted(known)})"
            )
    for channel in set(TOOLCHAIN_INSTALL.findall(workflow)):
        if channel not in toolchains:
            bad.append(
                f"the workflow installs toolchain {channel}, which no pinned "
                f"release declares (declared: {sorted(toolchains)})"
            )
    return sorted(bad)


def run(fetch=None, tc_fetch=None) -> int:
    paths = tracked_paths()
    urls = grc.upstream_urls(paths)
    stray = unroutable_urls(urls)
    repos = github_repos(urls)
    pins = {**submodule_pins(), **script_pins(paths)}

    observed: dict[str, tuple[str, int]] = {}
    failures: list[str] = []
    for repo, url in sorted(repos.items()):
        try:
            tags = releases(repo, fetch=fetch)
        except Unmeasurable as exc:
            failures.append(str(exc))
            continue
        observed[repo] = judge(pins.get(url), tags)

    # The workflow's own version literals, checked against the pins above. A
    # `rustup toolchain install` is only meaningful next to the release that
    # declares that channel, so the declared set is derived per pinned repo.
    toolchains: set[str] = set()
    for repo, url in sorted(repos.items()):
        ref = pins.get(url)
        if ref is None:
            continue
        try:
            channel = release_toolchain(repo, ref, fetch=tc_fetch)
        except Unmeasurable as exc:
            # A repository with no `rust-toolchain.toml` is the normal case, and
            # `gh` reports that as a failed call. Only a repo the workflow
            # actually installs a channel for can make this matter, and that is
            # what the comparison below decides -- so this is recorded, not
            # fatal.
            del exc
            continue
        if channel:
            toolchains.add(channel)
    workflow_path = ROOT / ".github" / "workflows" / "ci.yml"
    drift: list[str] = []
    try:
        drift = pin_consistency(workflow_path.read_text(errors="replace"), pins, toolchains)
    except OSError as exc:
        failures.append(f"cannot read {workflow_path}: {exc}")

    print(f"upstream-release-distance: {len(repos)} repository(ies) derived from the tree")
    for repo in sorted(observed):
        verdict, distance = observed[repo]
        pinned = PINNED.get(repo)
        mark = "  " if pinned == observed[repo] else "!!"
        print(f"  {mark} {repo:38s} {verdict:18s} distance={distance}")
    print(f"  workflow pin consistency: {len(drift)} complaint(s); "
          f"channels declared by pinned releases: {sorted(toolchains)}")

    bad = False
    if drift:
        bad = True
        print("upstream-release-distance: FAIL — the workflow disagrees with the pins:")
        for line in drift:
            print(f"    {line}")
        print("    A cache key or toolchain naming the old release restores the old")
        print("    binary under the new pin, and every lane then grades wz against a")
        print("    router nobody meant to run.")
    if stray:
        bad = True
        print("upstream-release-distance: FAIL — a derived URL this gate cannot route:")
        for url in stray:
            print(f"    {url}")
        print("    Every upstream must be reachable by the releases API, or the")
        print("    distance question simply goes unasked for it.")
    if failures:
        bad = True
        print("upstream-release-distance: FAIL — could not measure:")
        for line in failures:
            print(f"    {line}")
        print("    A gate that cannot measure must not report green (item 578 ③).")
    for repo in sorted(set(observed) | set(PINNED)):
        want, got = PINNED.get(repo), observed.get(repo)
        if repo not in observed and repo not in failures:
            if repo not in {r for r in repos}:
                bad = True
                print(f"upstream-release-distance: FAIL — pinned row {repo} names a")
                print("    repository the tree no longer fetches; drop the row.")
            continue
        if want is None:
            bad = True
            print(f"upstream-release-distance: FAIL — {repo} is fetched by this tree")
            print(f"    and carries no pinned row. Observed {got[0]} distance={got[1]}.")
        elif want != got:
            bad = True
            print(f"upstream-release-distance: FAIL — {repo}: pinned {want[0]}"
                  f" distance={want[1]}, observed {got[0]} distance={got[1]}.")
            if got[0] == "MEASURED" and want[0] == "MEASURED" and got[1] > want[1]:
                print("    Upstream published a release. That is open-debt item 579's")
                print("    work, not this table's — bump the pin, then this row.")
    if any(v[0] == "PIN_NOT_DERIVED" for v in observed.values()):
        print("    PIN_NOT_DERIVED means the tree fetches a repository whose pin no")
        print("    structure here explains. Add the shape, never an exception.")
    print("upstream-release-distance:", "FAIL" if bad else "OK")
    return 1 if bad else 0


FIXTURE_TAGS = {
    "a/one": ["v3", "v2", "v1"],
    "a/two": [],
}


def selftest() -> int:
    """Drive [`judge`] and the measurement/observation split against fixtures.

    ⚠ The fixtures are shapes THE OLD ANSWER WOULD HAVE SWALLOWED: an empty
    release list (which a gate that treated "no data" as "nothing to do" would
    call green) and a pin absent from a non-empty list (which a gate comparing
    only the newest tag would call up to date).
    """
    cases = [
        (("v1", FIXTURE_TAGS["a/one"]), ("MEASURED", 2)),
        (("v3", FIXTURE_TAGS["a/one"]), ("MEASURED", 0)),
        (("v9", FIXTURE_TAGS["a/one"]), ("PIN_NOT_A_RELEASE", 0)),
        ((None, FIXTURE_TAGS["a/one"]), ("PIN_NOT_DERIVED", 0)),
        (("v1", FIXTURE_TAGS["a/two"]), ("NO_RELEASES", 0)),
        ((None, FIXTURE_TAGS["a/two"]), ("NO_RELEASES", 0)),
    ]
    bad = 0
    for (pin, tags), want in cases:
        got = judge(pin, tags)
        if got != want:
            bad += 1
            print(f"  selftest FAIL: judge({pin!r}, {tags!r}) = {got}, want {want}")

    # An API failure must be an exception, never an empty list that reads as
    # NO_RELEASES. This is the one distinction condition ③ is made of.
    def explode(_repo: str) -> list[str]:
        raise Unmeasurable("fixture: the API is down")

    try:
        releases("a/one", fetch=explode)
        bad += 1
        print("  selftest FAIL: a failing fetch did not raise Unmeasurable")
    except Unmeasurable:
        pass

    # ── THE TWO ARMS WHOSE POPULATION IS ZERO ON THIS TREE ────────────────
    #
    # Every URL here is currently a GitHub one and every pin currently derives,
    # so `unroutable_urls` and `PIN_NOT_DERIVED` never fire in a real run — and
    # an arm that never fires is indistinguishable from one that cannot. They
    # are driven on fixtures instead, WITH the narrowing half: a GitHub URL must
    # NOT be reported stray, or the arm would red on everything and mean nothing.
    fixture_urls = frozenset(
        {
            "https://github.com/a/b",
            "https://github.com/a/c.git",
            "git@github.com:a/d",
            "https://gitlab.com/e/f",
            "git@bitbucket.org:g/h",
        }
    )
    routed = github_repos(fixture_urls)
    if sorted(routed) != ["a/b", "a/c", "a/d"]:
        bad += 1
        print(f"  selftest FAIL: github_repos routed {sorted(routed)}")
    stray = unroutable_urls(fixture_urls)
    if stray != ["git@bitbucket.org:g/h", "https://gitlab.com/e/f"]:
        bad += 1
        print(f"  selftest FAIL: unroutable_urls reported {stray}")

    # ── R2229: the workflow-consistency arm, with its narrowing control ────
    #
    # On a tree that has just been moved, this arm reports zero — and a zero
    # from a check that cannot fire reads the same as a tree that agrees with
    # itself. The control is the FIRST case: a workflow matching the pins must
    # produce NO complaint, or the arm would red on everything and mean nothing.
    fx_pins = {"https://github.com/eclipse-zenoh/zenoh": "1.10.0"}
    fx_tcs = {"1.97.1"}
    agreeing = (
        "          key: zenohd-1.10.0-ubuntu-22.04-x\n"
        "          run: rustup toolchain install 1.97.1 --profile minimal\n"
    )
    stale_key = agreeing.replace("zenohd-1.10.0", "zenohd-1.5.0")
    stale_tc = agreeing.replace("install 1.97.1", "install 1.85.0")
    for label, wf, want_complaints in (
        ("a workflow that agrees", agreeing, 0),
        ("a cache key at the old release", stale_key, 1),
        ("a toolchain at the old channel", stale_tc, 1),
        ("both stale", stale_key.replace("install 1.97.1", "install 1.85.0"), 2),
    ):
        got = pin_consistency(wf, fx_pins, fx_tcs)
        if len(got) != want_complaints:
            bad += 1
            print(f"  selftest FAIL: {label} gave {len(got)} complaint(s), want {want_complaints}")

    if bad:
        print(f"upstream-release-distance selftest: FAIL ({bad})")
        return 1
    print(
        f"upstream-release-distance selftest: OK ({len(cases)} classifier case(s), "
        f"the measure/observe split, the two zero-population arms, and the "
        f"workflow-consistency arm with its control)"
    )
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--selftest", action="store_true", help="drive the classifier on fixtures")
    args = ap.parse_args()
    if args.selftest:
        return selftest()
    return run()


if __name__ == "__main__":
    sys.exit(main())
