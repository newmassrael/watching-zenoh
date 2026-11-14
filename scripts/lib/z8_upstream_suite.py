#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
"""R3866 (no register item) -- Z8 (docs/zenoh-api-on-the-engine.md, section 6): upstream's own tests
against the patched graph.

The family is a drop-in: a user writes one `[patch.crates-io]` entry per crate and every crate of the
graph meets the same types. This script builds that graph the way a user would, and runs what
upstream ships to prove its `zenoh` -- the integration tests of `zenoh/tests` -- against it:

  * the pinned tree is provisioned on the host (a shallow clone of the tag), and its commit is
    asserted to be the one `UPSTREAM_VERSION` names, so the tests read are the tests of the pin;
  * a package is GENERATED under `target/z8-suite` (never committed, so no copy of upstream's tests
    enters this repository): the test files copied byte for byte, upstream's `zenoh-test` helper
    crate beside them with its dependencies pointed at the patched graph, every family crate in
    `[patch.crates-io]`, the top crate by path;
  * each test file is compiled ON ITS OWN, because a file that does not compile must not hide the
    rest, and each that compiles is run with a bound. A file's outcome is one of `pass`, `fail`
    (it compiled and a test failed: the names are kept), `no-compile` (the first errors are kept) or
    `timeout`.

A test that cannot pass is a recorded difference with its reason, never a deleted test: the report
lists every file and the table of reasons lives in the roadmap note, so a file that moves between
outcomes is a line that changes, not one that appears.

The ECOSYSTEM CRATE, `zenoh-ext`, is measured by the same command and in the same report (its rows
begin with `zenoh-ext.`): its source at the pin is copied into a workspace of its own beside the
package (`zenoh-ext-suite`), with its manifest's workspace inheritance resolved to the registry and
the family patched in, as a user who depends on it gets it, and its library's unit tests and its
test files are run against that graph. It is a workspace of its own so that a crate that does not
resolve or compile against the family stops none of the files of `zenoh/tests`; it shares their
build directory, so the family is compiled once.

The EXAMPLES BRIDGE runs every program of upstream's `examples` package, in the scenarios
`docs/z8-examples-expected.tsv` declares (a subscriber and the put it receives, a queryable and the
get it answers, ...). The package is generated twice, against upstream's own crates (`stock`, the
control) and with the family patched in (`wz`); each program is compiled on its own, each scenario
runs on both arms, and a scenario is `same` when the wz arm shows what the stock arm shows: the
lines each observation counts, their shape, and how each program ended. The verdicts are graded by
`z8_expectation_gate.py --check-examples`.

    z8_upstream_suite.py generate                 provision the tree and write the packages
    z8_upstream_suite.py measure [names...]       generate, then compile and run each file (all, or the named)
    z8_upstream_suite.py examples-run [names...]  build both arms of the examples, run each scenario
    z8_upstream_suite.py --selftest               the parsers and the verdicts, on text
"""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import re
import shutil
import signal
import socket
import subprocess
import sys
import time
from typing import NamedTuple

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(HERE))

import upstream_feature_census as ufc  # noqa: E402
import z8_expectation_gate as gate  # noqa: E402
from artifact_root import artifact  # noqa: E402

TAG = ufc.UPSTREAM_VERSION
REMOTE = "https://github.com/eclipse-zenoh/zenoh"

#: The family, as `[patch.crates-io]` entries: package name -> directory under `crates/`.
FAMILY = {
    "zenoh": "wz-zenoh",
    "zenoh-buffers": "wz-zenoh-buffers",
    "zenoh-codec": "wz-zenoh-codec",
    "zenoh-collections": "wz-zenoh-collections",
    "zenoh-config": "wz-zenoh-config",
    "zenoh-core": "wz-zenoh-core",
    "zenoh-keyexpr": "wz-zenoh-keyexpr",
    "zenoh-macros": "wz-zenoh-macros",
    "zenoh-protocol": "wz-zenoh-protocol",
    "zenoh-result": "wz-zenoh-result",
    "zenoh-runtime": "wz-zenoh-runtime",
    "zenoh-shm": "wz-zenoh-shm",
    "zenoh-util": "wz-zenoh-util",
}

#: Upstream crates the tests name that are not family members; they come from the registry at the
#: pin and are built over the patched family.
UPSTREAM_CRATES = ("zenoh-link", "zenoh-link-commons", "zenoh-transport")

#: Upstream's ecosystem crate. It imports the family directly and nothing of wz replaces it: the
#: family is what must meet it, so it is built from the pinned tree over the patched family, which
#: is the graph a user who depends on it gets.
EXT_PACKAGE = "zenoh-ext"
#: The prefix of the report rows of the ecosystem crate, which are not files of `zenoh/tests`.
EXT_PREFIX = "zenoh-ext."
#: The directory, under the suite's package, of the workspace the ecosystem crate is built in.
EXT_WORKSPACE = "zenoh-ext-suite"
#: The features upstream's CI runs the crate's tests with (`-F unstable,internal` over its
#: workspace): the advanced publisher and subscriber, the group and the caches are `unstable`.
EXT_FEATURES = "unstable,internal"
#: The unit tests of the crate's library, in the two builds a user can choose: with the unstable
#: half, as upstream's CI runs them (`lib`), and without it (`lib-stable`), which is the
#: serialization alone, the half that names nothing of the family's `internal`.
EXT_LIB_ARMS = {"lib": EXT_FEATURES, "lib-stable": ""}
#: The tables of a manifest of upstream's tree that `resolved_manifest` carries or knowingly drops.
KNOWN_TABLES = ("package", "badges", "features", "dependencies", "dev-dependencies")

#: Third-party crates of the tests, taken at the version upstream's workspace names.
THIRD_PARTY = (
    "futures",
    "itertools",
    "libc",
    "nonempty-collections",
    "predicates",
    "regex",
    "test-case",
    "tracing-capture",
    "tracing-subscriber",
    "tracing-tunnel",
)

COMPILE_BOUND_S = 3600
# A file of dozens of tests that each wait out a sleep runs for minutes: the liveliness file takes
# about nine once the routers it opens work. A run that needs more says so (`Z8_RUN_BOUND_S`).
RUN_BOUND_S = int(os.environ.get("Z8_RUN_BOUND_S", "1500"))
#: Files that need more than that, in seconds for the whole file: `regions` runs 126 tests, each in
#: a process of its own and each opening a dozen sessions, and takes ten minutes on a build host of
#: thirty-two cores; a runner of a few cores is allowed three times that. `Z8_RUN_BOUND_S` still
#: wins, so a person who asks for a bound gets it for every file.
FILE_RUN_BOUND_S = {"regions": 1800}


def run_bound(name: str) -> int:
    """The seconds a file may run: the one asked for, else the file's own, else the default."""
    if "Z8_RUN_BOUND_S" in os.environ:
        return RUN_BOUND_S
    return FILE_RUN_BOUND_S.get(name, RUN_BOUND_S)


def workspace_dependencies(text: str) -> dict[str, str]:
    """`name -> right-hand side` of the `[workspace.dependencies]` table of a manifest."""
    out: dict[str, str] = {}
    inside = False
    pending: tuple[str, str] | None = None
    for line in text.splitlines():
        if pending is not None:
            # A value that opens a table or an array on one line and closes it on a later one.
            name, rhs = pending
            rhs = f"{rhs} {without_comment(line.strip())}"
            if depth(rhs) > 0:
                pending = (name, rhs)
            else:
                out[name] = re.sub(r"\[\s+", "[", re.sub(r",?\s*\]", "]", rhs))
                pending = None
            continue
        if line.startswith("["):
            inside = line.strip() == "[workspace.dependencies]"
            continue
        if not inside:
            continue
        m = re.match(r"^([A-Za-z0-9_-]+)\s*=\s*(.+?)\s*$", line)
        if m:
            rhs = without_comment(m.group(2))
            if depth(rhs) > 0:
                pending = (m.group(1), rhs)
            else:
                out[m.group(1)] = rhs
    return out


def depth(rhs: str) -> int:
    """How many brackets and braces `rhs` leaves open, outside strings."""
    n, quoted = 0, False
    for ch in rhs:
        if ch == '"':
            quoted = not quoted
        elif not quoted and ch in "[{":
            n += 1
        elif not quoted and ch in "]}":
            n -= 1
    return n


def without_comment(rhs: str) -> str:
    """`rhs` without a trailing TOML comment: a `#` outside a string, to the end of the line."""
    quoted = False
    for i, ch in enumerate(rhs):
        if ch == '"':
            quoted = not quoted
        elif ch == "#" and not quoted:
            return rhs[:i].rstrip()
    return rhs


def with_features(rhs: str, features: list[str]) -> str:
    """The right-hand side of a dependency with `features` added, whatever its form."""
    feat = ", ".join(f'"{f}"' for f in features)
    if rhs.startswith('"'):
        return f"{{ version = {rhs}, features = [{feat}] }}"
    # `default-features` is a different key: only a bare `features = [` is an existing list.
    if re.search(r"(?<![-\w])features\s*=\s*\[", rhs):
        return re.sub(r"(?<![-\w])features\s*=\s*\[", f"features = [{feat}, ", rhs, count=1)
    return rhs.rstrip("} ").rstrip() + f", features = [{feat}] }}"


def member_third_party(text: str) -> dict[str, list[str]]:
    """`name -> extra features` of the third-party dependencies a package manifest inherits.

    A test of upstream's `zenoh` may name any crate the package depends on, not only its
    dev-dependencies, so the generated manifest takes both tables. `zenoh*` crates are the family and
    upstream's own, handled apart; an optional dependency is behind a feature of the package and is
    skipped."""
    out: dict[str, list[str]] = {}
    inside = False
    for line in text.splitlines():
        if line.startswith("["):
            inside = line.strip() in ("[dependencies]", "[dev-dependencies]")
            continue
        if not inside:
            continue
        m = re.match(r"^([A-Za-z0-9_-]+)\s*=\s*\{(.*)\}\s*$", line)
        if not m or "workspace" not in m.group(2) or "optional" in m.group(2):
            continue
        name = m.group(1)
        if name.startswith("zenoh"):
            continue
        feats = re.search(r"features\s*=\s*\[([^\]]*)\]", m.group(2))
        out[name] = re.findall(r'"([^"]+)"', feats.group(1)) if feats else []
    return out


def pinned_version(rhs: str) -> str:
    m = re.search(r'version\s*=\s*"([^"]+)"', rhs) or re.match(r'^"([^"]+)"$', rhs)
    return m.group(1) if m else TAG


def provision(src: pathlib.Path) -> None:
    """The tree of the pin at `src`: cloned when absent, and its commit asserted either way."""
    if not (src / ".git").exists():
        src.parent.mkdir(parents=True, exist_ok=True)
        subprocess.run(
            ["git", "clone", "--depth", "1", "--branch", TAG, REMOTE, str(src)], check=True
        )
    head = subprocess.run(
        ["git", "-C", str(src), "rev-parse", "HEAD"], check=True, capture_output=True, text=True
    ).stdout.strip()
    tagged = subprocess.run(
        ["git", "-C", str(src), "rev-parse", f"{TAG}^{{commit}}"], capture_output=True, text=True
    )
    if tagged.returncode == 0:
        if head != tagged.stdout.strip():
            raise SystemExit(f"z8: {src} is at {head}, not at the commit of tag {TAG} ({tagged.stdout.strip()})")
        return
    # A checkout made by cargo carries no tags: the version its crate declares is the pin's or it is
    # refused.
    declared = re.search(r'(?m)^version\s*=\s*"([^"]+)"', (src / "Cargo.toml").read_text(encoding="utf-8"))
    if not declared or declared.group(1) != TAG:
        raise SystemExit(f"z8: {src} has no tag {TAG} and declares version {declared.group(1) if declared else None}")


def stock() -> bool:
    """`Z8_STOCK`: the same package over upstream's own crates, with nothing patched.

    The control of a difference found against the patched graph: a test that fails the same way
    on the real library is a fact about the host, and one that passes there is about this tree."""
    return bool(os.environ.get("Z8_STOCK"))


#: The one line of upstream's `regions` entry that picks the locator a scenario dials.
LOCATORS_ANCHOR = "ztimeout!($session.info().locators())"
#: The same expression with the link-local addresses (169.254.0.0/16) left out of the list.
LOCATORS_WITHOUT_LINK_LOCAL = (
    'ztimeout!($session.info().locators()).into_iter()'
    '.filter(|l| !l.as_str().contains("/169.254.")).collect::<Vec<_>>()'
)


def skip_link_local() -> bool:
    """`Z8_SKIP_LINK_LOCAL`: the `regions` scenarios dial a locator that can be reached.

    Upstream's `loc!` dials the first IPv4 locator of `info().locators()`, and both upstream's
    enumeration and this tree's list every address of every adapter, as the platform reports them. A
    Windows host with a disconnected adapter reports that adapter's 169.254.x.y address first, which
    nothing answers, so a scenario fails on connect on the real library as on this tree (the control
    is `Z8_STOCK`). The option removes those addresses from the list the test reads, in the generated
    copy only; the engine's list is untouched. It is off by default: the files are otherwise
    byte for byte upstream's."""
    return bool(os.environ.get("Z8_SKIP_LINK_LOCAL"))


def without_link_local(text: str) -> str:
    """`text` (the entry of the `regions` tests) with `loc!` reading the locators minus link-local."""
    if text.count(LOCATORS_ANCHOR) != 1:
        raise SystemExit(
            f"z8: Z8_SKIP_LINK_LOCAL found {text.count(LOCATORS_ANCHOR)} places that read the locators "
            "where the harness expects one; the pinned tests changed"
        )
    return text.replace(LOCATORS_ANCHOR, LOCATORS_WITHOUT_LINK_LOCAL)


def manifest(deps: dict[str, str], member: dict[str, list[str]], out: pathlib.Path) -> str:
    """The generated package's manifest."""
    top = (
        f'zenoh = {{ version = "={TAG}", features = ["unstable", "internal"] }}'
        if stock()
        else f'zenoh = {{ path = "{ROOT.as_posix()}/crates/wz-zenoh", features = ["unstable", "internal"] }}'
    )
    lines = [
        "# GENERATED by scripts/lib/z8_upstream_suite.py -- never committed.",
        "[workspace]",
        'members = ["zenoh-test"]',
        # The ecosystem crate's workspace sits below this one and is a workspace of its own.
        f'exclude = ["{EXT_WORKSPACE}"]',
        "",
        "[package]",
        'name = "wz-z8-upstream-suite"',
        'version = "0.0.0"',
        'edition = "2021"',
        "publish = false",
        "autotests = true",
        "",
        "[dev-dependencies]",
        top,
    ]
    for name in FAMILY:
        if name == "zenoh":
            continue
        feats = ["unstable", "internal"] if name in ("zenoh-config",) else []
        if name == "zenoh-protocol":
            feats = ["unstable", "internal", "test"]
        if name == "zenoh-keyexpr":
            feats = ["unstable", "internal"]
        lines.append(f'{name} = {{ version = "={TAG}", features = {feats!r} }}'.replace("'", '"'))
    for name in UPSTREAM_CRATES:
        lines.append(f'{name} = "={TAG}"')
    # The helper's `internal` feature imports `zenoh::internal::runtime::{Runtime, RuntimeBuilder}`
    # and gives the tests a pair of runtimes (`open_pairs_runtime`). It is given by the package's
    # own `internal` feature, which is on only for the files that ask for it (`FILE_FEATURES`):
    # when the crate did not publish the runtime, with the feature on every one of the 33 files
    # failed to compile on that one import (first measurement), and the file-by-file answer this
    # harness is for needed it off for the others.
    lines.append('zenoh-test = { path = "zenoh-test", features = ["unstable"] }')
    lines.append(
        'tokio = { version = "1", features = ["rt-multi-thread", "time", "macros", "sync", "io-util", "net", "fs", "signal"] }'
    )
    taken = {"tokio"}
    for name in THIRD_PARTY:
        rhs = deps.get(name)
        lines.append(f"{name} = {rhs}" if rhs else f'{name} = "*"')
        taken.add(name)
    for name, feats in sorted(member.items()):
        if name in taken:
            continue
        rhs = deps.get(name, '"*"')
        lines.append(f"{name} = {with_features(rhs, feats) if feats else rhs}")
    # The features the test files name in their `cfg`s (82 sites of `unstable`, 16 of `internal`, ...),
    # which are features of upstream's `zenoh` package and so of this one. Each forwards to the
    # crates that carry the same feature; a feature the top crate does not declare is absent, and
    # the tests behind it are not measured (the report says which, so it is a recorded difference
    # and not a silence).
    lines += [
        "",
        "[features]",
        "default = []",
        'unstable = ["zenoh/unstable", "zenoh-config/unstable", "zenoh-protocol/unstable", "zenoh-keyexpr/unstable"]',
        'internal = ["zenoh/internal", "zenoh-config/internal", "zenoh-protocol/internal", "zenoh-keyexpr/internal", "zenoh-test/internal"]',
        # `zenoh-transport` is upstream's, from the registry: its handshake messages carry `ext_shm`
        # only when it is built with the feature too, and the protocol crate it shares with the
        # family has the field exactly when the feature is on, so the two must agree.
        'shared-memory = ["zenoh/shared-memory", "zenoh-protocol/shared-memory", "zenoh-buffers/shared-memory", "zenoh-transport/shared-memory"]',
        'plugins = ["zenoh/plugins"]',
        'transport_tcp = ["zenoh/transport_tcp"]',
        'transport_udp = ["zenoh/transport_udp"]',
        # The link-commons of the registry carries the tls module a test names only with its own
        # feature; upstream's tls link switches it on, and this package has no such link.
        'transport_tls = ["zenoh/transport_tls", "zenoh-link-commons/tls"]',
        'transport_quic = ["zenoh/transport_quic"]',
    ]
    if not stock():
        lines += ["", "[patch.crates-io]", *family_patch()]
    lines.append("")
    return "\n".join(lines)


def family_patch() -> list[str]:
    """The entries of `[patch.crates-io]` that put the family in the place of upstream's crates."""
    return [f'{name} = {{ path = "{ROOT.as_posix()}/crates/{directory}" }}' for name, directory in FAMILY.items()]


def quoted(value: str) -> list[str]:
    """The strings of a TOML array (or of any value), in order."""
    return re.findall(r'"([^"]+)"', value)


def toml_list(items: list[str]) -> str:
    return "[" + ", ".join(f'"{item}"' for item in items) + "]"


def inline_table(rhs: str) -> dict[str, str]:
    """`key -> value`, as written, of a TOML inline table on one line (a value of a manifest's table
    that spanned lines is joined first, by `table_entries` or `workspace_dependencies`)."""
    body = rhs.strip()
    if not (body.startswith("{") and body.endswith("}")):
        raise SystemExit(f"z8: {rhs!r} is not an inline table")
    parts: list[str] = []
    current, level, quoting = "", 0, False
    for ch in body[1:-1]:
        if ch == '"':
            quoting = not quoting
        elif not quoting and ch in "[{":
            level += 1
        elif not quoting and ch in "]}":
            level -= 1
        if ch == "," and level == 0 and not quoting:
            parts.append(current)
            current = ""
        else:
            current += ch
    parts.append(current)
    out: dict[str, str] = {}
    for part in (p.strip() for p in parts):
        if not part:
            continue
        key, sep, value = part.partition("=")
        if not sep:
            raise SystemExit(f"z8: {part!r} of {rhs!r} is not `key = value`")
        out[key.strip()] = value.strip()
    return out


def resolved(name: str, rhs: str, deps: dict[str, str], paths: dict[str, str]) -> str:
    """The right-hand side of a member's dependency with `workspace = true` resolved against `deps`
    (the workspace's table) as Cargo resolves it: the workspace's version and `default-features`, the
    union of the two lists of features and the member's `optional`. A path into upstream's tree is
    left out, so the crate comes from the registry and the patch decides what it is, unless `paths`
    gives the path of a copy. A dependency that does not inherit is the member's own line."""
    member = inline_table(rhs) if rhs.startswith("{") else {}
    if member.get("workspace") != "true":
        return rhs
    if name not in deps:
        raise SystemExit(f"z8: the dependency {name} inherits from upstream's workspace, which does not name it")
    workspace = deps[name]
    table = {"version": workspace} if workspace.startswith('"') else inline_table(workspace)
    out = {key: value for key, value in table.items() if key not in ("path", "features")}
    if name in paths:
        out["path"] = f'"{paths[name]}"'
    features = quoted(table.get("features", ""))
    features += [f for f in quoted(member.get("features", "")) if f not in features]
    if features:
        out["features"] = toml_list(features)
    if "optional" in member:
        out["optional"] = member["optional"]
    return "{ " + ", ".join(f"{key} = {value}" for key, value in out.items()) + " }"


def resolved_manifest(text: str, deps: dict[str, str], paths: dict[str, str]) -> str:
    """A manifest of upstream's tree for a crate copied out of its workspace: the package's name at the
    pin's version, its features as they are, and each dependency `resolved`. A table this function
    does not know is refused, so a pinned manifest that grows one is read before it is built."""
    tables = re.findall(r"(?m)^\[+([^\]]+)\]+\s*$", text)
    unknown = [t for t in tables if t not in KNOWN_TABLES and not t.startswith("package.metadata")]
    if unknown:
        raise SystemExit(f"z8: the pinned manifest has the table(s) {unknown}, which the harness does not carry")
    name = re.search(r'(?m)^name\s*=\s*"([^"]+)"', section(text, "package"))
    if not name:
        raise SystemExit("z8: the pinned manifest names no package")
    lines = [
        "# GENERATED by scripts/lib/z8_upstream_suite.py -- never committed.",
        "[package]",
        f'name = "{name.group(1)}"',
        f'version = "{TAG}"',
        'edition = "2021"',
        "publish = false",
    ]
    features = section(text, "features")
    if features:
        lines += ["", features.rstrip()]
    for table in ("dependencies", "dev-dependencies"):
        entries = table_entries(text, table)
        if entries:
            lines += ["", f"[{table}]", *(f"{dep} = {resolved(dep, rhs, deps, paths)}" for dep, rhs in entries)]
    lines.append("")
    return "\n".join(lines)


def ext_workspace_manifest(patched: bool) -> str:
    """The workspace of the ecosystem crate: the crate and a copy of upstream's test helper, which its
    tests import, and the family patched in unless the run is the stock control."""
    lines = [
        "# GENERATED by scripts/lib/z8_upstream_suite.py -- never committed.",
        "[workspace]",
        f'members = ["{EXT_PACKAGE}", "zenoh-test"]',
        'resolver = "2"',
    ]
    if patched:
        lines += ["", "[patch.crates-io]", *family_patch()]
    lines.append("")
    return "\n".join(lines)


def generate_ext(src: pathlib.Path, ws: pathlib.Path, deps: dict[str, str]) -> list[str]:
    """The ecosystem crate's workspace at `ws`, and the report rows it gives: the library's unit tests
    in each of `EXT_LIB_ARMS` and each of its test files. Its sources and tests and the helper's are
    copied byte for byte; only the manifests are generated."""
    crate = src / EXT_PACKAGE
    for part in ("src", "tests"):
        shutil.copytree(crate / part, ws / EXT_PACKAGE / part)
    (ws / EXT_PACKAGE / "Cargo.toml").write_text(
        resolved_manifest((crate / "Cargo.toml").read_text(encoding="utf-8"), deps, {"zenoh-test": "../zenoh-test"}),
        encoding="utf-8",
    )
    helper = src / "commons" / "zenoh-test"
    shutil.copytree(helper, ws / "zenoh-test")
    (ws / "zenoh-test" / "Cargo.toml").write_text(
        resolved_manifest((helper / "Cargo.toml").read_text(encoding="utf-8"), deps, {}), encoding="utf-8"
    )
    (ws / "Cargo.toml").write_text(ext_workspace_manifest(not stock()), encoding="utf-8")
    tests = sorted(p.stem for p in (crate / "tests").glob("*.rs"))
    clash = sorted(set(tests) & set(EXT_LIB_ARMS))
    if clash:
        raise SystemExit(f"z8: {EXT_PACKAGE} has test files named {clash}, the names of its library's rows")
    return [*(EXT_PREFIX + arm for arm in EXT_LIB_ARMS), *(EXT_PREFIX + test for test in tests)]


def ext_command(name: str) -> list[str]:
    """The `cargo test` of one row of the ecosystem crate (`zenoh-ext.<target>`), run in its workspace."""
    target = name[len(EXT_PREFIX):]
    if target in EXT_LIB_ARMS:
        selection, features = ["--lib"], EXT_LIB_ARMS[target]
    else:
        selection, features = ["--test", target], EXT_FEATURES
    return ["cargo", "test", "-p", EXT_PACKAGE, *selection, *(["--features", features] if features else [])]


def ext_env(out: pathlib.Path) -> dict[str, str]:
    """The environment of the ecosystem crate's runs: the build directory of the suite's package, so
    the family is compiled once for both workspaces, unless the caller chose one."""
    env = dict(os.environ)
    env.setdefault("CARGO_TARGET_DIR", str(out / "target"))
    return env


def helper_manifest(text: str) -> str:
    """Upstream's `zenoh-test` manifest with its workspace inheritance resolved to the patched graph."""
    text = re.sub(r"\n\[package\.metadata[^\n]*\n[^\[]*", "\n", text)
    text = re.sub(r"(?m)^edition\s*=.*$", 'edition = "2021"', text)
    text = re.sub(r"(?m)^version\s*=.*$", 'version = "0.0.0"', text)
    # A dependency inherited from upstream's workspace is any version of the package, which the
    # `[patch.crates-io]` of the generated manifest resolves for a family crate.
    return re.sub(r"workspace\s*=\s*true", 'version = "*"', text)


def generate(src: pathlib.Path, out: pathlib.Path) -> list[str]:
    provision(src)
    deps = workspace_dependencies((src / "Cargo.toml").read_text(encoding="utf-8"))
    if out.exists():
        shutil.rmtree(out)
    out.mkdir(parents=True)
    shutil.copytree(src / "zenoh" / "tests", out / "tests")
    if skip_link_local():
        entry = out / "tests" / "regions" / "main.rs"
        entry.write_bytes(without_link_local(entry.read_bytes().decode("utf-8")).encode("utf-8"))
    helper = out / "zenoh-test"
    shutil.copytree(src / "commons" / "zenoh-test", helper)
    (helper / "Cargo.toml").write_text(
        helper_manifest((src / "commons" / "zenoh-test" / "Cargo.toml").read_text(encoding="utf-8")),
        encoding="utf-8",
    )
    member = member_third_party((src / "zenoh" / "Cargo.toml").read_text(encoding="utf-8"))
    (out / "Cargo.toml").write_text(manifest(deps, member, out), encoding="utf-8")
    # The compiler the repository pins. The package is generated under `target/` of the clone on
    # a build host, where cargo finds the repository's own file by walking up, and anywhere else
    # (a scratch directory of a local run) it finds nothing and builds with whatever the machine
    # calls default: the first local measurement stopped on a deprecation the pinned compiler does
    # not have. The file is copied, not written here, so it stays the one place the channel lives.
    pin = ROOT / "rust-toolchain.toml"
    if pin.is_file():
        shutil.copyfile(pin, out / "rust-toolchain.toml")
    (out / "src").mkdir()
    (out / "src" / "lib.rs").write_text("", encoding="utf-8")
    names = sorted(p.stem for p in (out / "tests").glob("*.rs"))
    names += sorted(p.name for p in (out / "tests").iterdir() if p.is_dir() and (p / "main.rs").exists())
    names += generate_ext(src, out / EXT_WORKSPACE, deps)
    return names


#: The example programs of upstream's `examples` package that the host parity matrix runs
#: (docs/upstream-parity.md section 5b), each against upstream's `zenoh` and against the family.
PARITY_EXAMPLES = ("z_put", "z_sub", "z_get", "z_queryable", "z_pub_thr", "z_sub_thr", "z_ping", "z_pong")
#: Dependencies of upstream's examples package that the generated package leaves out. `zenoh-ext` is
#: named by the package but by none of PARITY_EXAMPLES nor its `src/lib.rs`: kept, it would bring an
#: ecosystem crate into both arms that the programs measured do not call.
PARITY_EXAMPLES_LEFT_OUT = ("zenoh-ext",)


def table_entries(text: str, table: str) -> list[tuple[str, str]]:
    """`(name, right-hand side)` of each entry of one table of a manifest, a value that spans lines
    joined into one."""
    out: list[tuple[str, str]] = []
    inside = False
    pending: tuple[str, str] | None = None
    for line in text.splitlines():
        if pending is not None:
            name, rhs = pending
            rhs = f"{rhs} {without_comment(line.strip())}"
            if depth(rhs) > 0:
                pending = (name, rhs)
            else:
                out.append((name, rhs))
                pending = None
            continue
        if line.startswith("["):
            inside = line.strip() == f"[{table}]"
            continue
        m = re.match(r"^([A-Za-z0-9_-]+)\s*=\s*(.+?)\s*$", line) if inside else None
        if m:
            rhs = without_comment(m.group(2))
            if depth(rhs) > 0:
                pending = (m.group(1), rhs)
            else:
                out.append((m.group(1), rhs))
    return out


def section(text: str, header: str) -> str:
    """The text of one table of a manifest, its header line included, or nothing."""
    m = re.search(rf"(?ms)^\[{re.escape(header)}\]\n.*?(?=^\[|\Z)", text)
    return m.group(0).rstrip() + "\n" if m else ""


def examples_manifest(examples_text: str, deps: dict[str, str], profile: str, arm: str,
                      core_features: list[str]) -> str:
    """The manifest of the examples package generated for one arm of the host parity matrix.

    Both arms get the same manifest but for two things: the `wz` arm patches the family in
    (`[patch.crates-io]`, as Z8 does) and states the preset's features of the engine crate. Each
    dependency of upstream's examples package is taken at the version upstream's workspace names,
    with the features the package adds; the release profile is upstream's workspace's, so both arms
    are compiled the same way."""
    lines = [
        "# GENERATED by scripts/lib/z8_upstream_suite.py examples -- never committed.",
        "[workspace]",
        "",
        "[package]",
        'name = "zenoh-examples"',
        'version = "0.0.0"',
        'edition = "2021"',
        "publish = false",
        "",
        "[features]",
        'default = ["zenoh/default"]',
        "",
        "[dependencies]",
    ]
    for name, rhs in table_entries(examples_text, "dependencies"):
        if name in PARITY_EXAMPLES_LEFT_OUT:
            continue
        if name == "zenoh":
            lines.append(f'zenoh = {{ version = "={TAG}", default-features = false }}')
            continue
        if "workspace" not in rhs or name not in deps:
            raise SystemExit(f"z8 examples: the dependency {name} = {rhs} is not one of the workspace's; "
                             "the pinned examples manifest changed")
        feats = re.search(r"(?<![-\w])features\s*=\s*\[([^\]]*)\]", rhs)
        extra = [f for f in (re.findall(r'"([^"]+)"', feats.group(1)) if feats else [])
                 if f'"{f}"' not in deps[name]]
        lines.append(f"{name} = {with_features(deps[name], extra) if extra else deps[name]}")
    if arm == "wz":
        feats = ", ".join(f'"{f}"' for f in core_features)
        lines.append(f'wz-capi-core = {{ path = "{ROOT.as_posix()}/crates/wz-capi-core", '
                     f"default-features = false, features = [{feats}] }}")
    lines += ["", "[build-dependencies]"]
    lines += [f"{name} = {rhs}" for name, rhs in table_entries(examples_text, "build-dependencies")]
    for name in PARITY_EXAMPLES:
        lines += ["", "[[example]]", f'name = "{name}"', f'path = "examples/{name}.rs"']
    lines += ["", profile.rstrip()]
    if arm == "wz":
        lines += ["", "[patch.crates-io]", *family_patch()]
    lines.append("")
    return "\n".join(lines)


def generate_examples(src: pathlib.Path, out: pathlib.Path, arm: str, core_features: list[str]) -> None:
    """The examples package of one arm under `out`: upstream's example sources of PARITY_EXAMPLES, its
    `src/lib.rs` and build script copied byte for byte, the manifest generated, and upstream's
    `Cargo.lock` as the starting lock of both arms, so the third-party crates they share resolve to the
    versions upstream released with."""
    provision(src)
    root_text = (src / "Cargo.toml").read_text(encoding="utf-8")
    deps = workspace_dependencies(root_text)
    profile = section(root_text, "profile.release")
    if not profile:
        raise SystemExit(f"z8 examples: {src}/Cargo.toml has no [profile.release]")
    if out.exists():
        shutil.rmtree(out)
    (out / "examples").mkdir(parents=True)
    pkg = src / "examples"
    shutil.copytree(pkg / "src", out / "src")
    shutil.copyfile(pkg / "build.rs", out / "build.rs")
    for name in (*(f"{n}.rs" for n in PARITY_EXAMPLES), "example.proto"):
        shutil.copyfile(pkg / "examples" / name, out / "examples" / name)
    (out / "Cargo.toml").write_text(
        examples_manifest((pkg / "Cargo.toml").read_text(encoding="utf-8"), deps, profile, arm, core_features),
        encoding="utf-8",
    )
    shutil.copyfile(src / "Cargo.lock", out / "Cargo.lock")
    pin = ROOT / "rust-toolchain.toml"
    if pin.is_file():
        shutil.copyfile(pin, out / "rust-toolchain.toml")


#: The two arms of the examples bridge: upstream's own crates, which are the control, and the family.
EXAMPLES_ARMS = ("stock", "wz")
#: The features every program of the examples package is built with: upstream's programs of shared
#: memory require both, and with them every one of the package compiles in one configuration.
EXAMPLES_FEATURES = ("shared-memory", "unstable")
#: The feature of the generated package that brings in the ecosystem crate. Upstream's package
#: depends on `zenoh-ext` for every program and three of its programs name it: a program that does
#: not must not be hidden by that crate's compile, as a test file must not be hidden by another that
#: does not compile, so the crate is optional here and the programs that name it require the feature.
ECOSYSTEM_FEATURE = "ecosystem"
#: The seconds a `stand` role is given to come up before the next role starts.
SETTLE_S = 2.0
#: The seconds a scenario waits after its last role, for what is in flight to arrive.
DRAIN_S = 2.0
#: The seconds a program the scenario stops is given to end before it is killed.
STOP_GRACE_S = 3.0


def example_requirements(text: str, sources: dict[str, str]) -> dict[str, list[str]]:
    """`program -> required features` of upstream's examples package: what its `[[example]]` table
    declares, and the ecosystem feature for a program whose source names the crate. `sources` is
    `program -> source` of every file of `examples/`; the package discovers the one file it does not
    declare (`z_bytes`), so the generated package declares every program and discovers none."""
    declared: dict[str, list[str]] = {}
    for block in re.findall(r"(?ms)^\[\[example\]\]\n(.*?)(?=^\[|\Z)", text):
        name = re.search(r'(?m)^name\s*=\s*"([^"]+)"', block)
        path = re.search(r'(?m)^path\s*=\s*"([^"]+)"', block)
        if not name or not path or path.group(1) != f"examples/{name.group(1)}.rs":
            raise SystemExit("z8 examples: an [[example]] of the pinned manifest is not `examples/<name>.rs`; "
                             "the manifest changed")
        required = re.search(r"(?m)^required-features\s*=\s*(\[[^\]]*\])", block)
        declared[name.group(1)] = quoted(required.group(1)) if required else []
    stray = sorted(set(declared) - set(sources))
    if stray:
        raise SystemExit(f"z8 examples: the pinned manifest declares {stray}, whose sources are not there")
    out: dict[str, list[str]] = {}
    for name, source in sorted(sources.items()):
        required = list(declared.get(name, []))
        if re.search(r"\bzenoh_ext\b", source):
            required.append(ECOSYSTEM_FEATURE)
        out[name] = required
    return out


def z8_examples_manifest(examples_text: str, deps: dict[str, str], arm: str, programs: dict[str, list[str]]) -> str:
    """The manifest of the examples package of one arm of the examples bridge.

    It is upstream's package with three things changed: the dependencies are resolved against
    upstream's workspace (`resolved`), the ecosystem crate is optional behind `ECOSYSTEM_FEATURE`
    (upstream's `default` asks for its defaults, which the feature does instead), and every program is
    declared with what it requires (`example_requirements`). The `wz` arm patches the family in; the
    `stock` arm is upstream's graph. Nothing else differs between the two, so a difference of what
    the programs do is a difference of the crates under them."""
    names = [name for name, _rhs in table_entries(examples_text, "features")]
    if ECOSYSTEM_FEATURE in names:
        raise SystemExit(f"z8 examples: the pinned package has a feature named {ECOSYSTEM_FEATURE}")
    features: list[str] = []
    moved: list[str] = []
    for name, rhs in table_entries(examples_text, "features"):
        kept: list[str] = []
        for item in quoted(rhs):
            if item.startswith(f"{EXT_PACKAGE}/"):
                if name == "default":
                    moved.append(item)
                    continue
                # Elsewhere a feature of the crate is asked for without bringing the crate in.
                item = item.replace(f"{EXT_PACKAGE}/", f"{EXT_PACKAGE}?/", 1)
            kept.append(item)
        features.append(f"{name} = {toml_list(kept)}")
    features.append(f"{ECOSYSTEM_FEATURE} = {toml_list([f'dep:{EXT_PACKAGE}', *moved])}")
    lines = [
        "# GENERATED by scripts/lib/z8_upstream_suite.py examples-run -- never committed.",
        "[workspace]",
        "",
        "[package]",
        'name = "zenoh-examples"',
        'version = "0.0.0"',
        'edition = "2021"',
        "publish = false",
        "autoexamples = false",
        "",
        "[features]",
        *features,
    ]
    for table in ("dependencies", "dev-dependencies", "build-dependencies"):
        lines += ["", f"[{table}]"]
        for name, rhs in table_entries(examples_text, table):
            value = resolved(name, rhs, deps, {})
            if name == EXT_PACKAGE:
                if table != "dependencies" or not value.startswith("{"):
                    raise SystemExit(f"z8 examples: {EXT_PACKAGE} = {rhs} is not the dependency the harness makes optional")
                value = value[:-1].rstrip() + ", optional = true }"
            lines.append(f"{name} = {value}")
    for name, required in sorted(programs.items()):
        lines += ["", "[[example]]", f'name = "{name}"', f'path = "examples/{name}.rs"']
        if required:
            lines.append(f"required-features = {toml_list(required)}")
    if arm == "wz":
        lines += ["", "[patch.crates-io]", *family_patch()]
    lines.append("")
    return "\n".join(lines)


def generate_z8_examples(src: pathlib.Path, out: pathlib.Path, arm: str) -> dict[str, list[str]]:
    """The examples package of one arm under `out`, and `program -> required features` of it.

    Upstream's sources, its library and its build script are copied byte for byte and its lock is
    the starting lock of both arms, as the host parity package does. A build directory left by an
    earlier run is kept: each arm's graph is a long compile and only the package's own files change."""
    provision(src)
    deps = workspace_dependencies((src / "Cargo.toml").read_text(encoding="utf-8"))
    pkg = src / "examples"
    text = (pkg / "Cargo.toml").read_text(encoding="utf-8")
    sources = {p.stem: p.read_text(encoding="utf-8") for p in sorted((pkg / "examples").glob("*.rs"))}
    programs = example_requirements(text, sources)
    out.mkdir(parents=True, exist_ok=True)
    for child in out.iterdir():
        if child.name == "target":
            continue
        if child.is_dir():
            shutil.rmtree(child)
        else:
            child.unlink()
    shutil.copytree(pkg / "src", out / "src")
    shutil.copyfile(pkg / "build.rs", out / "build.rs")
    shutil.copytree(pkg / "examples", out / "examples")
    (out / "Cargo.toml").write_text(z8_examples_manifest(text, deps, arm, programs), encoding="utf-8")
    shutil.copyfile(src / "Cargo.lock", out / "Cargo.lock")
    pin = ROOT / "rust-toolchain.toml"
    if pin.is_file():
        shutil.copyfile(pin, out / "rust-toolchain.toml")
    return programs


def executable_of(text: str, name: str) -> pathlib.Path | None:
    """The program `name` that a `cargo build --message-format json-render-diagnostics` wrote."""
    for line in text.splitlines():
        if not line.startswith("{"):
            continue
        try:
            message = json.loads(line)
        except json.JSONDecodeError:
            continue
        target = message.get("target") or {}
        if (
            message.get("reason") == "compiler-artifact"
            and target.get("name") == name
            and "example" in target.get("kind", [])
            and message.get("executable")
        ):
            return pathlib.Path(message["executable"])
    return None


def build_examples(
    pkg: pathlib.Path, programs: dict[str, list[str]], wanted: list[str], logs: pathlib.Path
) -> dict[str, pathlib.Path | list[str]]:
    """`program -> its executable`, or the first errors of its compile, for each of `wanted`. Each is
    compiled on its own, so a program that does not compile hides no other."""
    logs.mkdir(parents=True, exist_ok=True)
    built: dict[str, pathlib.Path | list[str]] = {}
    # The programs that need the ecosystem crate last: its feature changes the package's own
    # library, and a build that turned it on and off between programs would rebuild that each time.
    for name in sorted(wanted, key=lambda n: (ECOSYSTEM_FEATURE in programs[n], n)):
        features = [*EXAMPLES_FEATURES, *(f for f in programs[name] if f not in EXAMPLES_FEATURES)]
        log = logs / f"{name}.log"
        rc = run(
            ["cargo", "build", "--example", name, "--features", ",".join(features),
             "--message-format", "json-render-diagnostics"],
            pkg, log, COMPILE_BOUND_S,
        )
        exe = executable_of(log.read_text(encoding="utf-8", errors="replace"), name) if rc == 0 else None
        if exe is not None:
            built[name] = exe
        else:
            reason = "the build ran out of time" if rc is None else f"cargo exited {rc} and printed no error"
            built[name] = first_errors(log) or [reason]
    return built


def substitute(text: str, port: int) -> str:
    """`text` with the placeholders of the table (`z8_expectation_gate.PLACEHOLDERS`) given values."""
    return text.replace("{ep}", f"tcp/127.0.0.1:{port}").replace("{port}", str(port))


def free_port() -> int:
    """A TCP port of the loopback that nothing holds as the scenario starts."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


class Running:
    """One program of a scenario, its output and its errors in a file each.

    A program the scenario stops is sent an interrupt, the CTRL-C upstream's programs say they wait
    for, and is killed if it has not ended `STOP_GRACE_S` later. Its process is a group of its own, so
    the interrupt is the program's alone."""

    def __init__(self, argv: list[str], out: pathlib.Path, err: pathlib.Path):
        self.out, self.err = out.open("wb"), err.open("wb")
        self.stopped = False
        if os.name == "posix":
            self.proc = subprocess.Popen(
                argv, cwd=out.parent, stdin=subprocess.DEVNULL, stdout=self.out, stderr=self.err,
                start_new_session=True, preexec_fn=raise_open_files_limit,
            )
        else:
            self.proc = subprocess.Popen(
                argv, cwd=out.parent, stdin=subprocess.DEVNULL, stdout=self.out, stderr=self.err,
                creationflags=subprocess.CREATE_NEW_PROCESS_GROUP,
            )

    def wait(self, seconds: float) -> bool:
        """Whether the program ended within `seconds`."""
        try:
            self.proc.wait(timeout=seconds)
            return True
        except subprocess.TimeoutExpired:
            return False

    def stop(self) -> None:
        if self.proc.poll() is not None:
            return
        self.stopped = True
        try:
            if os.name == "posix":
                os.killpg(self.proc.pid, signal.SIGINT)
            else:
                self.proc.send_signal(signal.CTRL_BREAK_EVENT)
        except OSError:
            # It ended between the poll and the signal.
            pass
        if not self.wait(STOP_GRACE_S):
            self.proc.kill()
            self.proc.wait()

    def ending(self) -> str:
        """`stopped` when the scenario ended the program, else `exit <status>`. On POSIX a program
        that was sent the interrupt and still returned a status of its own had ended by itself."""
        code = self.proc.returncode
        if self.stopped and not (os.name == "posix" and code is not None and code >= 0):
            return "stopped"
        return f"exit {code}"

    def close(self) -> None:
        self.out.close()
        self.err.close()


class Ran(NamedTuple):
    """What a scenario's programs did on one arm: the port it gave them, each role's lines of output
    and how each role ended."""

    port: int
    lines: dict[str, list[str]]
    endings: dict[str, str]


class Unbuilt(NamedTuple):
    """A scenario that did not run on an arm: `program -> first errors` of what did not compile."""

    programs: dict[str, list[str]]


def run_scenario(row: gate.Scenario, built: dict[str, pathlib.Path | list[str]], logs: pathlib.Path) -> Ran | Unbuilt:
    """Run the roles of `row` in order on one arm, with their output under `logs`."""
    unbuilt = {
        role.program: built[role.program] for role in row.roles if not isinstance(built[role.program], pathlib.Path)
    }
    if unbuilt:
        return Unbuilt({program: errors for program, errors in unbuilt.items() if isinstance(errors, list)})
    logs.mkdir(parents=True, exist_ok=True)
    port = free_port()
    started: list[tuple[gate.Role, Running]] = []
    try:
        for role in row.roles:
            argv = [str(built[role.program]), *(substitute(arg, port) for arg in role.args)]
            running = Running(argv, logs / f"{role.name}.out", logs / f"{role.name}.err")
            started.append((role, running))
            if role.mode == "stand":
                time.sleep(SETTLE_S)
            elif not running.wait(role.seconds):
                running.stop()
        time.sleep(DRAIN_S)
    finally:
        for _role, running in started:
            running.stop()
            running.close()
    lines = {
        role.name: (logs / f"{role.name}.out").read_text(encoding="utf-8", errors="replace").splitlines()
        for role, _running in started
    }
    return Ran(port, lines, {role.name: running.ending() for role, running in started})


def shape(line: str) -> str:
    """A line with what differs from one run to the next made alike: an identity (8 or more hex digits
    with a letter among them: a session's id, a clock's), every number, every run of white space."""
    line = re.sub(r"\b(?=[0-9a-f]*[a-f])[0-9a-f]{8,}\b", "<id>", line)
    line = re.sub(r"\d+", "#", line)
    return re.sub(r"\s+", " ", line).strip()


def selected(obs: gate.Observation, ran: Ran) -> list[str]:
    """The lines of the observed role that contain the observation's text."""
    text = substitute(obs.text, ran.port)
    return [line for line in ran.lines.get(obs.role, []) if text in line]


def seen(obs: gate.Observation, ran: Ran) -> str:
    return ran.endings.get(obs.role, "not run") if obs.op == "exit" else str(len(selected(obs, ran)))


def met(obs: gate.Observation, ran: Ran) -> bool:
    if obs.op == "exit":
        return ran.endings.get(obs.role) == f"exit {obs.count}"
    count = len(selected(obs, ran))
    return count == obs.count if obs.op == "=" else count >= obs.count


def describe(obs: gate.Observation) -> str:
    return f"{obs.role} exit {obs.count}" if obs.op == "exit" else f"{obs.role} {obs.op}{obs.count} {obs.text}"


def unbuilt_text(unbuilt: Unbuilt) -> str:
    return "; ".join(f"{program}: {' | '.join(errors)}" for program, errors in sorted(unbuilt.programs.items()))


def judge(row: gate.Scenario, stock: Ran | Unbuilt, wz: Ran | Unbuilt) -> tuple[str, str]:
    """The verdict of a scenario and what it rests on. The stock arm is the control: a row it does not
    show judges nothing (`control`). Against it the wz arm is `no-compile`, `differs` (an observation
    it misses, a line it shapes otherwise, a role that ends otherwise) or `same`."""
    if isinstance(stock, Unbuilt):
        return "control", f"the stock arm did not compile {unbuilt_text(stock)}"
    misses = [obs for obs in row.observations if not met(obs, stock)]
    if misses:
        return "control", "the stock arm does not show " + "; ".join(
            f"{describe(obs)} (it shows {seen(obs, stock)})" for obs in misses
        )
    if isinstance(wz, Unbuilt):
        return "no-compile", unbuilt_text(wz)
    differences: list[str] = []
    for obs in row.observations:
        if not met(obs, wz):
            differences.append(f"{describe(obs)}: stock {seen(obs, stock)}, wz {seen(obs, wz)}")
        elif obs.op != "exit":
            ours = {shape(line) for line in selected(obs, stock)}
            theirs = {shape(line) for line in selected(obs, wz)}
            if ours != theirs:
                differences.append(
                    f"{describe(obs)}: only stock {sorted(ours - theirs)[:2]}, only wz {sorted(theirs - ours)[:2]}"
                )
    for role in row.roles:
        if stock.endings[role.name] != wz.endings[role.name]:
            differences.append(f"{role.name} ended: stock {stock.endings[role.name]}, wz {wz.endings[role.name]}")
    if differences:
        return "differs", " || ".join(differences)
    return "same", "; ".join(f"{describe(obs)}: stock {seen(obs, stock)}, wz {seen(obs, wz)}" for obs in row.observations)


def report_cell(text: str, limit: int = 800) -> str:
    """`text` as one cell of a report: no tab, no line break, bounded."""
    return re.sub(r"[\t\r\n]+", " ", text)[:limit]


def examples_run(names: list[str], src: pathlib.Path, root: pathlib.Path) -> int:
    """Build both arms of the examples package, run each scenario (all, or the named) on both and write
    `root/report.tsv`, one verdict a scenario, with the programs' output under `root/report`."""
    rows = gate.parse_examples_table(gate.EXAMPLES_EXPECTED.read_text(encoding="utf-8"))
    chosen = names or list(rows)
    unknown = [name for name in chosen if name not in rows]
    if unknown:
        raise SystemExit(f"z8 examples: {gate.EXAMPLES_EXPECTED} declares no scenario {', '.join(unknown)}")
    wanted = sorted({role.program for name in chosen for role in rows[name].roles})
    report = root / "report"
    if report.exists():
        shutil.rmtree(report)
    built: dict[str, dict[str, pathlib.Path | list[str]]] = {}
    programs: dict[str, list[str]] = {}
    for arm in EXAMPLES_ARMS:
        pkg = root / arm
        programs = generate_z8_examples(src, pkg, arm)
        absent = [program for program in wanted if program not in programs]
        if absent:
            raise SystemExit(f"z8 examples: the table runs {absent}, which upstream's package does not have")
        built[arm] = build_examples(pkg, programs, wanted, report / "compile" / arm)
    out = [f"# arms: {' '.join(EXAMPLES_ARMS)}; features: {','.join(EXAMPLES_FEATURES)}"]
    unrun = sorted(set(programs) - {role.program for row in rows.values() for role in row.roles})
    if unrun:
        out.append(f"# programs of the package no scenario runs: {', '.join(unrun)}")
    print("\n".join(out), flush=True)
    for name in chosen:
        ran = {arm: run_scenario(rows[name], built[arm], report / name / arm) for arm in EXAMPLES_ARMS}
        status, detail = judge(rows[name], ran["stock"], ran["wz"])
        out.append(f"{name}\t{status}\t{report_cell(detail)}")
        print(out[-1], flush=True)
    (root / "report.tsv").write_text("\n".join(out) + "\n", encoding="utf-8")
    return 0


#: The open files a test process may hold. The soft limit of a shell is 1024, which a test that
#: opens a dozen sessions in one process passes (each session of this engine holds runtimes of its
#: own and a link to every peer it meets): the first thing to fail is the build of a runtime, long
#: before the test says anything about routing. A CI runner starts with 65,536.
NOFILE = 1 << 16


def raise_open_files_limit() -> None:
    """Raise the soft limit of open files to [`NOFILE`], or to the hard limit when that is lower."""
    try:
        import resource
    except ImportError:
        # Windows has no soft limit of open files to raise: a process holds handles up to memory.
        return

    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    wanted = NOFILE if hard == resource.RLIM_INFINITY else min(NOFILE, hard)
    if soft != resource.RLIM_INFINITY and soft < wanted:
        resource.setrlimit(resource.RLIMIT_NOFILE, (wanted, hard))


def run(
    cmd: list[str], cwd: pathlib.Path, log: pathlib.Path, bound: int, env: dict[str, str] | None = None
) -> int | None:
    with log.open("w", encoding="utf-8") as fh:
        try:
            return subprocess.run(
                cmd,
                cwd=cwd,
                env=env,
                stdout=fh,
                stderr=subprocess.STDOUT,
                timeout=bound,
                # `preexec_fn` exists only where processes fork; elsewhere there is no limit to raise.
                preexec_fn=raise_open_files_limit if os.name == "posix" else None,
            ).returncode
        except subprocess.TimeoutExpired:
            return None


def first_errors(log: pathlib.Path, limit: int = 3) -> list[str]:
    errs = [l.strip() for l in log.read_text(encoding="utf-8", errors="replace").splitlines() if l.startswith("error")]
    return errs[:limit]


def failed_tests(log: pathlib.Path) -> list[str]:
    return re.findall(r"^test (\S+) \.\.\. FAILED", log.read_text(encoding="utf-8", errors="replace"), re.M)


def panic_reasons(text: str, limit: int = 3, place: bool = False) -> list[str]:
    """The distinct first lines of the panic messages of a run, most frequent first.

    The message is the line after `panicked at <place>:`; a run with a hundred failures that all say
    one thing is one reason, which is what the table of recorded differences is made of. With
    `place` the line of the test that panicked leads the message (`Z8_PLACES`): a test that has
    several assertions of one text says which one failed."""
    seen: dict[str, int] = {}
    for m in re.finditer(r"panicked at ([^\n]*):\n([^\n]*)", text):
        msg = re.sub(r"\s+", " ", m.group(2)).strip()[:160]
        if place:
            msg = f"{m.group(1)} {msg}"
        seen[msg] = seen.get(msg, 0) + 1
    return [f"{n}x {msg}" for msg, n in sorted(seen.items(), key=lambda kv: -kv[1])[:limit]]


def counts(text: str) -> tuple[int, int, int]:
    """`(passed, failed, ignored)` summed over the `test result:` lines of a run.

    A run that selects no test exits 0, so an exit status alone grades nothing: a file whose tests
    are compiled out by a feature it was not given is `empty`, not `pass`."""
    p = f = i = 0
    for m in re.finditer(r"test result: \w+\. (\d+) passed; (\d+) failed; (\d+) ignored", text):
        p, f, i = p + int(m.group(1)), f + int(m.group(2)), i + int(m.group(3))
    return p, f, i


#: The features of the build the tests are run in, upstream's own CI selection first: the unstable
#: surface, shared memory and the four transports the top crate carries (upstream's defaults are
#: all of them, and the authentication file opens tls and quic listeners without a `cfg` that
#: would leave it out of a build that lacks them). `Z8_FEATURES` replaces it (a second arm is
#: `unstable,internal`, which the harness runs apart because `internal` is the arm in which a
#: file may ask for a `Runtime`).
DEFAULT_FEATURES = "unstable,shared-memory,transport_tcp,transport_udp,transport_tls,transport_quic"

#: Features a file asks for beyond the build's, because its tests are compiled out without them
#: (the entry of the `regions` test directory opens with `#![cfg(feature = "internal")]`:
#: measured as 0 tests under the default, 126 with the feature; `keyexpr` and `atexit` hold tests
#: that only the feature compiles in: 16 against 15, and the close that runs in the background).
#: `session` asks for a `Runtime` of the node (`open_pairs_runtime`, `session::init`).
FILE_FEATURES = {
    "regions": ("internal",),
    "keyexpr": ("internal",),
    "atexit": ("internal",),
    "session": ("internal",),
}

#: Files whose tests each run in a process of their own, as upstream's CI runs them (nextest starts
#: one process per test). Every scenario module of `regions` installs its capture subscriber with
#: `tracing::subscriber::set_global_default(..).ok()`, which a process takes once: in a run of the
#: whole file only the first module (scenario 1) records anything, and the span counts of the
#: others read 0 whatever the node does. One `cargo test` over the file measures the harness.
ISOLATED_FILES = {"regions"}


def isolated_files() -> set[str]:
    """`ISOLATED_FILES` and the files `Z8_ISOLATE` names (comma separated): a flake of one test of
    any other file is measured by running that test alone, again and again (`Z8_ONLY`,
    `Z8_REPEAT`), which only an isolated file does."""
    return ISOLATED_FILES | {n for n in os.environ.get("Z8_ISOLATE", "").split(",") if n}


def isolated_run(
    base: list[str], cwd: pathlib.Path, log: pathlib.Path, bound: int, env: dict[str, str] | None = None
) -> int | None:
    """Run each test of a file in its own process; the logs are joined, the status is the worst.

    `bound` is for the whole file. `None` when it ran out."""
    listing = subprocess.run(
        [*base, "--", "--list", "--format", "terse"], cwd=cwd, env=env, capture_output=True, text=True
    )
    tests = re.findall(r"^(\S+): test$", listing.stdout, re.M)
    # A flake is measured by running the same tests again and again: `Z8_ONLY` keeps the tests
    # whose name contains it (one scenario module, say `scenario7::`), `Z8_REPEAT` runs each that
    # many times. Both default to the whole file once, which is what the table of outcomes reads.
    only = os.environ.get("Z8_ONLY", "")
    tests = [t for t in tests if only in t] * int(os.environ.get("Z8_REPEAT", "1"))
    deadline = time.monotonic() + bound
    status: int | None = 0
    with log.open("w", encoding="utf-8") as fh:
        for test in tests:
            left = int(deadline - time.monotonic())
            if left <= 0:
                return None
            one = log.with_name(log.name + ".one")
            rc = run([*base, "--", "--exact", test, "--test-threads=1"], cwd, one, left, env)
            text = one.read_text(encoding="utf-8", errors="replace")
            fh.write(text)
            if rc != 0 and os.environ.get("Z8_SHOW_FAILS"):
                # The report keeps a failure's message, not the run: a flake that only a loaded
                # host shows is read from the run itself, which is this (`Z8_SHOW_FAILS=<lines>`
                # prints the last that many lines of each failed run).
                keep = int(os.environ["Z8_SHOW_FAILS"])
                print(f"--- failed run of {test} (last {keep} lines)")
                print("\n".join(text.splitlines()[-keep:]))
                print("--- end of the failed run", flush=True)
            one.unlink()
            if rc is None:
                return None
            if rc != 0:
                status = rc
    return status


def measure(names: list[str], out: pathlib.Path) -> int:
    report = out / "report"
    report.mkdir(exist_ok=True)
    features = os.environ.get("Z8_FEATURES", DEFAULT_FEATURES)
    rows: list[str] = [
        f"# features: {features or '(none)'}",
        f"# {EXT_PACKAGE}: features {EXT_FEATURES}, and none for {EXT_PREFIX}lib-stable",
    ]
    for name in names:
        env: dict[str, str] | None = None
        if name.startswith(EXT_PREFIX):
            # `Z8_FEATURES` are features of the suite's package; the crate's rows take their own.
            base, cwd, env = ext_command(name), out / EXT_WORKSPACE, ext_env(out)
        else:
            wanted = [f for f in FILE_FEATURES.get(name, ()) if f not in features.split(",")]
            flags = ["--features", ",".join([*filter(None, [features]), *wanted])] if features or wanted else []
            base, cwd = ["cargo", "test", "--test", name, *flags], out
        clog, rlog = report / f"{name}.compile.log", report / f"{name}.run.log"
        rc = run([*base, "--no-run"], cwd, clog, COMPILE_BOUND_S, env)
        if rc != 0:
            rows.append(f"{name}\tno-compile\t{' | '.join(first_errors(clog))}")
            continue
        if name in isolated_files():
            rc = isolated_run(base, cwd, rlog, run_bound(name), env)
        else:
            rc = run([*base, "--", "--test-threads=1"], cwd, rlog, run_bound(name), env)
        passed, failed, ignored = counts(rlog.read_text(encoding="utf-8", errors="replace"))
        ran = f"ran={passed + failed} passed={passed} ignored={ignored}"
        if rc is None:
            rows.append(f"{name}\ttimeout\t{ran}")
        elif rc == 0 and passed + failed == 0:
            rows.append(f"{name}\tempty\t{ran}")
        elif rc == 0:
            rows.append(f"{name}\tpass\t{ran}")
        else:
            text = rlog.read_text(encoding="utf-8", errors="replace")
            rows.append(
                f"{name}\tfail\t{ran} [{', '.join(failed_tests(rlog))[:200]}] {' || '.join(panic_reasons(text, place=bool(os.environ.get('Z8_PLACES'))))}"
            )
    (out / "report.tsv").write_text("\n".join(rows) + "\n", encoding="utf-8")
    print("\n".join(rows))
    return 0


def selftest() -> int:
    deps = workspace_dependencies(
        '[workspace]\nmembers = []\n\n[workspace.dependencies]\nregex = "1.11"\n'
        'tokio = { version = "1.45", default-features = false }\n\n[profile.dev]\nx = 1\n'
    )
    assert deps == {"regex": '"1.11"', "tokio": '{ version = "1.45", default-features = false }'}, deps
    assert pinned_version(deps["tokio"]) == "1.45" and pinned_version(deps["regex"]) == "1.11"
    assert with_features('"1"', ["a"]) == '{ version = "1", features = ["a"] }'
    assert "features = [\"a\", \"b\"]" in with_features('{ version = "1", features = ["b"] }', ["a"])
    assert counts(
        "test result: ok. 3 passed; 0 failed; 1 ignored; 0 measured\ntest result: FAILED. 2 passed; 1 failed; 0 ignored"
    ) == (5, 1, 1)
    assert counts("running 0 tests\ntest result: ok. 0 passed; 0 failed; 0 ignored; 0 measured") == (0, 0, 0)
    assert without_comment('{ version = "1", default-features = false } # off for no_std') == (
        '{ version = "1", default-features = false }'
    )
    assert without_comment('"a#b"') == '"a#b"'
    multi = workspace_dependencies(
        '[workspace.dependencies]\nserde = { version = "1", default-features = false, features = [\n  "derive",\n] } # why\n'
        'serde_json = "1.0"\n'
    )
    assert multi == {
        "serde": '{ version = "1", default-features = false, features = ["derive"] }',
        "serde_json": '"1.0"',
    }, multi
    assert with_features('{ version = "1", default-features = false }', ["default"]) == (
        '{ version = "1", default-features = false, features = ["default"] }'
    )
    assert with_features(multi["serde"], ["default"]) == (
        '{ version = "1", default-features = false, features = ["default", "derive"] }'
    )
    assert workspace_dependencies('[workspace.dependencies]\nrand = { version = "0.8" } # why\n') == {
        "rand": '{ version = "0.8" }'
    }
    assert panic_reasons(
        "thread 'a' panicked at x.rs:1:2:\nboom here\nnote\nthread 'b' panicked at x.rs:3:4:\nboom here\n"
        "thread 'c' panicked at y.rs:5:6:\nother\n"
    ) == ["2x boom here", "1x other"]
    assert panic_reasons("thread 'a' panicked at x.rs:1:2:\nboom here\n", place=True) == ["1x x.rs:1:2 boom here"]
    assert member_third_party(
        "[dependencies]\nflume = { workspace = true }\nrand = { workspace = true, features = [\"default\"] }\n"
        "zenoh-core = { workspace = true }\nzenoh-shm = { workspace = true, optional = true }\n"
        "gone = { workspace = true, optional = true }\n[dev-dependencies]\nregex = { workspace = true }\n[features]\nx = []\n"
    ) == {"flume": [], "rand": ["default"], "regex": []}
    inherited = helper_manifest(
        '[package]\nedition = { workspace = true }\nname = "zenoh-test"\nversion = { workspace = true }\n\n'
        '[dependencies]\ntokio = { workspace = true, features = ["rt"] }\nzenoh-core = { workspace = true }\n'
    )
    assert 'edition = "2021"' in inherited and 'version = "0.0.0"' in inherited, inherited
    assert 'tokio = { version = "*", features = ["rt"] }' in inherited, inherited
    assert 'zenoh-core = { version = "*" }' in inherited, inherited
    read = "    ($session:expr) => {\r\n        " + LOCATORS_ANCHOR + "\r\n            .into_iter()\r\n"
    skipped = without_link_local(read)
    # A locator is `tcp/169.254.1.2:7447`: one slash after the protocol, not two.
    assert '"/169.254."' in skipped and '"//169.254."' not in skipped and skipped.count(".into_iter()") == 2 and "\r\n" in skipped, skipped
    for broken in ("", read + read):
        try:
            without_link_local(broken)
        except SystemExit:
            continue
        raise AssertionError("an unexpected number of readers must be refused")
    examples = examples_manifest(
        '[package]\nname = "zenoh-examples"\n\n[dependencies]\n'
        'clap = { workspace = true, features = ["derive"] }\n'
        'tokio = { workspace = true, features = ["io-std", "time"] }\n'
        'zenoh = { workspace = true, default-features = false }\n'
        'zenoh-ext = { workspace = true, default-features = false, features = [\n  "unstable",\n] }\n\n'
        '[build-dependencies]\nwhich = "7.0.2"\n',
        {"clap": '{ version = "4.5", features = ["derive"] }',
         "tokio": '{ version = "1.47", default-features = false }'},
        '[profile.release]\nlto = "fat"\n', "wz", ["engine-tokio", "link-tcp"])
    assert 'clap = { version = "4.5", features = ["derive"] }' in examples, examples
    assert 'tokio = { version = "1.47", default-features = false, features = ["io-std", "time"] }' in examples, examples
    assert f'zenoh = {{ version = "={TAG}", default-features = false }}' in examples, examples
    assert "zenoh-ext" not in examples.split("[dependencies]")[1].split("[build-dependencies]")[0], examples
    assert 'features = ["engine-tokio", "link-tcp"]' in examples and "[patch.crates-io]" in examples, examples
    assert 'which = "7.0.2"' in examples and 'lto = "fat"' in examples, examples
    assert examples.count("[[example]]") == len(PARITY_EXAMPLES), examples
    stock_examples = examples_manifest("[dependencies]\nzenoh = { workspace = true }\n", {}, "[profile.release]\n",
                                       "stock", [])
    assert "[patch.crates-io]" not in stock_examples and "wz-capi-core" not in stock_examples, stock_examples
    assert section("[a]\nx = 1\n[profile.release]\nlto = 1\n\n[b]\n", "profile.release") == (
        "[profile.release]\nlto = 1\n"), section("[a]\nx = 1\n[profile.release]\nlto = 1\n\n[b]\n", "profile.release")
    selftest_ecosystem()
    selftest_examples_bridge()
    print("z8-upstream-suite selftest: OK")
    return 0


def selftest_ecosystem() -> None:
    assert inline_table('{ a = "x,y", b = [1, 2], c = { d = 1 }, }') == {"a": '"x,y"', "b": "[1, 2]", "c": "{ d = 1 }"}
    for bad in ('"1.0"', "{ a }"):
        try:
            inline_table(bad)
        except SystemExit:
            continue
        raise AssertionError(f"accepted {bad!r}")
    deps = {
        "bincode": '"1.3.3"',
        "tokio": '{ version = "1.47.1", default-features = false }',
        "zenoh": f'{{ version = "={TAG}", path = "zenoh", default-features = false }}',
        "zenoh-test": '{ path = "commons/zenoh-test" }',
        "serde": '{ version = "1.0.225", default-features = false, features = ["derive"] }',
    }
    # Inherited: the workspace's version and `default-features`, the union of the features, the
    # member's `optional`, and a path of upstream's tree left out unless a copy's is given.
    assert resolved("bincode", "{ workspace = true }", deps, {}) == '{ version = "1.3.3" }'
    assert resolved("serde", '{ workspace = true, features = ["default", "derive"] }', deps, {}) == (
        '{ version = "1.0.225", default-features = false, features = ["derive", "default"] }')
    assert resolved("zenoh", "{ workspace = true, default-features = false, optional = true }", deps, {}) == (
        f'{{ version = "={TAG}", default-features = false, optional = true }}')
    assert resolved("zenoh-test", '{ workspace = true, features = ["internal"] }', deps,
                    {"zenoh-test": "../zenoh-test"}) == '{ path = "../zenoh-test", features = ["internal"] }'
    # Not inherited: the member's own line, whatever its form.
    assert resolved("which", '"7.0.2"', deps, {}) == '"7.0.2"'
    assert resolved("x", '{ version = "1", features = ["a"] }', deps, {}) == '{ version = "1", features = ["a"] }'
    try:
        resolved("gone", "{ workspace = true }", deps, {})
    except SystemExit:
        pass
    else:
        raise AssertionError("a dependency the workspace does not name must be refused")
    crate = (
        '[package]\nauthors = ["a <a@b>"]\ncategories = { workspace = true }\nname = "zenoh-ext"\n'
        'version = { workspace = true }\n\n[badges]\nmaintenance = { status = "x" }\n\n'
        '[features]\ndefault = ["zenoh/default"]\nunstable = ["zenoh/internal", "zenoh/unstable"]\n\n'
        '[dependencies]\nbincode = { workspace = true }\ntokio = { workspace = true, features = [\n  "rt",\n  "time",\n] }\n'
        'zenoh = { workspace = true, default-features = false }\n\n'
        '[dev-dependencies]\nzenoh-test = { workspace = true, features = ["internal", "unstable"] }\n\n'
        '[package.metadata.docs.rs]\nfeatures = ["unstable"]\n'
    )
    made = resolved_manifest(crate, deps, {"zenoh-test": "../zenoh-test"})
    assert 'name = "zenoh-ext"' in made and f'version = "{TAG}"' in made and "publish = false" in made, made
    assert '[features]\ndefault = ["zenoh/default"]\nunstable = ["zenoh/internal", "zenoh/unstable"]' in made, made
    assert 'bincode = { version = "1.3.3" }' in made, made
    assert 'tokio = { version = "1.47.1", default-features = false, features = ["rt", "time"] }' in made, made
    assert f'zenoh = {{ version = "={TAG}", default-features = false }}' in made, made
    assert 'zenoh-test = { path = "../zenoh-test", features = ["internal", "unstable"] }' in made, made
    assert "workspace" not in made and "badges" not in made and "docs.rs" not in made, made
    try:
        resolved_manifest(crate + '\n[lib]\nname = "x"\n', deps, {})
    except SystemExit:
        pass
    else:
        raise AssertionError("a table the harness does not carry must be refused")
    assert ext_command("zenoh-ext.lib") == ["cargo", "test", "-p", "zenoh-ext", "--lib", "--features", "unstable,internal"]
    assert ext_command("zenoh-ext.lib-stable") == ["cargo", "test", "-p", "zenoh-ext", "--lib"]
    assert ext_command("zenoh-ext.advanced") == [
        "cargo", "test", "-p", "zenoh-ext", "--test", "advanced", "--features", "unstable,internal"]
    patched, control = ext_workspace_manifest(True), ext_workspace_manifest(False)
    assert 'members = ["zenoh-ext", "zenoh-test"]' in patched and "[patch.crates-io]" in patched, patched
    assert f'zenoh = {{ path = "{ROOT.as_posix()}/crates/wz-zenoh" }}' in patched, patched
    assert "[patch.crates-io]" not in control, control
    # The suite's workspace leaves the crate's out, so a manifest of the crate that does not resolve
    # cannot stop the files of `zenoh/tests`.
    assert f'exclude = ["{EXT_WORKSPACE}"]' in manifest({}, {}, pathlib.Path(".")), "the suite must exclude the crate"


def selftest_examples_bridge() -> None:
    text = (
        '[package]\nname = "zenoh-examples"\n\n'
        '[features]\ndefault = ["zenoh-ext/default", "zenoh/default"]\nshared-memory = ["zenoh/shared-memory"]\n'
        'unstable = ["zenoh/unstable", "zenoh-ext/unstable"]\n\n'
        '[dependencies]\nclap = { workspace = true, features = ["derive"] }\n'
        'zenoh = { workspace = true, default-features = false }\n'
        'zenoh-ext = { workspace = true, default-features = false, features = [\n  "unstable",\n] }\n\n'
        '[dev-dependencies]\nrand = { workspace = true, features = ["default"] }\n\n'
        '[build-dependencies]\nwhich = "7.0.2"\n\n'
        '[[example]]\nname = "z_put"\npath = "examples/z_put.rs"\n\n'
        '[[example]]\nname = "z_pub_shm"\npath = "examples/z_pub_shm.rs"\nrequired-features = ["shared-memory", "unstable"]\n'
    )
    sources = {"z_put": "use zenoh::Config;", "z_pub_shm": "use zenoh::shm;", "z_bytes": "use zenoh_ext::z_serialize;"}
    programs = example_requirements(text, sources)
    assert programs == {"z_bytes": [ECOSYSTEM_FEATURE], "z_pub_shm": ["shared-memory", "unstable"], "z_put": []}, programs
    for broken, files in (
        (text + '\n[[example]]\nname = "z_gone"\npath = "examples/z_gone.rs"\n', sources),
        ('[[example]]\nname = "z_put"\npath = "other/z_put.rs"\n', sources),
    ):
        try:
            example_requirements(broken, files)
        except SystemExit:
            continue
        raise AssertionError("a declared program without its source, or at another path, must be refused")
    deps = {
        "clap": '{ version = "4.5", features = ["derive"] }',
        "zenoh": f'{{ version = "={TAG}", path = "zenoh", default-features = false }}',
        "zenoh-ext": f'{{ version = "={TAG}", path = "zenoh-ext", default-features = false }}',
        "rand": '{ version = "0.8.5", default-features = false }',
    }
    wz = z8_examples_manifest(text, deps, "wz", programs)
    assert 'default = ["zenoh/default"]' in wz, wz
    assert 'unstable = ["zenoh/unstable", "zenoh-ext?/unstable"]' in wz, wz
    assert f'{ECOSYSTEM_FEATURE} = ["dep:zenoh-ext", "zenoh-ext/default"]' in wz, wz
    assert 'clap = { version = "4.5", features = ["derive"] }' in wz, wz
    assert f'zenoh = {{ version = "={TAG}", default-features = false }}' in wz, wz
    assert f'zenoh-ext = {{ version = "={TAG}", default-features = false, features = ["unstable"], optional = true }}' in wz, wz
    assert 'rand = { version = "0.8.5", default-features = false, features = ["default"] }' in wz, wz
    assert 'which = "7.0.2"' in wz and "autoexamples = false" in wz, wz
    assert wz.count("[[example]]") == 3, wz
    assert f'name = "z_bytes"\npath = "examples/z_bytes.rs"\nrequired-features = ["{ECOSYSTEM_FEATURE}"]' in wz, wz
    assert 'name = "z_put"\npath = "examples/z_put.rs"\n\n' in wz, wz
    assert "[patch.crates-io]" in wz and f'zenoh = {{ path = "{ROOT.as_posix()}/crates/wz-zenoh" }}' in wz, wz
    stock_arm = z8_examples_manifest(text, deps, "stock", programs)
    assert "[patch.crates-io]" not in stock_arm, stock_arm
    # The two arms differ in the patch alone.
    assert wz.split("[patch.crates-io]")[0].rstrip() == stock_arm.rstrip(), (wz, stock_arm)
    try:
        z8_examples_manifest(text.replace("shared-memory =", f"{ECOSYSTEM_FEATURE} ="), deps, "wz", programs)
    except SystemExit:
        pass
    else:
        raise AssertionError("a package that already has the ecosystem feature must be refused")
    log = (
        "   Compiling zenoh v1.10.2\n"
        '{"reason":"compiler-artifact","target":{"name":"zenoh_examples","kind":["lib"]},"executable":null}\n'
        '{"reason":"compiler-artifact","target":{"name":"z_put","kind":["example"]},"executable":"/t/debug/examples/z_put"}\n'
        '{"reason":"build-finished","success":true}\n'
    )
    assert executable_of(log, "z_put") == pathlib.Path("/t/debug/examples/z_put"), executable_of(log, "z_put")
    assert executable_of(log, "z_sub") is None and executable_of(log, "zenoh_examples") is None
    assert substitute("-l {ep} at {port}", 7447) == "-l tcp/127.0.0.1:7447 at 7447"
    assert shape("[   3] zid 0123456789abcdef at 12345678.9 msg/s") == "[ #] zid <id> at #.# msg/s", shape(
        "[   3] zid 0123456789abcdef at 12345678.9 msg/s")
    row = gate.parse_examples_table(
        "put_sub\tsub:stand=z_sub -l {ep} ; put:run:10=z_put -e {ep}\t"
        "sub =1 Received PUT ('k': 'v') ; put exit 0 ; sub >=1 Opening\tsame\tyes\tx\n"
    )["put_sub"]
    stock_ran = Ran(7001, {"sub": ["Opening session...", ">> [Subscriber] Received PUT ('k': 'v')"], "put": []},
                    {"sub": "stopped", "put": "exit 0"})
    wz_ran = Ran(7002, {"sub": ["Opening session...", ">> [Subscriber] Received PUT ('k': 'v')"], "put": []},
                 {"sub": "stopped", "put": "exit 0"})
    status, detail = judge(row, stock_ran, wz_ran)
    assert status == "same" and "sub =1 Received PUT ('k': 'v'): stock 1, wz 1" in detail, (status, detail)
    lost = wz_ran._replace(lines={"sub": ["Opening session..."], "put": []})
    status, detail = judge(row, stock_ran, lost)
    assert status == "differs" and "sub =1 Received PUT ('k': 'v'): stock 1, wz 0" in detail, (status, detail)
    # The count is met and the line is not the same line.
    other = wz_ran._replace(lines={"sub": ["Opening session...", ">> [Subscriber] Received PUT ('k': 'v') (att)"], "put": []})
    status, detail = judge(row, stock_ran, other)
    assert status == "differs" and "only wz" in detail, (status, detail)
    crashed = wz_ran._replace(endings={"sub": "stopped", "put": "exit 101"})
    status, detail = judge(row, stock_ran, crashed)
    assert status == "differs" and "put exit 0: stock exit 0, wz exit 101" in detail and "put ended" in detail, detail
    ended = wz_ran._replace(endings={"sub": "exit 0", "put": "exit 0"})
    status, detail = judge(row, stock_ran, ended)
    assert status == "differs" and "sub ended: stock stopped, wz exit 0" in detail, (status, detail)
    unbuilt = Unbuilt({"z_put": ["error[E0432]: unresolved import `zenoh::internal::TerminatableTask`"]})
    assert judge(row, stock_ran, unbuilt) == (
        "no-compile", "z_put: error[E0432]: unresolved import `zenoh::internal::TerminatableTask`")
    status, detail = judge(row, stock_ran._replace(lines={"sub": [], "put": []}), wz_ran)
    assert status == "control" and detail.startswith("the stock arm does not show sub =1"), (status, detail)
    status, _ = judge(row, unbuilt, wz_ran)
    assert status == "control", status
    # A control that fails outranks a wz arm that did not compile: the row judges nothing then.
    status, _ = judge(row, stock_ran._replace(endings={"sub": "stopped", "put": "exit 1"}), unbuilt)
    assert status == "control", status
    assert report_cell("a\tb\nc", 3) == "a b", report_cell("a\tb\nc", 3)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("command", nargs="?", choices=("generate", "measure", "examples", "examples-run"))
    ap.add_argument("names", nargs="*")
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--arm", choices=("stock", "wz"), help="examples: upstream's zenoh, or the family patched in")
    ap.add_argument("--core-features", default="",
                    help="examples, arm wz: the features of wz-capi-core, comma separated (the preset's)")
    args = ap.parse_args()
    if args.selftest:
        return selftest()
    if not args.command:
        ap.error("a command, or --selftest")
    src = pathlib.Path(os.environ.get("Z8_UPSTREAM_SRC", artifact("target/z8-upstream")))
    if args.command == "examples":
        # The examples package of one arm of the host parity matrix (docs/upstream-parity.md 5b).
        if not args.arm:
            ap.error("examples takes --arm stock or --arm wz")
        out = pathlib.Path(os.environ.get("Z8_OUT", artifact(f"target/parity-rust/{args.arm}")))
        generate_examples(src, out, args.arm, [f for f in args.core_features.split(",") if f])
        print(out)
        return 0
    if args.command == "examples-run":
        # The examples bridge of Z8: both arms are built and run, so `--arm` and `Z8_STOCK` do not apply.
        root = pathlib.Path(os.environ.get("Z8_EXAMPLES_OUT", artifact("target/z8-examples")))
        return examples_run(args.names, src, root)
    out = pathlib.Path(os.environ.get("Z8_OUT", artifact("target/z8-suite")))
    found = generate(src, out)
    if args.command == "generate":
        print("\n".join(found))
        return 0
    return measure(args.names or found, out)


if __name__ == "__main__":
    sys.exit(main())
