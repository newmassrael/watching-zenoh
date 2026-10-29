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

    z8_upstream_suite.py generate            provision the tree and write the package
    z8_upstream_suite.py measure [names...]  generate, then compile and run each file (all, or the named)
    z8_upstream_suite.py --selftest          the parsers, on text
"""

from __future__ import annotations

import argparse
import os
import pathlib
import re
import shutil
import subprocess
import sys

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(HERE))

import upstream_feature_census as ufc  # noqa: E402

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


def manifest(deps: dict[str, str], member: dict[str, list[str]], out: pathlib.Path) -> str:
    """The generated package's manifest."""
    lines = [
        "# GENERATED by scripts/lib/z8_upstream_suite.py -- never committed.",
        "[workspace]",
        'members = ["zenoh-test"]',
        "",
        "[package]",
        'name = "wz-z8-upstream-suite"',
        'version = "0.0.0"',
        'edition = "2021"',
        "publish = false",
        "autotests = true",
        "",
        "[dev-dependencies]",
        f'zenoh = {{ path = "{ROOT}/crates/wz-zenoh", features = ["unstable", "internal"] }}',
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
    # Without `internal`: that feature of the helper imports `zenoh::internal::runtime::{Runtime,
    # RuntimeBuilder}`, which the crate does not publish (the engine is the runtime), and with it on
    # every one of the 33 files failed to compile on that one import (first measurement). Off, the
    # helper builds and only a test that asks for a `Runtime` of its own stops on it, which is the
    # file-by-file answer this harness is for.
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
        'internal = ["zenoh/internal", "zenoh-config/internal", "zenoh-protocol/internal", "zenoh-keyexpr/internal"]',
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
    lines += ["", "[patch.crates-io]"]
    for name, directory in FAMILY.items():
        lines.append(f'{name} = {{ path = "{ROOT}/crates/{directory}" }}')
    lines.append("")
    return "\n".join(lines)


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
    return names


#: The open files a test process may hold. The soft limit of a shell is 1024, which a test that
#: opens a dozen sessions in one process passes (each session of this engine holds runtimes of its
#: own and a link to every peer it meets): the first thing to fail is the build of a runtime, long
#: before the test says anything about routing. A CI runner starts with 65,536.
NOFILE = 1 << 16


def raise_open_files_limit() -> None:
    """Raise the soft limit of open files to [`NOFILE`], or to the hard limit when that is lower."""
    import resource

    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    wanted = NOFILE if hard == resource.RLIM_INFINITY else min(NOFILE, hard)
    if soft != resource.RLIM_INFINITY and soft < wanted:
        resource.setrlimit(resource.RLIMIT_NOFILE, (wanted, hard))


def run(cmd: list[str], cwd: pathlib.Path, log: pathlib.Path, bound: int) -> int | None:
    with log.open("w", encoding="utf-8") as fh:
        try:
            return subprocess.run(
                cmd,
                cwd=cwd,
                stdout=fh,
                stderr=subprocess.STDOUT,
                timeout=bound,
                preexec_fn=raise_open_files_limit,
            ).returncode
        except subprocess.TimeoutExpired:
            return None


def first_errors(log: pathlib.Path, limit: int = 3) -> list[str]:
    errs = [l.strip() for l in log.read_text(encoding="utf-8", errors="replace").splitlines() if l.startswith("error")]
    return errs[:limit]


def failed_tests(log: pathlib.Path) -> list[str]:
    return re.findall(r"^test (\S+) \.\.\. FAILED", log.read_text(encoding="utf-8", errors="replace"), re.M)


def panic_reasons(text: str, limit: int = 3) -> list[str]:
    """The distinct first lines of the panic messages of a run, most frequent first.

    The message is the line after `panicked at <place>:`; a run with a hundred failures that all say
    one thing is one reason, which is what the table of recorded differences is made of."""
    seen: dict[str, int] = {}
    for m in re.finditer(r"panicked at [^\n]*:\n([^\n]*)", text):
        msg = re.sub(r"\s+", " ", m.group(1)).strip()[:160]
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
#: measured as 0 tests under the default, 126 with the feature). The files that ask for a `Runtime` of the node are not in this
#: table: they need `zenoh::internal::runtime`, which this crate does not carry.
FILE_FEATURES = {"regions": ("internal",)}


def measure(names: list[str], out: pathlib.Path) -> int:
    report = out / "report"
    report.mkdir(exist_ok=True)
    features = os.environ.get("Z8_FEATURES", DEFAULT_FEATURES)
    rows: list[str] = [f"# features: {features or '(none)'}"]
    for name in names:
        wanted = [f for f in FILE_FEATURES.get(name, ()) if f not in features.split(",")]
        flags = ["--features", ",".join([*filter(None, [features]), *wanted])] if features or wanted else []
        clog, rlog = report / f"{name}.compile.log", report / f"{name}.run.log"
        rc = run(["cargo", "test", "--test", name, *flags, "--no-run"], out, clog, COMPILE_BOUND_S)
        if rc != 0:
            rows.append(f"{name}\tno-compile\t{' | '.join(first_errors(clog))}")
            continue
        rc = run(["cargo", "test", "--test", name, *flags, "--", "--test-threads=1"], out, rlog, RUN_BOUND_S)
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
                f"{name}\tfail\t{ran} [{', '.join(failed_tests(rlog))[:200]}] {' || '.join(panic_reasons(text))}"
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
    print("z8-upstream-suite selftest: OK")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("command", nargs="?", choices=("generate", "measure"))
    ap.add_argument("names", nargs="*")
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args()
    if args.selftest:
        return selftest()
    if not args.command:
        ap.error("a command, or --selftest")
    src = pathlib.Path(os.environ.get("Z8_UPSTREAM_SRC", ROOT / "target" / "z8-upstream"))
    out = pathlib.Path(os.environ.get("Z8_OUT", ROOT / "target" / "z8-suite"))
    found = generate(src, out)
    if args.command == "generate":
        print("\n".join(found))
        return 0
    return measure(args.names or found, out)


if __name__ == "__main__":
    sys.exit(main())
