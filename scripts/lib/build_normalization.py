#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
"""R4562 (no register item) -- the one rule that keeps where and when a build ran out of its bytes.

## Why this exists

A lane that holds a binary to a committed byte figure compares one host's build with another's,
and two inputs that have nothing to do with the code move those bytes:

  * the build's absolute paths. rustc writes the path of a source into each panic `Location`, and a
    C compiler expands the file macro to it; both land in read-only data, which `size` counts as
    text. The checkout, the artifact root and the cargo home differ per host, so one commit
    measured differently on each host, by the length of its paths;
  * the time of the build, which the C date and time macros and CMake's timestamp write into
    the output.

Layer Q removed the first for rustc with flags of its own in `scripts/run-ci.sh`, and
`scripts/check-footprint.sh` re-asserted it on the binary with a second copy of the prefixes.
Layer C1cs used neither, so its figures carried the paths of whichever host built them. This
file is the rule, once: the lanes ask it for flags, for an environment and for a verdict on a
built file, and none of them spells a prefix of its own.

## The rule

Prefixes, and what each becomes:

    the checkout                          /wz
    the artifact root, when it is not
      the checkout                        /wz     (it mirrors the tree, so a generated path
                                                   reads /wz/<tree path> in both modes)
    the cargo home                        /cargo

The replacements are fixed and their LENGTH is part of every committed figure: changing one moves
every baseline.

rustc takes them as `--remap-path-prefix=FROM=TO`, a C compiler as `-ffile-prefix-map=FROM=TO`
(the macro, debug-info and profile maps in one). Both apply the LAST mapping that matches, so
the order on the command line is the precedence, and the longer prefix has to win: a prefix
that another one starts with is written after it. rustc matches whole directories and gcc
matches strings, so "starts with" is read as a string, which orders a nested directory (an
artifact root or a cargo home inside the checkout) and a sibling that shares a stem
(`/srv/tree` and `/srv/tree-out`) the way both compilers need. Prefixes no other one starts
with keep the order above, which is the order Layer Q has always passed.

A prefix is refused, with the reason, when it is not absolute, when it holds whitespace (cargo
splits `RUSTFLAGS` and the cc crate splits `CFLAGS` on whitespace, so the flag would arrive as
two words), when it holds `=` (gcc splits FROM=TO at the first one), and when two prefixes are
the same directory with different replacements. A trailing slash is dropped: gcc would otherwise
glue the replacement to the next component.

`SOURCE_DATE_EPOCH` is the commit time of the tree's HEAD (`git log -1 --format=%ct`). It is set
and not inherited: a value the caller exported would build one commit into different bytes, so a
hosted workflow does not name it (`--check-workflows`).

## Adding to an environment, never replacing it

cargo reads `CARGO_ENCODED_RUSTFLAGS` when it is present and `RUSTFLAGS` otherwise, and either
takes the place of the `rustflags` of a configuration file. The flags are appended to whichever
of the two cargo will read, after what the caller had: the caller's flags still apply, and for
the same prefix the later mapping, this one, wins. The only configuration-file `rustflags` of
this tree are for windows-msvc (`.cargo/config.toml`), which no lane that measures bytes builds.

The cc crate reads four spellings of each C flags variable: with the target appended, with the
target appended in underscores, with a HOST or TARGET kind prefixed, and bare. The release this
tree locks joins all four; older releases took the first one set and ignored the rest. So the
flags are added to every spelling that is set, and the bare `CFLAGS` and `CXXFLAGS` are set
when they are not. CMake reads `CFLAGS` when it first configures a build directory.

## The verdict on a built file

A file holds a prefix when the prefix's bytes occur anywhere in it. That is the judgment
`check-footprint.sh` made with `strings` and a fixed-string grep: a path is printable, so the
two agree, and a byte search needs no tool that can be absent.

## Usage

    build_normalization.py --rustflags              the rustc flags, on one line
    build_normalization.py --cflags                 the C compiler flags, on one line
    build_normalization.py --env [--paths-only]     export lines for a shell to eval; with
                                                    --paths-only the epoch is left out, for a
                                                    build that takes its own build time as an
                                                    input (the Zephyr images' boot clock)
    build_normalization.py --check-binary FILE...   exit 1 when a file holds a prefix
    build_normalization.py --check-workflows        exit 1 when a workflow names the epoch
    build_normalization.py --selftest

`--repo-root`, `--artifacts` and `--cargo-home` say where the prefixes are, for a shell lane
that has resolved them already; otherwise the checkout is this file's, the artifact root is the
one `artifact_root.py` resolves, and the cargo home is cargo's own default. Exit 2 is a refusal,
with the reason on stderr.
"""

from __future__ import annotations

import argparse
import os
import pathlib
import re
import shlex
import subprocess
import sys
import tempfile
from collections.abc import Mapping
from dataclasses import dataclass

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from artifact_root import ENV as ARTIFACT_ROOT_ENV  # noqa: E402  (the one rule of where products are)
from artifact_root import artifact_root  # noqa: E402

#: The checkout this file belongs to.
CHECKOUT = pathlib.Path(__file__).resolve().parents[2]

#: What the checkout (and an artifact root) and the cargo home become.
WORKSPACE_TO = "/wz"
CARGO_TO = "/cargo"

EPOCH = "SOURCE_DATE_EPOCH"
RUSTFLAGS = "RUSTFLAGS"
ENCODED_RUSTFLAGS = "CARGO_ENCODED_RUSTFLAGS"
#: The bare C flags variables, set when they are not.
C_FLAGS = ("CFLAGS", "CXXFLAGS")
#: The other spellings the cc crate reads, added to when they are set.
_C_FLAGS_SPELLING = re.compile(r"^(?:(?:HOST|TARGET)_(?:CFLAGS|CXXFLAGS)|(?:CFLAGS|CXXFLAGS)_.+)$")
_SHELL_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


class NormalizationError(ValueError):
    """A prefix or an environment this rule refuses; the message says why."""


@dataclass(frozen=True)
class Prefixes:
    workspace: str
    artifacts: str
    cargo_home: str

    def distinct(self) -> tuple[str, ...]:
        """Every prefix once, in the rule's order."""
        return tuple(dict.fromkeys((self.workspace, self.artifacts, self.cargo_home)))


def _clean(path: str, what: str) -> str:
    if not path:
        raise NormalizationError(f"the {what} is empty")
    if not path.startswith("/"):
        raise NormalizationError(f"the {what} {path!r} is not an absolute path, and a compiler "
                                 f"matches the absolute paths it was handed")
    if any(c.isspace() for c in path):
        raise NormalizationError(
            f"the {what} {path!r} holds whitespace: cargo splits RUSTFLAGS and the cc crate "
            f"splits CFLAGS on whitespace, so its mapping would reach the compiler as two words "
            f"and the path would stay in the binary. Build from a path without whitespace.")
    if "=" in path:
        raise NormalizationError(
            f"the {what} {path!r} holds '=': gcc splits a prefix map at its first '=', so the "
            f"mapping would name another directory. Build from a path without '='.")
    stripped = path.rstrip("/")
    if not stripped:
        raise NormalizationError(f"the {what} is the file system root, and mapping it would "
                                 f"rename every path")
    return stripped


def resolve_prefixes(env: Mapping[str, str] | None = None, *, repo_root: str | None = None,
                     artifacts: str | None = None, cargo_home: str | None = None) -> Prefixes:
    """The three prefixes: each argument given wins, and an absent one is resolved the way the
    build resolves it (the checkout of this file, the artifact root's one rule, cargo's home)."""
    env = os.environ if env is None else env
    workspace = _clean(str(CHECKOUT) if repo_root is None else repo_root, "checkout")
    if artifacts is None:
        artifacts = str(artifact_root(dict(env), pathlib.Path(workspace)))
    if cargo_home is None:
        cargo_home = env.get("CARGO_HOME") or os.path.join(
            env.get("HOME") or os.path.expanduser("~"), ".cargo")
    return Prefixes(workspace, _clean(artifacts, "artifact root"), _clean(cargo_home, "cargo home"))


def mappings(p: Prefixes) -> list[tuple[str, str]]:
    """(FROM, TO) in command-line order: a prefix another one starts with comes first, since the
    last mapping that matches is the one both compilers apply."""
    entries = [(p.workspace, WORKSPACE_TO)]
    if p.artifacts != p.workspace:
        entries.append((p.artifacts, WORKSPACE_TO))
    entries.append((p.cargo_home, CARGO_TO))
    names = {WORKSPACE_TO: "the checkout or the artifact root", CARGO_TO: "the cargo home"}
    seen: dict[str, str] = {}
    for src, dst in entries:
        if seen.get(src, dst) != dst:
            raise NormalizationError(
                f"{names[seen[src]]} and {names[dst]} are the same directory, {src}: a path under "
                f"it cannot become both {seen[src]} and {dst}")
        seen[src] = dst
    unique = list(dict.fromkeys(entries))

    def starts_with_another(src: str) -> int:
        return sum(1 for other, _ in unique if other != src and src.startswith(other))

    return sorted(unique, key=lambda entry: starts_with_another(entry[0]))


def rustflags(p: Prefixes) -> list[str]:
    return [f"--remap-path-prefix={src}={dst}" for src, dst in mappings(p)]


def cflags(p: Prefixes) -> list[str]:
    return [f"-ffile-prefix-map={src}={dst}" for src, dst in mappings(p)]


def _git_env() -> dict[str, str]:
    # A hook exports GIT_DIR and GIT_INDEX_FILE for the repository it runs in; left in place they
    # would answer for that repository instead of the one named with -C.
    return {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}


def source_date_epoch(repo_root: str | os.PathLike[str]) -> str:
    """The commit time of HEAD in the tree at `repo_root`, in seconds since the Unix epoch."""
    proc = subprocess.run(["git", "-C", str(repo_root), "log", "-1", "--format=%ct"],
                          capture_output=True, text=True, env=_git_env())
    value = proc.stdout.strip()
    if proc.returncode != 0 or not value.isdigit():
        raise NormalizationError(
            f"the commit time of HEAD in {repo_root} could not be read (git exited "
            f"{proc.returncode}: {proc.stderr.strip()[:200]}); a build whose bytes are measured "
            f"dates itself from its commit, so it needs one")
    return value


def _joined(have: str, flags: list[str]) -> str:
    have = have.strip()
    return " ".join([have, *flags]) if have else " ".join(flags)


def normalized_env(base: Mapping[str, str], p: Prefixes, epoch: str | None) -> dict[str, str]:
    """The environment `base` with the flags added (the module doc says how) and the epoch set.
    An epoch of None leaves whatever `base` holds for it. `base` itself is not changed."""
    env = dict(base)
    rust = rustflags(p)
    if ENCODED_RUSTFLAGS in env:
        have = env[ENCODED_RUSTFLAGS]
        env[ENCODED_RUSTFLAGS] = "\x1f".join(([have] if have else []) + rust)
    else:
        env[RUSTFLAGS] = _joined(env.get(RUSTFLAGS, ""), rust)
    c = cflags(p)
    for name in sorted(env):
        if _C_FLAGS_SPELLING.match(name):
            env[name] = _joined(env[name], c)
    for name in C_FLAGS:
        env[name] = _joined(env.get(name, ""), c)
    if epoch is not None:
        env[EPOCH] = epoch
    return env


def env_lines(base: Mapping[str, str], env: Mapping[str, str]) -> list[str]:
    """The export lines that turn one environment into the other, for a shell to eval."""
    lines = []
    for name in sorted(env):
        if base.get(name) == env[name]:
            continue
        if not _SHELL_NAME.match(name):
            raise NormalizationError(
                f"{name} is set and a shell cannot export a variable of that name, so the flags "
                f"could not be added to it; set its spelling with underscores instead")
        lines.append(f"export {name}={shlex.quote(env[name])}")
    return lines


def leaked(data: bytes, p: Prefixes) -> list[str]:
    """The prefixes whose bytes occur in the data."""
    return [prefix for prefix in p.distinct() if prefix.encode() in data]


def check_binary(path: str | os.PathLike[str], p: Prefixes) -> list[str]:
    return leaked(pathlib.Path(path).read_bytes(), p)


def check_workflows(root: pathlib.Path) -> list[str]:
    """Every line of a hosted workflow that names the epoch."""
    findings = []
    workflows = root / ".github" / "workflows"
    for path in sorted([*workflows.glob("*.yml"), *workflows.glob("*.yaml")]):
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if EPOCH in line:
                findings.append(
                    f"{path.relative_to(root)}:{number}: names {EPOCH}, which "
                    f"scripts/lib/build_normalization.py sets from the commit for every build "
                    f"whose bytes are measured; a value set here would build one commit into "
                    f"different bytes on the hosted runner")
    return findings


def _remapped(path: str, maps: list[tuple[str, str]]) -> str:
    """What a compiler that applies the last matching mapping, by string, makes of a path."""
    for src, dst in reversed(maps):
        if path.startswith(src):
            return dst + path[len(src):]
    return path


def selftest() -> int:
    ok = 0
    bad = 0

    def expect(name: str, cond: bool) -> None:
        nonlocal ok, bad
        if cond:
            ok += 1
        else:
            bad += 1
            print(f"  build-normalization selftest FAIL: {name}", file=sys.stderr)

    def refused(why: str, **kw: str) -> bool:
        try:
            mappings(resolve_prefixes({}, **kw))
        except NormalizationError as e:
            return why in str(e)
        return False

    def at(tree: str, out: str | None = None, cargo: str = "/opt/cargo") -> Prefixes:
        return resolve_prefixes({}, repo_root=tree, artifacts=out or tree, cargo_home=cargo)

    plain = at("/srv/tree")
    rooted = at("/srv/tree", "/var/out")
    # Layer Q's flags as run-ci.sh spelled them before this file, byte for byte: any other
    # spelling moves every footprint baseline.
    legacy = "--remap-path-prefix=/srv/tree=/wz --remap-path-prefix=/opt/cargo=/cargo"
    legacy_rooted = ("--remap-path-prefix=/srv/tree=/wz --remap-path-prefix=/var/out=/wz "
                     "--remap-path-prefix=/opt/cargo=/cargo")
    expect("the flags without an artifact root are Layer Q's", " ".join(rustflags(plain)) == legacy)
    expect("the flags under an artifact root are Layer Q's",
           " ".join(rustflags(rooted)) == legacy_rooted)
    cli = subprocess.run([sys.executable, str(pathlib.Path(__file__).resolve()), "--rustflags",
                          "--repo-root", "/srv/tree", "--artifacts", "/var/out",
                          "--cargo-home", "/opt/cargo"], capture_output=True, text=True)
    expect("the command line prints the same flags, alone on one line",
           cli.returncode == 0 and cli.stdout == legacy_rooted + "\n")
    expect("the C flags map the same prefixes in the same order",
           cflags(rooted) == [f.replace("--remap-path-prefix=", "-ffile-prefix-map=")
                              for f in rustflags(rooted)])

    # The longer prefix wins wherever one starts with another.
    maps = mappings(at("/srv/tree", "/srv/tree/out"))
    expect("an artifact root inside the checkout is written after the checkout",
           maps.index(("/srv/tree/out", "/wz")) > maps.index(("/srv/tree", "/wz")))
    expect("a product under such a root reads as its tree path",
           _remapped("/srv/tree/out/crates/target/gen.rs", maps) == "/wz/crates/target/gen.rs"
           and _remapped("/srv/tree/crates/a/src/lib.rs", maps) == "/wz/crates/a/src/lib.rs")
    nested_cargo = mappings(at("/srv/tree", cargo="/srv/tree/.cargo"))
    expect("a cargo home inside the checkout is written after the checkout, and wins",
           nested_cargo[-1] == ("/srv/tree/.cargo", "/cargo")
           and _remapped("/srv/tree/.cargo/registry/src/x.rs", nested_cargo)
           == "/cargo/registry/src/x.rs")
    inside_cargo = mappings(at("/opt/cargo/tree"))
    expect("a checkout inside the cargo home is written after the cargo home",
           inside_cargo == [("/opt/cargo", "/cargo"), ("/opt/cargo/tree", "/wz")]
           and _remapped("/opt/cargo/tree/crates/a.rs", inside_cargo) == "/wz/crates/a.rs"
           and _remapped("/opt/cargo/registry/b.rs", inside_cargo) == "/cargo/registry/b.rs")
    sibling = mappings(at("/srv/tree-out", "/srv/tree"))
    expect("a sibling sharing a stem is ordered as gcc matches, by string",
           sibling == [("/srv/tree", "/wz"), ("/opt/cargo", "/cargo"), ("/srv/tree-out", "/wz")]
           and _remapped("/srv/tree-out/crates/a.rs", sibling) == "/wz/crates/a.rs")

    expect("a checkout with a space is refused, and the reason says why",
           refused("whitespace", repo_root="/srv/my tree", artifacts="/var/out",
                   cargo_home="/opt/cargo"))
    expect("a cargo home with a tab is refused",
           refused("whitespace", repo_root="/srv/tree", artifacts="/srv/tree",
                   cargo_home="/opt/car\tgo"))
    expect("a prefix with '=' is refused",
           refused("'='", repo_root="/srv/a=b", artifacts="/srv/a=b", cargo_home="/opt/cargo"))
    expect("a relative prefix is refused",
           refused("not an absolute path", repo_root="srv/tree", artifacts="/var/out",
                   cargo_home="/opt/cargo"))
    expect("the file system root is refused",
           refused("file system root", repo_root="/srv/tree", artifacts="/srv/tree",
                   cargo_home="/"))
    expect("an artifact root that is the cargo home is refused",
           refused("same directory", repo_root="/srv/tree", artifacts="/opt/cargo",
                   cargo_home="/opt/cargo"))
    expect("a trailing slash is dropped",
           at("/srv/tree/", cargo="/opt/cargo/") == Prefixes("/srv/tree", "/srv/tree", "/opt/cargo"))
    expect("the artifact root comes from its one rule, and is the checkout when unset",
           resolve_prefixes({ARTIFACT_ROOT_ENV: "/var/out"}, repo_root="/srv/tree",
                            cargo_home="/opt/cargo").artifacts == "/var/out"
           and resolve_prefixes({}, repo_root="/srv/tree", cargo_home="/opt/cargo").artifacts
           == "/srv/tree")
    expect("the cargo home is cargo's: the variable, else the home's .cargo, an empty one unset",
           resolve_prefixes({"CARGO_HOME": "/opt/c", "HOME": "/srv/u"}, repo_root="/srv/tree",
                            artifacts="/srv/tree").cargo_home == "/opt/c"
           and resolve_prefixes({"CARGO_HOME": "", "HOME": "/srv/u"}, repo_root="/srv/tree",
                                artifacts="/srv/tree").cargo_home == "/srv/u/.cargo")

    # The environment: added to, never replaced.
    rust = rustflags(rooted)
    c = " ".join(cflags(rooted))
    base = {"CFLAGS": "-O2", "CFLAGS_x86_64_unknown_linux_gnu": "-g", "TARGET_CXXFLAGS": "-Os",
            "RUSTFLAGS": "-Dwarnings", "PATH": "/bin", EPOCH: "1"}
    snapshot = dict(base)
    env = normalized_env(base, rooted, "1700000000")
    expect("the caller's C flags keep their place before the maps",
           env["CFLAGS"] == f"-O2 {c}" and env["CFLAGS_x86_64_unknown_linux_gnu"] == f"-g {c}"
           and env["TARGET_CXXFLAGS"] == f"-Os {c}")
    expect("an unset C++ flags variable is set to the maps", env["CXXFLAGS"] == c)
    expect("the caller's rustc flags keep their place before the maps",
           env["RUSTFLAGS"] == " ".join(["-Dwarnings", *rust]))
    expect("the epoch is set over an inherited one, and nothing else moves",
           env[EPOCH] == "1700000000" and env["PATH"] == "/bin" and base == snapshot)
    encoded = normalized_env({ENCODED_RUSTFLAGS: "-Dwarnings", "RUSTFLAGS": "--cfg x"}, rooted, None)
    expect("encoded flags, which cargo prefers, are the ones added to",
           encoded[ENCODED_RUSTFLAGS] == "\x1f".join(["-Dwarnings", *rust])
           and encoded["RUSTFLAGS"] == "--cfg x"
           and normalized_env({ENCODED_RUSTFLAGS: ""}, rooted, None)[ENCODED_RUSTFLAGS]
           == "\x1f".join(rust))
    expect("without an epoch the caller's is left as it was",
           normalized_env({EPOCH: "5"}, rooted, None)[EPOCH] == "5"
           and EPOCH not in normalized_env({}, rooted, None))
    lines = env_lines(base, env)
    exported = [shlex.split(line) for line in lines]
    expect("the export lines name what changed, once each, and read back to the values",
           [words[1].split("=", 1)[0] for words in exported]
           == sorted(k for k in env if base.get(k) != env[k])
           and all(words[0] == "export" and len(words) == 2
                   and env[words[1].split("=", 1)[0]] == words[1].split("=", 1)[1]
                   for words in exported))
    dashed = {"CFLAGS_x86_64-unknown-linux-gnu": "-g"}
    try:
        env_lines(dashed, normalized_env(dashed, rooted, None))
        expect("a set variable no shell can export is refused", False)
    except NormalizationError as e:
        expect("a set variable no shell can export is refused, by name",
               "CFLAGS_x86_64-unknown-linux-gnu" in str(e))

    # The verdict on a built file.
    expect("a file holding the checkout's path names it",
           leaked(b"\x00panicked at /srv/tree/crates/a.rs\x00", rooted) == ["/srv/tree"])
    expect("a file holding the artifact root's or the cargo home's path names it",
           leaked(b"/var/out/crates/target/x /opt/cargo/registry/y", rooted)
           == ["/var/out", "/opt/cargo"])
    expect("a file holding only the replacements is clean",
           leaked(b"/wz/crates/a.rs /cargo/registry/y", rooted) == [])

    with tempfile.TemporaryDirectory() as tmp:
        root = pathlib.Path(tmp)
        flows = root / ".github" / "workflows"
        flows.mkdir(parents=True)
        (flows / "clean.yml").write_text("jobs:\n  a:\n    runs-on: x\n", encoding="utf-8")
        expect("a workflow that does not name the epoch passes", check_workflows(root) == [])
        (flows / "pinned.yaml").write_text(f"env:\n  {EPOCH}: 0\n", encoding="utf-8")
        found = check_workflows(root)
        expect("a workflow that sets the epoch is named with its line",
               len(found) == 1 and found[0].startswith(".github/workflows/pinned.yaml:2:"))

        repo = root / "repo"
        repo.mkdir()
        git = ["git", "-C", str(repo), "-c", "user.name=wz", "-c", "user.email=wz@invalid",
               "-c", "commit.gpgsign=false", "-c", "core.hooksPath=/dev/null"]
        dated = {**_git_env(), "GIT_AUTHOR_DATE": "@1700000000 +0000",
                 "GIT_COMMITTER_DATE": "@1700000000 +0000"}
        made = (subprocess.run([*git, "init", "-q"], capture_output=True, env=dated).returncode == 0
                and subprocess.run([*git, "commit", "-q", "--allow-empty", "-m", "dated"],
                                   capture_output=True, env=dated).returncode == 0)
        expect("the epoch is the commit time of HEAD",
               made and source_date_epoch(repo) == "1700000000")
        try:
            source_date_epoch(root / "absent")
            expect("a tree with no commit to read is refused", False)
        except NormalizationError:
            expect("a tree with no commit to read is refused", True)

    print(f"  build-normalization selftest: {ok}/{ok + bad} arm(s) pass")
    return 0 if bad == 0 else 1


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description="The build normalization rule (see the module doc).")
    mode = ap.add_mutually_exclusive_group(required=True)
    mode.add_argument("--rustflags", action="store_true")
    mode.add_argument("--cflags", action="store_true")
    mode.add_argument("--env", action="store_true")
    mode.add_argument("--check-binary", nargs="+", metavar="FILE")
    mode.add_argument("--check-workflows", action="store_true")
    mode.add_argument("--selftest", action="store_true")
    ap.add_argument("--paths-only", action="store_true")
    ap.add_argument("--repo-root")
    ap.add_argument("--artifacts")
    ap.add_argument("--cargo-home")
    args = ap.parse_args(argv)
    if args.paths_only and not args.env:
        ap.error("--paths-only goes with --env")
    if args.selftest:
        return selftest()
    if args.check_workflows:
        findings = check_workflows(CHECKOUT)
        for finding in findings:
            print(f"  build-normalization FAIL: {finding}", file=sys.stderr)
        return 1 if findings else 0
    try:
        p = resolve_prefixes(repo_root=args.repo_root, artifacts=args.artifacts,
                             cargo_home=args.cargo_home)
        if args.rustflags:
            print(" ".join(rustflags(p)))
            return 0
        if args.cflags:
            print(" ".join(cflags(p)))
            return 0
        if args.env:
            epoch = None if args.paths_only else source_date_epoch(p.workspace)
            lines = env_lines(os.environ, normalized_env(os.environ, p, epoch))
            if lines:
                print("\n".join(lines))
            return 0
        rc = 0
        for path in args.check_binary:
            found = check_binary(path, p)
            if found:
                print(f"  build-normalization: {path} holds the build path prefix(es) "
                      f"{', '.join(found)}", file=sys.stderr)
                rc = 1
        return rc
    except (ValueError, OSError) as e:
        print(f"build-normalization: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
