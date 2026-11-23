#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
"""R4610 (no register item) -- what the verification lanes measure: the crates of the cooperative
engine, each in the feature sets the shipped builds give it.

## Why a set is read and not written

A coverage figure, a sanitizer's silence and the interpreter's are claims about one build, and
the builds this tree ships are two: the pico C library (the package's profile, resolved by the
pinned Kconfig interpreter: `wz_config.py --resolve-features pico configs/profiles/host-peer-ext.conf`)
and the MCU kit images (`deploy/zephyr-*/rust`). A feature list typed here would drift from both the
day either moved, and the lanes would go on measuring a build nobody ships. So a unit names where
its set comes from, and the set is resolved when the lane runs:

  * `library`: the C library's own crate takes the profile's cargo arguments as they resolve; a crate
    under it takes the features cargo enables for it in that build (`cargo tree -e normal` over the
    library's arguments, read with `--format '{p}|{f}'`);
  * `kit:<image>`: the features cargo enables for the crate in a kit image's build, for the image's
    target, from the image's committed lock file (`KITS` names each image's manifest and the
    arguments its overlays select, which the image's CMake derives from Kconfig);
  * `args`: a set written here, for a path a lane exists to look at that neither build reaches with
    its tests on a host (the read task of the cooperative engine's multi-threaded arm, the host
    lock), or a unit the interpreter can run at all.

A resolved feature the crate does not declare (one cargo reports for an optional dependency the
crate names with `dep:`) is dropped. A crate the build does not reach is a failure, never an empty
set: a unit with no build to measure would pass by measuring nothing.

## What a unit runs

`cargo test -p <crate> <cargo arguments> -- <test arguments>`, from `crates/`, under the lane's compiler and
flags (`scripts/verify.sh`). The cargo arguments carry the features and the targets (`--lib`, and
`--tests` where the crate's integration tests drive its C ABI); the test arguments are the name filters
of a unit the interpreter runs, whose other tests open sockets or call the host's C library.

## Modes

    --selftest           every reading and refusal driven through a fixture
    --units LANE         one line a unit, `<unit>|<crate>|<cargo arguments>|<test arguments>`, resolved
    --crates LANE        the crates the lane's units test, one a line (no resolution)
    --library-features   the C library's capabilities without its engine, comma separated: the list
                         `scripts/pico-c-program.sh` takes beside `WZ_PICO_ENGINE=coop`
    --programs           the C programs the sanitizer lanes run against the library, `<source>|<what>`
    --executables FILE   the test executables cargo's JSON report of a build names, one a line

LANE is one of `coverage`, `tsan`, `asan` and `miri`.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
LANES = ("coverage", "tsan", "asan", "miri")

# The C library: the package's profile, its crate, and the engine the profile must resolve to
# (the package ships the cooperative engine; a profile that resolves to another is refused rather
# than measured).
LIBRARY_PROFILE = "configs/profiles/host-peer-ext.conf"
LIBRARY_CRATE = "wz-capi-pico"
LIBRARY_ENGINE = "engine-coop"
PROFILE_PREFIX = ("--no-default-features", "--features")

# The kit images: the manifest of the image's Rust half, the cargo arguments of its build and the
# target it is built for. `client-fixed-get` is the T2G client of the fixed-memory profile that asks
# (overlays t2g_zeth, t2g_client, t2g_client_fixed and t2g_client_get, through the axes of
# `deploy/zephyr-admin-node/wz_axes.cmake`); `pico-abi` is the pico C ABI image on Zephyr's own driver
# with zenoh-pico's multi-threaded arm.
KITS: dict[str, tuple[str, tuple[str, ...], str]] = {
    "client-fixed-get": (
        "deploy/zephyr-admin-node/rust",
        ("--no-default-features", "--features", "net-zephyr-sockets,fixed-client,get,initial-sn-compact"),
        "thumbv7em-none-eabihf",
    ),
    "pico-abi": (
        "deploy/zephyr-capi-pico/rust",
        ("--no-default-features", "--features", "multi-thread"),
        "thumbv7em-none-eabihf",
    ),
}

# The cooperative engine's planes with the read task of the multi-threaded arm: the set Layer C1p32
# tests the engine in, and the arm whose threads the race detector is for.
COOP_THREADS = ("engine-coop,peer,multi-thread,link-udp,query,queryable,liveliness,liveliness-get,"
                "advanced,unstable-api,connectivity,app-transport")
# The lent records of the slot profile, as Layer C1ns tests `lent_tests` in.
LENT_RECORDS = ("alloc,no_std,session-unicast,session-unicast-open,session-unicast-accept,"
                "codec-init-body,codec-open-body,codec-close,codec-frame,codec-keep-alive,"
                "transport-keepalive,codec-push,pubsub-put,keyexpr-wildcard-single,"
                "keyexpr-wildcard-double,keyexpr-includes,codec-declare,codec-request,codec-response,"
                "codec-response-final,declare-subscriber,declare-queryable,query-queryable,"
                "liveliness-token,liveliness-subscriber,liveliness-get,session-slot")

LIB = ("--lib",)
LIB_TESTS = ("--lib", "--tests")
MEASURED = frozenset({"coverage", "tsan", "asan"})
SAFETY = frozenset({"coverage", "asan"})
MIRI = frozenset({"miri"})


@dataclass(frozen=True)
class Unit:
    """One cargo test run: a crate, where its feature set comes from, its targets, the lanes that
    run it and, for the interpreter, the test name filters."""

    unit: str
    crate: str
    source: str
    args: tuple[str, ...] = ()
    targets: tuple[str, ...] = LIB
    lanes: frozenset = MEASURED
    filters: tuple[str, ...] = ()


UNITS: tuple[Unit, ...] = (
    Unit("library", "wz-capi-pico", "library", targets=LIB_TESTS),
    Unit("library", "wz-capi-coop", "library"),
    Unit("library", "wz-runtime-coop", "library"),
    Unit("library", "wz-session-core", "library", lanes=SAFETY),
    Unit("coop-threads", "wz-capi-pico", "args", ("--no-default-features", "--features", COOP_THREADS),
         targets=LIB_TESTS),
    Unit("host-lock", "wz-capi-coop", "args"),
    Unit("host-lock", "wz-runtime-coop", "args",
         ("--features", "host-lock,alloc,wz-session-core/alloc,session-unicast")),
    Unit("kit-client", "wz-session-mcu", "kit:client-fixed-get", lanes=SAFETY),
    Unit("kit-client", "wz-runtime-coop", "kit:client-fixed-get", lanes=SAFETY),
    Unit("kit-client", "wz-session-core", "kit:client-fixed-get", lanes=SAFETY),
    Unit("kit-pico", "wz-runtime-coop", "kit:pico-abi", lanes=SAFETY),
    Unit("kit-pico", "wz-session-core", "kit:pico-abi", lanes=SAFETY),
    # The interpreter's units: the modules whose unsafe code lends places of an arena, and the
    # host lock made in its place. Their other tests open sockets, which it does not have.
    Unit("arena-cells", "wz-session-core", "args",
         ("--features", "codec-push,codec-request,codec-response,codec-response-final"), lanes=MIRI,
         filters=("key_arena::", "bounded::", "lent_control::", "lent_push::", "lent_request::",
                  "lent_response::")),
    Unit("arena-cells-fixed", "wz-session-core", "args",
         ("--no-default-features", "--features", "alloc,bounded-heapless"), lanes=MIRI,
         filters=("key_arena::", "bounded::")),
    Unit("lent-records", "wz-session-core", "args", ("--no-default-features", "--features", LENT_RECORDS),
         lanes=MIRI, filters=("lent_tests",)),
    Unit("lane-arena", "wz-capi-coop", "args", (), lanes=MIRI, filters=("tests::lane::", "tests::arena::")),
    Unit("host-os", "wz-capi-port", "args", (), lanes=MIRI, filters=("os::",)),
)

# What a lane sets for its own builds and a resolution must not see: the feature sets are read with
# the workspace's own toolchain and flags, as the shipped builds resolve them. A sanitizer's flags
# reaching `cargo tree` make it probe the target with them, which the workspace's stable compiler
# refuses; a nightly named for the lane would resolve with another cargo than the build's.
LANE_ENV = ("RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "RUSTDOCFLAGS", "RUSTUP_TOOLCHAIN",
            "LLVM_PROFILE_FILE", "MIRIFLAGS", "MIRI_SYSROOT")

# The C programs of the pico C ABI the sanitizer lanes build against the library and run: the
# examples of the release package, as the Platform workflow's `capi-examples` job runs them.
PROGRAMS: tuple[tuple[str, str], ...] = (
    ("crates/wz-capi-pico/examples/c/profiles.c", "example of pub/sub and query under profiles"),
    ("crates/wz-capi-pico/examples/c/transports.c", "example of tcp, udp and a group"),
    ("crates/wz-capi-pico/tests/c/pico_app_transport.c", "a transport the program supplies"),
    ("crates/wz-capi-pico/examples/c/own_transport.c", "a network stack of the program's own"),
    ("crates/wz-capi-pico/examples/c/batching.c", "batching on and off with a flush"),
    ("crates/wz-capi-pico/examples/c/e2e.c", "end-to-end protection across a session"),
    ("crates/wz-capi-pico/examples/c/supervision.c", "supervision of a periodic stream"),
    ("crates/wz-capi-pico/examples/c/periodic.c", "a program's own periodic task"),
    ("crates/wz-capi-pico/examples/c/keyed.c", "a keyed topic with a last value per instance"),
    ("crates/wz-capi-pico/examples/c/history.c", "history for a late subscriber"),
)


class Refused(Exception):
    """A set that cannot be resolved, said in a sentence."""


def units_of(lane: str, units: tuple[Unit, ...] = UNITS) -> list[Unit]:
    if lane not in LANES:
        raise Refused(f"no lane {lane!r}: the lanes are {', '.join(LANES)}")
    return [u for u in units if lane in u.lanes]


def crates_of(lane: str, units: tuple[Unit, ...] = UNITS) -> list[str]:
    """The crates the lane's units test, in the order first named."""
    out: list[str] = []
    for unit in units_of(lane, units):
        if unit.crate not in out:
            out.append(unit.crate)
    return out


def parse_profile_args(text: str) -> tuple[str, ...]:
    """The cargo arguments `wz_config.py --resolve-features` printed for the library."""
    tokens = tuple(text.split())
    if len(tokens) != 3 or tokens[:2] != PROFILE_PREFIX:
        raise Refused(f"the library profile resolved to {text.strip()!r}, not "
                      f"`--no-default-features --features <list>`")
    if LIBRARY_ENGINE not in tokens[2].split(","):
        raise Refused(f"the library profile does not resolve to the cooperative engine "
                      f"({LIBRARY_ENGINE}): {text.strip()}")
    return tokens


def library_features(profile_args: tuple[str, ...]) -> str:
    """The library's capabilities without its engine, which pico-c-program.sh names itself."""
    return ",".join(f for f in profile_args[2].split(",") if f != LIBRARY_ENGINE)


def parse_tree(text: str) -> dict[str, list[str]]:
    """Each package of `cargo tree --prefix none --format '{p}|{f}'` output with the features cargo
    enabled for it, read from the first line that names it (a repeated package is the same build)."""
    found: dict[str, list[str]] = {}
    for line in text.splitlines():
        if "|" not in line:
            continue
        package, _, features = line.partition("|")
        name = package.strip().split(" ")[0]
        if not name or name in found:
            continue
        features = features.strip()
        if features.endswith("(*)"):
            features = features[: -len("(*)")].strip()
        found[name] = [f for f in features.split(",") if f]
    return found


def feature_args(crate: str, enabled: dict[str, list[str]], declared: dict[str, set[str]],
                 where: str) -> tuple[str, ...]:
    """The cargo arguments that build `crate` with exactly the features `where` gives it."""
    if crate not in enabled:
        raise Refused(f"{where} does not reach {crate}, so it gives the crate no build to measure")
    if crate not in declared:
        raise Refused(f"{crate} is not a package of the crates workspace")
    kept = [f for f in enabled[crate] if f in declared[crate] and f != "default"]
    return ("--no-default-features", "--features", ",".join(kept)) if kept else ("--no-default-features",)


def parse_executables(text: str) -> list[str]:
    """The test executables a `cargo test --no-run --message-format=json` report names."""
    out: list[str] = []
    for line in text.splitlines():
        if not line.startswith("{"):
            continue
        try:
            msg = json.loads(line)
        except ValueError:
            continue
        if (msg.get("reason") == "compiler-artifact" and msg.get("executable")
                and (msg.get("profile") or {}).get("test")):
            if msg["executable"] not in out:
                out.append(msg["executable"])
    return out


class Resolver:
    """Runs the commands a resolution needs, each once."""

    def __init__(self) -> None:
        self._profile: tuple[str, ...] | None = None
        self._trees: dict[str, dict[str, list[str]]] = {}
        self._declared: dict[str, set[str]] | None = None

    @staticmethod
    def _run(cmd: list[str]) -> str:
        env = resolution_env(os.environ)
        proc = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True, env=env)
        if proc.returncode != 0:
            raise Refused(f"`{' '.join(cmd)}` exited {proc.returncode}: {proc.stderr.strip()[-800:]}")
        return proc.stdout

    def profile(self) -> tuple[str, ...]:
        if self._profile is None:
            self._profile = parse_profile_args(self._run(
                [sys.executable, "scripts/lib/wz_config.py", "--resolve-features", "pico", LIBRARY_PROFILE]))
        return self._profile

    def declared(self) -> dict[str, set[str]]:
        if self._declared is None:
            meta = json.loads(self._run(["cargo", "metadata", "--format-version", "1", "--no-deps",
                                         "--manifest-path", "crates/Cargo.toml"]))
            self._declared = {p["name"]: set(p.get("features", {})) for p in meta["packages"]}
        return self._declared

    def tree(self, key: str) -> dict[str, list[str]]:
        if key not in self._trees:
            fmt = ["-e", "normal", "--prefix", "none", "--format", "{p}|{f}", "--locked"]
            if key == "library":
                cmd = ["cargo", "tree", "--manifest-path", "crates/Cargo.toml", "-p", LIBRARY_CRATE,
                       *self.profile(), *fmt]
            else:
                manifest, args, target = KITS[key]
                cmd = ["cargo", "tree", "--manifest-path", f"{manifest}/Cargo.toml", *args,
                       "--target", target, *fmt]
            self._trees[key] = parse_tree(self._run(cmd))
        return self._trees[key]

    def cargo_args(self, unit: Unit) -> tuple[str, ...]:
        if unit.source == "args":
            return unit.args
        if unit.source == "library":
            if unit.crate == LIBRARY_CRATE:
                return self.profile()
            return feature_args(unit.crate, self.tree("library"), self.declared(),
                                f"the C library ({LIBRARY_PROFILE})")
        if unit.source.startswith("kit:"):
            kit = unit.source[len("kit:"):]
            if kit not in KITS:
                raise Refused(f"unit {unit.unit} of {unit.crate} names no kit image {kit!r}")
            return feature_args(unit.crate, self.tree(kit), self.declared(), f"the kit image {kit}")
        raise Refused(f"unit {unit.unit} of {unit.crate} has no source {unit.source!r}")


def resolution_env(environ: object) -> dict[str, str]:
    """The environment a resolution runs in: the caller's, without what a lane sets for its builds."""
    return {key: value for key, value in dict(environ).items() if key not in LANE_ENV}


def unit_line(unit: Unit, cargo_args: tuple[str, ...]) -> str:
    fields = (unit.unit, unit.crate, " ".join((*cargo_args, *unit.targets)), " ".join(unit.filters))
    for value in fields:
        if "|" in value or "\n" in value:
            raise Refused(f"unit {unit.unit} of {unit.crate} carries a separator in {value!r}")
    return "|".join(fields)


def selftest() -> int:
    cases = 0

    # Every lane has a unit, and every unit a lane and a source this file resolves.
    for lane in LANES:
        assert units_of(lane), f"lane {lane} has no unit"
    assert all(u.lanes and u.lanes <= set(LANES) for u in UNITS), "a unit names no lane or an unknown one"
    assert all(u.source in ("args", "library") or u.source[len("kit:"):] in KITS for u in UNITS)
    assert all(u.filters for u in UNITS if "miri" in u.lanes), "an interpreter unit without filters"
    assert crates_of("coverage") == ["wz-capi-pico", "wz-capi-coop", "wz-runtime-coop",
                                     "wz-session-core", "wz-session-mcu"], crates_of("coverage")
    try:
        units_of("valgrind")
    except Refused:
        cases += 1
    else:
        raise AssertionError("an unknown lane was given units")
    cases += 1

    # The profile's arguments: the shape wz_config prints, the engine, and the list without it.
    args = parse_profile_args("--no-default-features --features engine-coop,peer,query\n")
    assert args == ("--no-default-features", "--features", "engine-coop,peer,query"), args
    assert library_features(args) == "peer,query"
    for bad, needle in (("--no-default-features --features engine-tokio,peer", "cooperative engine"),
                        ("--no-default-features", "not "),
                        ("--features engine-coop extra words", "not ")):
        try:
            parse_profile_args(bad)
        except Refused as error:
            assert needle in str(error), (bad, str(error))
            cases += 1
        else:
            raise AssertionError(f"{bad!r} was read as the library's arguments")

    # cargo tree's lines: the first naming of a package wins, a repeat marker and an empty list read.
    tree = parse_tree("wz-capi-pico v0.1.0 (/x/crates/wz-capi-pico)|engine-coop,std\n"
                      "wz-session-core v0.1.0 (/x/crates/wz-session-core)|alloc,codec-push\n"
                      "wz-session-core v0.1.0 (/x/crates/wz-session-core)|alloc (*)\n"
                      "wz-capi-port v0.1.0 (/x/crates/wz-capi-port)| (*)\n"
                      "noise without a separator\n")
    assert tree == {"wz-capi-pico": ["engine-coop", "std"], "wz-session-core": ["alloc", "codec-push"],
                    "wz-capi-port": []}, tree
    cases += 1

    # A resolved set keeps what the crate declares, drops an optional dependency's name and
    # `default`, and an empty one is a build with no feature; a crate the build does not reach fails.
    declared = {"wz-session-core": {"alloc", "codec-push", "default"}, "wz-capi-port": {"std"}}
    enabled = {"wz-session-core": ["alloc", "hashbrown", "default", "codec-push"], "wz-capi-port": []}
    assert feature_args("wz-session-core", enabled, declared, "w") == (
        "--no-default-features", "--features", "alloc,codec-push")
    assert feature_args("wz-capi-port", enabled, declared, "w") == ("--no-default-features",)
    for crate, needle in (("wz-session-mcu", "does not reach"), ("wz-other", "does not reach")):
        try:
            feature_args(crate, enabled, declared, "the build")
        except Refused as error:
            assert needle in str(error), str(error)
            cases += 1
        else:
            raise AssertionError(f"{crate} was given a set by a build that does not reach it")
    try:
        feature_args("wz-session-mcu", {"wz-session-mcu": ["alloc"]}, declared, "the build")
    except Refused as error:
        assert "not a package" in str(error), str(error)
        cases += 1
    else:
        raise AssertionError("a crate of no workspace was given a set")

    # A unit's line: its targets after its features, its filters last, and a separator refused.
    line = unit_line(Unit("u", "wz-capi-coop", "args", filters=("tests::lane::", "os::")),
                     ("--features", "a,b"))
    assert line == "u|wz-capi-coop|--features a,b --lib|tests::lane:: os::", line
    try:
        unit_line(Unit("u", "c", "args"), ("--features", "a|b"))
    except Refused:
        cases += 1
    else:
        raise AssertionError("a separator inside a field was written")

    # The resolver: an args unit is itself, a kit the table lacks is refused.
    resolver = Resolver()
    assert resolver.cargo_args(Unit("u", "c", "args", ("--features", "x"))) == ("--features", "x")
    for unit, needle in ((Unit("u", "c", "kit:nowhere"), "no kit image"), (Unit("u", "c", "elsewhere"), "no source")):
        try:
            resolver.cargo_args(unit)
        except Refused as error:
            assert needle in str(error), str(error)
            cases += 1
        else:
            raise AssertionError(f"{unit.source} was resolved")

    # A resolution does not see a lane's flags or its nightly, and keeps the rest of the caller's.
    clean = resolution_env({"RUSTFLAGS": "-Zsanitizer=thread", "CARGO_ENCODED_RUSTFLAGS": "-Zx",
                            "RUSTUP_TOOLCHAIN": "nightly", "MIRI_SYSROOT": "/s", "PATH": "/bin"})
    assert clean == {"PATH": "/bin"}, clean
    cases += 1

    # cargo's report: only test executables, each once, and a line that is not JSON passes by.
    report = "\n".join((
        json.dumps({"reason": "compiler-artifact", "executable": "/t/deps/a-1", "profile": {"test": True}}),
        json.dumps({"reason": "compiler-artifact", "executable": "/t/deps/a-1", "profile": {"test": True}}),
        json.dumps({"reason": "compiler-artifact", "executable": "/t/build/b", "profile": {"test": False}}),
        json.dumps({"reason": "compiler-artifact", "executable": None, "profile": {"test": True}}),
        json.dumps({"reason": "build-finished", "success": True}),
        "{not json",
        "   Compiling a v0.1.0",
    ))
    assert parse_executables(report) == ["/t/deps/a-1"], parse_executables(report)
    cases += 1

    print(f"verify_plan selftest: {cases} cases pass")
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="the units the verification lanes run")
    mode = ap.add_mutually_exclusive_group(required=True)
    mode.add_argument("--selftest", action="store_true")
    mode.add_argument("--units", metavar="LANE")
    mode.add_argument("--crates", metavar="LANE")
    mode.add_argument("--library-features", action="store_true")
    mode.add_argument("--programs", action="store_true")
    mode.add_argument("--executables", type=Path, metavar="FILE")
    args = ap.parse_args(argv)
    if args.selftest:
        return selftest()
    try:
        if args.units is not None:
            resolver = Resolver()
            lines = [unit_line(unit, resolver.cargo_args(unit)) for unit in units_of(args.units)]
            print("\n".join(lines))
        elif args.crates is not None:
            print("\n".join(crates_of(args.crates)))
        elif args.library_features:
            print(library_features(Resolver().profile()))
        elif args.programs:
            print("\n".join(f"{source}|{what}" for source, what in PROGRAMS))
        else:
            found = parse_executables(args.executables.read_text(encoding="utf-8", errors="replace"))
            if not found:
                raise Refused(f"{args.executables} names no test executable")
            print("\n".join(found))
    except (Refused, OSError) as error:
        print(f"  verify-plan FAIL: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
