#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
"""R311y881 (no register item) — the APT PACKAGE census: what each CI job
downloads, and why.

The open-debt numbers nearest to it live in the unregistered half of the
register: 317 / 307 / 291 / 323 are the apt CEILING, and this gate does NOT
close them. It measures the thing the ceiling was standing in for, and the
measurement is why they cannot be closed by picking a better number.

## The class this exists for

Four consecutive rounds tuned the apt CEILING (`scripts/lib/apt-install.sh`):
R311y865 bounded `update`, R311y872 fixed the kill, R311y874 raised the
numbers, R311y876 stopped a failed `update` vetoing the install. Not one of
them asked what the ceiling is bounding. R311y881 measured it off the run
32266212482 job logs, and the measurement refutes the premise the whole
lineage rests on:

    cmake-data   1913 kB  in  67.5s   ~28 kB/s
    cmake        5010 kB  in 187.7s   ~27 kB/s
    libclang-14-dev 25.2 MB  killed at 633s, needs ~933s alone

At 27 kB/s the `routing-adminspace` job's 32.3 MB needs ~1200s and the
`cross-mcu` job's 142 MB needs ~88 MINUTES, which is past the job's own
`timeout-minutes`. NO ceiling number is right for both, and no ceiling number
is right for the second at all. The variable is throughput and the lever is
BYTES -- which nothing was looking at, because the package lists are
copy-pasted and nobody owned them.

## What it pins

Every `apt-install.sh` invocation in `.github/workflows/ci.yml`, as a
`<job>::<package>` SET -- not a count, which moves for two reasons and says
which neither. A site absent from ADJUDICATED is a package nobody justified;
a row with no site is a justification that outlived its code (the shape
open-debt item 47 names). Both are FAIL.

## What it DERIVES rather than believes

`cmake` is the one package whose need is decidable from this tree, so this
gate decides it instead of reading prose. `cargo tree -e normal,build -i
cmake --workspace --all-features` answers with exactly one consumer,
`zenoh-pico-sys`, and that crate has no dependents at all -- it is built only
by a `--workspace` command or by being named. So a job may install `cmake`
only if one of its `--layer` steps runs a layer whose `run-ci.sh` body
reaches that crate, or if the job invokes cmake outside cargo (Zephyr's west
build, which is declared below by name).

The other packages are adjudicated as PROSE and that is a stated limit, not
an oversight: `libclang-dev` is needed wherever `bindgen` is in the closure,
which is everywhere, because `sce-forge-runtime`'s build script
build-depends on `sce-build` -> `libxml` -> `bindgen`. A prose reason can go
stale the way open-debt item 338 describes, and nothing here re-checks it.

## The OTHER direction (R2104, open-debt item 522)

Everything above measures EXCESS: is each installed package justified. The
question it does not ask is SHORTFALL: is each package the build REQUIRES
actually installed. Those are two different failures and only one of them was
gated, so the tree carried the other for as long as it has existed.

Measured 2026-08-25 from a downstream report: `libxml2-dev` appears ZERO times
in any workflow, and the build requires it. On a clean `ubuntu:24.04` the build
dies with "The system library `libxml-2.0` required by crate `libxml` was not
found". Every hosted run passes only because the GitHub runner IMAGE happens to
carry libxml2 — an inheritance nothing declares, nothing checks, and nothing
would notice the removal of.

The tree already KNEW, in three places, and knowing was not enough:
`ci.yml`'s own comment says the resolved tree "pulls bindgen (libclang),
libxml, and the vendor/sce crates" while the install line beside it names only
`libclang-dev clang perl`; `run-ci.sh` states "CI Linux has libxml2 (it builds
...)" as a fact about someone else's image; and the `portability` job installs
libxml2 through vcpkg on Windows with a paragraph explaining exactly why the
build needs it. Three statements of the requirement, no installation of it.

WHAT THE SHORTFALL ARM DERIVES. The population is not a list of libraries
anyone typed. `cargo metadata --all-features` resolves the real build graph;
every package in it that has a build script has that script READ; and the
pkg-config module names it probes for are the system libraries the build will
demand. Today that derivation yields exactly one, `libxml-2.0`, wanted by the
`libxml` crate — which is the crate the downstream error names.

`MODULE_APT` maps a module to the Debian package that provides it, and it is
the one hand-written thing here. It is not believed: wherever `pkg-config` and
`dpkg` are both present the gate RESOLVES each row -- `pkg-config
--variable=pcfiledir <mod>` then `dpkg -S <that>/<mod>.pc` -- and reds on a row
that names the wrong package. Both directions again: a probed module with no
row fails, and a row nothing probes fails.

WHICH JOBS. The same reverse-reachability the `cmake` arm uses, over the real
resolve graph: a job needs the package if anything it runs reaches a workspace
member whose closure contains the probing crate. Scoped to jobs whose
`runs-on` names ubuntu, because `apt-install.sh` is what this file is about —
`portability` (macOS + Windows) needs libxml2 just as much and gets it from
vcpkg, which is out of this gate's subject rather than exempt from it.

STATED LIMIT: this arm sees pkg-config consumers and nothing else. `libclang`
is dlopen'd by `clang-sys` rather than probed, `perl` is a program, and
`libpcap-dev` is here for a header a gate reads. Those stay adjudicated as
prose above. The class this closes is the one that actually bit: a crate that
asks pkg-config for a library nobody installed.
"""

from __future__ import annotations

import functools
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CI_YML = ROOT / ".github/workflows/ci.yml"
RUN_CI = ROOT / "scripts/run-ci.sh"

# `<job>::<package>` -> why that job needs it. The job key is the YAML job id
# (the `  <id>:` line), not the human `name:`, because the id is what the rest
# of the file refers to.
#
# Reasons are grouped by package so a reader sees the whole answer for one
# package at once; the table itself is flat so the gate can compare sets.
ADJUDICATED: dict[str, str] = {}


def _add(pkg: str, why: str, jobs: list[str]) -> None:
    for job in jobs:
        ADJUDICATED[f"{job}::{pkg}"] = why


# bindgen, via `sce-forge-runtime`'s BUILD SCRIPT: it build-depends on
# `sce-build` -> `libxml` -> `bindgen`, so every crate that uses the SCE forge
# runtime -- which is every wz crate carrying a generated codec -- compiles a
# libclang consumer. 25.2 MB of a 32.3 MB job, and the largest single item in
# this whole census.
#
# It is worth naming what that build script is FOR, because it is not wz:
# `vendor/sce/backends/rust/forge-runtime/build.rs` generates SCE's own
# numerical-conformance test fixtures. R311y22 moved wz's codegen into
# committed `out/**` so "a plain `cargo build` of the wz stack needs no
# libxml2/SCE toolchain" (`scripts/regen-codegen.sh`), and this build-dep is
# why that sentence is not true. SCE is pinned and read-only from wz sessions,
# so this is a HANDOFF, not a row anyone here can delete.
_add(
    "libclang-dev",
    "bindgen, reached through sce-forge-runtime's build script (sce-build -> "
    "libxml -> bindgen). Every wz crate with a generated codec pulls it.",
    [
        "ci",
        "validate-codegen",
        "verdict-legs",
        # R2163 — Layer C1cn's own job, peeled off `ci` for its budget. It
        # compiles EVERY member at its non-default features, so every reason on
        # this row that reaches a member reaches it. No `cmake`: that one is
        # DERIVED below, and this lane names members individually rather than
        # running a `--workspace` command, so it never reaches zenoh-pico-sys.
        "nondefault",
        "footprint",
        "interop",
        "cross-mcu",
        "zephyr-mcu",
        "feature-gates",
        "routing-adminspace",
        "transport-modes",
        "isolated-crates",
        "capi-c-arms",
        "e2e-demo",
    ],
)
_add(
    "clang",
    "the compiler driver bindgen's clang-sys resolves against; paired with "
    "libclang-dev above and carried on the same jobs.",
    [
        "ci",
        "validate-codegen",
        "verdict-legs",
        # R2163 — Layer C1cn's own job, peeled off `ci` for its budget. It
        # compiles EVERY member at its non-default features, so every reason on
        # this row that reaches a member reaches it. No `cmake`: that one is
        # DERIVED below, and this lane names members individually rather than
        # running a `--workspace` command, so it never reaches zenoh-pico-sys.
        "nondefault",
        "footprint",
        "interop",
        "cross-mcu",
        "zephyr-mcu",
        "feature-gates",
        "routing-adminspace",
        "transport-modes",
        "isolated-crates",
        "capi-c-arms",
        "e2e-demo",
    ],
)
# `ring`, reached through quinn / rustls / tokio-rustls wherever a TLS or QUIC
# transport-link feature is selected. Verified by `cargo tree -i ring` on
# `wz-runtime-tokio --features routing-accept,transport-link-quic`.
_add(
    "perl",
    "ring's build, reached through quinn / rustls wherever a TLS or QUIC "
    "transport-link feature is selected.",
    [
        "ci",
        "validate-codegen",
        "verdict-legs",
        # R2163 — Layer C1cn's own job, peeled off `ci` for its budget. It
        # compiles EVERY member at its non-default features, so every reason on
        # this row that reaches a member reaches it. No `cmake`: that one is
        # DERIVED below, and this lane names members individually rather than
        # running a `--workspace` command, so it never reaches zenoh-pico-sys.
        "nondefault",
        "footprint",
        "feature-gates",
        "routing-adminspace",
        "transport-modes",
        "isolated-crates",
        "capi-c-arms",
        "e2e-demo",
    ],
)
# R2054 (open-debt item 384) — the ADJUDICATOR for `wz_capture::link`'s BSD
# address-family table. That set (`BSD_AF_INET6 = [24, 28, 30]`) was decided
# once by hand, in a session, by feeding `tcpdump` families in both byte orders;
# the repository kept the answer and not the question. Layer C1bn now runs
# `bsd_af_tcpdump_adjudicator` with `WZ_TCPDUMP_REQUIRE=1`, which asks the tool
# the same question on every run -- so the tool has to be on that job. ONE job
# only, and the smallest one that owns wz-capture's default-feature tests: this
# is a ~500 kB package on a mirror this file measures at ~27 kB/s, so it is
# carried where the gate is and nowhere else.
_add(
    "tcpdump",
    "the adjudicator Layer C1bn holds wz_capture::link's BSD address-family "
    "table against (item 384); armed with WZ_TCPDUMP_REQUIRE so its absence "
    "reds instead of skipping.",
    ["feature-gates"],
)
# R2055 (open-debt item 391) — the ADJUDICATOR for `LINK_TYPE_SWEEP_CEILING`.
# The link-type sweep claims to cover every type a capture file can name, which
# is a claim about libpcap's assignments, and nothing re-read libpcap: a type
# above the ceiling would be invisible to the sweep built to see it. libpcap
# states the bound itself as `DLT_MATCHING_MAX` in `pcap/dlt.h`, and that header
# is what `libpcap-dev` puts on the runner. Layer C1bn runs
# `pcap_dlt_header_adjudicator` with `WZ_DLT_HEADER_REQUIRE=1`, so an absent
# header reds instead of skipping. ONE job, the same one as `tcpdump` above and
# for the same reason: it is where wz-capture's default-feature tests live.
# R2058 (open-debt item 250) — `/etc/protocols`, one of the two sources the IP
# protocol furniture split reads (the other is `tcpdump`, above). It splits the
# 241 numbers this build calls furniture into the ones a shipped tool speaks for
# and the ones nobody here has examined, so a number that gains an opinion reds
# instead of hiding in a count. `netbase` is Priority: important and therefore
# already on the runner image; declared anyway because Layer C1bn ARMS on the
# file's absence, which makes its presence a statement rather than a guess. The
# install is a no-op when it is already there, so the mirror cost is nil.
_add(
    "netbase",
    "/etc/protocols, which Layer C1bn holds the IP protocol furniture class "
    "against (item 250); armed with WZ_PROTO_REGISTRY_REQUIRE so its absence "
    "reds instead of skipping.",
    ["feature-gates"],
)
_add(
    "libpcap-dev",
    "pcap/dlt.h, which Layer C1bn holds LINK_TYPE_SWEEP_CEILING against via "
    "DLT_MATCHING_MAX (item 391); armed with WZ_DLT_HEADER_REQUIRE so its "
    "absence reds instead of skipping.",
    ["feature-gates"],
)
# The `cmake` rows are DERIVED below as well as listed here; the list is what
# makes an unjustified site fail by name, the derivation is what stops this
# reason from being believed after the tree stops supporting it.
_add(
    "cmake",
    "zenoh-pico-sys's build script (the only `cmake` crate consumer in the "
    "workspace), reached directly or through wz-integration-tests' "
    "dev-dependency on it. DERIVED below, not believed.",
    ["ci", "validate-codegen", "interop", "feature-gates", "transport-modes",
     "isolated-crates", "capi-c-arms", "e2e-demo"],
)
_add(
    "cmake",
    "Zephyr's own west/CMake build, invoked BY west rather than by a command "
    "this tree writes, so the derivation cannot see it. Declared by name in "
    "DECLARED_OUTSIDE_CARGO.",
    ["zephyr-mcu"],
)
_add("ninja-build", "Zephyr's west build generator.", ["zephyr-mcu"])
_add("device-tree-compiler", "Zephyr devicetree.", ["zephyr-mcu"])
_add("xz-utils", "unpacking the Zephyr SDK tarball.", ["zephyr-mcu"])
_add(
    "gcc-arm-none-eabi",
    "the bare-metal ARM toolchain the cross-compile and MCU boot lanes link "
    "with.",
    ["cross-mcu", "zephyr-mcu"],
)
_add(
    "libnewlib-arm-none-eabi",
    "newlib for that toolchain.",
    ["cross-mcu", "zephyr-mcu"],
)
_add(
    "qemu-system-arm",
    "the MCU boot lanes' emulator (Layer Q / the Zephyr boot).",
    ["cross-mcu", "zephyr-mcu"],
)
# R2104 (open-debt item 522) — this row used to name three jobs, on the reason
# that libxml was built "from a checkout rather than the image's copy" on those
# and not the others. The SHORTFALL arm refutes it: `libxml`'s build script
# probes pkg-config on EVERY job that compiles it, which is all thirteen, and
# the other ten were getting the binary from the runner image.
_add(
    "pkg-config",
    "the tool libxml's build script probes libxml-2.0 through; required "
    "wherever that build script runs, which the SHORTFALL arm derives as "
    "every job reaching the crate.",
    [
        "ci",
        "validate-codegen",
        "verdict-legs",
        # R2163 — Layer C1cn's own job, peeled off `ci` for its budget. It
        # compiles EVERY member at its non-default features, so every reason on
        # this row that reaches a member reaches it. No `cmake`: that one is
        # DERIVED below, and this lane names members individually rather than
        # running a `--workspace` command, so it never reaches zenoh-pico-sys.
        "nondefault",
        "footprint",
        "interop",
        "cross-mcu",
        "zephyr-mcu",
        "feature-gates",
        "routing-adminspace",
        "transport-modes",
        "isolated-crates",
        "capi-c-arms",
        "e2e-demo",
    ],
)
_add("python3-yaml", "the workflow-shape lints Layer C0 runs on ci.yml.", ["ci"])
# R2104 (open-debt item 522) — the other half of the `libclang-dev` chain, and
# the package this file was carrying a hole for. `libxml`'s build script probes
# pkg-config for `libxml-2.0` and PANICS when it is absent; every job below
# builds a member whose closure reaches that crate. The job list is the same as
# `libclang-dev`'s and that is not a copy: SHORTFALL below derives it from the
# resolve graph, so the two lists check each other rather than agreeing by
# habit.
_add(
    "libxml2-dev",
    "libxml's build script probes pkg-config for `libxml-2.0`; reached "
    "through sce-forge-runtime's build script (sce-build -> libxml), the same "
    "chain libclang-dev is carried for. DERIVED by the SHORTFALL arm.",
    [
        "ci",
        "validate-codegen",
        "verdict-legs",
        # R2163 — Layer C1cn's own job, peeled off `ci` for its budget. It
        # compiles EVERY member at its non-default features, so every reason on
        # this row that reaches a member reaches it. No `cmake`: that one is
        # DERIVED below, and this lane names members individually rather than
        # running a `--workspace` command, so it never reaches zenoh-pico-sys.
        "nondefault",
        "footprint",
        "interop",
        "cross-mcu",
        "zephyr-mcu",
        "feature-gates",
        "routing-adminspace",
        "transport-modes",
        "isolated-crates",
        "capi-c-arms",
        "e2e-demo",
    ],
)
_add(
    "protobuf-compiler",
    "the Protobuf reference emit Layer B verifies.",
    ["validate-codegen"],
)

# The crate whose build script is the only `cmake` consumer in the workspace,
# and the crate that reaches it through a DEV-dependency.
#
# The second name is here because leaving it out is a mistake this file already
# made. `cargo tree -e normal,build -i zenoh-pico-sys` answers "no dependents",
# and acting on that would have dropped `cmake` from jobs whose lanes test
# `wz-integration-tests` — whose dev-dependency on it `-e normal,build` does
# not show. `-e normal,build,dev` is the question that has the whole answer.
CMAKE_CRATES = ("zenoh-pico-sys", "wz-integration-tests")

# Jobs whose cmake use no command in this tree spells, so the derivation below
# structurally cannot find it. One entry, and it has to earn its place: the
# value is the caller, so a reader can go and check.
DECLARED_OUTSIDE_CARGO = {
    "zephyr-mcu": "`west build` drives Zephyr's own CMake build system",
}


def ci_sites() -> dict[str, set[str]]:
    """job id -> the packages its `apt-install.sh` steps install."""
    lines = CI_YML.read_text().splitlines()
    job = None
    out: dict[str, set[str]] = {}
    for i, line in enumerate(lines):
        m = re.match(r"^  ([A-Za-z0-9_-]+):\s*$", line)
        if m:
            job = m.group(1)
        if "apt-install.sh" not in line or line.strip().startswith("#"):
            continue
        if job is None:
            raise RuntimeError(f"{CI_YML.name}:{i + 1}: an apt step outside any job")
        text = line.split("apt-install.sh", 1)[1]
        j = i
        # A package list may be wrapped across continuation lines.
        while lines[j].rstrip().endswith("\\"):
            j += 1
            text += " " + lines[j]
        pkgs = {w for w in text.replace("\\", " ").split() if w and not w.startswith("-")}
        out.setdefault(job, set()).update(pkgs)
    return out


# A REAL cmake invocation, as opposed to the token `cmake` appearing as an apt
# package name or as a stand-in argument.
#
# The distinction is not pedantic: `run-ci.sh`'s own Layer C0g drives
# `apt-install.sh` with the literal argument `cmake` five times, so a rule that
# accepted the bare token would mark every job running C0g as needing cmake and
# the derived arm would answer yes to everything — a check that cannot say no.
CMAKE_INVOCATION = re.compile(
    r"command -v cmake|cmake\s+(?:-S|--build|\.\.)|for tool in [^\n]*\bcmake\b"
)


def job_reachable_text(path: Path = CI_YML) -> dict[str, str]:
    """job id -> everything that job runs, followed one level deep.

    `path` defaults to `ci.yml`, which is what the arms above are about. The
    shortfall arm passes every workflow in turn, because a requirement can go
    unmet in any of them and `release.yml` was the one it was unmet in.

    A job's own `run:` blocks are not the whole of what it runs: `--layer N`
    reaches a `run-ci.sh` function, and `bash scripts/<x>.sh` reaches a script
    that may shell out again. The first version of this scan read ONLY the
    `--layer` steps, and its first red claimed `interop`, `cross-mcu` and
    `capi-c-arms` had no use for cmake — three jobs that build zenoh-pico,
    mbedtls and zenoh-c through `cmake -S` in exactly the scripts it was not
    reading. A gate's first finding is a claim to adjudicate, not a verdict to
    obey (open-debt item 271's shape), and this comment is what that cost.
    """
    yml = path.read_text().splitlines()
    job = None
    raw: dict[str, list[str]] = {}
    for line in yml:
        m = re.match(r"^  ([A-Za-z0-9_-]+):\s*$", line)
        if m:
            job = m.group(1)
        if job:
            raw.setdefault(job, []).append(line)

    src = RUN_CI.read_text()
    dispatch = dict(re.findall(r"run_layer ([A-Za-z0-9]+) ([a-z0-9_]+)", src))
    body_lines = src.splitlines()
    starts = {}
    for i, line in enumerate(body_lines):
        m = re.match(r"^([a-z0-9_]+)\(\)\s*\{", line)
        if m:
            starts[m.group(1)] = i

    def layer_body(fn: str) -> str:
        """One `run-ci.sh` function, bounded by the top-level closing brace.

        Brace COUNTING was the first attempt and it silently over-ran: shell
        carries `{` inside `${...}`, inside comments and inside strings, so the
        depth never returned to zero and the "body" ran to the end of a
        14000-line file. Every job then appeared to reach every crate, the
        derived arm accepted all of them, and the gate printed a green line
        about a check that had not discriminated anything. `run-ci.sh` closes
        its functions with a brace in column 0, which is a fact about the file
        rather than about shell, so this reads that instead.
        """
        start = starts.get(fn)
        if start is None:
            return ""
        out = [body_lines[start]]
        for line in body_lines[start + 1:]:
            out.append(line)
            if line == "}":
                break
        return "\n".join(out)

    def code_only(text: str) -> str:
        """Drop whole-line comments.

        The derivation must read what a job RUNS, not what anyone wrote about
        it. Without this the check answered yes to four jobs on the strength of
        the comments R311y881 had just added to say cmake was NOT needed there:
        a sentence explaining an absence was counted as evidence of a presence.
        Trailing comments are left alone — a `#` mid-line is only reliably a
        comment after a shell parse, and getting that wrong would drop code.
        """
        return "\n".join(
            line for line in text.splitlines() if not line.lstrip().startswith("#")
        )

    out: dict[str, str] = {}
    for j, lines in raw.items():
        text = code_only("\n".join(lines))
        parts = [text]
        for name in re.findall(r"--layer ([A-Za-z0-9]+)", text):
            parts.append(code_only(layer_body(dispatch.get(name, ""))))
        # `run-ci.sh` is followed PER LAYER above and must not be pulled in
        # whole here. It was, in this scan's second version, and the effect was
        # a check that could not say no: every job runs some `--layer` step, so
        # every job swallowed a file that contains `--workspace`, and the
        # derived arm accepted all thirteen while printing nothing. A gate that
        # answers yes to everything reads exactly like a gate that is happy.
        seen = {"run-ci.sh"}
        pending = list(re.findall(r"scripts/([A-Za-z0-9_./-]+\.sh)", text))
        while pending:
            rel = pending.pop()
            if rel in seen:
                continue
            seen.add(rel)
            path = ROOT / "scripts" / rel
            if not path.is_file():
                continue
            body = code_only(path.read_text())
            parts.append(body)
            pending.extend(re.findall(r"scripts/([A-Za-z0-9_./-]+\.sh)", body))
        out[j] = "\n".join(parts)
    return out


def jobs_needing_cmake() -> set[str]:
    """Job ids whose reachable text builds a CMAKE_CRATES member or runs cmake.

    A layer reaches the crate by running a `--workspace` cargo command (which
    builds every member, the crate included) or by naming it. A script reaches
    cmake by calling it. The scan is deliberately OVER-inclusive: a job it does
    not name is a job with no mention anywhere in anything it runs, which is
    the only direction a removal may be argued from.
    """
    needing = set()
    for j, text in job_reachable_text().items():
        if "--workspace" in text or any(c in text for c in CMAKE_CRATES):
            needing.add(j)
        elif CMAKE_INVOCATION.search(text):
            needing.add(j)
    return needing


# ─── The SHORTFALL arm (R2104, open-debt item 522) ──────────────────────────
#
# What the build DEMANDS of the machine, against what the workflow installs.

# `pkg_config::Config::…probe("mod")` / `probe_library("mod")`, the two spellings
# the pkg-config crate offers. Matched in a build script's own source, so the
# answer comes from the crate that will do the probing rather than from anyone's
# recollection of which crates need libraries.
PKG_CONFIG_PROBE = re.compile(r"""\.probe(?:_library)?\(\s*["']([^"']+)["']""")

# pkg-config module -> the Debian package that ships its `.pc`.
#
# The ONE hand-written thing in this arm, and it is verified rather than
# believed: `_module_owner` resolves each row through pkg-config and dpkg
# wherever both are present. A probed module with no row here is a FAIL that
# names it; a row here that nothing probes is a FAIL too, because a mapping
# that outlives its consumer is the shape open-debt item 47 is about.
MODULE_APT: dict[str, str] = {
    "libxml-2.0": "libxml2-dev",
}

# The probe's own tool. A `.probe()` shells out to `pkg-config`, so a job that
# reaches a probing crate needs the binary as much as it needs the `.pc` file,
# and it was riding on the runner image on ten of the thirteen jobs.
#
# NOT resolved through dpkg the way MODULE_APT rows are, and the reason is a
# measurement: on this workstation `/usr/bin/pkg-config` is a symlink into
# `pkgconf-bin`, so dpkg answers `pkgconf-bin` — a package name that is correct
# here and wrong as an apt argument on the images this workflow runs. The
# installable name is stable across those releases; the provider is not.
PKG_CONFIG_TOOL = "pkg-config"


@functools.lru_cache(maxsize=1)
def _metadata() -> dict:
    """The resolved build graph, at `--all-features`.

    All features because the question is what any lane may demand, and a lane
    that turns a feature on must not be the first thing to discover the library
    is missing.
    """
    proc = subprocess.run(
        [
            "cargo", "metadata", "--all-features", "--format-version", "1",
            "--manifest-path", str(ROOT / "crates/Cargo.toml"),
        ],
        capture_output=True, text=True, check=False,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"`cargo metadata` failed (rc={proc.returncode}): {proc.stderr}")
    return json.loads(proc.stdout)


def probed_modules() -> dict[str, set[str]]:
    """pkg-config module -> the crates whose build scripts ask for it."""
    out: dict[str, set[str]] = {}
    for pkg in _metadata()["packages"]:
        for target in pkg["targets"]:
            if "custom-build" not in target["kind"]:
                continue
            src = Path(target["src_path"])
            if not src.is_file():
                # An unreadable build script is a hole in the population, and a
                # population with a hole must not report a clean shortfall.
                raise RuntimeError(
                    f"build script for `{pkg['name']}` is not on disk ({src}); "
                    f"run `cargo fetch` so the graph can be read"
                )
            for mod in PKG_CONFIG_PROBE.findall(src.read_text(errors="replace")):
                out.setdefault(mod, set()).add(pkg["name"])
    return out


def members_reaching(crates: set[str]) -> set[str]:
    """Workspace members whose dependency closure contains any of `crates`.

    Walked backwards over cargo's own `resolve` graph — every dependency kind,
    dev included, for the reason the `cmake` arm records: `-e normal,build`
    answers "no dependents" for a crate a test target pulls in, and acting on
    that answer is how a needed package gets dropped.
    """
    meta = _metadata()
    by_id = {p["id"]: p for p in meta["packages"]}
    rev: dict[str, set[str]] = {}
    for node in meta["resolve"]["nodes"]:
        for dep in node["deps"]:
            rev.setdefault(dep["pkg"], set()).add(node["id"])

    seen = {i for i in by_id if by_id[i]["name"] in crates}
    stack = list(seen)
    while stack:
        for parent in rev.get(stack.pop(), ()):
            if parent not in seen:
                seen.add(parent)
                stack.append(parent)
    return {by_id[i]["name"] for i in meta["workspace_members"] if i in seen}


# Every apt install this tree writes, in either spelling. `apt-install.sh` is
# the one `ci.yml` uses and the one the arms above are about; `release.yml`
# calls `apt-get install` directly. The shortfall arm has to know both, because
# a hole in the workflow nobody remembers is exactly where this class lives —
# `release.yml` was carrying the same missing `libxml2-dev` when item 522 was
# filed, and it is not reached by anything scoped to `apt-install.sh`.
APT_INSTALL = re.compile(r"apt-install\.sh|apt-get\s+install")

WORKFLOWS = ROOT / ".github/workflows"


def linux_jobs(path: Path) -> set[str]:
    """Job ids in `path` whose `runs-on` names ubuntu — the ones apt applies to.

    Bounded to the `jobs:` block: the `on:` triggers (`push`, `pull_request`,
    `workflow_dispatch`) sit at the same indentation and match the same job-id
    pattern the rest of this file uses. They have no `runs-on`, so they fall out
    here — but only because this asks for one.

    A job on a non-ubuntu runner is OUT OF SUBJECT, not exempt: `portability`
    builds the same crates on macOS and Windows and gets libxml2 from vcpkg,
    which this gate has nothing to say about.
    """
    out: set[str] = set()
    job = None
    in_jobs = False
    for line in path.read_text().splitlines():
        if re.match(r"^jobs:\s*$", line):
            in_jobs = True
            continue
        if not in_jobs:
            continue
        m = re.match(r"^  ([A-Za-z0-9_-]+):\s*$", line)
        if m:
            job = m.group(1)
        elif job and re.match(r"^    runs-on:.*ubuntu", line):
            out.add(job)
    return out


def apt_sites(path: Path) -> dict[str, set[str]]:
    """job id -> the packages its apt steps install, in either spelling."""
    lines = path.read_text().splitlines()
    job = None
    out: dict[str, set[str]] = {}
    for i, line in enumerate(lines):
        m = re.match(r"^  ([A-Za-z0-9_-]+):\s*$", line)
        if m:
            job = m.group(1)
        if line.strip().startswith("#") or not APT_INSTALL.search(line):
            continue
        if job is None:
            continue
        text = APT_INSTALL.split(line, 1)[1]
        j = i
        while lines[j].rstrip().endswith("\\"):
            j += 1
            text += " " + lines[j]
        pkgs = {w for w in text.replace("\\", " ").split() if w and not w.startswith("-")}
        out.setdefault(job, set()).update(pkgs)
    return out


def _module_owner(module: str) -> str | None:
    """The Debian package providing `module`'s `.pc`, or None if not resolvable.

    None means "this machine cannot answer" — pkg-config or dpkg absent, or the
    library simply not installed — which is a fact about the machine and not a
    verdict about the row. The caller says so rather than turning it into one.
    """
    if shutil.which("pkg-config") is None or shutil.which("dpkg") is None:
        return None
    where = subprocess.run(
        ["pkg-config", "--variable=pcfiledir", module],
        capture_output=True, text=True, check=False,
    )
    if where.returncode != 0 or not where.stdout.strip():
        return None
    owner = subprocess.run(
        ["dpkg", "-S", f"{where.stdout.strip()}/{module}.pc"],
        capture_output=True, text=True, check=False,
    )
    if owner.returncode != 0 or ":" not in owner.stdout:
        return None
    # `libxml2-dev:amd64: /usr/lib/.../libxml-2.0.pc` -> `libxml2-dev`
    return owner.stdout.split(":", 1)[0].strip()


# ─── The DOCUMENTED-PREREQ arm (R2105, open-debt item 526) ──────────────────
#
# The two arms above keep CI honest with itself. Neither says anything to a
# person building this tree by hand, and item 526 is what that costs: a
# downstream consumer met "The system library `libxml-2.0` required by crate
# `libxml` was not found" -- an error naming a CRATE, not a package -- with no
# document anywhere in the tree telling them what to install. Measured before
# the fix: README.md, README.ko.md and THIRD_PARTY.md carried ZERO mentions of
# `libxml2-dev`, `libclang-dev`, `pkg-config` or `clang`.
#
# THE LIST IS DERIVED, WHICH IS THE ONLY REASON WRITING IT DOWN IS SAFE. A
# hand-maintained prerequisites section is a second source of truth that starts
# rotting the day it is written (open-debt item 47). The set here is computed:
# the packages that EVERY job installs. That is a meaningful population rather
# than a convenient one -- a package on all thirteen jobs is one no lane can
# avoid, so it is exactly what a build of any part of this workspace needs,
# while `cmake` (9 jobs) or `perl` (10) belong to the lanes that name them.
#
# The downstream report suggested three packages. The derivation says FOUR:
# `clang` is on every job and was missing from that list. Copying the report
# would have inherited its hole, which is the whole argument for deriving.
DOC_BLOCK = re.compile(
    r"<!-- BUILD-PREREQS-BEGIN -->(.*?)<!-- BUILD-PREREQS-END -->",
    re.DOTALL,
)

# Package names come from the INSTALL LINE inside the block and from nothing
# else. The first version tokenised the whole block after stripping backticks,
# and the fence ` ```sh ` then arrived as a package called `sh` -- on both
# READMEs at once, which is what a parser reading decoration rather than
# content looks like. `APT_INSTALL` is the same matcher the arms above use on
# the workflows, so the doc and the workflow are read by one rule.
_NOT_A_PACKAGE = {"sudo", "apt-get", "apt", "install"}


def documented_prereqs() -> dict[str, set[str]]:
    """README path -> the packages its BUILD-PREREQS block names.

    Every `README*.md` at the repository root, found by glob rather than
    listed: this tree carries an English and a Korean README, and a list here
    would be one more place for them to diverge -- which is the class this arm
    exists to close, one level up.
    """
    out: dict[str, set[str]] = {}
    for path in sorted(ROOT.glob("README*.md")):
        m = DOC_BLOCK.search(path.read_text(encoding="utf-8"))
        if m is None:
            out[path.name] = set()
            continue
        pkgs: set[str] = set()
        for line in m.group(1).splitlines():
            if not APT_INSTALL.search(line):
                continue
            pkgs.update(
                w for w in APT_INSTALL.split(line, 1)[1].split()
                if w and not w.startswith("-") and w not in _NOT_A_PACKAGE
            )
        out[path.name] = pkgs
    return out


def universal_packages(sites: dict[str, set[str]]) -> set[str]:
    """Packages every job installs -- what a build of any part of this needs."""
    if not sites:
        return set()
    return set.intersection(*sites.values())


def undocumented(sites: dict[str, set[str]]) -> list[str]:
    """Findings where a README's prerequisite block and the CI truth disagree."""
    want = universal_packages(sites)
    if not want:
        # Every job installing nothing in common is possible in principle and
        # false today; either way an empty expectation would make this arm
        # agree with any README at all.
        return [
            "no package is installed by EVERY job, so the documented-prereq "
            "arm has nothing to hold a README to and just asserted nothing"
        ]

    docs = documented_prereqs()
    if not docs:
        return [f"no README*.md at {ROOT} -- this arm has no subject"]

    findings: list[str] = []
    for name, got in sorted(docs.items()):
        if not got:
            findings.append(
                f"{name} carries no <!-- BUILD-PREREQS-BEGIN --> block. A "
                f"person building this tree by hand has nowhere to learn that "
                f"it needs {' '.join(sorted(want))}; the error they get names "
                f"a crate, not a package."
            )
            continue
        for pkg in sorted(want - got):
            findings.append(
                f"{name}'s prerequisite block does not name `{pkg}`, which "
                f"every CI job installs. A reader following that block builds "
                f"a tree the CI would not."
            )
        for pkg in sorted(got - want):
            findings.append(
                f"{name}'s prerequisite block names `{pkg}`, which is NOT "
                f"installed by every job -- it belongs to the lanes that need "
                f"it, not to the baseline. Drop it, or move the claim."
            )
    return findings


def shortfall() -> list[str]:
    """Every (workflow, job, package) the build demands and no apt step installs."""
    probed = probed_modules()
    if not probed:
        # `cargo metadata` resolved, every build script was read, and not one of
        # them probes for anything. That is possible in principle and false
        # today; either way an empty population must not print a clean line.
        return [
            "SHORTFALL population is EMPTY: no build script in the resolved "
            "graph probes pkg-config. Either the probe pattern has drifted from "
            "what the pkg-config crate offers, or this arm just asserted nothing."
        ]

    findings: list[str] = []
    for module in sorted(MODULE_APT.keys() - probed.keys()):
        findings.append(
            f"MODULE_APT maps `{module}`, which no build script in the resolved "
            f"graph probes for. A mapping that outlives its consumer is open-debt "
            f"item 47's shape — delete the row."
        )

    workflows = sorted(WORKFLOWS.glob("*.yml"))
    if not workflows:
        return [f"no workflow file under {WORKFLOWS} — the shortfall arm has no subject"]

    for module, crates in sorted(probed.items()):
        pkg = MODULE_APT.get(module)
        if pkg is None:
            findings.append(
                f"crate(s) {', '.join(sorted(crates))} probe pkg-config for "
                f"`{module}` and MODULE_APT does not say which Debian package "
                f"provides it. Add the row; a build that asks for a library no "
                f"workflow installs runs only where the runner image happens to "
                f"carry it."
            )
            continue

        owner = _module_owner(module)
        if owner is not None and owner != pkg:
            findings.append(
                f"MODULE_APT says `{module}` comes from `{pkg}`, but dpkg on this "
                f"machine says `{owner}` owns its .pc file. Fix the row."
            )

        members = members_reaching(crates)
        for wf in workflows:
            sites = apt_sites(wf)
            reach = job_reachable_text(wf)
            for job in sorted(linux_jobs(wf)):
                text = reach.get(job, "")
                if "--workspace" not in text and not any(m in text for m in members):
                    continue
                for want, what in ((pkg, f"the library `{module}` resolves to"),
                                   (PKG_CONFIG_TOOL, "the tool the probe itself runs")):
                    if want in sites.get(job, set()):
                        continue
                    findings.append(
                        f"{wf.name} job `{job}` builds a member that reaches "
                        f"{'/'.join(sorted(crates))}, whose build script probes "
                        f"pkg-config for `{module}` — and it never installs "
                        f"`{want}`, {what}. It passes today only because the "
                        f"runner image happens to carry it; nothing declares "
                        f"that, and nothing would notice its removal. Add "
                        f"`{want}` to that job's apt install line."
                    )
    return findings


def main() -> int:
    try:
        sites = ci_sites()
    except (OSError, RuntimeError) as e:
        print(f"  apt-packages FAIL: {e}", file=sys.stderr)
        return 1
    if not sites:
        # A census that measured nothing must never read as one that found
        # nothing.
        print("  apt-packages FAIL: no apt-install.sh step found in ci.yml", file=sys.stderr)
        return 1

    found = {f"{job}::{pkg}" for job, pkgs in sites.items() for pkg in pkgs}
    failed = False

    for key in sorted(found - ADJUDICATED.keys()):
        failed = True
        job, pkg = key.split("::", 1)
        print(
            f"  apt-packages FAIL: job `{job}` installs `{pkg}` and nothing says why.\n"
            f"    Every byte here is fetched over a mirror measured at ~27 kB/s "
            f"(run 32266212482), so an unjustified package is minutes of a job's "
            f"budget. Name what needs it in {Path(__file__).name}, or drop it.",
            file=sys.stderr,
        )

    for key in sorted(ADJUDICATED.keys() - found):
        failed = True
        print(
            f"  apt-packages FAIL: ADJUDICATED names `{key}`, which ci.yml no "
            f"longer installs. A justification that outlives its code is the "
            f"shape open-debt item 47 is about — delete the row in the commit "
            f"that removed the package.",
            file=sys.stderr,
        )

    # The DERIVED arm. Only ever runs against jobs that install `cmake`; a job
    # that does not is none of this check's business.
    needing = jobs_needing_cmake()
    for job in sorted(j for j, pkgs in sites.items() if "cmake" in pkgs):
        if job in needing or job in DECLARED_OUTSIDE_CARGO:
            continue
        failed = True
        print(
            f"  apt-packages FAIL: job `{job}` installs `cmake`, but nothing it "
            f"runs reaches {' or '.join('`' + c + '`' for c in CMAKE_CRATES)} — "
            f"the only consumer of the `cmake` crate in this workspace and the "
            f"only crate that dev-depends on it — and nothing it runs invokes "
            f"cmake directly either.\n"
            f"    That is ~6.9 MB (cmake 5010 kB + cmake-data 1913 kB) of a "
            f"download this job cannot use. Drop `cmake` from its list.",
            file=sys.stderr,
        )

    # The SHORTFALL arm. Runs even when the arms above have already failed, so
    # one round sees the whole picture instead of two.
    try:
        missing = shortfall()
    except (OSError, RuntimeError, json.JSONDecodeError) as e:
        print(f"  apt-packages FAIL: the shortfall arm could not read its input: {e}",
              file=sys.stderr)
        return 1
    for finding in missing:
        failed = True
        print(f"  apt-packages FAIL: {finding}", file=sys.stderr)

    # The DOCUMENTED-PREREQ arm. Runs even when the arms above have failed, so
    # one round sees the whole picture instead of two.
    for finding in undocumented(sites):
        failed = True
        print(f"  apt-packages FAIL: {finding}", file=sys.stderr)

    if failed:
        return 1

    derived = len([j for j, pkgs in sites.items() if "cmake" in pkgs])
    modules = probed_modules()
    baseline = universal_packages(sites)
    print(
        f"  apt-packages: {len(found)} (job, package) pair(s) across "
        f"{len(sites)} job(s), every one adjudicated; {derived} cmake site(s) "
        f"derived against {'/'.join(CMAKE_CRATES)} rather than believed; "
        f"{len(modules)} pkg-config module(s) the build demands "
        f"({', '.join(sorted(modules))}) installed everywhere they are reached; "
        f"{len(baseline)} package(s) on EVERY job ({' '.join(sorted(baseline))}) "
        f"documented in {len(documented_prereqs())} README(s)"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
