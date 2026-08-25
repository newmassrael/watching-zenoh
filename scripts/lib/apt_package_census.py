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
"""

from __future__ import annotations

import re
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
_add(
    "pkg-config",
    "libxml's build script locates libxml2 through it; carried on the jobs "
    "whose lanes build it from a checkout rather than the image's copy.",
    ["ci", "capi-c-arms", "e2e-demo"],
)
_add("python3-yaml", "the workflow-shape lints Layer C0 runs on ci.yml.", ["ci"])
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


def job_reachable_text() -> dict[str, str]:
    """job id -> everything that job runs, followed one level deep.

    A job's own `run:` blocks are not the whole of what it runs: `--layer N`
    reaches a `run-ci.sh` function, and `bash scripts/<x>.sh` reaches a script
    that may shell out again. The first version of this scan read ONLY the
    `--layer` steps, and its first red claimed `interop`, `cross-mcu` and
    `capi-c-arms` had no use for cmake — three jobs that build zenoh-pico,
    mbedtls and zenoh-c through `cmake -S` in exactly the scripts it was not
    reading. A gate's first finding is a claim to adjudicate, not a verdict to
    obey (open-debt item 271's shape), and this comment is what that cost.
    """
    yml = CI_YML.read_text().splitlines()
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

    if failed:
        return 1

    derived = len([j for j, pkgs in sites.items() if "cmake" in pkgs])
    print(
        f"  apt-packages: {len(found)} (job, package) pair(s) across "
        f"{len(sites)} job(s), every one adjudicated; {derived} cmake site(s) "
        f"derived against {'/'.join(CMAKE_CRATES)} rather than believed"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
