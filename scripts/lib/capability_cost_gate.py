#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
"""R3397 (no register item) -- what a capability costs, and that a build without it pays nothing.

## Why this exists

The C ABI crates are composed from capability features (`peer`, `scout`, `link-udp`, `query`,
...): a build that leaves one out is supposed to link neither the ABI doors nor the runtime plane
behind them. That is a claim about the BINARY, and nothing graded the binary. It broke without a
word once already: the node-clock feature (`time-hlc`) pulled the runtime's storage module, which
pulled the whole query plane, into a build that answered no query. It was found by reading a
symbol table by hand, and the same hand-reading found that `peer` alone did not compile, because
the accept loop had been getting its request codec from that same leak.

This gate reads the binary. For each case in [`CASES`] it builds the library with exactly that
feature set and checks four facts about it:

  1. SIZE        the text segment (`size`) is within the case's budget;
  2. ABSENCE     no defined symbol matches a FORBIDDEN pattern: the plane the case left out;
  3. PRESENCE    a symbol matches every REQUIRED pattern: the plane the case put in;
  4. EXPORTS     the library exports the pinned number of C symbols, where one is pinned;
  5. STATEMENT   the conformance digest the library carries (the NUL-terminated
                 `sha256:<64 hex>` its build script wrote, read out of the binary's bytes) is
                 the digest `wz_config.conformance_statement` gives the case's feature set
                 (the end-to-end check that a library states the configuration it was built
                 with, read from its own bytes). Where the case's ABI makes the digest's door
                 a capability (`conformance-digest`, `deploy/wz-config.toml`) and the case's
                 features leave it out, the library carries NO digest, and one it carries is
                 the finding: a door the features do not name was linked. Every case is a build
                 whose configuration is known, so each is also the end-to-end witness that a
                 library states the build it is.

Each size case is built under the limits and policies of its ABI's own preset, its original's
defconfig (`case_limits`, `wz_config.build_of` with no preset), as the ABI's release is: the
pico cases at the bounds zenoh-pico holds, so a size, a ratio and a reading of the memory a build
reserves are the shipped build's and never the host defaults of its build constants. They turn no
zenoh-c layout arm on. [`STATEMENT_CASES`] are the builds that state a limit and a policy of
their own, graded on fact 5 alone, on each ABI, and the shared-memory arm of the zenoh-c drop-in.

PRESENCE is what makes ABSENCE mean something. A forbidden pattern that no build can match is a
check that cannot fail (`--selftest` pins the matcher, and the full builds here are the live
control: every pattern a client build is forbidden is REQUIRED of a build that has the plane).

## What a budget is, and is not

A budget is a ceiling a measured size sits under with a small margin, not a target. It moves in
the commit that moves the size, with the new measurement stated; a size that grew without anyone
choosing it is what this gate exists to refuse. The sizes are `size` text on the pinned toolchain
(`rust-toolchain.toml`) and are comparable only to themselves: a different compiler moves them,
which is why the margin is a percentage and not a byte count.

A budget is set from a reading and from nothing else: a case added before any host read it has
none (`max_text` None), and fails `--check` with the budget its reading sets (`budget_for`, the
reading and two percent, rounded up to the hundred), which `--measure` prints too.

A case may read its features from a registered profile (`Case.features_from`) where another lane
builds a library from that profile: `pico-api-coop-nostd` is the Linux twin of the Windows
like-for-like library (`pico_windows_package.LIKE_PROFILE`), built with the features that lane
builds it with, resolved from the same profile when the case is built, so the two lanes hold one
list and not two. It is built in the release client's form, which both cases take from one
definition (`NOSTD_RELEASE_FORM`), so the twin and the client differ by their features alone.

## Where and when the build ran

Every build here (the size cases, the statement cases and the pico reference) runs in the
environment `build_normalization.py` gives: rustc and the C compiler map the checkout, the
artifact root and the cargo home to fixed names, and the epoch is the commit's. A path left in a
library makes its text measure the host's directory names as well as the code, and two hosts
reading one commit then disagree by the difference in their path lengths. So after each size case
is built, and after each pico reference, the library is searched for the three prefixes, and one
that holds any is a failure, with `--measure` too: a figure read from such a library is not one a
budget or a ceiling row (below) can be set from, so its ratio is neither graded nor printed. The
host performance matrix asks `pico_reference_tree` for its reference in the environment of
`build_env` too, so the library it times is the one this gate measures, from the same directory.

The rustc flags reach cargo through the variable the rule adds them to, after any flags the
caller exported. A case that names configuration files of its own (`Case.cargo_configs`, the
named link choices under `crates/.cargo`) has their flags for the host's target read here and
added to that variable after the rule's (`config_rustflags`), and is built for that target named
(`--target`), so they reach the library's crates and not the build scripts. They are not handed
to cargo with `--config`: cargo joins every configured table that matches the target, the
caller's own configuration among them, so a linker chosen there (`-fuse-ld=`) would link such a
case with another linker than the cases beside it, while the variable replaces every configured
table. A linker such a file names for that target (`target.<triple>.linker`,
`read_config_tables`) goes in the variable cargo reads that key from, which outranks every
configuration file as the key named with `--config` would; the gate's own `-C linker=cc` is in
the flags beside it, and a library another linker wrote is a finding (below). The workspace's own
configuration has flags for windows-msvc only. What the rule does not remove is the toolchain: a
host with another C compiler or linker builds other bytes from the same tree, and its reading is
comparable only to readings made with that toolchain. So every library and every reference is
linked by the same linker, GNU ld through the C compiler
(`GATE_RUSTFLAGS`, `reference_build`; a host without it is refused by name, `gnu_ld_version`),
and each pico case prints the linker of both of its libraries as each library's `.comment` names
it (`linker_of`); a library another linker wrote is a finding (`link_findings`).

## The denominator

A pico case is also measured against zenoh-pico built as the SAME build: the pinned submodule,
Release and shared, with every switch `deploy/wz-config.toml` answers set from that answer for
the case's features (`wz_config.pico_reference`). The gate builds it on the host it builds wz on,
reads back the header pico generated to find any switch pico built otherwise than asked, and
prints the ratio, so a size claim against pico is a number this gate printed, with its toolchain
beside it, and never one copied from elsewhere. Rounds 3393 to 3395 divided by a
libzenohpico of unrecorded build; round 3472 corrected them with a reference whose switches were
chosen by hand, and three of them (interest, matching, the receive cache) were set otherwise
than the declaration says wz has them.

## The ceiling (docs/upstream-parity.md D9)

The text budget holds a case to its OWN figure, and a budget moves with the growth it records, so
a case can fall behind zenoh-pico a budget move at a time with no finding: the MCU kit's build
cells did exactly that (D8). Each pico case is therefore also held to the ratio of its text to
the reference's, by its row in `deploy/pico_host_ceiling.json`:

- WHY A RATIO. Both libraries are built on the same host in the same run, so what a host moves
  alike on both sides (its linker, its libc, its section layout) cancels, and the ratio of one
  tree is comparable across hosts within `RATIO_TOLERANCE`, where its bytes are not (the notes
  of `CASES` record hosted CI reading a tree thousands of bytes off a build host). The reference
  is built with the host's C compiler, so a failing row names the toolchain it was read with
  beside this run's.
- WHY A RATCHET. A case that is no WIN is an open-debt item (D5), paid largest ratio first, and
  meanwhile may not get worse than its committed reading: `ratio_at_most` is that reading's ratio
  rounded up, and a reading over it by more than the tolerance fails. A reading under it by more
  than the tolerance passes and prints the tighter row to commit, so the bound follows every
  gain down. A case that reads WIN fails until its row is locked (the gate prints the row), and a
  locked case reads WIN or fails (D1): no budget or row move clears a LOSS once won.
- POPULATION. Every pico case has exactly one row and every row a pico case, so a case cannot
  join outside the ceiling. A row with `ratio_at_most` null is unfilled: it fails `--check`
  with the row this run reads, and `--measure` prints the rows of every case it builds.
- ONE TABLE, TWO LANES. The release DLL of each width of Windows has its row in the same table
  (`pico_windows_package.CEILING_CASES`), and so do the like-for-like library of each width and
  each of wz's doors over it (`pico_windows_package.FEATURE_CASES`), read and graded by the
  Windows package job, since only a Windows host builds them. The rule of a row is
  `pico_host_ceiling.py`'s, which both lanes import; this gate holds the table to the population
  of both (`ceiling_cases`), so a Windows row is checked for its shape on every tree, wherever it
  is graded.

## The builds at once

The cases are independent builds, and each ends in a fat LTO link that runs on one core: built one
after another, a run granted 22 cores used 1.5 of them on average and took 985 s. So a run builds
them side by side, as many at once as its cores and its memory allow (`build_width`): the cores
and the memory are what bx granted the run (`BX_GRANT_CORES`, `BX_GRANT_MEM_MB`), else the
process's CPU affinity and the memory the kernel calls available, each build held to
`CASE_BUILD_MB`, and each cargo given its share of the cores as `CARGO_BUILD_JOBS`. The builds
start heaviest first by the seconds of `c1cs_case_weights.tsv`, and are graded and printed in the
order of `CASES` and then `STATEMENT_CASES` whatever order they end in: what a build's commands
print is held (`run_held`) and shown when its case is graded, so the log and the verdict read as
they did when the builds ran in turn.

Each size case builds in a target directory of its own (`case_target`), and each statement case in
one of its own: two cargo processes on one target directory wait on its lock, and a case of the same
profile replaced the library the last one left there. The cost is that each directory builds the
dependencies the cases used to share. The paths a size case's build writes under its directory are
mapped to the shared directory's (`build_normalization.relocated_env`), so a library reads the
same bytes whichever directory built it. Two cases can share a zenoh-pico reference, which is built
and read with its directory locked (`reference_held`).

## The hosted shards

Built one after another, the cases took the job's clock: run 45051019628 read 1,013 s of the lane
and 1,114 s of the job against its 1200 s budget (92 percent), and every case added since the eight
the budget was sized for (378 s) put it nearer. The hosted lane is therefore a matrix, and
`--shards N --shard K` builds the cases (size and statement alike) that `census_shard_plan.plan`
deals to shard K over the seconds of `c1cs_case_weights.tsv`, in the order of `CASES` and then
`STATEMENT_CASES`. Every shard computes the same plan from the
same tree, so the shards partition the cases whatever the weights say: they decide the balance,
never which case is built. A case with no row is planned at the median and named on stderr. Each
case prints its seconds (`<id>: <N>s`), which is what the table is refreshed from; they are read
with the run's other builds beside the case, so they weigh the cases against each other and do not
add up to the run's. The checks of the committed ceiling table itself are run by every shard, since
they build nothing.

## The parts of the fleet

The fleet's planner of the whole gate (`scripts/lib/runci_plan.py`, `PARTED_LANES`) gives this
lane to the build machines as parts, each a unit a machine runs by itself: `--parts` lists them,
`shard-K-of-N` for the `FLEET_PARTS` shards, and `--part shard-K-of-N` builds the shard it names,
as `--shards N --shard K` does. A part builds its cases at once on its machine (above), so the
parts divide the work between machines and the grant divides it on each.

Usage:
    capability_cost_gate.py --check [--shards N --shard K | --part P] [ID...]
                               build every case (or the shard's, or the named ones), grade it
    capability_cost_gate.py --measure [--shards N --shard K | --part P] [ID...]
                               build the same and print what was measured, with each pico
                               case's ceiling row to commit
    capability_cost_gate.py --parts        the lane's parts, one a line, for the fleet's planner
    capability_cost_gate.py --selftest     grade the grader on synthetic input
"""

from __future__ import annotations

import datetime
import argparse
import concurrent.futures
import contextlib
import functools
import hashlib
import importlib
import io
import os
import pathlib
import re
import subprocess
import sys
import tarfile
import tempfile
import time
import types
from collections.abc import Callable, Iterator, Mapping
from dataclasses import dataclass, field

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import wz_config  # noqa: E402  (the one declaration, and its resolver)
import census_shard_plan  # noqa: E402  (the one cost planner of the sharded hosted lanes)
import build_normalization  # noqa: E402  (the one rule that keeps paths and time out of bytes)
import elf_facts  # noqa: E402  (the one reader of an ELF's version needs)
from artifact_root import artifact  # noqa: E402  (a sibling: where products are)
import pico_windows_package  # noqa: E402  (the Windows lane, whose cases share the ceiling table)
import wz_package  # noqa: E402  (the shipping entry: how a release file is made from its build)
from pico_host_ceiling import (  # noqa: E402  (the one rule of the ceiling table's rows)
    DEBT_PLACEHOLDER, HOST_CEILING, HOST_CEILING_SCHEMA, RATIO_TOLERANCE, ceil_ratio,
    ceiling_reading, ceiling_row, ceiling_rows, format_row, grade_ceiling, load_ceiling,
    row_findings, table_findings,
)

ROOT = pathlib.Path(__file__).resolve().parents[2]
CRATES = ROOT / "crates"
PICO_SOURCE = ROOT / "vendor" / "zenoh-pico"
# The reference builds, one directory per (pin, switches, toolchain), so a run that asks for the
# same build again reads it instead of building it. Products, so under the artifact root when one
# is set (scripts/lib/artifact-root.sh), like the cargo target directory below.
PICO_BUILDS = artifact("crates/target/pico-reference")
# Each case's seconds on a hosted runner, which the shards are planned by (module doc, "The hosted
# shards").
CASE_WEIGHTS = census_shard_plan.CASE_WEIGHTS
# A case's library is under the directory of the cargo profile it was built with. The size cases
# name it to cargo rather than inherit one: a target directory outside the checkout and the
# artifact root would put paths no mapping covers into the library, and the gate would read a
# library from here that cargo wrote elsewhere.
TARGET = artifact("crates/target")
# Each size case builds in a target directory of its own under this one (`case_target`), so that
# the cases of a run build at the same time (module doc, "The builds at once"): two cargo processes
# on one target directory wait on its lock, and a case of the same profile would replace the
# library another case left there. The paths a case's build writes under its directory are mapped
# to `TARGET`'s (`build_normalization.relocated_env`), so its bytes do not depend on which
# directory built it.
CASE_TARGETS = TARGET / "capability-cost"

# The features every pico build has, read from the one place that states them, the declaration's
# `[base] pico`, so a feature the crate's default gains (or loses) reaches the cases from there
# and not from a second copy here; `wz_config --selftest` holds the cases to the empty selection.
PICO_BASE = ",".join(
    wz_config.read_decl_toml(wz_config.DECL.read_text(encoding="utf-8"))["base"]["pico"]
)

# The linker of every library this gate builds and of every zenoh-pico reference: GNU ld, driven
# by the C compiler (`cc -fuse-ld=bfd`), so both arms of a ratio are linked by one linker. The
# toolchain's own default on this target is its bundled lld, which no C build reaches without
# naming that toolchain's directory, while GNU ld comes with the C compiler on every host that
# builds here, hosted ubuntu-22.04 included. `gnu_ld_version` refuses a host without it by name
# before anything is built, and `link_findings` refuses a library another linker wrote.
GNU_LD = "-fuse-ld=bfd"
GATE_RUSTFLAGS = ["-C", "linker=cc", "-C", f"link-arg={GNU_LD}"]
# What `comment_linker` answers for a library whose `.comment` names no linker, as GNU ld's.
NO_LINKER_NAMED = "no linker named in .comment"

# The profile every artifact a deployer receives is built with (`crates/Cargo.toml`: fat LTO, one
# codegen unit). A case measures what ships, so it is built with this profile or one inheriting it;
# the optimized build of daily work (`release`, thin LTO) carries copies a shipped library does not.
SHIP_PROFILE = "ship"
# The configuration of the library without `std` (`crates/.cargo/capi-nostd.toml`), which a case
# composes with the profile of the same name.
NOSTD_CONFIG = ".cargo/capi-nostd.toml"
# The code generation flag that file gives an x86 or x64 library on any host: no innermost loop's
# head aligned with no-ops (docs/c-abi-migration/arch-win-ext.md, step W1).
NOSTD_LOOP_ALIGNMENT = "llvm-args=-x86-experimental-pref-innermost-loop-alignment=0"
# The crate a C program links for a case's ABI crate, and the name that crate's manifest gives its
# dependency on the ABI: the pico ABI is an rlib (`wz-capi-pico`), and its C library is
# `wz-capi-pico-lib`, which takes the ABI's capabilities through its dependency `abi`. A case names
# the ABI crate, whose manifest and features it reads; its build names the artifact.
ARTIFACT_OF_PACKAGE: dict[str, tuple[str, str]] = {"wz-capi-pico": ("wz-capi-pico-lib", "abi")}


def artifact_package(package: str) -> str:
    """The crate cargo builds for the C library of `package`: its artifact crate, or itself."""
    return ARTIFACT_OF_PACKAGE.get(package, (package, ""))[0]


def artifact_features(package: str, features: str) -> str:
    """`features`, a comma list of `package`'s, as the build of its artifact crate names them:
    each through the artifact's dependency on the ABI crate, or as they are where the package is
    its own C library."""
    through = ARTIFACT_OF_PACKAGE.get(package, (package, ""))[1]
    named = [f.strip() for f in features.split(",") if f.strip()]
    return ",".join(f"{through}/{f}" if through else f for f in named)
# The Linux C ABI library with its relative relocations packed (DT_RELR,
# `crates/.cargo/capi-packed-relocs.toml`, docs/c-abi-size-diet.md T6): a glibc 2.36 loader. The
# linker argument is the file's; a case whose configuration gives it is held to a library that has
# DT_RELR and asks for the C library version that refuses an older loader by name
# (`link_findings`), and its zenoh-pico reference is linked with it too (`reference_args`).
PACKED_RELOCS_CONFIG = ".cargo/capi-packed-relocs.toml"
PACKED_RELOCS_LINK = "-Wl,-z,pack-relative-relocs"
# The version need a linker writes beside DT_RELR when the library asks libc.so.6 for any GLIBC_2
# version: a C library older than 2.36 has no such version and refuses to load the library, where
# without it the old loader would ignore DT_RELR and run the library with its pointers unrelocated.
RELR_VERSION_NEED = "GLIBC_ABI_DT_RELR"
# The library without `std` on Linux with the prebuilt standard crates' unwind tables discarded
# at the link (`crates/.cargo/capi-discard-unwind-tables.toml`, docs/c-abi-size-diet.md T7): a
# case whose configuration gives the script is held to a library with no `.eh_frame`
# (`link_findings`), and so is its zenoh-pico reference, compiled without unwind tables and
# linked with the same script (`reference_build`). The script's path in the file is from
# `crates/`, where cargo runs the linker; the reference's link runs in its CMake tree, so it is
# given the script's absolute path.
# The file names GNU ld itself, the one linker that honours the discard, so the form is the same
# outside this gate.
DISCARD_UNWIND_CONFIG = ".cargo/capi-discard-unwind-tables.toml"
DISCARD_UNWIND_SCRIPT = "wz-capi-pico/link/discard-unwind-tables.ld"
DISCARD_UNWIND_LINK = f"-Wl,-T,{DISCARD_UNWIND_SCRIPT}"
# The library without `std` on Linux with the code a traced run of the perf matrix executed laid out
# together ahead of the rest of its text (`crates/.cargo/capi-run-text.toml`,
# docs/win-budget/rss.md section 5.4): where functions lie, not what they are, so a size reading
# moves by alignment alone. The order is wz's own: its zenoh-pico reference is not linked with the
# script (`reference_build` passes on no argument it does not name).
RUN_TEXT_CONFIG = ".cargo/capi-run-text.toml"
RUN_TEXT_SCRIPT = "wz-capi-pico/link/run-text.ld"
RUN_TEXT_LINK = f"-Wl,-T,{RUN_TEXT_SCRIPT}"
# The output section the script lays the run's code in, and a line of its list, one a function
# (`run_text_lines`): a library linked with a list that places functions and holding no such
# section placed none of them (`link_findings`).
RUN_TEXT_SECTION = ".text.run"
RUN_TEXT_LIST_LINE = re.compile(r"^    \*\(.+\)$", re.MULTILINE)
# How the gate builds the library a release ships without `std` on Linux, as `Case` fields: the
# profile and configuration of that name, the relocations packed, the unwind tables discarded and
# the run's code laid out (the files above), and the names such a library leaves undefined and
# needs (pico-client-coop-nostd's note says why). One definition, taken by the release client's
# case and by the Linux twin of the Windows like-for-like library, so the two differ by their
# features alone and a link choice the release gains reaches both.
NOSTD_RELEASE_FORM: Mapping[str, object] = types.MappingProxyType({
    "profile": "capi-nostd",
    "cargo_configs": (NOSTD_CONFIG, PACKED_RELOCS_CONFIG, DISCARD_UNWIND_CONFIG, RUN_TEXT_CONFIG),
    "forbid_undefined": (r"^rust_eh_personality$", r"^_Unwind_Resume(@|$)"),
    "require_needed": (r"^libc\.so",),
})
# The C compiler's like of `-C force-unwind-tables=no`: code with no unwind tables, the
# asynchronous ones GCC writes by default on x86_64 included.
NO_UNWIND_CFLAGS = ("-fno-asynchronous-unwind-tables", "-fno-unwind-tables")
# Every library this gate builds is ONE build with its line tables, the shipping entry's
# (`wz_package.ship_debug_env`), and every figure is read from that build with its debug
# information taken off (`wz_package.strip_debug`), the file a deployer receives, written apart
# under `SHIPPED_TARGET` so the build cargo left keeps its line tables for the size ledger
# (`size_ledger_gate.py`), which reads its areas from them. A second build with line tables beside
# one without them is not the same code (measured: its executable sections differed), so the line
# tables of any other build would describe other code than the one measured. The zenoh-pico
# reference is built so too (`reference_build`): GCC's level 1 (clang's line tables only), without
# its command line in the producer string, where the prefix maps would put the host's paths, and
# the same strip. Taking debug sections off moves no code, and that is not taken on trust: a file
# whose executable sections are not its build's is refused (`link_findings`).
LINE_TABLES_CFLAGS = ("-g1", "-gno-record-gcc-switches")
SHIPPED_TARGET = TARGET / "shipped"
# The reference's file without its debug information, under its build directory.
SHIPPED_PICO = pathlib.Path("shipped") / "libzenohpico.so"

# Planes a build without the capability must not carry, as demangled-symbol patterns. The same
# patterns are REQUIRED of a build that has the capability.
ACCEPT = r"accept_loop::(accept_any|accept_loop_|AcceptEvent|SpawnedFaces|next_spawned)"
RESPONDER = r"scouting_responder|ScoutingResponder"
SCOUTING = r"scouting_glue|scouting_fanout|ScoutFanOut"
GOSSIP = r"gossip_plane|GossipPlane"
UDP = r"udp_pipeline|UdpDriver|udp_writer"
CLOCK = r"uhlc|NodeClock"
# The declaration's table of limits names every limit whatever the build has (`limit_binding`'s
# `held_at` and `select_at` for `MaxAdvancedPublishers`, `SessionLimits::max_advanced_publishers`,
# since 3d47ed315): the limit is not the plane, so its names are not read as it.
ADVANCED = r"(?<!max_)advanced_publisher|(?<!Max)AdvancedPublisher"
# pico's two header arms (`multi-thread`): each exports doors the other must not. A build
# without the capability is the single-threaded arm, so the two are each other's absence.
THREADED = r"^(z_mutex_init|zp_start_read_task)$"
SINGLE_THREADED = r"^(zp_spin_once|zp_read)$"
# pico's connectivity plane (`connectivity`), which the default build has and a build of
# upstream's default header does not.
CONNECTIVITY = r"^(z_info_transports|z_declare_transport_events_listener)$"
# The multicast transport (`multicast-transport`, open-debt item 913): the group face and its
# pipeline, which pico's default build has (`Z_FEATURE_MULTICAST_TRANSPORT`) and zenoh-c's too.
MULTICAST = r"multicast_glue|multicast_pipeline|MulticastLinkDriver"
# The standard library's own runtime: its panic hook's backtrace symbolizer and the demangler and
# decompressor it reads debug information with, which a library built with `std` links whatever its
# panic strategy, and one built without it (`os-host`, docs/c-abi-engine-and-memory.md P4) has none
# of.
STD_RUNTIME = r"std::backtrace_rs::|rustc_demangle::|addr2line::"
# The Keccak permutation of zenoh's SHAKE128 derivation of a session's initial sequence number,
# which the tokio engine announces by and the cooperative pico client does not
# (`wz-session-core`'s `initial-sn-compact`, zenoh-pico drawing that origin at random).
KECCAK = r"keccak::"
# The `log` facade's logger call, which a diagnostic of the session core links where its `log`
# feature is on (`wz-session-core`'s `diag`): the tokio engine's runtime takes the crate with its
# defaults and so has it, and the cooperative library without `std` takes it without them and
# installs no logger, so it has none, as zenoh-pico built without a log level has no log call. A
# module whose name ends in `log` (`event_log::`) is not the facade.
LOG_FACADE = r"(?<![\w])log::"
# The allocator's abort on a refused request: what an allocation that cannot fail answers a full
# heap with (`Box::new`, `Vec::push`, `alloc::alloc::handle_alloc_error` called by hand), the
# program ended where a refusing build answers the caller. One such allocation left anywhere in a
# build links it.
HEAP_ABORT = r"handle_alloc_error"
# The one body every table of a session whose tables take their memory on use takes its rows
# through (`wz_session_core::on_use::take_rows`, out of line by `#[inline(never)]`): a library of
# that form links it, and one whose tables are laid out at the open calls it from nowhere.
ON_USE_ROWS = r"wz_session_core::on_use::take_rows"
# Forbidden patterns whose control build (one that must link the pattern) is not yet a case, each
# with why: the selftest holds every other forbidden pattern to a case that requires it. A pattern
# leaves this table in the commit that adds its control.
CONTROL_PENDING: dict[str, str] = {}
# The engine a pico build runs its sessions on (`engine-tokio` / `os-host`,
# docs/capi-pico-on-coop-engine.md): a build of one links none of the other.
TOKIO_ENGINE = r"wz_capi_core::|wz_runtime_tokio::"
COOP_ENGINE = r"wz_capi_coop::"
# The cooperative engine's listening role (`wz-capi-coop`'s `listen`): the listeners its links open
# on a port, which the session's driver holds (`wz_runtime_coop::faces::LinkSupervisor::listen`)
# since d781d9310 moved the ports out of the engine. The driver's table of ports is in every build,
# so the witness is what only an open port makes: a listener of the links, reached through its
# table of functions.
COOP_LISTEN = r"wz_runtime_coop::ip_stack::Ip(Udp|Tls)?Listener<"
# The cooperative engine's scouting window (`wz_capi_coop::scout`) and the session's window it
# pumps: what a cooperative build that scouts has and the tokio engine's `SCOUTING` is not.
COOP_SCOUT = r"wz_capi_coop::scout|scouting_host"
# The node a session of the C ABI can hold behind its handle (`router-node`): the router data
# plane run as a session, which a build without the feature opens none of. The pattern is the
# module only the feature compiles and not `RouterForwarder`, whose accept loop a default build
# instantiates too (capic-default's note).
ROUTER_NODE = r"drive::router_node::"
# The acceptor half of the unicast handshake (`session-unicast-accept`): the cookie an InitAck
# carries, which only a session that takes another's Init writes. A build that listens has it; a
# client opens and never accepts, so the half is a plane it leaves out like the accept loop.
ACCEPT_HANDSHAKE = r"accept_cookie::encode_accept_cookie"
# wz's own doors that judge, emit and cost a configuration without opening it (`config-verdict`,
# on by default): the emitter and the validators behind them are linked through these alone.
CONFIG_VERDICT = r"^wz_capi_c_config_(validate|to_json5|device_requires|verdict_)"


@dataclass(frozen=True)
class Case:
    id: str
    package: str
    lib: str
    features: str | None  # None: the crate's default features
    # None: no budget yet, which `grade` refuses with the budget the reading sets.
    max_text: int | None
    forbid: tuple[str, ...] = ()
    require: tuple[str, ...] = ()
    exports: int | None = None
    # The cargo profile (`crates/Cargo.toml`): the shipping one or one inheriting it. It is not a
    # capability, so it leaves the pico reference alone: that is derived from the features only.
    profile: str = SHIP_PROFILE
    # Patterns no symbol the library leaves UNDEFINED may match (`nm -u`): a name the library
    # expects whoever loads it to define, which no C program linking it does.
    forbid_undefined: tuple[str, ...] = ()
    # Patterns each of which some library the library names as needed (DT_NEEDED) must match: a
    # library that names no C library leaves its calls unversioned, and the loader binds an
    # unversioned call to the oldest version of the symbol.
    require_needed: tuple[str, ...] = ()
    # The cargo configuration files whose flags and linker the build takes (paths from `crates/`,
    # read by `case_config`), with the host's own target named (`--target`), so that what a file
    # gives the library's crates does not reach the build scripts. Empty: the profile alone.
    cargo_configs: tuple[str, ...] = ()
    # The registered profile (`configs/profiles/<id>.conf`) whose resolved features the case is
    # built with (`profile_features`), its `features` None beside it: a case that stands for a
    # library another lane builds from a profile reads the list where that lane does and holds no
    # copy of it.
    features_from: str | None = None
    note: str = field(default="", compare=False)


# Budgets are the measured text plus about two percent (`budget_for`). See the module doc.
CASES: tuple[Case, ...] = (
    # 2026-10-29 -- nine of the pico cases below and `capic-default` were moved to the hosted
    # reading of run 40729400547 (head `04d21adb3`) plus 3,500, to the hundred, because the clock
    # work of that day grew them, and the growth is the feature's, chosen. Measured on a local
    # checkout at the commits between the budgets (`dbaf933f6d`) and that head, in bytes of
    # text, the same toolchain at each: `pico-client-coop` 914,691 -> 915,099 with `5b1bf6b185` (the
    # session's link driver named by its type) -> 919,507 with `81587d61e3` (the node clock on
    # `HlcCore`), and unmoved by every commit after; `-admin-space` 1,260,203 -> 1,263,099 ->
    # 1,267,279; `-query` 1,201,741 -> 1,203,729 -> 1,207,909. `capic-default` 9,130,749 -> 9,153,670
    # with `81587d61e3` and what is before it -> 9,191,686 with the clock-quality work that follows
    # it (the statechart and its host, the trusted-only policy, the registry of clocks, the
    # standing) -> 9,204,244 with `d8995bc4f1` (the gateway/south reader) -> 9,204,316 at the head.
    # The timestamp stack of the session API is in none of these images: no C ABI crate enables
    # `pubsub-ts-stack`.
    # 2026-11-20 (the PoC's fourth landing) -- 16 budgets move by what that landing adds, on top of
    # the hosted reading of round 4567: each delta measured against main `4df161c9e` on one machine,
    # both trees built there one after the other (the offset between that machine and hosted
    # cancels): pico-default +8,192, pico-peer +8,856, capic-default +32,120, -lean +14,212,
    # capic-router-node +21,808, pico-client +2,938, -udp +2,954, the coop cases +8,152 to +8,432.
    # The symbol diff (`nm -C -S`, text) names what was chosen: the session's clock as a type
    # (`drive_phase_on`, `drive_connect_phase_on`, `timeout_on<TokioTime>` in place of the
    # unparameterised forms), the group's declarations answered from session-core
    # (`GroupKeyexprAnswers`, `build_group_announcement`, the tokio `GroupKeyexprs` gone), a
    # group member as a face (`FaceSnapshot::of_group_member`), and the conduit a held sender
    # drops at once behind (the QoS work). In the coop cases the same, less the program clock's
    # word, which a build without `time-base` no longer carries (-700 against the first reading).
    # capic-client, -peer and -scout sit far under budgets that need no move; pico-client-small
    # and capic-client-small shrank.
    # 2026-11-20 (the PoC's third landing) -- 18 budgets move by what that landing adds, on top of
    # step 4b round 2a's moves of the same day: each delta measured against main `cd240d4b4` on
    # one machine (both trees built there, so the offset between that machine and hosted
    # cancels): pico-default +20,284 (and the +559 main sat over on hosted 44646497313),
    # pico-peer +5,668 (+286), capic-router-node +23,249 (+1,328), capic-default +27,048, -lean
    # +26,768, capic-client-small +8,793, pico-client +2,840, -small +4,316, -udp +4,056, the coop
    # cases +362 to +1,044. The symbol diff of `pico-default` (`nm -C -S`, text, +16,780) names
    # what was chosen: the group's zp_batch window (`multicast_tx_push_in` +13,046), the owed
    # replies sent after the observer is let go (`take_owed_declarations` +2,530), the
    # watchdog's thread line (`threads_now` +2,611), the datagram inline write and the cookie
    # policy. capic-client, -peer and -scout sit far under budgets that need no move.
    # 2026-11-05 (round 4290) -- six cases over their budgets on hosted run 41974391826 (head
    # `9cd2d9499f`) and further at origin `05f6ab65b1`: pico-client, -small, -udp, pico-peer,
    # pico-default, capic-client-small (capic-default and capic-router-node were moved by
    # `9e3e643439`, whose bisection splits the same window). The symbol diff of `pico-default`
    # (`nm -C -S`, text, both built on the fleet from wz `82d5bf1e71` and from `00a18afca9`) is
    # +97,344, of which `sce_rust_runtime` is +71,493: three `Engine<P>` methods that exist only
    # with SCE's engine inbox (ADR 0084), monomorphised once per wz policy (six policies):
    # `apply_inbox_input` 34,277 (SCE `a192f70dde`, pin `07cb8c5020`), `apply_held_inputs` 32,847
    # (`f047e875e1`, pin `0907db47a2`), `end_host_invoke` 6,916; with the inbox receivers' drop glue
    # and the channel waker another ~24,000 in `core`/`std`/`alloc`, and `wz_codecs` -19,952 (the
    # views and parts forms). wz's own C ABI crates moved by under 200. Then +29,500 to
    # `05f6ab65b1`, all in `wz_codecs` and `wz_session_core`: `2274c65e57`, a record read in the
    # lent form at the heap's capacity (the receive profile `RxShared`). The pins are wz's choice
    # and the inbox is the engine they carry, so each budget moves to its reading on hkl001 at
    # `05f6ab65b1` plus 3,500, to the hundred. The SCE session that owns ADR 0084 took the
    # per-policy copies (a non-generic body, child routing compiled out where a policy has no
    # children); when that lands these six and the two above come back down.
    # 2026-11-06 -- it landed: the SCE pin moved to `06f8147241` (one policy-free held input in the
    # std inbox, a non-generic end of a started invoke, and `HAS_HOST_INVOKES`, which every wz
    # machine states false). Every case read on hkl001 at origin `215e687827` with that pin. In
    # `pico-default` (`nm -C -S`) `apply_inbox_input` and `end_host_invoke` are gone and
    # `apply_held_inputs` is 6 copies of 13,748 together, against 74,040 for the three; the text
    # fell from 4,496,400 or less to 4,404,550 (-91,850, the drop glue and channel the inbox no
    # longer copies per policy included). The nine cases the inbox moved come back down, each to
    # its reading and its own margin: these six and `capic-client-small` to the reading and 3,500,
    # `capic-default`, `capic-default-lean` (which took `capic-default`'s budget) and
    # `capic-router-node` to the reading, the 3,184 `capic-default`'s note gives the hosted lane
    # over a build machine, and 3,500, each to the hundred.
    # 2026-11-06, later -- hosted run 42121505586 (`aefdd5ca0e`, no crate change since that
    # reading) read `pico-default` at 4,408,146, 46 over, and `pico-peer` 11 under: the hosted
    # lane reads these images up to 3,600 above hkl001, so a margin taken over a build machine's
    # reading went to the lane and left none for growth. The nine budgets are now that run's
    # reading and 3,500, to the hundred, which is the form the older notes below use.
    # 2026-11-08 -- hosted run 42403286547 (`c91572906a`) read `pico-client-udp` 1,920,340,
    # `pico-peer` 2,982,441 and `pico-default` 4,417,274, over by 3,340, 4,141 and 5,574. Three
    # commits since `aefdd5ca0e`: the fragment pacing policy (its writer, clock and wait were
    # linked with the policy off, about 3,100 to 3,700 here), the keyexpr relation memo
    # (`c74d81592c`, about 2,400: the double star's descent remembers the suffix pairs it
    # refuted, which repaid an exponential recursion) and the interface policy of a multicast link
    # (`cfc80eec5f`, about 500: a value policy, so both values' code is linked, C3). Pacing is now
    # a strategy type of the writer, so a build with it off links none of it: on hkl001 1,919,044
    # -> 1,915,960, 2,978,949 -> 2,975,865 and 4,413,678 -> 4,409,990. The memo and the interface
    # policy are chosen growth. With the lane's offset over hkl001 on the same pico code (that run
    # against hkl001: +1,296, +3,492, +3,596) the hosted readings are 1,917,256, 2,979,357 and
    # 4,413,586, and each budget is that and 3,500, to the hundred.
    # 2026-11-09 -- hosted run 42444920480 (`14c0595c31`) read `pico-client` 1,856,700 (800 over)
    # and `capic-router-node` 6,010,776 (1,176 over); on the build machine (`pc2`) the same
    # commit reads `pico-client` 1,855,436, so the lane is +1,264 there. Since that head: the
    # route memos per table version, the link restriction and the targeted query (value
    # policies, both values linked, C3), the reliable-gap policy (`pico-client` 1,860,660 at its
    # commit, +5,224 for all of these), and the admission retry with the all-or-none send, which
    # took the publish fan-out's probe and reserve legs into every build through a `dyn` the
    # fan-out made whether or not the policy was on (+7,204 more, in `publish_all`,
    # `publish_aliased_all_for` and the probe path of the session). The legs are now made only
    # where a policy states them (`WIRE_LEGS_IN_BUILD` in `faces.rs`), which gave back 4,216 of
    # it (1,867,864 -> 1,863,648). The rest, about 2,300, is below the fan-out: the writer
    # queue's `try_reserve` and `Permit` (a method of the link driver trait, so every driver
    # has it), `build_publish_push`, and a few hundred in the publish options' clone, chosen. The
    # nine cases over their budgets on `pc2` at origin `47ec060afa` plus that change read
    # `pico-client` 1,863,648, `-small` 1,521,073, `-udp` 1,925,724, `pico-peer` 2,985,089,
    # `pico-default` 4,418,990, `capic-client-small` 1,971,258, `capic-router-node` 6,047,612,
    # `capic-default` 11,161,472 and `capic-default-lean` 9,583,884. Each budget is that reading
    # plus the lane's offset over `pc2` (1,264 for the client images, which the same run fixes;
    # the 3,500 the older notes give the peer and default images; the 3,184 `capic-default`'s
    # note gives the C images) and 3,500, to the hundred. The C images were not taken apart
    # symbol by symbol; the window above is all that grew them, and the next hosted reading
    # corrects an offset that is off.
    # 2026-11-09, later -- hosted run 42505060630 (`7e94c0a7fd`): the hosted lane read every case
    # of the window above under its budget at `232aa60694` (`capic-default` 11,162,484), which
    # fixes the pico offsets; the C offset is +1,012 over `pc2` (11,161,472 there), not the 3,184
    # the note above reused. At `7e94c0a7fd` `capic-default` reads 11,179,716 (11,516 over) and
    # `capic-default-lean` 9,602,204 (11,604 over); no other case moved. TAKEN APART on `pc2`
    # (`size -A` and `nm -S` of both builds, `capic-default`, 11,161,472 -> 11,178,704): every
    # symbol keeps its size and the code sections are equal; the whole +17,232 that `size`
    # counts is `.rela.dyn` (718 relative relocations of 24 bytes), and `.data.rel.ro` grew by
    # 12,000 beside it. Static tables of pointers, which fits the diff of the round: the
    # document history of `wz-capture` (`doc_revision.rs`, +1,106 lines: revision 60 and the key
    # sets the row-facts document is held to), which the frame writer of the `e2e-sender`
    # feature reaches. A pointer table in a shared object costs its data and a relocation for
    # each pointer. The table that holds them was not named by a symbol (they are anonymous
    # constants). Chosen growth of the row-facts round, not a leak; the budget is the hosted
    # reading and 3,500, to the hundred.
    # 2026-11-16 -- hosted run 43807729116 (`3148fdfc84`) read 17 cases over their budgets after
    # the c2 landing (`ef49dc9911` -> `1ee477a334`, 387 commits) and the 6e one. TAKEN APART on
    # `pc2` (`nm -C -S`, text symbols, both trees built there): the largest single item was the
    # face loop of the tokio runtime, a 25 KB (pico) / 41 KB (zenoh-c) body monomorphised once per
    # caller's closure pair, 4 and 5 copies; it is now compiled once (`face_drive_loop_core`),
    # which gave back 73,916 of `pico-peer` and 181,348 of `capic-default`. The rest is chosen
    # growth of the features the window landed, by owning module: `pico-client-coop` +24,017
    # (the transport messages read through SCE's generated views, `wz_codecs::transport_*` and
    # `sce_forge_runtime::view`; `inbound` +5,067; the reassembly dispatch +2,910), `pico-client`
    # +43,314 (the same, plus the session's declaration aggregation and the writer queue), and
    # `capic-default` +235,360 (the route caches +31,269, the keyexpr index +26,269, QUIC's
    # streams +24,349, router forwarding +24,095, the storage's persistent map +22,006, the
    # open plan and the config reader +32,586, the plugin search dirs +3,222). Readings on `pc2`
    # at `0a230c587c` with the face loop compiled once: each budget below that moved is that
    # reading plus the lane's offset over `pc2` (1,264 the pico client and coop images, 3,600
    # `pico-peer` and `pico-default`, 1,012 the C images) and 3,500, to the hundred.
    # 2026-11-18 -- the answer to a peer's Interest asks the session's egress policy
    # (`SessionLinkActions::send_declare` +551 of the +2,508 the symbol diff of pico-client-udp
    # reads on pc2 between `d8f187dddc` and this tree; the rest is drop glue the build laid out
    # anew). Every C ABI build gained it; the cases it took over are moved to the hosted reading
    # at `d8f187dddc` (run 44032688827) and the growth pc2 read for that case between the two
    # trees (Layer C1cs run on both, one host), and 3,500, to the hundred: here 1,921,552 and
    # +2,484.
    # 2026-11-19 -- step 3b of the policy binding: a code path a policy guards now folds on the
    # build's DOMAIN and not on its default, and a host build allows every value, so the paths a
    # run-time snapshot may turn on are linked. Measured on pc2 against main at `458774b1f`,
    # +18,736; by symbol the all-or-none and retry publish legs (`publish_all` +3,458,
    # `publish_aliased_all_for` +2,988 and +782, `reserve_staged` +1,667, `probe_wire` +1,666,
    # `reserved_wire` +926, `stage_wire_push` +679, `send_reserved_at` +649, the reservation's
    # drop glue +551), the rest the renamed dispatch (`dispatch_declare` -> `_at`, nets to
    # +195). A build that wants them out narrows the domain (`WZ_POLICY_*_ALLOWS_ON=off`). Chosen;
    # the budget moves by that growth, to the hundred.
    # 2026-11-20 -- the lane has been red since the c7 landing (`ddcc2f3a42`, run 44257522247):
    # the budgets above were moved by growth measured on a host, and the hosted reading they
    # were moved from was already over. TAKEN APART by symbol (`nm -C -S`, both trees built on one
    # host). The c7 landing (`4050dd889` -> `ddcc2f3a4`): `capic-router-node` +37,567 (the token
    # plane's advertisement and future pushes, `advertise_change::<TokenPlane>` +11,791; the route
    # memos moved into the broker hat and the client leg's held faces; a liveliness get stating its
    # links, `liveliness_get_on_links` +7,010; the session's transport body re-laid, net +4,256),
    # `pico-client` +5,596 and `pico-client-coop` +3,718 (the statement doors on link sets, the
    # all-or-none reservation `try_reserve_rooms_for`, the typed zid in `z_open` and
    # `wire_zid`). Rounds 4521 to 4526 (`f7ab3a770` -> `64d1da2e4`): `capic-client` +10,424, the
    # document layer of step 4a (`policy_document::{read_ext_member, compose, resolve_document}`, the
    # `Refusal` and `ValueSet` displays, `ZenohNodeConfig::read_over` with the `wz` member) and its
    # generated tables (`.rela.dyn` +4,104, `.data.rel.ro` +2,560); `capic-router-node` +19,425,
    # the same and Round 4523's `EndpointKey`, a key per listing of an endpoint, monomorphised
    # through the loop's maps and sorts (net about +5,000); `pico-default` +561. Chosen growth of
    # those rounds. Each budget that moved is the hosted reading at `64d1da2e4` (run
    # 44458681692), plus the growth `pc2` read between that tree and the tree that moves it (both
    # built on `pc2`, which reads within 1,200 bytes of hosted CI on every case), and 3,500, to
    # the hundred.
    # 2026-11-20 -- step 5 of the staged policy binding, the config doors of the three ABIs, and
    # Rounds 4545 to 4549, which landed without moving a budget. Read on `pc2` (main `4481c5ac8`
    # against the step's tree): every pico case +15,795 to +17,955, `capic-router-node` +9,132,
    # `capic-default` +11,920, `capic-default-lean` +11,856. TAKEN APART by symbol (one host,
    # `nm -C -S` and section sizes). Step 5 on `pico-client-coop` (+16,359): the doors
    # `zext_config_policy` +1,359 and `zext_config_profile` +862, the composition
    # `policy_document::compose` +1,315 and `resolve_under` +432, `session::resolve_policy` +408,
    # one `select_at` per policy (about 28 bytes each), and the policy and profile tables the
    # composition reads, whose string pointers a shared library relocates (`.rela.dyn` +5,712,
    # `.data.rel.ro` +3,536); the JSON5 reader stays out, behind `config-document`. Step 5 on
    # `capic-client` (+9,376): the config's `wz` member held whole (`ConfigState::insert`
    # +2,648, `install_parsed` +1,424, `render_nested` +1,037) and its resolution at the open
    # (`resolve_document_in` +815). Main's own, read against `4c57f1760` (the tree the budgets of
    # Round 4550 were read on, which Rounds 4545 to 4549 were not in): `capic-default` +21,134 of
    # text symbols, the token interests a node sends north and the answers it holds
    # (`register_token` +2,857, `hold_own_interest` +1,027, `build_interest_propagated_as` +846),
    # a node's liveliness get through its routers (`ask_routers_current_tokens` +2,213, the local
    # face's `TokensGet` and `State::handle` +2,769) and the queue sizes a document states
    # (`OpenPlan::resolve` +690, `into_arguments` +691); `pico-peer` +191. Chosen. Each budget
    # that moved is the step's reading on `pc2` and 3,500, to the hundred; the pico export pins
    # count the two doors.
    # 2026-11-20 -- step 4b round 2a, the first bound read from the session's limits: +1,156 on
    # pc2 (`cd240d4b4` against `6316ea555`). The symbol diff of pico-default, the case that holds
    # every part (+1,372 of text, +421 of symbols): the refusal a subscriber declare now returns
    # (`declare_subscriber_on_wire` +191, `RegisterError`'s Display +106), the group that leaves
    # off a mirrored subscription it refuses (`subscribe_on` +175), `with_limits` +72 and the
    # quota asked in `register_sink` +48 (`mcast_face_up` -369); the rest is read-only data, the
    # build's `SessionLimits` among it. The snapshot's defaults are one constant
    # (`SessionLimits::BUILD`), not three 402-byte bodies of stores, which the first build of the
    # round carried. Chosen growth; each budget at its line moves by its pc2 growth, to the
    # hundred.
    # 2026-11-20 -- step 4b round 2b, the six other bounds a program's own calls fill: +48 on pc2
    # (`022e6268b` against the round's head), the quota words. The symbol diff of pico-default,
    # both trees built on one machine (+665 of text symbols there, +1,948 on pc2): the group's
    # queryable declared before it is announced (`multicast::answer_on` +662), a token admitted
    # before its declare leaves (`TokenPlace::take` +321 and its drop +412,
    # `LivelinessToken::new_held` -307) and the group paths that leave a refused entity off
    # (`declare_token_on` +182, `get_on_wire` +202); the C ABI's router node adds the local
    # face's end of a get its registry refuses (`State::handle` +530) and the group's join
    # (`FaceGroup::join` +317). Chosen growth; each budget at its line moves by its pc2 growth,
    # to the hundred.
    # 2026-11-20 -- the hosted reading again. Hosted run 44669791897 (main `cd240d4b4`) read
    # eight cases over their budgets, pico-default by 38,192, and no hosted C1cs has decided
    # since. Hosted read `7e14fb72d` 559 over (run 44646497313), and both trees built on one
    # build host put +37,633 of text on pico-default between the two: Rounds 4557 and 4558
    # grew it and moved no budget. The symbol diff (+31,791 of text symbols) names their
    # refusals reaching every caller: the refused node clock's `OpenError` through the open
    # (`open_blocking` +1,499, `bind_listener` +1,822, `bind_listeners` +1,886, the drive
    # closures, `LateBinds::spawn`), pico's connect timeout on the tokio open
    # (`drive_connect_phase` +2,151, `open_on_tokio` +1,384) and a value outside its limit's
    # domain (`OutsideLimitDomain`'s Display +755). Each of the eight budgets is that hosted
    # reading, the growth from `cd240d4b4` to `e924c1792` measured on that build host (+6,356
    # here, +26,144 on pico-default), and 3,500, to the hundred; the other thirteen cases sit
    # under theirs.
    # 2026-11-21 -- step 4b rounds 2 to 4, landed together: the six peer-filled bounds, the
    # semaphore's bound as the limit's value, the session's limits in its parameters, the
    # document's `zext/limits` read with named refusals, and the three doors that open under it.
    # +12,802 here, both trees (`b58b71c19` and the round's head) built on one machine. The
    # symbol diff of pico-client-small (+6,580 of text symbols; .text +6,864, .data.rel.ro
    # +4,904, .rodata +1,920, .eh_frame +1,512): the reader of `zext/limits` (`compose_limits`
    # +1,453, `FoundLimit::find` +1,382) and the limit tables it finds a limit in (read-only
    # data), the quotas asked on the observer's paths (`dispatch_event` +824) and the open that
    # resolves the document's limits (`resolve_policy` +552, `open_blocking` +155, `z_open`
    # +151). A limit read from the build has no selector in its entry, so its selection (about
    # 180 bytes each, which the round's first build linked for all 59) is not linked. Chosen
    # growth; each budget moves by its growth on that machine, to the hundred.
    # 2026-11-22 -- the step 4b carry (the limits read from the session's snapshot by their
    # readers, the runtime limits handed to the node clocks and the opens, the tokio node's connect
    # list refused past its limit, the slot build's peer tables and a task's reply stage held to
    # the session's limits), with the hosted reds of run 44895098050 (main `c72460b30`), which
    # read pico-client-coop-admin-space 92 over its budget and capic-router-node 656 over. Both
    # trees (main `abb1552d1` and the carry's head) built on one machine: pico +7,732 to +10,324,
    # pico-peer +2,124, capic +3,561 to +20,566. The symbol diff of pico-client-small (+4,854 of
    # text symbols; .text +5,088, .eh_frame +1,880, .rela.dyn +720) and of capic-router-node
    # (+16,238; .text +16,512): the face drive loop's closures (`face_drive_loop_core`,
    # `drive_face_shared`, the face set's poll), the UDP writer paced by the session's policy
    # (`udp_writer_task_paced` +5,858 against `udp_writer_task` -6,400) and the tables built
    # with the session's limits (`SubscriberTable`'s default +831, the liveliness table +861);
    # the open's timeout is a named future (`timeout_on` -1,000 or so per caller). Chosen
    # growth. Each budget that moves is the hosted reading of run 44895098050, that growth, and
    # 3,500, to the hundred; the five capic cases that stay sit under theirs with the growth.
    # 2026-11-23 -- the session drive made one loop for every caller and the dial and the
    # initiator's open made once (`session_glue::drive_session_dyn`, `session_open::dial_locator`),
    # with the face loop's steps taken as effects (`accept_loop::FaceLoop`). Every case read on one
    # machine at main `634d1b7ba` and with the change, both trees built there. A build that drives
    # sessions from more than one place (the accept loop, the C ABI's roles, a reconnect) lost the
    # copies its callers held of the loop, the dial and the handshake: pico-peer -28,336,
    # pico-default -12,768, capic-peer -23,996, capic-router-node -49,636, capic-default -262,136,
    # capic-default-lean -244,452. A client, which drives one session from one place, pays the
    # boundaries for nothing: +619 of text symbols in this case and the rest in unwind tables and
    # vtables, +3,904 here, +2,364 pico-client-small, +1,360 pico-client-udp, +3,448 capic-client,
    # +2,828 capic-client-small, +13,988 capic-scout. Chosen: the boundaries are the structure that
    # keeps a library's code from growing with the number of places that drive it, and each case's
    # budget moves by its own change and keeps its headroom.
    Case("pico-client","wz-capi-pico", "libwz_capi_pico.so", PICO_BASE, 2_024_404,
         # 2026-11-22 -- the step 4b carry and run 44895098050's reading:
         # 2,007,557 hosted, +9,344 on one machine.
         # 2026-11-25 -- the crate's default and the pico base name the cooperative engine (P1 of
         # docs/c-abi-engine-and-memory.md): this case builds on it, and its budget and row are the
         # tokio engine's until the first reading on it moves them.
         forbid=(ACCEPT, RESPONDER, SCOUTING, GOSSIP, CLOCK, ADVANCED, THREADED,
                 CONNECTIVITY, MULTICAST, TOKIO_ENGINE, COOP_LISTEN, KECCAK, STD_RUNTIME),
         require=(SINGLE_THREADED, COOP_ENGINE),
         profile="capi-nostd", cargo_configs=(NOSTD_CONFIG,),
         note="a single-threaded pub/sub client that dials TCP: no listener, no scouting, "
              "no UDP, no clock, no unstable API. 1,794,085 measured, down from 1,868,267 "
              "with the unstable API and the connectivity plane. Hosted reads run higher than "
              "the first figure, and read 1,828,525 on 2026-10-26 before the key set's data-key "
              "gate; 1,831,017 after it (`5c5f3f77c`, `e43c55563`, `9e1856fb1`: the gate, the "
              "delivery by selection and the canonical form, which every build links whether "
              "its key set is open or closed, +2,492); 1,831,845 with the per-peer allowance "
              "(`c76528c00`, +828); 1,833,173 on the head that followed, which also holds the "
              "reply key gate (`169bd005b`) and the engine port's advanced plane. The budget "
              "moves to that reading with its margin. 1,849,773 on hosted CI on 2026-10-27 "
              "(head `f4bdeaee5`, +16,600): the growth is in the code every pico build links "
              "and is not attributed to one commit; the budget moves to that reading. "
              "1,861,801 on hosted CI on 2026-10-29 (head `017e3c711`), and 1,868,097 on a "
              "build machine on the tree of round 3939, whose readings track the hosted ones "
              "(capic-default's note): the budget is that reading and 3,500, to the hundred"),
    # 2026-11-19 -- step 3b, as pico-client's note of this day says: +16,788 on pc2.
    # 2026-11-20 -- step 4b round 2a, as pico-client's note of this day says: +764 on pc2.
    # 2026-11-20 -- step 4b round 2b, as pico-client's note of this day says: +48 on pc2.
    # 2026-11-20 -- the hosted reading again, as pico-client's note of this day says: 1,623,992
    # at `cd240d4b4` and +5,072 since.
    # 2026-11-21 -- step 4b rounds 2 to 4, as pico-client's note of this day says: +14,846 on
    # one machine.
    # 2026-11-23 -- one session drive, dial and open for every caller, as pico-client's note of
    # this day says: +2,364 on one machine; the budget moves by it and keeps its headroom.
    Case("pico-client-small", "wz-capi-pico", "libwz_capi_pico.so", PICO_BASE, 1_657_964,
         # 2026-11-22 -- the step 4b carry and run 44895098050's reading:
         # 1,644,062 hosted, +8,004 on one machine.
         # 2026-11-25 -- the crate's default and the pico base name the cooperative engine (P1 of
         # docs/c-abi-engine-and-memory.md): this case builds on it, and its budget and row are the
         # tokio engine's until the first reading on it moves them.
         forbid=(ACCEPT, RESPONDER, SCOUTING, GOSSIP, CLOCK, ADVANCED, THREADED,
                 CONNECTIVITY, MULTICAST, TOKIO_ENGINE, COOP_LISTEN, KECCAK),
         require=(SINGLE_THREADED, COOP_ENGINE), profile="capi-small",
         note="the pico-client build with panics aborting: the like-for-like of zenoh-pico's C. "
              "1,468,134 measured against pico-client's 1,790,361 (-18.0%). Read 1,498,558 on "
              "hosted CI on 2026-10-26 with the key set's gate and the engine port's advanced "
              "plane, which pico-client's note above attributes. 1,510,582 on hosted CI on "
              "2026-10-27 (head `f4bdeaee5`, +12,024), the growth pico-client's note states. "
              "1,517,026 measured locally on the head of round 3901 (`53b4fdc31`, 26 over "
              "the earlier budget of 1,517,000, which no hosted run graded: they were "
              "cancelled), and 1,517,268 with the router session's get on it (`9de15171e`, "
              "+242) while no router symbol is linked into this build (`nm` finds none), so "
              "the step is the layout of code every pico build links and not a plane this "
              "build gained. The budget is the latter reading and 3,500, rounded up to the "
              "hundred. 1,524,973 measured locally on the head of the round that ends the "
              "queries pending on a face with it (4,173 over 1,520,800): the head under it was "
              "not measured here, so what is that round's and what the earlier rounds' is not "
              "separated, and the budget is that reading and 3,500, rounded up to the hundred"),
    # 2026-11-18 -- the egress-policy answer, as pico-client's note of this day says: 1,985,436
    # hosted at `d8f187dddc` and +2,508 on pc2.
    # 2026-11-19 -- step 3b, as pico-client's note of this day says: +21,616 on pc2.
    # 2026-11-20 -- step 4b round 2a, as pico-client's note of this day says: +1,140 on pc2.
    # 2026-11-20 -- step 4b round 2b, as pico-client's note of this day says: +48 on pc2.
    # 2026-11-20 -- the hosted reading again, as pico-client's note of this day says: 2,049,727
    # at `cd240d4b4` and +7,600 since.
    # 2026-11-21 -- step 4b rounds 2 to 4, as pico-client's note of this day says: +12,976 on
    # one machine.
    # 2026-11-23 -- one session drive, dial and open for every caller, as pico-client's note of
    # this day says: +1,360 on one machine; the budget moves by it and keeps its headroom.
    Case("pico-client-udp", "wz-capi-pico", "libwz_capi_pico.so", PICO_BASE + ",link-udp", 2_088_660,
         # 2026-11-22 -- the step 4b carry and run 44895098050's reading:
         # 2,075,981 hosted, +7,732 on one machine.
         # 2026-11-25 -- the crate's default and the pico base name the cooperative engine (P1 of
         # docs/c-abi-engine-and-memory.md): this case builds on it, and its budget and row are the
         # tokio engine's until the first reading on it moves them.
         forbid=(ACCEPT, RESPONDER, SCOUTING, GOSSIP, CLOCK, ADVANCED, THREADED, CONNECTIVITY,
                 MULTICAST, TOKIO_ENGINE, COOP_LISTEN, KECCAK, STD_RUNTIME),
         require=(UDP, SINGLE_THREADED, COOP_ENGINE),
         profile="capi-nostd", cargo_configs=(NOSTD_CONFIG,),
         note="1,894,361 on hosted CI on 2026-10-26, 1,889,713 before the key set's gate: the "
              "same growth as pico-client's, whose note attributes it. 1,910,913 on hosted CI on "
              "2026-10-27 (head `f4bdeaee5`, +16,552), the growth pico-client's note states. "
              "1,919,305 on hosted CI on 2026-10-29 (head `1ab111232`, 305 over the 1,919,000 "
              "it held): the one of the cases that read the day's clock growth that the budgets "
              "above did not move; the budget moves to that reading plus 3,500, to the hundred. "
              "1,929,813 on a build machine on the tree of round 3939, the growth "
              "pico-client's note states: that reading and 3,500, to the hundred"),
    # The same client on the cooperative engine: the program steps its session, and no runtime
    # thread or tokio is linked. Its links dial UDP in every build, so it is compared with the
    # pico that pico-client-udp is (`link-udp` names that here; it adds nothing to this build).
    #
    # The budgets of the cooperative cases below are the pc2 readings of 2026-10-27 and 5,500,
    # after the runtime's host locks became each value's own (`wz-runtime-coop`'s `HostMutex`,
    # whose enter and leave are out of line): every case read about 4,000 less than before it
    # (pico-client-coop 934,883 to 930,823), which the budgets keep. The per-case notes state
    # the history up to the day before, and each reading of this day is the figure in the
    # budget less 5,500.
    #
    # The three cases that carry `unstable-api` (unstable, connectivity, admin-space) read about
    # 109,800 bytes more on pc2 once `zext_config_device_requires` (`device_requires.rs`, a
    # door of the unstable surface) joined: 934,049 to 1,043,866, 1,003,773 to 1,113,554 and
    # 1,159,421 to 1,269,025, and the five cases without `unstable-api` read about 1,100 more
    # (pico-client-coop 930,823 to 931,919), which the 5,500 holds. The attribution is by the
    # feature set (only the cases with `unstable-api` grew), not by a symbol diff; the likely
    # source is that the door reads a config's locators through `parse_any_locator`, the
    # grammar of every protocol the tree has, in client builds that parse only the dial's. The
    # budgets of the three move over that door (the 5,500 above them, as the rest), and
    # narrowing what the door parses to the build's protocols is the door's owner's (the
    # round's carry).
    # 2026-10-31 -- the cooperative cases, read again. Round 3958 moved nine budgets to the hosted
    # reading of run 41008974420 (head `c7f635944`, 05:32Z on 10-30) plus 3,500, and its note said
    # the pc2 and hosted readings had drifted 10,000 bytes apart. They had not. Hosted run
    # 41140796607 (head `c27afce98`) reads pico-client-coop at 940,723, and pc2 read 940,971 on a
    # tree between the two heads (937,467 at `04d21adb3`, `size` text of `cargo build --release
    # -p wz-capi-pico --no-default-features --features engine-coop,link-udp`; the C reference is
    # the same 404,694 on both days, and a GNU-ld build of the same tree reads 933,813, so the
    # linker is not it either). The 951,015 was the size of that one commit, which later work
    # took back out. Four cases (coop, -local, -scout, pico-peer-coop) read under their old
    # budgets again and have them back. Five grew for good, by the hosted reading of that run
    # plus 3,500, to the hundred: -unstable 1,053,690 (old 1,049,400), -connectivity 1,124,750
    # (1,123,900), -admin-space 1,297,697 (1,289,900), -query 1,239,868 (1,231,200) and
    # -local-queryable 1,258,240 (1,248,500). BISECTED on pc2 over the 104 commits that touch the
    # crates these images link, with `-query` (`engine-coop,link-udp,query,queryable`) as the
    # witness: 1,227,388 at `04d21adb3`, 1,225,064 at `62c3339c18`, then 1,248,756 at the very next
    # commit that touches them, `69bc0b0e0b` (the SCE pin b1ede72108, which declares which codecs
    # may refuse to encode: +23,692), and 1,239,572 at the head, the later pins having given 9,184
    # of it back. The five are the ones whose images encode through the codecs that now return a
    # Result, which is why the base `coop` image (937,467 to 940,971) hardly moved. What is left
    # (+12,184 over the baseline) is that refusal path, until the SCE tree lands the list bounds
    # and the gate normal form its pin note says are due.
    # 941,200 -> 949,300 with the first hosted run since round 4029 (head `133e48a08`, 955,495): the
    # reading less the 11,748 the alias table of the declaration registries no longer costs (a
    # `Vec`, where a `BTreeMap` made the registry's first reading 13,056 over the tree of round 4060
    # on this machine and the second 1,308) and 5,500, an estimate the next hosted run replaces. The
    # four cases below move the same way; the other coop cases fall back under their budgets.
    # 2026-11-02 -- six more cases over their budgets on hosted run 41411911409: -unstable 1,060,126,
    # -connectivity 1,131,210, -query 1,249,456, -local-queryable 1,268,472, -scout 1,025,278 and
    # pico-peer-coop 1,074,176, each moved to that reading plus 3,500, to the hundred. BISECTED on
    # the build machines with `-unstable` as the witness (`engine-coop,link-udp,unstable-api`):
    # 1,055,458 at `8e37dda152` (the last move of the budgets), 1,056,718 at `c4e9a65195` (the
    # link admission, +1,260), 1,056,726 at `da222d0afb` and at
    # `81e87c37f5`, then 1,059,750 at `4d50e0d1a8`, the last of the four SCE pin moves of the
    # day (lists held within bounds, flags the value says, gated fields grouped, Interest flags
    # are arms): +3,032, which is the generated codecs the pin regenerates, and the 2,900 the
    # two `unstable-api` cases were over. The tree at the head reads 1,059,886, 136 more, from
    # the later work on the session. The four cases without `unstable-api` were over by 156 to 478.
    # 2026-11-03 -- thirteen cases over their budgets on hosted run 41589047498 (head `d7dc86a826`),
    # the nine coop cases by 20,266 to 37,716, pico-peer by 25,017, pico-default by 8,818,
    # capic-client-small by 979 and capic-default by 32,222. BISECTED on one build host (hkl001)
    # with this case as the witness, over the 111 commits from round 4119 (the hosted run that last
    # read it under its budget) to the SCE pins: 946,919 at round 4119, 947,655 at round 4155,
    # 947,663 at round 4166 (`4032f0aa20`), then 982,807 at `85f794fa03` (the SCE pin c3d930c95c,
    # a document states the protocol's bound: +35,144) and 970,839 at `78e443084b` (the pin
    # 9619440966, the profile's numbers read from a deployment: -11,968), unmoved after. The
    # symbol diff of round 4166 against the head (`nm -C -S`, text, +20,336 net) puts it in two
    # places: `decode_one_record` 1,438 -> 18,628, which now holds the borrowed-to-owned
    # conversions of the arms it decodes (`Interest`, `Oam`, `Declare` and the others), and the
    # codecs' new shape (`MsgPutIn<Lent<Node>>::try_into_owned_in` 9,201 where `MsgPut`'s was
    # 6,782; the views' `decode_into`). The growth is the pin's codec shape, chosen with ADR 0077
    # (`owned_origin` and views for every codec), so each budget moves to the larger of the hosted
    # reading and the head's on hkl001 (which reads within 250 of it here) plus 3,500, to the
    # hundred. Whether moving those conversions out of `decode_one_record` takes any of it back is
    # not measured, and is the round's carry. The other cases were not bisected apart; the window
    # is the same, and every other commit in it moved the witness by 744 in all.
    # 2026-11-05 -- the nine coop cases over their budgets on hosted run 41884918361 (head
    # `82d5bf1e71`) by 293 to 2,304, each 4,472 to 4,916 over its own reading on hosted run
    # 41732702195 (`d20e5e2bd2`, the last C1cs run that measured: every run between failed to
    # build `AwaitRelease` unused, round 4233), the two query cases 9,232 and 9,248. Read on one
    # build host (pc3) from the crates of `d20e5e2bd2` and of the head: this case 970,623 ->
    # 975,087 (+4,464), `-query` 1,281,392 -> 1,290,640 (+9,248). The symbol diff (`nm -C -S`,
    # text) is wz-capi-pico's own code, all of it from `5f69859f65` (zenoh-pico's own API tests
    # run against wz): the release latches by which an undeclare and a close wait for the callbacks
    # in flight and the closure's drop, as pico's `_z_sync_group_wait` does (`ReleaseLatch`,
    # `LatchList`, `PicoSessionHandle::keep_background` +1,057, `z_close` +479), the batching
    # doors (`zp_batch_*`), and in the query cases a get's cancellation token
    # (`CancellationToken::cancel` +927). The growth is pico's undeclare and close contract,
    # chosen with that commit, so each coop budget moves to its hosted reading (the larger; pc3
    # reads this case 472 lower) plus 3,500, to the hundred.
    # 2026-11-20 -- step 4b round 2a, as pico-client's note of this day says: +512 on pc2, the
    # engine's registry held to the limits its open resolves (`resolve_limits`, `with_limits`)
    # and the build's `SessionLimits` it copies. Each coop case below moves by its own reading.
    # 2026-11-20 -- step 4b round 2b, as pico-client's note of this day says: +32 on pc2, the
    # engine registry's quota words; the query cases add the refusal a get and a queryable
    # return. Each coop case below moves by its own reading.
    # 2026-11-21 -- step 4b rounds 2 to 4, as pico-client's note of this day says: +15,600 on
    # one machine.
    # The single-threaded cooperative client as every pico library is built: on the host's own calls
    # without `std` (`os-host`; docs/win-budget/std-heap.md, S1: a C library has no `std` form), the
    # C library's heap and `abort` in its place, and no unwinding (`capi-nostd`, whose configuration
    # drops the unwind tables). The dated notes above read the same client built with `std`, a form
    # the crate no longer has; its row went with it, and this case is the client's own ceiling row.
    Case("pico-client-coop-nostd", "wz-capi-pico", "libwz_capi_pico.so", "os-host,link-udp",
         # 2026-11-28 -- set from its reading at `ce63a0f7bd` (GNU ld 2.42), 237,978 against
         # zenoh-pico's 329,664, by `budget_for`. The 1,049,200 it carried was pico-client-coop's
         # budget of 2026-11-21, taken when the case was added as a ceiling the form sat under
         # until its first reading set its own; no reading had replaced it.
         242_800,
         forbid=(ACCEPT, RESPONDER, SCOUTING, GOSSIP, CLOCK, ADVANCED, THREADED, CONNECTIVITY,
                 MULTICAST, TOKIO_ENGINE, COOP_LISTEN, STD_RUNTIME, KECCAK, LOG_FACADE, HEAP_ABORT),
         require=(UDP, SINGLE_THREADED, COOP_ENGINE),
         # 443 exports: `zext_callbacks_refused` (d80d315d1).
         exports=443, **NOSTD_RELEASE_FORM,
         note="Linked with its relative relocations packed, as pico-client-coop is, and so is "
              "its zenoh-pico reference: 1,590 relative relocations (38,160 bytes of "
              "`.rela.dyn`) in the form read on 2026-11-22, a packed table of 440. Linked "
              "with the prebuilt standard crates' unwind tables discarded (32,788 bytes of "
              "`.eh_frame` and `.eh_frame_hdr` in that form), and so is its reference, its C "
              "compiled with -fno-asynchronous-unwind-tables -fno-unwind-tables (72,096 bytes of "
              "tables in zenoh-pico's own build). "
              "pico-client-coop's capabilities and its 441 C exports, and `rust_eh_personality`: "
              "the prebuilt `core`'s unwind tables name it and LTO keeps the reference "
              "(measured: undefined in the first build, so no C program linked), so the library "
              "defines it, as an abort that nothing reaches (`src/os/no_std_host.rs`), and a "
              "`#[no_mangle]` item of a cdylib is exported. `_Unwind_Resume`, which the prebuilt "
              "crates' cleanup paths call, is defined too, local to the library and so not "
              "exported: left undefined, the C compiler's as-needed link mapped `libgcc_s` into "
              "every program of the library for that one name (docs/win-budget/rss.md, R4). "
              "No `critical-section` "
              "implementation: the locks are the host's own calls through `wz-host-sync`"),
    # The same client in the form the zenoh-pico preset ships once its axis of the moment names
    # on-use (`tables-on-use`): each table takes its memory at its first row and the open
    # reserves no arena, the state its one block. Its package, profile, configuration files,
    # exports and patterns are pico-client-coop-nostd's, and its features differ by the moment
    # alone, so the size ledger steps from that case to this one by `tables-on-use`.
    Case("pico-client-coop-nostd-on-use", "wz-capi-pico", "libwz_capi_pico.so",
         # 2026-11-28 -- set from its reading at `33bd90da25`, 240,432, by `budget_for`: the
         # first reading's 246,600 ratcheted down by the on-use bodies taken back since.
         "os-host,link-udp,tables-on-use", 245_300,
         forbid=(ACCEPT, RESPONDER, SCOUTING, GOSSIP, CLOCK, ADVANCED, THREADED, CONNECTIVITY,
                 MULTICAST, TOKIO_ENGINE, COOP_LISTEN, STD_RUNTIME, KECCAK, LOG_FACADE, HEAP_ABORT),
         require=(UDP, SINGLE_THREADED, COOP_ENGINE, ON_USE_ROWS),
         exports=443, **NOSTD_RELEASE_FORM,
         note="pico-client-coop-nostd with its tables on use: each allocation of the form answers "
              "a refusal as a value (the engine's claim, the state's block, the tables' first "
              "rows, a key's), so the allocator's abort is forbidden as it is there. Its first "
              "reading was 241,680 bytes of text, 0.73x zenoh-pico's, +3,702 over its D12 twin "
              "read in the same run; its budget is set from the later reading its comment states"),
    # The cooperative client with the unstable API, which the reference pico of the test lanes is
    # built with (`-DZ_FEATURE_UNSTABLE_API`): entity global ids, source info, cancellation
    # tokens. Nothing of it is the engine's, so it costs the ABI's own code and no engine's.
    # 2026-11-21 -- step 4b rounds 2 to 4, as pico-client's note of this day says: +15,672 on
    # one machine.
    Case("pico-client-coop-unstable", "wz-capi-pico", "libwz_capi_pico.so",
         # 2026-11-20 -- step 4b round 2a, as pico-client-coop's note says: +512 on pc2.
         # 2026-11-20 -- step 4b round 2b, as pico-client-coop's note says: +32 on pc2.
         # 2026-11-21 -- the fifth PoC set, as pico-client-coop's note says: +8,680 on one host.
         # 2026-11-22 -- the step 4b carry and run 44895098050's reading:
         # 1,159,413 hosted, +9,488 on one machine.
         "os-host,link-udp,unstable-api", 1_172_500,
         forbid=(ACCEPT, RESPONDER, SCOUTING, GOSSIP, CLOCK, ADVANCED, THREADED, CONNECTIVITY,
                 MULTICAST, TOKIO_ENGINE, COOP_LISTEN),
         require=(UDP, SINGLE_THREADED, COOP_ENGINE),
         profile="capi-nostd", cargo_configs=(NOSTD_CONFIG,),
         note="the pico-client-coop build with the unstable API: 894,893 measured against its "
              "891,491, 2.21 times the same pico (404,880), and 448 exports against its 441. "
              "916,041 on pc2 on 2026-10-26 against 902,337 before the slot observer "
              "(+13,704, as pico-client-coop's). 933,285 on pc2 on 2026-10-27 against 916,041 "
              "before the table of faces (+17,244, as pico-client-coop's). 938,109 on pc2 on "
              "2026-10-27, 2,109 over the old budget of 936,000; moved as pico-client-coop's, "
              "to the pc2 reading and 5,500"),
    # The cooperative client that delivers a put to its own subscribers
    # (`Z_FEATURE_LOCAL_SUBSCRIBER`), which the reference pico of the test lanes is not built with
    # but a program that publishes and subscribes on one session needs.
    # 2026-11-21 -- step 4b rounds 2 to 4, as pico-client's note of this day says: +15,508 on
    # one machine.
    Case("pico-client-coop-local", "wz-capi-pico", "libwz_capi_pico.so",
         # 2026-11-20 -- step 4b round 2a, as pico-client-coop's note says: +496 on pc2.
         # 2026-11-20 -- step 4b round 2b, as pico-client-coop's note says: +32 on pc2.
         # 2026-11-21 -- the fifth PoC set, as pico-client-coop's note says: +8,524 on one host.
         # 2026-11-22 -- the step 4b carry and run 44895098050's reading:
         # 1,054,174 hosted, +9,592 on one machine.
         "os-host,link-udp,local-subscriber", 1_067_300,
         forbid=(ACCEPT, RESPONDER, SCOUTING, GOSSIP, CLOCK, ADVANCED, THREADED, CONNECTIVITY,
                 MULTICAST, TOKIO_ENGINE, COOP_LISTEN),
         require=(UDP, SINGLE_THREADED, COOP_ENGINE),
         profile="capi-nostd", cargo_configs=(NOSTD_CONFIG,),
         note="the pico-client-coop build that delivers a put to its own subscribers: 898,019 "
              "measured against its 891,519, 2.22 times the same pico (405,414). 919,291 on pc2 "
              "on 2026-10-26 against 905,671 before the slot observer (+13,620, as "
              "pico-client-coop's). 937,779 on pc2 on 2026-10-27 against 919,291 before the "
              "table of faces (+18,488). 942,603 on pc2 on 2026-10-27, 2,103 over the old "
              "budget of 940,500; moved as pico-client-coop's, to the pc2 reading and 5,500"),
    # The cooperative client with the connectivity plane (`Z_FEATURE_CONNECTIVITY`): the listing
    # of its transports and links and the listeners that hear them come and go. The engine reports
    # its faces whatever the build, so the plane's own cost is the ABI's.
    # 2026-11-21 -- step 4b rounds 2 to 4, as pico-client's note of this day says: +15,580 on
    # one machine.
    Case("pico-client-coop-connectivity", "wz-capi-pico", "libwz_capi_pico.so",
         # 2026-11-20 -- step 4b round 2a, as pico-client-coop's note says: +644 on pc2.
         # 2026-11-20 -- step 4b round 2b, as pico-client-coop's note says: +32 on pc2.
         # 2026-11-21 -- the fifth PoC set, as pico-client-coop's note says: +8,572 on one host.
         # 2026-11-22 -- the step 4b carry and run 44895098050's reading:
         # 1,229,265 hosted, +9,580 on one machine.
         "os-host,link-udp,unstable-api,connectivity", 1_242_400,
         forbid=(ACCEPT, RESPONDER, SCOUTING, GOSSIP, CLOCK, ADVANCED, THREADED, MULTICAST,
                 TOKIO_ENGINE, COOP_LISTEN),
         require=(UDP, SINGLE_THREADED, COOP_ENGINE, CONNECTIVITY),
         profile="capi-nostd", cargo_configs=(NOSTD_CONFIG,),
         note="the pico-client-coop build with the unstable API and the connectivity plane: "
              "950,729 measured against the unstable build's 882,019, 2.16 times the same pico "
              "(439,791), and 563 exports against its 448. 985,013 on pc2 on 2026-10-26 "
              "against 971,165 before the slot observer (+13,848, as pico-client-coop's). "
              "1,002,849 on pc2 on 2026-10-27 against 985,013 before the table of faces (+17,836). 1,007,877 on pc2 on 2026-10-27, 2,377 over "
              "the old budget of 1,005,500; moved as pico-client-coop's, to the pc2 reading "
              "and 5,500"),
    # The cooperative client with pico's admin space (`Z_FEATURE_ADMIN_SPACE`): the queryable that
    # answers `@/<zid>/pico/**`, which needs the answering end and, for the peers it lists, the
    # engine's faces. It lists no connectivity listener, so that plane's exports stay out.
    # 2026-11-21 -- step 4b rounds 2 to 4, as pico-client's note of this day says: +15,921 on
    # one machine.
    Case("pico-client-coop-admin-space", "wz-capi-pico", "libwz_capi_pico.so",
         # 2026-11-20 -- step 4b round 2a, as pico-client-coop's note says: +460 on pc2.
         # 2026-11-20 -- step 4b round 2b, as pico-client-coop's note says: +128 on pc2.
         # 2026-11-21 -- the fifth PoC set, as pico-client-coop's note says: +8,429 on one host.
         # 2026-11-22 -- the step 4b carry and run 44895098050's reading:
         # 1,420,192 hosted, +10,054 on one machine.
         "os-host,link-udp,admin-space", 1_433_800,
         forbid=(ACCEPT, RESPONDER, SCOUTING, GOSSIP, CLOCK, ADVANCED, THREADED, CONNECTIVITY,
                 MULTICAST, TOKIO_ENGINE, COOP_LISTEN),
         require=(UDP, SINGLE_THREADED, COOP_ENGINE),
         profile="capi-nostd", cargo_configs=(NOSTD_CONFIG,),
         note="the pico-client-coop build with the answering end, the unstable API and the "
              "admin space: 1,091,379 measured, 2.46 times the same pico (444,284), and 493 "
              "exports. 1,115,141 on the bench host on 2026-10-26 against 1,114,729 at the "
              "commit before (a7f11d66e), measured on the same host in both orders: +412 for "
              "the engine's delivery and answering sets held under the port's lock instead of "
              "in thread-locals, which an MCU kernel gives a Rust image none of "
              "(docs/upstream-parity.md section 5a, E1); the budget moves over that reading. "
              "1,139,989 on pc2 on 2026-10-26 against that 1,115,141 before the slot observer "
              "(+24,848): the +13,704 of pico-client-coop's note and about 11,000 more in "
              "the builds that answer queries (the next two cases read +9,500 and +9,000 over "
              "the client's), which the symbol diff of the client build cannot say and which "
              "is not yet attributed. 1,157,649 on pc2 on 2026-10-27 against 1,139,989 before the "
              "table of faces (+17,660, as pico-client-coop's). 1,160,937 on hosted CI on "
              "2026-10-27 (head `f4bdeaee5`), which reads about 3,300 over pc2 as the earlier "
              "hosted figures did; the budget follows the hosted reading, which is the gate's. "
              "1,163,845 on pc2 on 2026-10-27 with the listening role (pico-client-coop's "
              "note), +6,196 over the reading before it; moved to the pc2 reading and 5,500, "
              "an estimate the first hosted run replaces. 1,279,229 on hosted CI on 2026-10-27 "
              "(head `e6d953fc2`), the first hosted reading since the listening role: 8,200 "
              "over pc2's 1,271,029, where the cases without the query plane read 800 over; "
              "the budget follows the hosted reading and 3,500"),
    # The cooperative client that asks and answers queries: the requesting end and the answering
    # end, which is what the next case adds its loopback leg to.
    # 2026-11-19 -- step 3b (pico-client's note of this day): the targeted get folds on the
    # domain, so it is linked; +2,732 on pc2, by symbol `issue_get` +1,454 and
    # `zext_get_to_peer` +314, the leg reply moved out of `fan_get` (+2,934 / -2,917).
    # 2026-11-21 -- step 4b rounds 2 to 4, as pico-client's note of this day says: +16,320 on
    # one machine.
    Case("pico-client-coop-query", "wz-capi-pico", "libwz_capi_pico.so",
         # 2026-11-20 -- step 4b round 2a, as pico-client-coop's note says: +492 on pc2.
         # 2026-11-20 -- step 4b round 2b, as pico-client-coop's note says: +136 on pc2.
         # 2026-11-21 -- the fifth PoC set, as pico-client-coop's note says: +8,868 on one host.
         # 2026-11-22 -- the step 4b carry and run 44895098050's reading:
         # 1,373,248 hosted, +10,300 on one machine.
         "os-host,link-udp,query,queryable", 1_387_100,
         forbid=(ACCEPT, RESPONDER, SCOUTING, GOSSIP, CLOCK, ADVANCED, THREADED, CONNECTIVITY,
                 MULTICAST, TOKIO_ENGINE, COOP_LISTEN),
         require=(UDP, SINGLE_THREADED, COOP_ENGINE),
         profile="capi-nostd", cargo_configs=(NOSTD_CONFIG,),
         note="the pico-client-coop build with the requesting and answering ends of a query: "
              "1,137,368 measured against pico-client-coop's 875,843, 2.60 times the same pico "
              "(437,624), and 541 exports against its 441. 1,161,344 on 2026-10-25, with the "
              "growth of pico-client-coop above. 1,186,508 on pc2 on 2026-10-26 against "
              "1,163,252 before the slot observer (+23,256, see the admin-space case). 1,207,600 "
              "on 2026-10-27 against 1,186,508 before the table of faces (+21,092: a get is one "
              "leg for each face and one for the session's own queryables, issued in two loops). "
              "1,210,960 on hosted CI on 2026-10-27 (head `f4bdeaee5`), the hosted reading the "
              "budget follows. 1,213,796 on pc2 on 2026-10-27 with the listening role "
              "(pico-client-coop's note), +6,196 over the reading before it; moved to the pc2 "
              "reading and 5,500, an estimate the first hosted run replaces. 1,221,476 on "
              "hosted CI on 2026-10-27 (head `e6d953fc2`), 8,240 over pc2's 1,213,236; the "
              "budget follows the hosted reading and 3,500"),
    # The same, with a get delivered to the session's own queryables
    # (`Z_FEATURE_LOCAL_QUERYABLE`), which a program that asks its own queryable needs.
    # 2026-11-19 -- step 3b, the targeted get of the previous case's note: +2,764 on pc2.
    # 2026-11-21 -- step 4b rounds 2 to 4, as pico-client's note of this day says: +16,284 on
    # one machine.
    Case("pico-client-coop-local-queryable", "wz-capi-pico", "libwz_capi_pico.so",
         # 2026-11-20 -- step 4b round 2a, as pico-client-coop's note says: +492 on pc2.
         # 2026-11-20 -- step 4b round 2b, as pico-client-coop's note says: +76 on pc2.
         # 2026-11-21 -- the fifth PoC set, as pico-client-coop's note says: +8,304 on one host.
         # 2026-11-22 -- the step 4b carry and run 44895098050's reading:
         # 1,389,476 hosted, +10,324 on one machine.
         "os-host,link-udp,query,queryable,local-queryable", 1_403_300,
         forbid=(ACCEPT, RESPONDER, SCOUTING, GOSSIP, CLOCK, ADVANCED, THREADED, CONNECTIVITY,
                 MULTICAST, TOKIO_ENGINE, COOP_LISTEN),
         require=(UDP, SINGLE_THREADED, COOP_ENGINE),
         profile="capi-nostd", cargo_configs=(NOSTD_CONFIG,),
         note="the pico-client-coop-query build with the get delivered to the session's own "
              "queryables: 1,151,161 measured against its 1,137,368 (+13,793), 2.62 times the "
              "same pico (440,160). 1,175,052 on 2026-10-25, the same growth. 1,199,576 on pc2 "
              "on 2026-10-26 against 1,176,860 before the slot observer (+22,716). 1,224,096 on "
              "2026-10-27 against 1,199,576 before the table of faces (+24,520: the session's own "
              "leg is a leg of its own). 1,227,456 on hosted CI on 2026-10-27 (head "
              "`f4bdeaee5`), the hosted reading the budget follows. 1,230,320 on pc2 on "
              "2026-10-27 with the listening role (pico-client-coop's note), +6,224 over the "
              "reading before it; moved to the pc2 reading and 5,500, an estimate the first "
              "hosted run replaces. 1,238,764 on hosted CI on 2026-10-27 (head `e6d953fc2`), "
              "8,724 over pc2's 1,230,040; the budget follows the hosted reading and 3,500"),
    # The cooperative client that scouts (`Z_FEATURE_SCOUTING`): `z_scout`, and the lookup `z_open`
    # runs when its config names no locator, over the engine's own window and no tokio engine.
    # 2026-11-21 -- step 4b rounds 2 to 4, as pico-client's note of this day says: +15,560 on
    # one machine.
    Case("pico-client-coop-scout", "wz-capi-pico", "libwz_capi_pico.so",
         # 2026-11-20 -- step 4b round 2a, as pico-client-coop's note says: +512 on pc2.
         # 2026-11-20 -- step 4b round 2b, as pico-client-coop's note says: +32 on pc2.
         # 2026-11-21 -- the fifth PoC set, as pico-client-coop's note says: +8,660 on one host.
         # 2026-11-22 -- the step 4b carry and run 44895098050's reading:
         # 1,131,749 hosted, +9,444 on one machine.
         "os-host,link-udp,scout", 1_144_700,
         forbid=(ACCEPT, RESPONDER, SCOUTING, GOSSIP, CLOCK, ADVANCED, THREADED, CONNECTIVITY,
                 MULTICAST, TOKIO_ENGINE, COOP_LISTEN),
         require=(UDP, SINGLE_THREADED, COOP_ENGINE, COOP_SCOUT),
         profile="capi-nostd", cargo_configs=(NOSTD_CONFIG,),
         note="the pico-client-coop build with the scouting window: 961,479 measured against "
              "pico-client-coop's 875,843 (+85,636), 2.34 times the same pico (410,391), and 464 "
              "exports. 981,698 measured on pc2 on 2026-10-26 against the earlier 981,000 budget; "
              "the same host read 987,023, 985,903, 985,879 and 981,698 at four successive "
              "commits, so the ceiling is moved to the latest reading with 1,302 of room. "
              "994,918 on pc2 on 2026-10-26 against 981,182 before the slot observer (+13,736, "
              "as pico-client-coop's, whose note holds the symbol diff of this very build). "
              "1,012,138 on pc2 on 2026-10-27 against 994,918 before the table of faces (+17,220). "
              "1,016,562 on hosted CI on 2026-10-27 (head `f4bdeaee5`), the hosted reading the "
              "budget follows. 1,019,354 on pc2 on 2026-10-27 with the listening role "
              "(pico-client-coop's note), +7,216 over the reading before it; moved to the pc2 "
              "reading and 5,500, an estimate the first hosted run replaces"),
    # The cooperative peer (`peer` with no tokio engine): the client of pico-client-coop that also
    # listens on a `tcp/` endpoint and takes each inbound link as a face of its session
    # (`docs/capi-pico-on-coop-engine.md`, step L4).
    # 2026-11-21 -- step 4b rounds 2 to 4, as pico-client's note of this day says: +15,340 on
    # one machine.
    Case("pico-peer-coop", "wz-capi-pico", "libwz_capi_pico.so",
         # 2026-11-20 -- step 4b round 2a, as pico-client-coop's note says: +508 on pc2.
         # 2026-11-20 -- step 4b round 2b, as pico-client-coop's note says: +48 on pc2.
         # 2026-11-21 -- the fifth PoC set, as pico-client-coop's note says: +8,788 on one host.
         # 2026-11-22 -- the step 4b carry and run 44895098050's reading:
         # 1,195,275 hosted, +9,544 on one machine.
         "os-host,link-udp,peer", 1_208_400,
         forbid=(ACCEPT, RESPONDER, SCOUTING, GOSSIP, CLOCK, ADVANCED, THREADED, CONNECTIVITY,
                 MULTICAST, TOKIO_ENGINE),
         require=(UDP, SINGLE_THREADED, COOP_ENGINE, COOP_SCOUT, COOP_LISTEN),
         profile="capi-nostd", cargo_configs=(NOSTD_CONFIG,),
         note="the pico-client-coop-scout build with the listening role, which `peer` brings "
              "with the scouting window: 1,057,120 measured on pc2 on 2026-10-27, 2.54 times the "
              "same pico (415,527), and 464 exports, as the scout build's. The budget is that "
              "reading and 5,500, the margin of the cooperative cases above, an estimate of the "
              "hosted reading that the first hosted run replaces. 1,058,200 on pc2 after the "
              "peers' commits of 2026-10-27 joined, and 1,063,560 with the session holding one "
              "face for each remote zid (the admission, the displacement and the dial role "
              "standing by, which only a build that listens carries): +5,360, and the budget "
              "moved to that reading and 5,500. 1,064,448 with the gate that gives a link's "
              "session nothing between its handshake and the decision (+888), the budget "
              "moved to that reading and 5,500 again"),
    # The like-for-like library of the Windows release (`pico_windows_package.LIKE_PROFILE`, the
    # release profile without wz's own doors, whose rows are `pico-api-windows-<width>`) built on
    # Linux in the release client's form, so its bytes are read area by area by the size ledger,
    # where a DLL's are not. Its features are that profile's, resolved when it is built:
    # zenoh-pico's default build (the peer role, the multicast transport, the multi-threaded arm)
    # with the advanced plane, the unstable API and connectivity, so its planes are held as
    # pico-default's are.
    Case("pico-api-coop-nostd", "wz-capi-pico", "libwz_capi_pico.so", None, 1_056_200,
         forbid=(SINGLE_THREADED, ACCEPT, RESPONDER, SCOUTING, GOSSIP, TOKIO_ENGINE, KECCAK,
                 STD_RUNTIME),
         require=(UDP, THREADED, CONNECTIVITY, COOP_ENGINE, COOP_SCOUT, COOP_LISTEN),
         **NOSTD_RELEASE_FORM, features_from=pico_windows_package.LIKE_PROFILE,
         note="pico-client-coop-nostd's form (NOSTD_RELEASE_FORM: the profile, the configuration "
              "files, the run-text layout among them, and the names it leaves undefined and "
              "needs) with the features of the library pico_windows_package.py --size-features "
              "builds first, so the two lanes build one feature set, each on its own platform. No "
              "budget and no ceiling row until the first reading: --measure prints both"),
    # 2026-11-03 -- `pico-peer` 2,946,185 on hosted run 41481900203, 185 over its budget of
    # 2,946,000, which the 2026-11-02 move of the coop cases had not reached; moved to that reading
    # plus 3,500, to the hundred. The growth is the day's, as the coop cases' was (the SCE pin
    # moves of 11-02, which regenerate the codecs this image links); it is not separated further.
    # 2026-11-03, later -- 2,949,477 on a build host (hkl002) with the order fence on the lanes, the
    # scouting ask socket of its own and the peers' commits of the day, against 2,945,401 on that
    # host at the hosted reading's head; the hosted run reads about 780 above that host, so the
    # hosted reading is about 2,950,300 and the budget is that and 3,500, to the hundred.
    # 2026-11-03, the SCE pins -- 2,978,817 on hosted run 41589047498 (2,978,017 on hkl001 at the
    # head), the growth pico-client-coop's note of this day attributes; that and 3,500.
    # 2026-11-15 -- the face loop's heartbeat and the watcher that reports a loop that stopped
    # (`wz_runtime_tokio::liveness`). The symbol diff of this build (hkl002, the head against
    # `c42ab17ced`) put 19 KB of the first form's growth in the float formatter its report linked,
    # and 3 KB in a sort; both were taken out (whole milliseconds, threads in the kernel's order).
    # What stays is the watcher's thread and its look, the `/proc` reading, the start and join of
    # the thread and the face loop's beat: 2,985,705 -> 3,016,571 on pc2 (+30,866). Chosen growth,
    # a node that accepts reports its own stop; the budget is the hosted reading at `c42ab17ced`
    # (2,989,197) and that growth, 3,020,063, and 3,500, to the hundred.
    # 2026-11-18 -- the egress-policy answer, as pico-client's note of this day says: 3,130,907
    # hosted at `d8f187dddc` and +3,132 on pc2.
    # 2026-11-19 -- step 3b, as pico-client's note of this day says: +21,764 on pc2.
    # 2026-11-20 -- step 4b round 2a, as pico-client's note of this day says: +1,136 on pc2.
    # 2026-11-20 -- step 4b round 2b, as pico-client's note of this day says: +48 on pc2.
    # 2026-11-20 -- the hosted reading again, as pico-client's note of this day says: 3,206,730
    # at `cd240d4b4` and +9,128 since.
    # 2026-11-21 -- step 4b rounds 2 to 4, as pico-client's note of this day says: +13,680 on
    # one machine.
    # 2026-11-23 -- one session drive, dial and open for every caller, as pico-client's note of
    # this day says: -28,336 on one machine; the budget moves by it and keeps its headroom.
    Case("pico-peer", "wz-capi-pico", "libwz_capi_pico.so", PICO_BASE + ",peer", 3_218_864,
         # 2026-11-22 -- the step 4b carry and run 44895098050's reading:
         # 3,241,530 hosted, +2,124 on one machine.
         # 2026-11-25 -- the crate's default and the pico base name the cooperative engine (P1 of
         # docs/c-abi-engine-and-memory.md): this case builds on it, and its budget and row are the
         # tokio engine's until the first reading on it moves them.
         forbid=(ACCEPT, RESPONDER, SCOUTING, GOSSIP, CLOCK, ADVANCED, THREADED, CONNECTIVITY,
                 MULTICAST, TOKIO_ENGINE, KECCAK),
         require=(UDP, SINGLE_THREADED, COOP_ENGINE, COOP_SCOUT, COOP_LISTEN),
         profile="capi-nostd", cargo_configs=(NOSTD_CONFIG,),
         note="peer implies scout and with it the UDP group"),
    # 2026-11-03, the SCE pins -- 4,356,318 on hosted run 41589047498 (4,355,414 on hkl001 at the
    # head), the growth pico-client-coop's note of this day attributes; that and 3,500.
    # 2026-11-05 -- 4,373,066 on hosted run 41884918361 (`82d5bf1e71`), 20,852 over its reading at
    # `d20e5e2bd2`; on pc3 4,348,530 -> 4,369,394 from the crates of the two. The symbol diff:
    # wz-capi-core's multicast faces from `5f69859f65` (a group liveliness subscriber declared on
    # the wire and replayed to a face that comes up: `declare_liveliness_subscriber_on_wire`
    # +6,034, `mcast_face_up` +3,235, `faces::multicast::listen_on` +1,594, the subscriber map's
    # sort and B-tree), the same commit's release latches and advanced miss listeners (the coop
    # note above), and `436683e036`'s open handoff (`handoff::Reporter`) and runtime pool. Chosen
    # growth, so the budget is the hosted reading and 3,500, to the hundred.
    # 2026-11-15 -- the loops' heartbeats and their watcher, as `pico-peer`'s note of this day
    # takes apart: 4,420,270 -> 4,451,052 on pc2 (+30,782). Chosen; the hosted reading at
    # `c42ab17ced` (4,423,858) and that growth, 4,454,640, and 3,500, to the hundred.
    # 2026-11-17 -- hosted run 43914611055 (`65ec9acd16`) read 4,592,024, 1,124 over. On pc2 the
    # budget's own tree (`4ef678910d`) reads 4,583,800 and `65ec9acd16` 4,588,276 (+4,476). The
    # symbol diff by owning module: the dialled handshake held to `open_timeout` alone
    # (`wz_capi_core::drive` +2,703, `accept_loop::dial_face` +897), the receive pool's settle
    # (`frame_arena` +842), the handshake ext chains staged in upstream's order (`ext_chain`
    # +522); the multicast member table's strategy type nets to nothing (`multicast_glue`
    # +1,564, `multicast_dispatch` -1,606). Chosen growth; the hosted reading and 3,500.
    # 2026-11-19 -- step 3b, as pico-client's note of this day says: +26,704 on pc2.
    # 2026-11-20 -- the three pico internals clang emits calls to into every program of the unstable
    # arm (`header_internals`): +465 of text on pc2 (`2df58c881` 4,681,351 against the fix's
    # 4,681,816), and the symbol diff is those three functions alone (+149: `_z_cancellation_
    # token_clear` 123, `_remove_on_cancel_handler` 14, `_z_sync_group_notifier_drop` 12). Chosen
    # growth; the budget moves by it, to the hundred.
    # 2026-11-20 -- step 4b round 2a, as pico-client's note of this day says: +1,372 on pc2.
    # 2026-11-20 -- step 4b round 2b, as pico-client's note of this day says: +1,948 on pc2.
    # 2026-11-20 -- the hosted reading again, as pico-client's note of this day says: 4,685,692
    # at `cd240d4b4` and +26,144 since.
    # 2026-11-21 -- step 4b rounds 2 to 4, as pico-client's note of this day says: +17,224 on
    # one machine.
    # 2026-11-23 -- one session drive, dial and open for every caller, as pico-client's note of
    # this day says: -12,768 on one machine; the budget moves by it and keeps its headroom.
    Case("pico-default", "wz-capi-pico", "libwz_capi_pico.so", None, 4_739_032,
         # 2026-11-22 -- the step 4b carry and run 44895098050's reading:
         # 4,740,260 hosted, +8,024 on one machine.
         # 2026-11-25 -- the crate's default and the pico base name the cooperative engine (P1 of
         # docs/c-abi-engine-and-memory.md): this case builds on it, and its budget and row are the
         # tokio engine's until the first reading on it moves them.
         # Gossip is off in the preset (decision Q7), and the tokio engine's own planes (its
         # accept loop, responder and scouting glue) are not linked.
         forbid=(SINGLE_THREADED, ACCEPT, RESPONDER, SCOUTING, GOSSIP, TOKIO_ENGINE, KECCAK,
                 STD_RUNTIME),
         require=(UDP, THREADED, CONNECTIVITY, COOP_ENGINE, COOP_SCOUT, COOP_LISTEN),
         profile="capi-nostd", cargo_configs=(NOSTD_CONFIG,),
         # 814 exports: `zext_session_step`, the step of a session opened without its read task,
         # which the multi-threaded arm has. 813 with `zext_callbacks_refused` (d80d315d1) and
         # `rust_eh_personality`, which the library without `std` defines (pico-client-coop-nostd's
         # note).
         exports=814,
         note="every capability on: the symbol count is the drop-in's. 811 with the three pico "
              "internals clang emits calls to into every program of the unstable arm "
              "(`header_internals`: `_z_cancellation_token_clear`, "
              "`_z_cancellation_token_remove_on_cancel_handler`, `_z_sync_group_notifier_drop`). "
              "808 with the config "
              "doors of the open's policies (`zext_config_policy`, `zext_config_profile`; "
              "`zext_config_document` is behind `config-document`, off). 806 with the door that "
              "tells a session's peers its declarations again (`zext_redeclare`, unstable "
              "surface). 809 -> 802 when the "
              "seven single-threaded entry points left the multi-threaded arm; 804 with the "
              "conformance digest's door (`zext_conformance_digest`, decision C15); 803 with the "
              "door that answers what a configuration asks of the operating system "
              "(`zext_config_device_requires`); 805 with the get addressed to one node "
              "(`zext_get_to_peer`, in every build with the query plane). 4,216,542 "
              "measured with the multicast transport pico's default has (open-debt item 913), "
              "3,790,610 without it. 4,301,320 measured locally on the head of the round that "
              "ends the queries pending on a face with it (1,320 over 4,300,000), the growth "
              "pico-client-small's note states: the budget is that reading and 3,500, rounded "
              "up to the hundred. 4,340,654 on hosted CI on 2026-10-29 (head `017e3c711`) and "
              "4,343,962 on a build machine on the tree of round 3939: the local readings run "
              "under the hosted ones (capic-default's note), so the budget is the build "
              "machine's reading and 3,500, to the hundred"),
    # 2026-11-21 -- step 4b rounds 2 to 4, as pico-client's note of this day says: +18,362 on
    # one machine.
    # 2026-11-23 -- one session drive, dial and open for every caller, as pico-client's note of
    # this day says: +3,448 on one machine; the budget moves by it and keeps its headroom.
    Case("capic-client","wz-capi-c", "libwz_capi_c.so", "", 3_021_848,
         forbid=(ACCEPT, RESPONDER, SCOUTING, GOSSIP, UDP, CLOCK, ADVANCED, MULTICAST,
                 ROUTER_NODE, ACCEPT_HANDSHAKE, CONFIG_VERDICT),
         # The tokio engine's own marks, which the pico client required while its default was that
         # engine: the zenoh-c drop-in still runs on it, with zenoh's derivation of the initial
         # sequence number and the runtime's `log` facade. It links `std`, so it is the control of
         # the standard library's runtime and of the allocator's abort, which every pico case forbids
         # or leaves out now that the pico C library has no `std` form.
         require=(TOKIO_ENGINE, KECCAK, LOG_FACADE, STD_RUNTIME, HEAP_ABORT)),
    # 2026-11-03, the SCE pins -- 1,974,779 on hosted run 41589047498 (1,973,891 on hkl001 at the
    # head), the growth pico-client-coop's note of this day attributes; that and 3,500.
    # 2026-11-21 -- step 4b rounds 2 to 4, as pico-client's note of this day says: +19,522 on
    # one machine.
    # 2026-11-23 -- one session drive, dial and open for every caller, as pico-client's note of
    # this day says: +2,828 on one machine; the budget moves by it and keeps its headroom.
    Case("capic-client-small", "wz-capi-c", "libwz_capi_c.so", "", 2_009_228,
         forbid=(ACCEPT, RESPONDER, SCOUTING, GOSSIP, UDP, CLOCK, ADVANCED, MULTICAST,
                 ROUTER_NODE, ACCEPT_HANDSHAKE, CONFIG_VERDICT),
         profile="capi-small",
         note="the capic-client build with panics aborting: 1,797,992 measured against "
              "capic-client's 2,172,515 (-17.2%). 1,839,572 on hosted CI on 2026-10-27 (head "
              "`f4bdeaee5`), over the earlier budget of 1,834,000 by 5,572. 1,875,160 on hosted "
              "CI (run 40482567212, head `36f037a6b`) and 1,874,448 on pc2: +35,588 over "
              "`f4bdeaee5` while no pico lane moved, so it is the C ABI's own growth in "
              "between (the accept bounds, `dc42cd9a7`, and the lifecycle verbs served on the "
              "fixed node, `c0e98be2d` to `bcb8c1c57`) and not a build that changed. "
              "1,921,843 on hosted CI at `23c300730` (571 exports against 570), +46,683 in the "
              "step that added the door that answers what a configuration asks of the "
              "operating system (`wz_capi_c_config_device_requires`, `0a85b8692`: the plan "
              "`z_open` runs and the requirement derived from it, linked into a client "
              "build); 1,923,539 at `bbd53d1ea` and 1,923,619 on hosted CI at `e6d953fc2`. "
              "The attribution is from the hosted readings of those heads, not a symbol diff. "
              "The budget follows the hosted reading and 3,500 of margin. "
              "1,938,355 measured on a local checkout at `d8995bc4f1` (the gateway/south key "
              "honoured on a peer and a router hat: +13,606 over its parent's 1,924,749, the "
              "config reader a client links), and 1,939,048 with the receive of a reply on "
              "arrival (`dd83d5f01`) and the forwarders' route record behind it (+693). The "
              "budget is that reading and 3,500, rounded up to the hundred. Whether to shrink the "
              "reader instead of accepting the growth was not put to the owner of `d8995bc4f1`, "
              "whom no session could name: the budget moves so that the gate says something "
              "else, and the question stays open. 1,954,049 measured locally with the QoS "
              "overwrite of `qos/network` (the interceptor, the reader of the key and the "
              "rewrite the session applies): +11,880 over the 1,942,169 the parent measured. "
              "The budget is that reading and 3,500, rounded up to the hundred. 1,959,369 "
              "with the mutual-TLS and server-name keys of the tls link read and the quic "
              "link taking them (+5,320): 1,962,900 with the margin. 1,965,443 measured "
              "locally on 2026-10-30 (+6,074 since, 2,543 of it past that margin): the "
              "`region_name` key a client reads and announces in its Init, and the partition "
              "of `gateway/south` the plan now carries to the stance, which the node "
              "applies and a client only holds. The budget is that reading and 3,500, "
              "rounded up to the hundred: 1,969,000. 1,970,277 measured locally on the head "
              "of the round that ends the queries pending on a face with it (1,277 over): "
              "the head under it was not measured here, so what is that round's and what the "
              "earlier rounds' is not separated, and the budget is that reading and 3,500, "
              "rounded up to the hundred. 1,979,119 measured on a build machine (hkl002) on "
              "2026-11-04 at `b01d6bc9dd` (819 over 1,978,300, +4,340 over the hosted reading "
              "of 1,974,779 the budget was set from): the session handle of the C ABI, which "
              "holds the registry of faces or a node and which every operation of this ABI "
              "reads through, is in every build that holds a session, and is the likely "
              "growth; it was not bisected, and a symbol diff would be needed to say so. The "
              "budget is that reading and 3,500, rounded up to the hundred."),
    # 2026-11-21 -- step 4b rounds 2 to 4, as pico-client's note of this day says: +20,209 on
    # one machine.
    # 2026-11-23 -- one session drive, dial and open for every caller, as pico-client's note of
    # this day says: +13,988 on one machine; the budget moves by it and keeps its headroom.
    Case("capic-scout", "wz-capi-c", "libwz_capi_c.so", "scout", 3_309_288,
         forbid=(ACCEPT, RESPONDER, GOSSIP, CLOCK, ADVANCED, MULTICAST, ROUTER_NODE),
         require=(SCOUTING, UDP)),
    # 2026-11-21 -- step 4b rounds 2 to 4, as pico-client's note of this day says: +20,448 on
    # one machine.
    # 2026-11-23 -- one session drive, dial and open for every caller, as pico-client's note of
    # this day says: -23,996 on one machine; the budget moves by it and keeps its headroom.
    Case("capic-peer", "wz-capi-c", "libwz_capi_c.so", "peer", 4_061_504,
         forbid=(GOSSIP, CLOCK, ADVANCED, MULTICAST, ROUTER_NODE),
         require=(ACCEPT, RESPONDER, SCOUTING, UDP)),
    # The C ABI as a node (`router-node`, which implies `peer` and the query and liveliness
    # planes): the router data plane behind a session handle, which no build without the feature
    # links (the forbid of the cases above and of capic-default). 5,735,886 text and 743 exports
    # measured on a build machine (hkl002) on 2026-11-04 at `b01d6bc9dd`, the first reading of
    # it: against capic-peer's 3,425,868 and 591, the node, the query and liveliness planes the
    # feature implies, and their doors. The budget is that reading and 3,500, rounded up to the
    # hundred. The first build of this case did not compile: the node used the interceptors'
    # `install_on` and the gossip policy's autoconnect fields without their features.
    # 2026-11-05 -- 5,795,873 text and 743 exports on a build machine (hkl002) at `0c7298a48d`,
    # 56,473 over the budget and 59,987 over its first reading (5,735,886, 2026-11-04). The growth
    # was NOT split: the build at the one commit between the two SCE pin moves of the day and the
    # node's engine (`900984dbf2`) does not compile (`session_state` is unused in this feature
    # set there; `b67b3440cf` made it conditional), so no reading stands between them, and
    # `capic-default`'s note shows what the pin moves alone put into a build that links the
    # generated codec. What the node added since the first reading: the engine port
    # (`SessionEngine` for the node, `PeriodicJob`), the face source of the listings and listeners,
    # the shared-memory provider and the clock a node holds, and the doors read through the
    # session handle. Chosen growth, so the budget is that reading and 3,500, to the hundred.
    # The same day, 29,492 more on the same machine from `0c7298a48d` to `6dc6c68d9c` (5,825,365),
    # which `capic-default` grew by the same amount (29,412) over the same commits: the only commit
    # of them that changes code is `2274c65e57` (a record read in the lent form at the heap's
    # capacity, another session's), so the growth is its, by that and not by a reading at that
    # commit. The budget is the reading of `6dc6c68d9c` and 3,500, to the hundred.
    # 2026-11-06, later -- hosted run 42161910521 (`b65f96aff6`) read 5,894,781, 86,681 over, and
    # `capic-default` 86,141 over, while `capic-default-lean`, which has no node, stayed inside:
    # the growth is the node's. The commits between the last budget and that run that change
    # this crate's dependencies are the router session's, the persistent hash map the tables'
    # stores are held in (`446ee33ef7`, `2788076e9a`) and the declaration log (`fe6f3ac205`);
    # the keyexpr index of the faces' subscriptions (`51279e5529`) came after it. At
    # `a7331c59ea` on pc3: 5,961,373 here and 11,048,057 for `capic-default` (the lean case
    # 9,543,617, unchanged). Chosen growth, the tables' sharing is the owner's decision of
    # 2026-11-05; the budget is that reading, 3,600 for the hosted lane and 3,500, to the
    # hundred.
    # 2026-11-07 -- 5,988,284 on pc3 at `a250c2ff26`, 26,911 over the reading above. SPLIT by
    # reading on pc3 at the commits between: `5de08a3373` (where the next commits branched)
    # 5,961,373, +0; the client store of the broker hat's subscriptions, queryables and tokens,
    # the gated token reconciliation and the persistent map of the advertised tokens on it
    # (`9fc9f7106e`) 5,988,113, +26,740; the peers' commits to `9bf10ad6e8` alone 5,961,544,
    # +171 and one export (the conformance digest). The two add up to the reading after the
    # rebase. Chosen growth (`docs/router-table-snapshots.md` section 6.5); the budget is that
    # reading, 3,600 and 3,500, to the hundred.
    # 2026-11-07, later -- 6,002,476 on pc3 on the face table's branch rebased on `e18b0b27e2`,
    # 14,192 over the reading above. SPLIT on pc3: `e18b0b27e2` alone 5,993,040, +4,756, the
    # peers' commits (`capic-default-lean`'s note of this day splits the same commits); the
    # router's faces held by id and by tier, a persistent map and a set per tier (the commit
    # "Hold the router's faces by id and by tier"), +9,436. Chosen growth
    # (`docs/router-table-snapshots.md` section 6.6); the budget is that reading, 3,600 and
    # 3,500, to the hundred.
    # 2026-11-15 -- the loops' heartbeats and their watcher (`pico-peer`'s note of this day), and
    # the router's probe of its tables' lock: 6,048,928 -> 6,075,734 on pc2 (+26,806). Chosen;
    # the hosted reading at `c42ab17ced` (6,052,832) and that growth, 6,079,638, and 3,500, to
    # the hundred.
    # 2026-11-15, later -- a fragment chain is sent off the router's threads, where it waited for
    # room with the tables held; the send queue's wait is parking_lot's condition variable. The
    # symbol diff on pc2 against `eb14784d20` (6,075,734 -> 6,082,094): `send_chain_off_thread`
    # and its blocking task about +5,700, the condition variable about +2,500, the std mutex and
    # condition variable paths that left about -2,800. Chosen; that reading, the 3,904 the hosted
    # lane read over pc2 at `c42ab17ced`, and 3,500, to the hundred.
    # 2026-11-17 -- the 8e integration read 6,202,708 on pc5, 36,408 over. TAKEN APART on pc5
    # against `0a230c587c` built there (6,288,528; `nm -C -S`, text symbols): the face loop
    # compiled once gave back 112,939 in `accept_loop`; the daemon reading of a config file linked
    # 25,416 into every build that reads a document, because recording a replaced value cloned and
    # compared the whole configuration and so pulled in the equality of every section. Each
    # override now answers for the one value it writes, and that build reads 6,167,768. What
    # stays is chosen: the config reader's new keys +3,618 (`read_over`), the C ABI's drive
    # +4,365, router forwarding's per-key stats filters +2,780, the receive pool sized by the
    # negotiated batch +1,162. pc5 reads the MCU images byte for byte as pc2 does, so the
    # reading stands for pc2's; that reading, the 1,012 of the 2026-11-16 note, and 3,500, to the
    # hundred.
    # 2026-11-18 -- 6,189,972 on hosted run 44032688827 (`d8f187dddc`), 18,148 over its reading
    # at `65ec9acd16`. The symbol diff of the two trees (one host, +17,016): a publisher asks for
    # its subscribers at its declaration under its `aggregation/publishers` aggregate, as
    # upstream's does (`7340af9967`): `SharedSession::declare_write_filter` +6,016,
    # `undeclare_write_filter` +3,832, the BTree of the filter's Interest holds (+2,066, +1,921 and
    # its rebalancing +2,455), `FilterAsk::hold` +348, `z_declare_publisher` +351. Chosen, and
    # with it the egress-policy answer of pico-client's note of this day (+284 on pc2): that
    # reading and that growth, and 3,500, to the hundred.
    # 2026-11-19 -- step 3b (pico-client's note of this day): +31,620 on pc2; by symbol the same
    # publish legs and `publish_declared_all` +3,980; the udp writer's pacing is now chosen by
    # the snapshot (`ByPolicy` replaces `Unpaced`, the same size), and the unicast send moved
    # into the dispatch (-4,715 / +1,379).
    # 2026-11-20 -- step 4b round 2a, as pico-client's note of this day says: +1,680 on pc2
    # (+810 of symbols, the same parts as pico-default's).
    # 2026-11-20 -- step 4b round 2b, as pico-client's note of this day says: +2,900 on pc2
    # (+1,471 of text symbols on one machine, pico-default's parts and the local face's).
    # 2026-11-20 -- the hosted reading again, as pico-client's note of this day says: 6,331,248
    # at `cd240d4b4` and +30,148 since.
    # 2026-11-21 -- step 4b rounds 2 to 4, as pico-client's note of this day says: +20,420 on
    # one machine.
    # 2026-11-23 -- one session drive, dial and open for every caller, as pico-client's note of
    # this day says: -49,636 on one machine; the budget moves by it and keeps its headroom.
    # 2026-11-23, later -- the no-heap integration of this day read 6,404,412 in Layer C1cs on a
    # build machine, 3,132 over: the cooperative engine's lent tables in place of heap ones, the
    # receive lane on a queue of the SCE document, the send gate's atomics and the dial of the
    # tcp and tls links begun without waiting. Not taken apart by symbol. Chosen with those
    # changes; the budget is that reading.
    Case("capic-router-node", "wz-capi-c", "libwz_capi_c.so", "router-node", 6_404_412,
         # 2026-11-22, alias -- an aliased Put fanned out to clients is encoded once and its key re-
         # written per face in place (`LeafPush`, `docs/router-fanout-cost.md` row 6): 6,449,020 on
         # the fleet (+1,432 over the budget, router builds only; the pico and MCU cases held at main's).
         # 2026-11-22, latest -- the router stops writing a face's frames on the routing thread
         # and routes a frame's Puts under one table read, lending the key and the literal Put, with
         # a route kept per face alias (`docs/router-fanout-cost.md` rows 1 and 4): 6,437,908 at
         # main `85330b9e0` -> 6,445,692 on hkl002 (+7,784). By symbol: the alias route table
         # (`AliasRoutes` keep +1,181, get +482, its hashbrown rehash +1,570, Arc and drop glue
         # +731), `deliver_to_client_subscribers` +755, `register` +302, `client_leg_for` +296,
         # `client_carrier` +212; the writer queue's inline write paths shrank (-345). Chosen: the
         # forward of one literal Put to one client fell from 7 allocations and 233 B to 3 and 139.
         # 2026-11-22 -- the step 4b carry and run 44895098050's reading:
         # 6,407,956 hosted, +20,566 on one machine.
         # 2026-11-22, later -- a fan-out to the client faces encodes its carrier once and frames
         # those bytes on every face (`docs/router-fanout-cost.md`): 6,425,764 at main `087427170`
         # -> 6,433,468 on hkl002 (+7,704). By symbol: `EncodedPush::of` +3,898 (the Push encoder
         # inlined into it), `deliver_to_client_subscribers` +1,638, the `ExtEntryWire` and
         # `TimestampWire` `write_source` instances +573 and +400, `credited_send` +547,
         # `SharedCarrier`'s drop +173, the `OnceCell` init +116, `egress_through` -556 and
         # -700, `LiteralPush`'s drop -114. Chosen: a forward to sixteen subscribers allocates 22
         # times and 893 B, where it allocated 85 times and 7,262 B
         # (`crates/wz-runtime-tokio/tests/router_hot_path_cost.rs`); the budget moves by that
         # growth and keeps its headroom.
         # What the declaration says the capability implies (`deploy/wz-config.toml`): the peer
         # role and the scouting and UDP link under it, and the multicast transport.
         require=(ROUTER_NODE, ACCEPT, RESPONDER, SCOUTING, UDP, MULTICAST),
         note="router-node: the C ABI that opens a router, and a peer or client that keeps its "
              "south apart, as the router data plane"),
    # 2026-11-03, the SCE pins -- 9,456,022 on hosted run 41589047498 and 9,458,478 on hkl001 at
    # the head (the larger), the growth pico-client-coop's note of this day attributes; that and
    # 3,500.
    # 2026-11-05 -- 9,497,241 on hosted run 41884918361 (`82d5bf1e71`), 33,739 over its reading at
    # `d20e5e2bd2`; on pc3 9,458,362 -> 9,492,273 from the crates of the two. The symbol diff:
    # wz-capi-core's multicast faces from `5f69859f65` (pico-default's note: the group liveliness
    # subscriber on the wire, `mcast_face_up`, `listen_on`, their maps), the drop-in's node doors
    # of `436683e036` and the node series before it (`query::HeldRoute`, `PublisherHandle`,
    # `QuerierHandle`, `bytes::install_external`, the accept loop's face set), and the runtime
    # pool's shutdown; the open handoff that replaced an mpsc channel takes some of it back
    # (`Sender::send` -3,239, `open_blocking` -1,546). Chosen growth, so the budget is the hosted
    # reading and 3,500, to the hundred.
    # 2026-11-05 -- 9,605,829 on a build machine (hkl002) at `0c7298a48d`, 111,772 over its
    # reading at `c179611fc9` (9,494,057, the commit the budget above was set at, on the same
    # machine). SPLIT by building the same case at the commits between, each on hkl002:
    #   `814859ddf2`  9,544,741  (+50,684, before any commit of the node's operations: the SCE pin
    #                 moved to `07cb8c5020`, the one-pass lent decode, with the census fixes)
    #   `f532f5051f`  9,544,741  (+0, the node's timestamp and declared key)
    #   `081395adab`  9,544,901  (+160, the node's peers, transports, links and listeners)
    #   `685e6b1f89`  9,544,901  (+0)
    #   `900984dbf2`  9,600,117  (+55,216, the SCE pin moved to `0907db47a2`, reserved Rust
    #                 destinations: generated code, no commit of the node's)
    #   `8ef208ab60`  9,600,117  (+0, the node's shared-memory provider)
    #   `0c7298a48d`  9,605,829  (+5,712, from the node's advanced publisher and subscriber and its
    #                 group, with the session refactors of the same hours, not split further)
    # So 105,900 of the 111,772 are the two moves of the SCE pin, which the generated codec of every
    # build that links it carries, and at most 5,872 are the node's operations, which live behind
    # `router-node` and reach this build only through the session handle's second arm and the
    # shared group rules. Chosen growth. The budget is the reading, 3,184 for the hosted run's
    # difference from this machine at the previous budget (9,497,241 against 9,494,057), and
    # 3,500, to the hundred.
    # Then 29,412 more, 9,635,241 at `6dc6c68d9c` (the commits `0c7298a48d` to there are docs, tests
    # and a build profile but for `2274c65e57`, a record read in the lent form at the heap's
    # capacity, another session's: its growth, by that and not by a reading at that commit, and
    # `capic-router-node` grew by the same 29,492). The budget is that reading, 3,184 and 3,500, to
    # the hundred.
    # 2026-11-05 -- `router-node` is on in the default (the owner's decision of that day: the
    # default of this ABI is zenoh-c's preset, and zenoh-c opens a router in its default build), so
    # this case holds the node and the forbid of its symbols is gone. The build without it is
    # `capic-default-lean`, the same features but that one, whose budget is the one this case had
    # before the node was linked in. Read on a build machine (hkl002) at `0f06557ed6` with the
    # change: 10,921,145 text and 836 exports, against 9,635,241 and 836 for the lean case on the
    # same tree, so the node is 1,285,904 bytes (13.3 percent) and adds no export of its own (the
    # doors it reads through are the ABI's, in both). The budget is that reading, 3,184 for the
    # hosted lane's difference from this machine and 3,500, to the hundred.
    # 2026-11-06, later -- the node's growth `capic-router-node`'s note gives (86,141 over on
    # hosted run 42161910521): 11,048,057 on pc3 at `a7331c59ea`, and the budget is that reading,
    # 3,600 and 3,500, to the hundred.
    # 2026-11-07 -- the router tables' growth `capic-router-node`'s note of this day splits:
    # 11,074,936 on pc3 at `a250c2ff26`, of which 26,792 the client store and the tokens' changes
    # and 87 the peers' commits (the lean case 9,543,776, inside); the budget is that reading,
    # 3,600 and 3,500, to the hundred.
    # 2026-11-07, later -- 11,097,952 on pc3 on the face table's branch rebased on `e18b0b27e2`,
    # 23,016 over the reading above; `e18b0b27e2` alone read 11,089,160, 7,060 over the budget
    # already. SPLIT on pc3: the peers' commits +14,224 (the same commits as
    # `capic-default-lean`'s +14,156, split in its note), the face table +8,792
    # (`capic-router-node`'s note of this day). Chosen growth; the budget is that reading, 3,600
    # and 3,500, to the hundred.
    # 2026-11-09, after that -- the table above is not chosen growth but a link-in. The envelope
    # of every document asked at run time which revision it writes and which planes it declares
    # by walking the whole document history, so the history (every key set and value family of
    # every revision) was a run-time structure of each build that writes a document, though only
    # the audit and the tests read it. The envelope now reads a table of the newest row of each
    # document made when the library is compiled (`EMITTED` in `doc_revision.rs`), and the
    # history left the image: `pc2` reads 10,843,648, which is 335,056 UNDER the reading before
    # the growth (11,161,472) and 335,056 under the reading of `7e94c0a7fd`'s window taken apart
    # above. A gain taken, so the budget comes back down: the reading, the +1,012 offset over
    # `pc2` and 3,500, to the hundred.
    # 2026-11-10 -- hosted run 42628697148 (`80a88aae4e`) read 10,859,740 (11,540 over) and the
    # next (`e0461bff3f`) 10,859,888. SPLIT on `pc2`: `0265c3a66f` 10,846,072, `efe34452e1`
    # 10,846,076, `80a88aae4e` 10,854,632, so the step is the value range round alone (+8,556,
    # `.text` +7,872). TAKEN APART by `nm -S`: +7,808 in eleven names, every one the proto
    # encoder's (`Encoder::message` +2,128, the nanopb option merge `Merged::merge` +2,059 and
    # `Merged::set` +1,249, `proto_range::field_range` +582 and `value_range` +482, the rest the
    # encoder's refusal and its phrase). The frame writer of `e2e-sender` encodes a payload by
    # its `.proto`, and it now refuses a value the field's `int_size` cannot hold instead of
    # writing what nanopb would truncate: the growth is that check, chosen. The hosted lane read
    # 5,108 over `pc2` on the same commit, not the 1,012 above; the budget is the hosted reading
    # of `e0461bff3f` and 3,500, to the hundred.
    # 2026-11-15 -- the loops' heartbeats and their watcher (`pico-peer`'s note of this day):
    # 10,856,404 -> 10,881,977 on pc2 (+25,573). Chosen; the hosted reading at `c42ab17ced`
    # (10,861,512) and that growth, 10,887,085, and 3,500, to the hundred.
    # 2026-11-15, later -- the chain sent off the router's threads and the send queue's condition
    # variable, as `capic-router-node`'s note of this day takes apart: 10,881,977 -> 10,887,773 on
    # pc2. Chosen; that reading, the 5,108 the hosted lane read over pc2 at `c42ab17ced`, and
    # 3,500, to the hundred.
    # 2026-11-17 -- the 8e integration, as `capic-router-node`'s note of this day takes apart:
    # 11,210,541 on pc5 with the daemon reading's whole-configuration compare removed (11,239,389
    # with it). Chosen; that reading, the 1,012 of the 2026-11-16 note, and 3,500, to the hundred.
    # 2026-11-18 -- 11,214,893 hosted at `d8f187dddc` and +468 on pc2, the publisher's ask of
    # `capic-router-node`'s note and the egress-policy answer of pico-client's, and 3,500.
    # 2026-11-19 -- step 3b, as `capic-router-node`'s note of this day says: +29,940 on pc2.
    # 2026-11-20 -- Rounds 4541 to this one (the program transport, the session policies, the
    # shared key ids, end-to-end protection on the pico ABI and the application plane): on pc2
    # 11,285,921 at `8593d2f86` -> 11,319,761 (+33,840). By symbol, the end-to-end sender's
    # profile rules (`wz_app_frame::e2e_profile` read_rules/read_cell/read_derive and
    # `e2e_frame::resolve`, +11,621; `e2e-sender` is on in this ABI's default build), the
    # session link's held handshake answer, declaration-progress watch and per-link key forms
    # (`SessionLinkActions`, +4,360, each a policy domain a host build leaves open), the open
    # (`drive::open_blocking`, +2,231) and the zid derivation (+466); the `.proto` reader moved
    # from `wz_capture` to `wz_app_frame` and nets to nothing (-323); the rest is their read-only
    # data. Chosen; that reading and 3,500, to the hundred.
    # 2026-11-20 -- step 4b round 2a, as pico-client's note of this day says: +1,028 on pc2.
    # 2026-11-20 -- step 4b round 2b, as pico-client's note of this day says: +3,272 on pc2
    # (+2,042 of text symbols on one machine, capic-router-node's parts).
    # 2026-11-20 -- the hosted reading again, as pico-client's note of this day says:
    # 11,398,161 at `cd240d4b4` and +32,660 since.
    # 2026-11-21 -- step 4b rounds 2 to 4, as pico-client's note of this day says: +21,424 on
    # one machine.
    # 2026-11-22 -- the fan-out's shared carrier, as `capic-router-node`'s note of this day takes
    # apart: 11,483,973 at main `087427170` -> 11,491,513 on hkl002 (+7,540). Chosen for the
    # same reason; the budget moves by that growth and keeps its headroom.
    # 2026-11-22, latest -- the router changes `capic-router-node`'s note of this day names:
    # 11,495,937 at main `85330b9e0` -> 11,503,677 on hkl002 (+7,740). Main itself already read
    # 297 over the earlier budget on that host; the budget keeps 4,127 over the new reading.
    # 2026-11-22, after it -- the face loop made once on the heap for its node (one `Box::pin` of
    # the loop's state machine and its drop): 11,495,965 at main `85330b9e0` -> 11,496,805 on one
    # machine (+840), both trees built there; the budget moves by that growth and keeps the
    # headroom the note above states.
    # 2026-11-23 -- one session drive, dial and open for every caller, as pico-client's note of
    # this day says: -262,136 on one machine (11,506,377 -> 11,244,241). The hosted run of main
    # `634d1b7ba` read this case at 11,511,533, 2,889 over the budget; the budget is that reading less
    # this change, and 3,500, to the hundred.
    # 2026-11-27 -- hosted run 45798145950 read 11,348,893 at `72ce26dae` (95,993 over); a build
    # host reads 11,332,677 on main `f5a045229` with S6 steps 3 to 5. Taken apart by symbol against
    # `9eeb13832`, the commit that set the budget (11,247,697 there): wz-capi-core +76,869 (the
    # faces' fan and undo, `fan_query`, `fan_undo::record`, the publish loops), wz-capi-c +35,161
    # (the config ACL verdict door's document reader +30,142, the advanced subscriber's state
    # +8,977), wz-runtime-tokio +30,863 and wz-session-core +22,440 (the direct delivery's
    # dispatch and the reply stage moved out of the observer, the group send stage), and the
    # proto schema's move from wz-app-frame to wz-app-schema -57,219 net. Chosen growth; the
    # budget is that reading and 3,500, to the hundred.
    Case("capic-default", "wz-capi-c", "libwz_capi_c.so", None, 11_336_200,
         require=(ROUTER_NODE, ACCEPT, RESPONDER, SCOUTING, GOSSIP, UDP, CLOCK, ADVANCED,
                  MULTICAST, ACCEPT_HANDSHAKE, CONFIG_VERDICT),
         exports=838,
         note="838 exports with the door that answers what a config's access control decides "
              "(`wz_capi_c_config_acl_verdicts`, c87d823ca, `config-verdict` with `interceptors`), "
              "837 before. 837 with the conformance digest's door (`wz_capi_c_conformance_digest`, "
              "decision C15), 836 before. "
              "zenoh-c's default links and pubkey auth (rustls on ring, quinn, tungstenite, "
              "rsa): 8,866,359 measured, up from about 5.1 MB without them; 9,029,823 with "
              "the multicast transport (open-debt item 913). 9,214,622 and 836 exports on "
              "hosted CI on 2026-10-27 (head `e6d953fc2`), 4,622 over the earlier budget with "
              "the door `wz_capi_c_config_device_requires` (the pin's revision 7). 9,246,262 "
              "measured locally with the QoS overwrite, and 9,306,189 with the router node "
              "carrying an authentication and the quic link taking the mutual-TLS and "
              "server-name keys of the tls link (+59,927, nearly all of it in the peer and "
              "router roles: the client builds moved by about 5,300). The accept loop is "
              "instantiated for the router forwarder, which handed it no authentication "
              "before and so had none of that code to carry. 9,316,459 measured locally on "
              "2026-10-30 (+10,270 since): the band and class a link negotiated, and the "
              "multihop gossip key, which the graph's ingest, reflood and link-added delta "
              "read, the gossip core renders as text, and the engine port lists for a node's "
              "admin space. 9,327,578 measured locally on 2026-10-30 (+11,119 since): the "
              "router node's multicast group and the peer as a node, which carries the "
              "peer hat, the autoconnect intents, the whole sample and query a hosted "
              "subscriber or queryable is shown, and the shared memory of the node's "
              "session. 9,331,648 measured locally on 2026-10-30 (+4,070 since): the "
              "region_name key, whose reader, name check and offer link the region "
              "extension's emit into every build that holds a session. The growth is the "
              "features', chosen. The budget is that reading and 3,500, rounded up to the "
              "hundred. 9,336,873 measured locally on the head of the round that ends the "
              "queries pending on a face with it (1,673 over 9,335,200), the growth "
              "capic-client-small's note states: the budget is that reading and 3,500, "
              "rounded up to the hundred. The local readings above run about 80,000 under "
              "the hosted ones: hosted CI read 9,416,742 at `017e3c711`, whose local reading "
              "was 9,331,648, and a build machine reads the hosted figure within a thousand "
              "bytes. 9,420,262 on a build machine on the tree of round 3939: the budget is "
              "that reading and 3,500, to the hundred. Hosted CI read 9,470,386 at `7f04bea6a7` "
              "(8,386 over 9,462,000) and 9,463,502 at `d46109c70a` (1,502 over); the lean "
              "get (`5893b87a10`) lies between the two and the fall of 6,884 was not bisected "
              "to it. The growth that remains over the earlier budget is not attributed to "
              "one commit: the budget moves to the hosted reading of `d46109c70a` and 3,500, "
              "rounded up to the hundred"),
    # The default build of the C ABI with `router-node` left out: what a build that says so
    # (a client, a small peer, `CONFIG_WZ_CAP_ROUTER_NODE=n`) pays, kept graded so that the node
    # being on in the default does not make the build without it free to grow. The features are
    # the default list of `crates/wz-capi-c/Cargo.toml` less `router-node`; `wz_config` holds the
    # manifest to the declaration, and this case to the manifest (the case's features are read as
    # cargo resolves them, so a feature added to the default and not here shows as a difference in
    # `require`). Its first reading is the budget `capic-default` had at 6dc6c68d9c.
    # 2026-11-07 -- 9,557,932 on pc3 at `e18b0b27e2`, 9,632 over the budget and 14,156 over the
    # reading `capic-default`'s note of this day gives (9,543,776). SPLIT by reading on pc3 at the
    # commits between: `b65c1bbdf`, `0f68d04ea7` and `9655f33d54` each 9,543,776, +0; the bound
    # on the size of a query a node runs (`0d8b5d8242`) 9,551,516, +7,740; the paced fragments of
    # a UDP link (`a584247f7e`) 9,556,256, +4,740; the commits after it to `e18b0b27e2` +1,676.
    # The face table does not reach this build (its reading on the branch is the same). Chosen
    # growth; the budget is that reading, 3,600 and 3,500, to the hundred.
    # 2026-11-09 -- hosted run 42505060630 read 9,602,204 (11,604 over); `capic-default`'s note of
    # this day gives the cause and the cure, which reach this build the same way: `pc2` reads
    # 9,266,124 now, 335,056 UNDER the reading before the growth. The budget is that reading, the
    # 1,100 this image reads over `pc2` on the hosted lane (9,602,204 against 9,601,116) and
    # 3,500, to the hundred.
    # 2026-11-10 -- hosted run 42638072176 (`e0461bff3f`) read 9,282,528 (11,728 over); the step
    # is the proto encoder's range check `capic-default`'s note of this day takes apart, which
    # reaches this build by the same `e2e-sender` frame writer. Chosen; the budget is that
    # reading and 3,500, to the hundred.
    # 2026-11-15 -- the loops' heartbeats and their watcher (`pico-peer`'s note of this day):
    # 9,278,968 -> 9,302,557 on pc2 (+23,589). Chosen; the hosted reading at `c42ab17ced`
    # (9,284,152) and that growth, 9,307,741, and 3,500, to the hundred.
    # 2026-11-19 -- step 3b, as `capic-router-node`'s note of this day says: +29,164 on pc2.
    # 2026-11-20 -- Rounds 4541 to this one, as `capic-default`'s note of this day takes apart:
    # 9,531,881 -> 9,566,045 on pc2 (+34,164). Chosen; that reading and 3,500, to the hundred.
    # 2026-11-21 -- step 4b rounds 2 to 4, as pico-client's note of this day says: +21,732 on
    # one machine.
    # 2026-11-23 -- one session drive, dial and open for every caller, as pico-client's note of
    # this day says: -244,452 on one machine; the budget moves by it and keeps its headroom.
    Case("capic-default-lean", "wz-capi-c", "libwz_capi_c.so",
         "link-udp,timestamping,peer,scout,query,queryable,liveliness,liveliness-get,advanced,"
         "group,gossip,transport_tls,transport_quic,transport_quic_datagram,transport_ws,"
         "transport_unixsock-stream,transport_multilink,auth_pubkey,e2e-sender,config-verdict,"
         "transport_compression,auth_usrpwd,interceptors,multicast-transport",
         # 2026-11-18 -- 9,488,445 hosted at `d8f187dddc` (2,545 over) and +896 on pc2: the
         # publisher's ask of `capic-router-node`'s note and the egress-policy answer of
         # pico-client's, chosen; that reading and that growth, and 3,500, to the hundred.
         # 2026-11-20 -- step 4b round 2a, as pico-client's note of this day says: +516 on pc2.
         # 2026-11-20 -- step 4b round 2b, as pico-client's note of this day says: +1,796 on pc2.
         # 2026-11-20 -- the hosted reading again, as pico-client's note of this day says:
         # 9,618,897 at `cd240d4b4` and +30,560 since.
         # 2026-11-21 -- the gates' batch over main 8d9b0e530: +1,372 on one host, every moved symbol a
         # renamed monomorph of equal size but +497 (std's thread packet drop); the build host reads this
         # case about 1 percent over that host, which put main at its budget and this batch 3,469 over.
         # 2026-11-22 -- the step 4b carry and run 44895098050's reading:
         # 9,691,657 hosted, +3,561 on one machine.
         # 2026-11-27 -- hosted run 45798145950 read 9,530,941 at `72ce26dae` (76,593 over); a
         # build host reads 9,509,921 on main `f5a045229` with S6 steps 3 to 5. The growth is
         # capic-default's of this day less the router node's share. Chosen; that reading and
         # 3,500, to the hundred.
         9_513_500,
         forbid=(ROUTER_NODE,),
         require=(ACCEPT, RESPONDER, SCOUTING, GOSSIP, UDP, CLOCK, ADVANCED, MULTICAST),
         note="the default of the C ABI without the router node"),
)


@dataclass
class Measured:
    text: int
    symbols: list[str]  # demangled names of the defined symbols
    exports: int
    # Every distinct NUL-terminated `sha256:<64 hex>` string in the binary: the conformance
    # digest is one, and a binary that holds none or two cannot say which build it is.
    digests: tuple[str, ...] = ()
    # The names of the symbols the library leaves undefined, as it states them (unmangled).
    undefined: tuple[str, ...] = ()
    # The shared libraries the library names as needed (DT_NEEDED).
    needed: tuple[str, ...] = ()
    # The build path prefixes the library still holds (build_normalization.leaked).
    leaked: tuple[str, ...] = ()
    # The linker that wrote the library, as its `.comment` names it (`linker_of`).
    linker: str = ""
    # The linker arguments the case's configuration files gave the library (`link_args`).
    link_args: tuple[str, ...] = ()
    # Whether the dynamic section has DT_RELR, and whether the library asks the C library for
    # `RELR_VERSION_NEED`.
    relr: bool = False
    relr_need: bool = False
    # Whether the library holds unwind tables (an `.eh_frame` or `.eh_frame_hdr` section).
    eh_frame: bool = False
    # The executable sections the file measured does not hold as its build does
    # (`wz_package.strip_debug`).
    code_moved: tuple[str, ...] = ()
    # Whether the library holds the section a run-text list lays a run's code out in
    # (`RUN_TEXT_SECTION`).
    run_text: bool = False


# The conformance digest as the library stores it: a C string, so the NUL is part of the match and
# a longer hex run or an unterminated one is not taken for it.
DIGEST_IN_BINARY = re.compile(rb"sha256:[0-9a-f]{64}\x00")


def digests_in(data: bytes) -> tuple[str, ...]:
    return tuple(sorted({m.group(0)[:-1].decode("ascii") for m in DIGEST_IN_BINARY.finditer(data)}))


#: The ABI whose library each package a case builds is.
ABI_OF_PACKAGE = {"wz-capi-pico": "pico", "wz-capi-c": "c"}


def case_abi(case: Case | StatementCase) -> str:
    return ABI_OF_PACKAGE[case.package]


def stated_values(decl: dict, limits: Mapping[str, str]) -> dict[str, str]:
    """`limits` (a build's `WZ_LIMIT_` and `WZ_POLICY_` environment) without the allowances of a
    policy's domain: the statement names each limit's and policy's value, not what else a policy
    may take."""
    allowances = {wz_config.policy_allows_symbol(pol, value)
                  for pol in decl["policies"] for value in wz_config.policy_values(pol)}
    return {name: value for name, value in limits.items() if name not in allowances}


def stated_digest(case: Case | StatementCase, features: set[str],
                  limits: Mapping[str, str] | None = None) -> str:
    """The digest the conformance statement gives the case's build: its ABI and features, and the
    limits and policies it is built under (`case_limits` when not given)."""
    decl = wz_config.load_decl()
    given = case_limits(case) if limits is None else limits
    return wz_config.env_statement(decl, case_abi(case), sorted(features),
                                   stated_values(decl, given), {})["digest"]


#: The capability whose door answers the conformance digest (`zext_conformance_digest`).
DIGEST_CAPABILITY = "conformance-digest"


def digest_door(case: Case | StatementCase, features: set[str]) -> bool:
    """Whether the case's library has the door that carries the conformance digest. Where the
    declaration makes the door a capability of the case's ABI, the case's features decide; on an
    ABI the capability does not name, every build has the door."""
    cap = wz_config.load_decl()["caps"].get(DIGEST_CAPABILITY)
    if cap is None or case_abi(case) not in cap["abis"]:
        return True
    return DIGEST_CAPABILITY in features


# The fifth fact for the builds the size cases do not make: the build script reads limits and
# policies from the environment and the zenoh-c layout arm from a feature, and every size case
# builds under its ABI's own preset and no arm on (the zenoh-c original's preset sets no limit).
# Without these, a value no preset sets is held only by unit tests that hand the reader its answers
# (`wz-conformance-build`, and the statement vectors both writers reproduce). These cases make real
# libraries with a limit and a policy of their own and the arm upstream's published zenoh-c
# archive has. Each must carry the digest its
# statement gives.
#
# They grade the digest and nothing else, so they carry no budget. They build with the dev profile
# into a target directory of their own. A stated limit or policy changes the fingerprint of every
# crate that reads it, so building them in the size cases' directory would rebuild the tree there
# twice for every run.
STATEMENT_TARGET = TARGET / "conformance-statement"


@dataclass(frozen=True)
class StatementCase:
    id: str
    package: str
    lib: str
    features: str
    env: tuple[tuple[str, str], ...]
    # The pico C library has no `std` and does not unwind, so it is built with the profile that
    # aborts (`capi-nostd`); a library with `std` takes the dev profile.
    profile: str = "dev"
    note: str = field(default="", compare=False)


STATEMENT_CASES: tuple[StatementCase, ...] = (
    StatementCase("statement-pico-stated", "wz-capi-pico", "libwz_capi_pico.so",
                  "os-host,link-udp,conformance-digest",
                  (("WZ_LIMIT_MAX_SUBSCRIPTIONS", "32"), ("WZ_POLICY_SN_RESOLUTION", "bits-16")),
                  profile="capi-nostd",
                  note="the pico client on the cooperative engine (pico-client-coop-nostd's features "
                       "and the digest's door, which the pico preset leaves out) with a limit and "
                       "a policy stated off their defaults"),
    StatementCase("statement-capic-shm-arm", "wz-capi-c", "libwz_capi_c.so",
                  "default,zenoh-c-shared-memory",
                  (("WZ_LIMIT_MAX_QUERYABLES", "24"), ("WZ_POLICY_MULTICAST_LOOPBACK", "off")),
                  note="the zenoh-c default with the shared-memory arm on, the arm upstream's "
                       "published archive is built with, and a limit and a policy stated"),
)


def limit_env(base: Mapping[str, str], limits: Mapping[str, str]) -> dict[str, str]:
    """`base` (the gate's environment, see `build_env`) with every limit and policy it states
    removed and `limits` added. Otherwise a value the shell happened to export would build another
    library than the case names, and the statement would still match it."""
    env = {k: v for k, v in base.items()
           if not k.startswith(("WZ_LIMIT_", "WZ_POLICY_"))}
    return {**env, **limits}


def statement_env(case: StatementCase, base: Mapping[str, str]) -> dict[str, str]:
    """The environment a statement case builds in: its own limits and policies alone."""
    return limit_env(base, dict(case.env))


@functools.cache
def original_limits(abi: str) -> tuple[tuple[str, str], ...]:
    """The limits and policies of `abi`'s own preset, its original's defconfig with no preset
    named (`wz_config.build_of`), as name and value. Resolved once a run: every size case of the
    ABI is built under them. Raises `wz_config.PresetError` when it does not resolve (the pinned
    Kconfig interpreter is not provisioned, or the defconfig is refused)."""
    _, lines = wz_config.build_of(wz_config.load_decl(), abi, [])
    return tuple((name, value) for name, _, value in (line.partition("=") for line in lines))


def case_limits(case: Case | StatementCase) -> dict[str, str]:
    """The limits and policies a case is built under: a statement case's own, a size case's its
    ABI's preset (`original_limits`), and none for a package that is no ABI's library."""
    if isinstance(case, StatementCase):
        return dict(case.env)
    abi = ABI_OF_PACKAGE.get(case.package)
    return dict(original_limits(abi)) if abi is not None else {}


def build_statement_case(case: StatementCase, base: Mapping[str, str],
                         held: list[tuple[str, str]] | None = None) -> tuple[str, ...]:
    """Build a statement case and return the conformance digests its library carries; what cargo
    prints is added to `held` when one is given (`run_held`)."""
    run_held(statement_cmd(case), statement_env(case, base), held)
    return digests_in((statement_target(case) / statement_profile_dir(case) / case.lib).read_bytes())


def statement_target(case: StatementCase) -> pathlib.Path:
    """The target directory a statement case builds in: one of its own, so the two build at the
    same time (module doc, "The builds at once"). It is graded on its digest alone, which holds no
    path, so its directory is not mapped as a size case's is."""
    return STATEMENT_TARGET / case.id


def statement_cmd(case: StatementCase) -> list[str]:
    """The cargo command (from `crates/`) that builds a statement case's C library."""
    return ["cargo", "build", "--profile", case.profile, "-p", artifact_package(case.package), "--quiet",
            "--no-default-features", "--features", artifact_features(case.package, case.features),
            "--target-dir", str(statement_target(case))]


def statement_profile_dir(case: StatementCase) -> str:
    """The directory of the target directory cargo leaves a statement case's library in."""
    return "debug" if case.profile == "dev" else case.profile


def grade_statement(case: StatementCase, got: tuple[str, ...], stated: str,
                    unstated: str, door: bool = True) -> list[str]:
    """The findings for a statement case; empty when it passes. `unstated` is the digest of the
    same features with nothing stated. A case equal to it would state nothing the size cases do
    not, and its pass would hold nothing; so would a case whose features leave the digest's door
    out (`door` false), which builds no digest to read."""
    findings: list[str] = []
    if not door:
        findings.append(f"{case.id}: its features leave out `{DIGEST_CAPABILITY}`, so its library "
                        f"has no door to carry the digest this case exists to read")
    if stated == unstated:
        findings.append(f"{case.id}: its environment states nothing the defaults do not, so it "
                        f"holds no reading the size cases do not hold")
    if got != (stated,):
        findings.append(
            f"{case.id}: the library carries the conformance digest(s) {list(got) or 'none'}, and "
            f"the statement of its features and environment ({', '.join(f'{k}={v}' for k, v in case.env)}) "
            f"is {stated}. The build script (wz-conformance-build) read another build than the one "
            f"this case made: a feature, limit or policy it did not see, or a stale build that cargo "
            f"was not told to redo when the environment moved.")
    return findings


def grade(case: Case, got: Measured, stated: str | None = None, door: bool = True) -> list[str]:
    """The findings for one case; empty when it passes. Pure, so the selftest can drive it.
    `stated` is the digest the case's conformance statement gives; None skips that fact (the
    selftest's synthetic cases have no statement). `door` is whether the case's build has the
    door that carries it (`digest_door`): without it the library must carry no digest at all."""
    findings: list[str] = []
    if stated is not None and not door and got.digests:
        findings.append(
            f"{case.id}: the library carries the conformance digest(s) {list(got.digests)}, and its "
            f"features leave out `{DIGEST_CAPABILITY}`, the capability of the door that carries "
            f"one: something links the door the feature set does not name."
        )
    if stated is not None and door and got.digests != (stated,):
        findings.append(
            f"{case.id}: the library carries the conformance digest(s) {list(got.digests) or 'none'}, "
            f"and the statement of its feature set is {stated}. The build script "
            f"(wz-conformance-build) read another build than the one this case made, or the two "
            f"writers of the canonical form disagree (their fixture tests say which)."
        )
    if case.max_text is None:
        findings.append(
            f"{case.id}: text is {got.text} bytes and the case has no budget yet: set its "
            f"max_text to {budget_for(got.text)}, this reading and its margin (`budget_for`), "
            f"with the reading stated in its note."
        )
    elif got.text > case.max_text:
        findings.append(
            f"{case.id}: text is {got.text} bytes, over its budget of {case.max_text} "
            f"({got.text - case.max_text} over). Either the size grew without anyone choosing it "
            f"(find what linked in: nm -C --size-sort), or the growth is the point and the "
            f"budget moves in this commit with the new measurement stated."
        )
    for pattern in case.forbid:
        hits = [s for s in got.symbols if re.search(pattern, s)]
        if hits:
            findings.append(
                f"{case.id}: {len(hits)} symbol(s) match `{pattern}`, a plane this build leaves "
                f"out (first: {hits[0][:140]}). Something the feature set does not name is "
                f"pulling it in."
            )
    for pattern in case.require:
        if not any(re.search(pattern, s) for s in got.symbols):
            findings.append(
                f"{case.id}: no symbol matches `{pattern}`, a plane this build has. Either the "
                f"build lost the capability or the pattern can no longer match, and an absence "
                f"check built on it grades nothing."
            )
    for pattern in case.forbid_undefined:
        hits = [s for s in got.undefined if re.search(pattern, s)]
        if hits:
            findings.append(
                f"{case.id}: the library leaves {hits[0]} undefined, a name it expects whoever "
                f"loads it to define and is to define itself (the case's note says why)."
            )
    for pattern in case.require_needed:
        if not any(re.search(pattern, n) for n in got.needed):
            findings.append(
                f"{case.id}: the library names no needed library matching `{pattern}` "
                f"(it names {list(got.needed) or 'none'}): its calls into it are unversioned, "
                f"and the loader binds them to the oldest version of each symbol."
            )
    if case.exports is not None and got.exports != case.exports:
        findings.append(
            f"{case.id}: exports {got.exports} C symbols, pinned at {case.exports}. A symbol "
            f"was added or lost in the build every consumer links."
        )
    return findings


def purity_findings(subject: str, leaked: tuple[str, ...]) -> list[str]:
    """The finding for a library that still holds a build path prefix; empty when it holds none."""
    if not leaked:
        return []
    return [
        f"{subject}: the library holds the build path prefix(es) {', '.join(leaked)}, so its text "
        f"measures where it was built as well as what it is, and no other host can read the same "
        f"figure. Something reached the library outside scripts/lib/build_normalization.py: a C "
        f"build that does not read CFLAGS, a directory outside the mapped prefixes, or a path the "
        f"code holds as a string (env! of a directory) rather than as a source location."
    ]


def build_env() -> tuple[dict[str, str], build_normalization.Prefixes]:
    """The environment every build of this gate runs in, and the prefixes it maps: the caller's
    environment under the rule of `build_normalization.py`, dated by this tree's HEAD."""
    prefixes = build_normalization.resolve_prefixes()
    epoch = build_normalization.source_date_epoch(prefixes.workspace)
    return build_normalization.normalized_env(os.environ, prefixes, epoch), prefixes


def host_triple() -> str:
    """The target the toolchain builds for by default: this host's."""
    out = subprocess.run(["rustc", "-vV"], cwd=CRATES, capture_output=True, text=True,
                         check=True).stdout
    for line in out.splitlines():
        if line.startswith("host:"):
            return line.split(":", 1)[1].strip()
    raise RuntimeError("rustc -vV names no host target")


# The keys a `[target.<key>]` table of a configuration file a case names may set: the ones this
# gate hands the build (`case_config`).
CONFIG_TABLE_KEYS = ("rustflags", "linker")
# The words of a `cfg(...)` predicate: a name, a string, or one of `( ) , =`.
CFG_TOKEN = re.compile(r'\s*(?:([A-Za-z_][A-Za-z0-9_]*)|("[^"\\]*")|([(),=]))')


@dataclass(frozen=True)
class ConfigTable:
    """One `[target.<key>]` table of a cargo configuration file: its key (a target triple or
    `cfg(...)`), its `rustflags` and its `linker`."""
    key: str
    rustflags: tuple[str, ...] = ()
    linker: str | None = None


def read_config_tables(text: str) -> list[ConfigTable]:
    """The `[target.<key>]` tables of a cargo configuration file, in file order, read as TOML by
    the floor interpreter's reader (`wz_config.read_decl_toml`). The files a case names hold
    those tables and nothing else, each setting only `CONFIG_TABLE_KEYS`; anything else is refused
    by name rather than skipped, so a setting this gate would not pass on cannot sit in one
    unnoticed. A linker is a program name, in a triple's table: cargo resolves a path against the
    file's place and takes a triple's linker over a `cfg(...)` table's, which the variable this
    gate hands it in (`target_linker_env`) would not reproduce."""
    doc = wz_config.read_decl_toml(text)
    for name in doc:
        if name != "target":
            raise ValueError(f"`{name}` is not a `[target.<key>]` table, the only kind this gate "
                             "passes on to the build")
    target = doc.get("target", {})
    if not isinstance(target, dict):
        raise ValueError("`target` is not a table of `[target.<key>]` tables")
    tables: list[ConfigTable] = []
    for key, table in target.items():
        if not isinstance(table, dict):
            raise ValueError(f"`target.{key}` is not a table")
        for name in table:
            if name not in CONFIG_TABLE_KEYS:
                raise ValueError(f"`[target.{key}]` sets `{name}`, which this gate does not pass "
                                 "on to the build")
        flags = table.get("rustflags", [])
        if not isinstance(flags, list) or not all(isinstance(f, str) for f in flags):
            raise ValueError(f"`rustflags` of `[target.{key}]` is not an array of strings")
        linker = table.get("linker")
        if linker is not None:
            if key.startswith("cfg("):
                raise ValueError(f"`[target.{key}]` sets `linker`, which this gate passes for a "
                                 "target triple's table only")
            if not isinstance(linker, str) or not linker or "/" in linker or "\\" in linker:
                raise ValueError(f"`linker` of `[target.{key}]` is not a program name")
        tables.append(ConfigTable(key, tuple(flags), linker))
    return tables


def cfg_matches(expr: str, cfg: set[str]) -> bool:
    """Whether the predicate `expr` of a `cfg(...)` table key holds for a target whose
    `rustc --print cfg` lines are `cfg`: a name, `key = "value"`, and `all`, `any` and `not`
    of predicates. A predicate of another shape is refused, never read as false."""
    tokens: list[str] = []
    pos = 0
    expr = expr.strip()
    while pos < len(expr):
        m = CFG_TOKEN.match(expr, pos)
        if not m:
            raise ValueError(f"`cfg({expr})` is not a predicate this gate reads")
        tokens.append(m.group(1) or m.group(2) or m.group(3))
        pos = m.end()

    def at(i: int) -> str:
        if i >= len(tokens):
            raise ValueError(f"`cfg({expr})` ends inside a predicate")
        return tokens[i]

    def predicate(i: int) -> tuple[bool, int]:
        name = at(i)
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name):
            raise ValueError(f"`cfg({expr})` has {name!r} where a name belongs")
        follows = tokens[i + 1] if i + 1 < len(tokens) else None
        if follows == "=":
            value = at(i + 2)
            if not value.startswith('"'):
                raise ValueError(f"`cfg({expr})` gives `{name}` a value that is not a string")
            return f"{name}={value}" in cfg, i + 3
        if follows == "(":
            if name not in ("all", "any", "not"):
                raise ValueError(f"`cfg({expr})` names `{name}(...)`, which is no predicate")
            values: list[bool] = []
            i += 2
            while at(i) != ")":
                value, i = predicate(i)
                values.append(value)
                if at(i) == ",":
                    i += 1
                elif at(i) != ")":
                    raise ValueError(f"`cfg({expr})` has {at(i)!r} between two predicates")
            if name == "not":
                if len(values) != 1:
                    raise ValueError(f"`cfg({expr})`: `not` takes one predicate")
                return not values[0], i + 1
            return (all(values) if name == "all" else any(values)), i + 1
        return name in cfg, i + 1

    held, end = predicate(0)
    if end != len(tokens):
        raise ValueError(f"`cfg({expr})` goes on after its predicate")
    return held


def config_rustflags(text: str, triple: str, cfg: set[str]) -> list[str]:
    """The flags a cargo configuration file gives the crates of a build for `triple`, whose
    `rustc --print cfg` lines are `cfg`: its `[target.<triple>]` table's, then those of each
    `[target.'cfg(...)']` table that holds, joined as cargo joins them."""
    tables = read_config_tables(text)
    flags = [f for table in tables if table.key == triple for f in table.rustflags]
    for table in tables:
        key = table.key
        if key.startswith("cfg(") and key.endswith(")") and cfg_matches(key[4:-1], cfg):
            flags += table.rustflags
    return flags


def config_linker(text: str, triple: str) -> str | None:
    """The linker a cargo configuration file names for `triple` (`[target.<triple>] linker`),
    or None."""
    return next((t.linker for t in read_config_tables(text) if t.key == triple and t.linker), None)


def target_linker_env(triple: str) -> str:
    """The variable cargo reads `target.<triple>.linker` from."""
    return f"CARGO_TARGET_{re.sub(r'[-.]', '_', triple).upper()}_LINKER"


def target_cfg(triple: str) -> set[str]:
    """The `rustc --print cfg` lines of `triple`: `unix`, `target_os="linux"`, ..."""
    out = subprocess.run(["rustc", "--print", "cfg", "--target", triple], cwd=CRATES,
                         capture_output=True, text=True, check=True).stdout
    return {line.strip() for line in out.splitlines() if line.strip()}


def merged_config(files: list[tuple[str, str]], triple: str,
                  cfg: set[str]) -> tuple[list[str], str | None]:
    """What the configuration files `files` (each its name and its text) give a build for
    `triple`: their flags in the order given, and the linker of the last that names one, as cargo
    merges `--config` files left to right. A file that cannot be read is refused by its name."""
    flags: list[str] = []
    linker: str | None = None
    for name, text in files:
        try:
            flags += config_rustflags(text, triple, cfg)
            linker = config_linker(text, triple) or linker
        except ValueError as e:
            raise ValueError(f"{name}: {e}") from e
    return flags, linker


def case_config(case: Case, triple: str, cfg: set[str]) -> tuple[list[str], str | None]:
    """What the case's configuration files give its library (`merged_config`), in the order it
    names them."""
    return merged_config([(f"crates/{path}", (CRATES / path).read_text(encoding="utf-8"))
                          for path in case.cargo_configs], triple, cfg)


def with_rustflags(env: Mapping[str, str], extra: list[str]) -> dict[str, str]:
    """`env` with `extra` after the rustc flags it gives (the caller's and the normalization's),
    in the encoded variable: cargo reads it first, it keeps a flag's spaces, and it replaces every
    configured `rustflags` table, the caller's own cargo configuration among them."""
    env = dict(env)
    encoded = env.pop(build_normalization.ENCODED_RUSTFLAGS, None)
    plain = env.pop(build_normalization.RUSTFLAGS, "")
    # cargo reads the encoded form when it is set and the plain one, split on whitespace, if not.
    flags = [f for f in encoded.split("\x1f") if f] if encoded is not None else plain.split()
    env[build_normalization.ENCODED_RUSTFLAGS] = "\x1f".join(flags + extra)
    return env


def link_args(flags: list[str]) -> list[str]:
    """The linker arguments among rustc flags: `-C link-arg=X` and `-Clink-arg=X`."""
    out: list[str] = []
    for i, flag in enumerate(flags):
        if flag.startswith("-Clink-arg="):
            out.append(flag[len("-Clink-arg="):])
        elif flag == "-C" and i + 1 < len(flags) and flags[i + 1].startswith("link-arg="):
            out.append(flags[i + 1][len("link-arg="):])
    return out


def has_unwind_tables(data: bytes) -> bool:
    """Whether an ELF file has an `.eh_frame` or `.eh_frame_hdr` section."""
    return bool({s.name for s in elf_facts.sections(data)} & {".eh_frame", ".eh_frame_hdr"})


def has_run_text(data: bytes) -> bool:
    """Whether an ELF file has the section a run-text list lays a run's code out in."""
    return any(s.name == RUN_TEXT_SECTION for s in elf_facts.sections(data))


def run_text_lines(script: str) -> int:
    """The functions a run-text script's list places: the lines of its SECTIONS statement, one a
    function, as `perf_matrix.py run-text` writes them; a line of the head comment is not one."""
    found = re.search(r"^SECTIONS$", script, re.MULTILINE)
    return 0 if found is None else len(RUN_TEXT_LIST_LINE.findall(script, found.end()))


def discards_unwind_tables(link: tuple[str, ...]) -> bool:
    """Whether linker arguments name the script that discards the unwind tables, by its path from
    `crates/` (a wz library) or by its absolute path (a reference)."""
    return any(a.startswith("-Wl,-T,") and a.endswith(DISCARD_UNWIND_SCRIPT) for a in link)


def link_findings(subject: str, lib: Measured | Reference,
                  run_text_listed: int | None = None) -> list[str]:
    """What is wrong with how a library was linked, against the linker arguments it was linked
    with; empty when it was linked as asked. `run_text_listed` is the number of functions the
    run-text list places, the committed script's (`run_text_lines`) when not given."""
    findings: list[str] = []
    if lib.code_moved:
        findings.append(f"{subject}: taking its debug information off changed its executable "
                        f"sections ({', '.join(lib.code_moved)}), so the file measured is not the "
                        f"build its line tables describe")
    if GNU_LD in lib.link_args and lib.linker and not lib.linker.startswith(NO_LINKER_NAMED):
        findings.append(f"{subject}: linked with `{GNU_LD}` and its .comment names {lib.linker}: "
                        f"another linker than GNU ld wrote it, so the two arms of the ratio are "
                        f"not linked alike. A `-fuse-ld=` or `-C linker=` given after the gate's "
                        f"(the caller's RUSTFLAGS, the C compiler's own default) chose it.")
    if discards_unwind_tables(lib.link_args) and lib.eh_frame:
        findings.append(f"{subject}: linked with the script that discards the unwind tables and "
                        f"still has an `.eh_frame`: the linker ({lib.linker}) kept them, so its "
                        f"text is that of the form with tables. GNU ld honours the script's "
                        f"discard; lld keeps .eh_frame under it and mold refuses it.")
    if RUN_TEXT_LINK in lib.link_args and not lib.run_text:
        listed = (run_text_lines((CRATES / RUN_TEXT_SCRIPT).read_text(encoding="utf-8"))
                  if run_text_listed is None else run_text_listed)
        if listed:
            findings.append(f"{subject}: linked with the run-text script, whose list places "
                            f"{listed} function(s), and holds no `{RUN_TEXT_SECTION}`: no function "
                            f"of this build matched a line of the list, so the list names another "
                            f"build's functions (make it again: scripts/pico-compare.sh run-text) "
                            f"or the linker ({lib.linker}) did not apply the script, and its text "
                            f"lies in the linker's own order.")
    if PACKED_RELOCS_LINK not in lib.link_args:
        return findings
    if not lib.relr:
        findings.append(f"{subject}: linked with `{PACKED_RELOCS_LINK}` and has no DT_RELR: "
                        f"the linker ({lib.linker}) did not pack its relative relocations, so its "
                        f"text is the unpacked form's. GNU ld from 2.38 and lld from 15 pack them; "
                        f"an older GNU ld ignores the option with a warning.")
    elif not lib.relr_need:
        findings.append(f"{subject}: has DT_RELR and does not ask for `{RELR_VERSION_NEED}`, so "
                        f"a C library older than 2.36 loads it, ignores the packed table and runs "
                        f"it with its pointers unrelocated. The linker ({lib.linker}) writes that "
                        f"need when the library asks libc.so.6 for a GLIBC_2 version.")
    return findings


def gnu_ld_line(output: str) -> str | None:
    """The `GNU ld ...` line of `cc -fuse-ld=bfd -Wl,--version`, or None."""
    return next((line.strip() for line in output.splitlines() if line.startswith("GNU ld")), None)


def gnu_ld_version(env: Mapping[str, str]) -> str:
    """The GNU ld the C compiler links with when asked for it (`GNU_LD`): the linker of both arms
    of every case. A host without it is refused by name rather than linked by another."""
    proc = subprocess.run(["cc", GNU_LD, "-Wl,--version"], capture_output=True, text=True,
                          env=dict(env), check=False)
    line = gnu_ld_line(proc.stdout + proc.stderr)
    if line is None:
        raise RuntimeError(f"`cc {GNU_LD}` finds no GNU ld (ld.bfd) on this host, and every "
                           f"library this gate builds and its zenoh-pico reference are linked with "
                           f"it, so both arms of a ratio have one linker: install binutils' ld.bfd")
    return line


def linker_of(lib: pathlib.Path) -> str:
    """The linker that wrote `lib`, as its `.comment` names it. lld and mold write their name
    there and GNU ld writes none, so a library that names no linker was linked by GNU ld or by
    another linker that names itself nowhere."""
    out = subprocess.run(["readelf", "-p", ".comment", str(lib)], capture_output=True, text=True,
                         check=False).stdout
    return comment_linker(out)


def comment_linker(dump: str) -> str:
    """The linker a `readelf -p .comment` dump names (`linker_of`)."""
    for line in dump.splitlines():
        words = line.split("]", 1)[1].strip() if "]" in line else ""
        if re.search(r"\b(LLD|lld|mold|gold)\b", words):
            return words.split(" (", 1)[0]
    return f"{NO_LINKER_NAMED} (GNU ld names none)"


@dataclass(frozen=True)
class CaseBuild:
    """How a case's library is built: the cargo command (run from `crates/`), the environment it
    runs in, the library it leaves, the linker arguments its flags give, which its zenoh-pico
    reference is linked with alike (`reference_build`), and the `NAME=value` lines of the limits
    and policies in that environment, for a run's record. The host performance matrix
    (`scripts/host-bench/perf_matrix.py wz-arm`) builds its arm W by this plan, so the library it
    times is built as the library this gate measures."""

    cmd: tuple[str, ...]
    env: Mapping[str, str]
    lib: pathlib.Path
    link_args: tuple[str, ...]
    limits: tuple[str, ...] = ()


def cargo_profiles(manifest: str) -> dict[str, dict[str, str]]:
    """The keys of each `[profile.<name>]` table of a Cargo manifest, each value as written; the
    tables of a profile's package overrides are not the profile's."""
    out: dict[str, dict[str, str]] = {}
    current: dict[str, str] | None = None
    for line in manifest.splitlines():
        head = re.match(r"^\[profile\.([\w-]+)\]\s*$", line)
        if head:
            current = out.setdefault(head.group(1), {})
        elif line.startswith("["):
            current = None
        elif current is not None:
            pair = re.match(r"^([\w-]+)\s*=\s*(.+?)\s*$", line)
            if pair:
                current[pair.group(1)] = pair.group(2)
    return out


def inherits_from(profile: str, base: str, profiles: Mapping[str, Mapping[str, str]]) -> bool:
    """Whether `profile` is `base` or reaches it through its `inherits` chain in `profiles`
    (`cargo_profiles`); a chain that loops or ends elsewhere does not."""
    seen: set[str] = set()
    while profile not in seen:
        if profile == base:
            return True
        seen.add(profile)
        parent = profiles.get(profile, {}).get("inherits")
        if parent is None:
            return False
        profile = parent.strip('"')
    return False


def case_target(case: Case) -> pathlib.Path:
    """The target directory a size case builds in, its own (`CASE_TARGETS`)."""
    return CASE_TARGETS / case.id


def case_build(case: Case, env: Mapping[str, str], triple: str | None = None,
               cfg: set[str] | None = None, limits: Mapping[str, str] | None = None,
               prefixes: build_normalization.Prefixes | None = None,
               target_dir: pathlib.Path | None = None) -> CaseBuild:
    """The build of `case` in `env` (the gate's, `build_env`), under `limits` (`case_limits` when
    not given) and none of the limits and policies `env` states (`limit_env`), with its line
    tables as the shipping entry builds a release (`wz_package.ship_debug_env` of the case's
    profile). A case that names configuration files is built for the host's own target, `triple`
    (this host's when not given), whose `rustc --print cfg` lines are `cfg` (rustc's when not
    given), so their flags reach the library's crates and not the build scripts. A linker they
    name for that target goes in the variable cargo reads that key from (`target_linker_env`),
    which outranks every configuration file, the caller's among them, as the key named with
    `--config` would, and reaches the build scripts as the key does. The build is made in
    `target_dir`, the case's own target directory (`case_target`) when not given, whose paths read
    as `TARGET`'s under `prefixes` (the gate's, `build_env`; this host's when not given). A
    directory is given where builds run one after another and would otherwise each build every
    dependency again (the size ledger's `--per-feature` steps)."""
    stated = case_limits(case) if limits is None else dict(limits)
    target = case_target(case) if target_dir is None else target_dir
    cmd = ["cargo", "build", "--profile", case.profile, "-p", artifact_package(case.package), "--quiet",
           "--target-dir", str(target)]
    lib_dir = target / case.profile
    flags = list(GATE_RUSTFLAGS)
    linker: dict[str, str] = {}
    if case.cargo_configs:
        triple = triple or host_triple()
        config_flags, config_link = case_config(case, triple,
                                                target_cfg(triple) if cfg is None else cfg)
        flags += config_flags
        if config_link is not None:
            linker[target_linker_env(triple)] = config_link
        cmd += ["--target", triple]
        lib_dir = target / triple / case.profile
    features = feature_list(case)
    if features is not None:
        cmd += ["--no-default-features"]
        if features:
            cmd += ["--features", artifact_features(case.package, features)]
    placed = build_normalization.relocated_env(
        limit_env(env, stated), str(target), str(TARGET),
        build_normalization.resolve_prefixes() if prefixes is None else prefixes)
    return CaseBuild(tuple(cmd), {**with_rustflags(placed, flags),
                                  **wz_package.ship_debug_env(case.profile), **linker},
                     lib_dir / case.lib, tuple(link_args(flags)),
                     tuple(f"{k}={v}" for k, v in stated.items()))


def strip_tool() -> pathlib.Path:
    """The tool the shipping entry takes debug information off with
    (`wz_package.toolchain_objcopy`), or a RuntimeError saying why this host has none."""
    try:
        return wz_package.toolchain_objcopy()
    except wz_package.Refusal as e:
        raise RuntimeError(str(e)) from e


def run_held(cmd: list[str], env: Mapping[str, str], held: list[tuple[str, str]] | None) -> None:
    """Run a cargo command from `crates/`. With `held`, its output is kept instead of shown: its
    standard output and its standard error are added to the list as a pair, and a failure raises
    `subprocess.CalledProcessError` carrying both, so builds that run at the same time print in
    the order they are graded and not as their lines arrive."""
    if held is None:
        subprocess.run(cmd, cwd=CRATES, env=dict(env), check=True)
        return
    proc = subprocess.run(cmd, cwd=CRATES, env=dict(env), capture_output=True, text=True)
    if proc.returncode != 0:
        raise subprocess.CalledProcessError(proc.returncode, cmd, proc.stdout, proc.stderr)
    held.append((proc.stdout, proc.stderr))


def build(case: Case, env: Mapping[str, str], prefixes: build_normalization.Prefixes,
          limits: Mapping[str, str] | None = None,
          held: list[tuple[str, str]] | None = None,
          target_dir: pathlib.Path | None = None) -> Measured:
    """Build `case` (`case_build`, under `limits`, in `target_dir`) and measure the build
    without its debug information, the file a deployer receives, written to
    `SHIPPED_TARGET`/<case>/; cargo's own file keeps its line tables. What cargo prints is kept in
    `held` when one is given (`run_held`)."""
    plan = case_build(case, env, limits=limits, prefixes=prefixes, target_dir=target_dir)
    run_held(list(plan.cmd), plan.env, held)
    lib = SHIPPED_TARGET / case.id / plan.lib.name
    lib.parent.mkdir(parents=True, exist_ok=True)
    moved = wz_package.strip_debug(plan.lib, lib, None, strip_tool())
    size_out = subprocess.run(["size", str(lib)], capture_output=True, text=True, check=True).stdout
    text = int(size_out.splitlines()[1].split()[0])
    names = subprocess.run(
        ["nm", "-C", "--defined-only", str(lib)], capture_output=True, text=True, check=True
    ).stdout.splitlines()
    symbols = [line.split(" ", 2)[2] for line in names if line.count(" ") >= 2]
    dynamic = subprocess.run(
        ["nm", "-D", "--defined-only", str(lib)], capture_output=True, text=True, check=True
    ).stdout.splitlines()
    exports = sum(1 for line in dynamic if len(line.split()) == 3 and line.split()[1] == "T")
    undefined = subprocess.run(
        ["nm", "-u", str(lib)], capture_output=True, text=True, check=True
    ).stdout.splitlines()
    dynamic_section = subprocess.run(
        ["readelf", "-d", str(lib)], capture_output=True, text=True, check=True
    ).stdout.splitlines()
    needed = tuple(re.sub(r".*\[(.*)\].*", r"\1", line) for line in dynamic_section
                   if "(NEEDED)" in line)
    data = lib.read_bytes()
    return Measured(text=text, symbols=symbols, exports=exports, digests=digests_in(data),
                    leaked=tuple(build_normalization.leaked(data, prefixes)),
                    undefined=tuple(line.split()[-1] for line in undefined if line.split()),
                    needed=needed, linker=linker_of(lib), link_args=plan.link_args,
                    relr=any("(RELR)" in line for line in dynamic_section),
                    relr_need=RELR_VERSION_NEED in elf_facts.version_tags(data),
                    eh_frame=has_unwind_tables(data), code_moved=tuple(moved),
                    run_text=has_run_text(data))


@dataclass(frozen=True)
class Reference:
    """zenoh-pico built as the same build as a case: its text, the pin it was built from, the
    toolchain, and the switches pico built otherwise than asked."""

    text: int
    pin: str
    toolchain: str
    refused: tuple[str, ...]
    leaked: tuple[str, ...] = ()
    # The linker that wrote the reference, as its `.comment` names it (`linker_of`).
    linker: str = ""
    # The linker arguments it was linked with (its case's, `reference_args`), and what
    # `Measured` holds of DT_RELR.
    link_args: tuple[str, ...] = ()
    relr: bool = False
    relr_need: bool = False
    eh_frame: bool = False
    # The C compiler flags it was built with beyond the rule's (`reference_build`).
    cflags: tuple[str, ...] = ()
    # What `Measured` holds of the strip, and of the run's laid-out code.
    code_moved: tuple[str, ...] = ()
    run_text: bool = False


@functools.cache
def profile_features(profile: str) -> str:
    """The features of the registered profile `profile` as a comma list, as the Windows package
    lane builds its C library from it (`pico_windows_package.resolve_profile`, then
    `library_features`). Resolved once a run. Raises `wz_config.PresetError` when the profile
    does not resolve (the pinned Kconfig interpreter is not provisioned, among the reasons) or
    names what that library cannot carry."""
    try:
        resolved = pico_windows_package.resolve_profile(wz_config.load_decl(), profile)
        table = wz_config.manifest_features(wz_config.MANIFESTS["pico"])
        return ",".join(pico_windows_package.library_features(resolved["features"], table))
    except pico_windows_package.Refusal as e:
        raise wz_config.PresetError(f"profile {profile}: {e}") from e


def feature_list(case: Case | StatementCase) -> str | None:
    """The features a case is built with, a comma list, or None for its crate's default: its own,
    or those of the profile it reads them from (`Case.features_from`, `profile_features`)."""
    if isinstance(case, Case) and case.features_from is not None:
        return profile_features(case.features_from)
    return case.features


def case_features(case: Case | StatementCase) -> set[str]:
    """The features of the case's package its build turns on, as cargo resolves them."""
    feats = wz_config.manifest_features(CRATES / case.package / "Cargo.toml")
    listed = feature_list(case)
    start = ["default"] if listed is None else [f for f in listed.split(",") if f]
    return wz_config.enabled_features(feats, start)


# The margin a budget is set with over the reading it is set from (module doc, "What a budget
# is"), in percent, and the step it is rounded up to.
BUDGET_MARGIN_PERCENT = 2
BUDGET_STEP = 100


def budget_for(text: int) -> int:
    """The budget a reading of `text` bytes sets: the reading and `BUDGET_MARGIN_PERCENT`
    percent, rounded up to `BUDGET_STEP` bytes."""
    steps = -(-(text * (100 + BUDGET_MARGIN_PERCENT)) // (100 * BUDGET_STEP))
    return steps * BUDGET_STEP


def first_line(cmd: list[str]) -> str:
    return subprocess.run(cmd, capture_output=True, text=True, check=True).stdout.splitlines()[0]


def run_quiet(cmd: list[str], env: Mapping[str, str]) -> None:
    """Run a build step with its output held, and show the end of it if the step fails: a
    reference that could not be built is a failure of this gate, and it says why."""
    proc = subprocess.run(cmd, capture_output=True, text=True, env=env)
    if proc.returncode != 0:
        tail = "\n".join((proc.stdout + proc.stderr).splitlines()[-20:])
        raise RuntimeError(f"`{' '.join(cmd)}` exited {proc.returncode}:\n{tail}")


def refused_switches(asked: dict[str, int], header: str) -> list[str]:
    """The switches pico's generated header states otherwise than `asked`: pico's CMake turns
    some off when another is off (matching without interest, scouting without the UDP unicast
    link), and a reference that silently differs from the build it stands for is the defect this
    gate's denominator exists to remove."""
    on, _ = wz_config.pico_flag_states(header)
    return sorted(s for s, v in asked.items() if (s in on) != bool(v))


def reference_key(pin: str, toolchain: str, flags: list[str], env: Mapping[str, str]) -> str:
    """The directory name of the reference build of `flags` at `pin` with `toolchain`, under the C
    flags and the epoch of `env`: one per build, so a run that asks for the same build again reads
    it instead of building it, and a switch, the pin, the compiler or the rule's flags or epoch
    that moves gets a build of its own (CMake takes the C flags only when it first configures a
    directory)."""
    parts = [pin, toolchain, *flags, env.get("CFLAGS", ""), env.get(build_normalization.EPOCH, "")]
    return hashlib.sha256("\n".join(parts).encode()).hexdigest()[:16]


def reference_build(link_args: tuple[str, ...]) -> tuple[tuple[str, ...], tuple[str, ...]]:
    """The linker arguments and the C flags of the zenoh-pico reference of a case whose library
    was linked with `link_args`, so a choice of the build moves both sides of the ratio alike:
    the linker (`GNU_LD`) and packed relocations as they are, and for a library whose unwind tables are discarded, C
    compiled without unwind tables (`NO_UNWIND_CFLAGS`) and linked with the same script, for
    what the C runtime's own objects still bring. Its line tables are always asked
    (`LINE_TABLES_CFLAGS`), as its case's are."""
    link: list[str] = []
    cflags: list[str] = list(LINE_TABLES_CFLAGS)
    for arg in link_args:
        if arg in (GNU_LD, PACKED_RELOCS_LINK):
            if arg not in link:
                link.append(arg)
        elif discards_unwind_tables((arg,)):
            link.append(f"-Wl,-T,{CRATES / DISCARD_UNWIND_SCRIPT}")
            cflags += NO_UNWIND_CFLAGS
    return tuple(link), tuple(cflags)


def reference_args(asked: dict[str, int], link: tuple[str, ...] = ()) -> list[str]:
    """The CMake arguments of zenoh-pico built with `asked` set: each switch, and `link`, the
    linker arguments `reference_build` gives it."""
    args = [f"-D{s}={v}" for s, v in sorted(asked.items())]
    if link:
        args.append(f"-DCMAKE_SHARED_LINKER_FLAGS={' '.join(link)}")
    return args


@contextlib.contextmanager
def reference_held(work: pathlib.Path) -> Iterator[None]:
    """Hold the reference directory `work` while it is built or read: two cases of a run can ask
    for the same reference at once (module doc, "The builds at once"), and another program on this
    host (the performance matrix) can ask for it while this gate runs. A lock on a file beside the
    directory, which the kernel releases with the process that held it."""
    import fcntl  # POSIX only, and imported here: wz_config imports this module on every host

    work.parent.mkdir(parents=True, exist_ok=True)
    with open(work.parent / f"{work.name}.lock", "w", encoding="utf-8") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        yield


def pico_reference_tree(asked: dict[str, int], env: Mapping[str, str],
                        link: tuple[str, ...] = (),
                        cflags: tuple[str, ...] = (),
                        jobs: int | None = None) -> tuple[pathlib.Path, str, str]:
    """Build zenoh-pico with `asked` set, from an export of the pinned submodule (pico's CMake
    writes a header into its source tree, which must not dirty the submodule), in `env` (the
    gate's, `build_env`), unless that build is there already. Returns its directory (`src` the
    export, `build` the CMake tree), the full pin and the toolchain. The host performance matrix
    (`scripts/host-bench/perf_matrix.py`) links this same build, asked for in the environment of
    `build_env` too, so the library it times is the one whose size this gate prints. `link` and
    `cflags` are what `reference_build` adds; the C flags join the rule's in `CFLAGS`, which
    CMake reads when it first configures the tree and the key holds. `jobs` is how many compilers
    its build runs at once, every core of the host when not given."""
    if cflags:
        env = {**env, "CFLAGS": " ".join(f for f in (env.get("CFLAGS", ""), *cflags) if f)}
    pin = subprocess.run(["git", "-C", str(PICO_SOURCE), "rev-parse", "HEAD"], capture_output=True,
                         text=True, check=True).stdout.strip()
    toolchain = f"{first_line(['cc', '--version'])}; {first_line(['cmake', '--version'])}"
    flags = reference_args(asked, link)
    work = PICO_BUILDS / reference_key(pin, toolchain, flags, env)
    lib = work / "build" / "lib" / "libzenohpico.so"
    with reference_held(work):
        if not lib.exists():
            archive = subprocess.run(["git", "-C", str(PICO_SOURCE), "archive", "--format=tar",
                                      "HEAD"], capture_output=True, check=True).stdout
            with tarfile.open(fileobj=io.BytesIO(archive)) as tar:
                tar.extractall(work / "src", filter="data")
            run_quiet(["cmake", "-S", str(work / "src"), "-B", str(work / "build"),
                       "-DCMAKE_BUILD_TYPE=Release", "-DBUILD_SHARED_LIBS=ON",
                       "-DBUILD_EXAMPLES=OFF", "-DBUILD_TESTING=OFF", *flags], env)
            run_quiet(["cmake", "--build", str(work / "build"), "--parallel",
                       str(jobs or os.cpu_count() or 1)], env)
    return work, pin, toolchain


def pico_reference_build(asked: dict[str, int], env: Mapping[str, str],
                         prefixes: build_normalization.Prefixes,
                         link: tuple[str, ...] = (),
                         cflags: tuple[str, ...] = (),
                         jobs: int | None = None) -> Reference:
    """zenoh-pico built with `asked` set, compiled with `cflags` and linked with `link` under
    `env` ([`pico_reference_tree`], `jobs` compilers at once), measured without its debug
    information (`SHIPPED_PICO` in its directory, as a case is in `build`), and searched for the
    build path prefixes `env` maps. The file without debug information is written and read with
    the directory held (`reference_held`), since two cases can share the reference."""
    work, pin, toolchain = pico_reference_tree(asked, env, link, cflags, jobs)
    lib = work / SHIPPED_PICO
    with reference_held(work):
        lib.parent.mkdir(exist_ok=True)
        moved = wz_package.strip_debug(work / "build" / "lib" / "libzenohpico.so", lib, None,
                                       strip_tool())
        dynamic_section = subprocess.run(
            ["readelf", "-d", str(lib)], capture_output=True, text=True, check=True
        ).stdout.splitlines()
        data = lib.read_bytes()
        header = (work / "build" / "include" / "zenoh-pico" / "config.h").read_text()
        size_out = subprocess.run(["size", str(lib)], capture_output=True, text=True,
                                  check=True).stdout
        linker = linker_of(lib)
    return Reference(text=int(size_out.splitlines()[1].split()[0]), pin=pin[:12],
                     toolchain=toolchain, refused=tuple(refused_switches(asked, header)),
                     leaked=tuple(build_normalization.leaked(data, prefixes)),
                     linker=linker, link_args=link,
                     relr=any("(RELR)" in line for line in dynamic_section),
                     relr_need=RELR_VERSION_NEED in elf_facts.version_tags(data),
                     eh_frame=has_unwind_tables(data), cflags=cflags, code_moved=tuple(moved))


def case_reference(case: Case, got: Measured, env: Mapping[str, str],
                   prefixes: build_normalization.Prefixes,
                   jobs: int | None = None) -> Reference | None:
    """zenoh-pico built as the same build as the case whose library is `got`, or None for a case
    that has none here. Only the pico ABI's cases have one: zenoh-c's original is a Rust build of
    its own the lanes that install the oracle provision, and this lane does not."""
    if case.package != "wz-capi-pico":
        return None
    asked = wz_config.pico_reference(wz_config.load_decl(), case_features(case))
    link, cflags = reference_build(got.link_args)
    return pico_reference_build(asked, env, prefixes, link, cflags, jobs)


def report_reference(case: Case, got: Measured, ref: Reference | None) -> list[str]:
    """Print the case's size against its zenoh-pico reference (`case_reference`), and return the
    findings for that reference when it holds a build path or was not linked as asked."""
    if ref is None:
        print(f"  capability-cost: {case.id}: no same-build reference in this lane (zenoh-c's is "
              f"provisioned only where the oracle is installed)")
        return []
    print(f"  capability-cost: {case.id}: zenoh-pico {ref.pin} as the same build: text "
          f"{ref.text}; wz is {got.text / ref.text:.2f} times it ({ref.toolchain})")
    print(f"  capability-cost: {case.id}: wz linked by {got.linker} with the linker arguments "
          f"{list(got.link_args)}, zenoh-pico by {ref.linker} with {list(ref.link_args)} and "
          f"the C flags {list(ref.cflags)} beyond the rule's")
    if ref.refused:
        print(f"  capability-cost: {case.id}: pico built {', '.join(ref.refused)} otherwise than "
              f"asked, so the two builds differ there")
    subject = f"{case.id} (its zenoh-pico reference)"
    return purity_findings(subject, ref.leaked) + link_findings(subject, ref)


# ── the pico ceiling of the host libraries (docs/upstream-parity.md D9) ────────────────────────
#
# The table's rule is `pico_host_ceiling.py`'s, shared with the Windows package lane; what is this
# gate's is the population of its own cases, how a case is read, and the command that reads one.


def ceiling_cases() -> list[str]:
    """The cases the ceiling holds: every pico case of this gate, the ones `case_reference`
    builds a reference for, and the release DLL of each width of Windows with the like-for-like
    library and each door over it, which the Windows package lane builds and grades
    (`pico_windows_package.CEILING_CASES`, `pico_windows_package.FEATURE_CASES`). This gate holds
    the table to all of them, so a row of either lane is checked on every tree whichever host
    builds it."""
    return ([c.id for c in CASES if c.package == "wz-capi-pico"]
            + list(pico_windows_package.CEILING_CASES) + list(pico_windows_package.FEATURE_CASES))


def measure_command(case_id: str) -> str:
    """The command that prints a case's row, which an unfilled row's finding names."""
    return f"`python3 scripts/lib/capability_cost_gate.py --measure {case_id}`"


def case_reading(got: Measured, ref: Reference | None, date: str) -> dict | None:
    """The reading a case is held to its row by, or None when it has none: no reference, or a
    library on either side that holds a build path or was not linked as asked, whose text is no
    figure (its purity or link finding fails the run instead)."""
    if ref is None or got.leaked or ref.leaked:
        return None
    if link_findings("", got) or link_findings("", ref):
        return None
    return ceiling_reading(got.text, ref.text, ref.pin, ref.toolchain, date)


def shard_cases(shards: int, shard: int, weights: dict[str, int], notes: list[str]) -> list[str]:
    """The ids of the cases shard `shard` of `shards` builds, size cases and statement cases dealt
    together by their seconds (module doc, "The hosted shards"), in the order the gate builds them."""
    ids = [c.id for c in CASES] + [c.id for c in STATEMENT_CASES]
    planned = set(census_shard_plan.plan([(i, "") for i in ids], weights, shards, notes)[shard])
    return [i for i in ids if i in planned]


# The parts the fleet's planner cuts this lane into (`scripts/lib/runci_plan.py`, `PARTED_LANES`):
# the cases dealt to this many shards by their seconds, as the hosted matrix deals them (module
# doc, "The parts of the fleet").
FLEET_PARTS = 2
PART_NAME = re.compile(r"shard-(0|[1-9][0-9]*)-of-([1-9][0-9]*)")


def fleet_parts(parts: int = FLEET_PARTS) -> list[str]:
    """The names of the lane's parts, one a shard: what `--parts` prints for the planner."""
    return [f"shard-{k}-of-{parts}" for k in range(parts)]


def part_shard(name: str) -> tuple[int, int]:
    """The shards and the shard (`--shards N --shard K`) a part's name says; a ValueError naming
    the parts for a name that is none."""
    found = PART_NAME.fullmatch(name)
    if found is None or int(found.group(1)) >= int(found.group(2)):
        raise ValueError(f"{name!r} is no part of Layer C1cs: a part is shard-K-of-N with K under "
                         f"N, as `--parts` lists them ({', '.join(fleet_parts())})")
    return int(found.group(2)), int(found.group(1))


# The memory one build is held to when a run decides how many of its builds run at once
# (`build_width`). An estimate, not a reading: no run of this gate has recorded the peak of one
# build, so it is set above what a fat LTO link of the largest library (the C ABI default, about
# 9 MB of text) is expected to take. Each run prints it beside its width; the peak bx records for a
# run is the measurement that replaces it.
CASE_BUILD_MB = 4096
GRANT = re.compile(r"[1-9][0-9]*")


def available_cpus() -> int:
    """The CPUs this process may run on."""
    try:
        return len(os.sched_getaffinity(0)) or 1
    except AttributeError:
        return os.cpu_count() or 1


def available_mb(meminfo: pathlib.Path = pathlib.Path("/proc/meminfo")) -> int | None:
    """The memory the kernel calls available, in MB, or None where it does not say."""
    try:
        text = meminfo.read_text(encoding="ascii")
    except OSError:
        return None
    found = re.search(r"^MemAvailable:\s+(\d+) kB$", text, re.MULTILINE)
    return int(found.group(1)) // 1024 if found else None


def granted(env: Mapping[str, str], cpus: int, available: int | None) -> tuple[int, int | None, str]:
    """The cores and the memory in MB the builds of a run share, and where each was read: what bx
    granted the run (`BX_GRANT_CORES`, `BX_GRANT_MEM_MB`), else `cpus` (`available_cpus`) and
    `available` (`available_mb`, None when unknown). A grant that is no positive whole number is
    read as none."""
    cores_given = env.get("BX_GRANT_CORES", "")
    memory_given = env.get("BX_GRANT_MEM_MB", "")
    if GRANT.fullmatch(cores_given):
        cores, cores_from = int(cores_given), "BX_GRANT_CORES"
    else:
        cores, cores_from = max(1, cpus), "the CPU affinity"
    memory: int | None
    if GRANT.fullmatch(memory_given):
        memory, memory_from = int(memory_given), "BX_GRANT_MEM_MB"
    else:
        memory, memory_from = available, "MemAvailable"
    shown = f"{memory} MB by {memory_from}" if memory is not None else "the memory unknown"
    return cores, memory, f"{cores} core(s) by {cores_from}, {shown}"


def build_width(builds: int, cores: int, memory: int | None,
                per_build: int = CASE_BUILD_MB) -> tuple[int, int]:
    """How many of `builds` independent builds run at once on `cores` cores and `memory` MB
    (None: unknown, which bounds nothing), and the cargo jobs each is given: no more at once than
    there are builds, cores, or builds of `per_build` MB in the memory, and at least one; the
    cores shared among them, rounded up, as Layer G shares them among its targets. A fat LTO link
    runs on one core, so builds side by side are what keeps the cores busy."""
    width = max(1, min(builds, cores))
    if memory is not None:
        width = min(width, max(1, memory // per_build))
    return width, max(1, -(-cores // width))


def build_order(ids: list[str], weights: Mapping[str, int]) -> list[str]:
    """The order a run starts its builds in: heaviest first by `weights` (the seconds of
    `c1cs_case_weights.tsv`), so the longest build does not start last; ties, and builds with no
    weight, after them in the order given."""
    return sorted(ids, key=lambda i: -weights.get(i, 0))


@dataclass(frozen=True)
class SizeRun:
    """What the build of a size case left for its grading: its library, its zenoh-pico reference,
    the seconds of both, and what its commands printed (`run_held`)."""

    got: Measured
    ref: Reference | None
    seconds: int
    held: tuple[tuple[str, str], ...]


@dataclass(frozen=True)
class StatementRun:
    """What the build of a statement case left for its grading: its digests, its seconds, and what
    its command printed."""

    digests: tuple[str, ...]
    seconds: int
    held: tuple[tuple[str, str], ...]


def run_case(case: Case, env: Mapping[str, str], prefixes: build_normalization.Prefixes,
             limits: Mapping[str, str], jobs: int) -> SizeRun:
    """Build a size case and its zenoh-pico reference with `jobs` compilers at once each, their
    output held. Its seconds are read while the run's other builds run beside it."""
    started = time.monotonic()
    held: list[tuple[str, str]] = []
    got = build(case, {**env, "CARGO_BUILD_JOBS": str(jobs)}, prefixes, limits, held)
    ref = case_reference(case, got, env, prefixes, jobs)
    return SizeRun(got, ref, round(time.monotonic() - started), tuple(held))


def run_statement(case: StatementCase, env: Mapping[str, str], jobs: int) -> StatementRun:
    """Build a statement case with `jobs` compilers at once, its output held."""
    started = time.monotonic()
    held: list[tuple[str, str]] = []
    got = build_statement_case(case, {**env, "CARGO_BUILD_JOBS": str(jobs)}, held)
    return StatementRun(got, round(time.monotonic() - started), tuple(held))


def _shown(text: str | bytes | None) -> str:
    return text.decode(errors="replace") if isinstance(text, bytes) else (text or "")


def show_held(held: tuple[tuple[str | bytes | None, str | bytes | None], ...]) -> None:
    """Print what a build's commands printed, each stream to its own."""
    for out, err in held:
        if out:
            sys.stdout.write(_shown(out))
            sys.stdout.flush()
        if err:
            sys.stderr.write(_shown(err))


class Builds:
    """The builds of a run, `width` at a time, each on a thread that waits on its cargo or CMake
    process, read back in the order the gate grades them. Leaving it cancels the builds not yet
    started and waits for the ones running, so a failure that ends the run waits for no build
    queued after it."""

    def __init__(self, width: int) -> None:
        self._pool = concurrent.futures.ThreadPoolExecutor(max_workers=width)
        self._runs: dict[str, concurrent.futures.Future] = {}

    def __enter__(self) -> Builds:
        return self

    def __exit__(self, *_exc: object) -> None:
        self._pool.shutdown(wait=True, cancel_futures=True)

    def start(self, key: str, run: Callable[[], SizeRun | StatementRun]) -> None:
        self._runs[key] = self._pool.submit(run)

    def result(self, key: str) -> SizeRun | StatementRun:
        """The build of `key` once it has ended, what its commands printed shown first; a command
        that failed has its output shown, and its error raised."""
        try:
            run = self._runs[key].result()
        except subprocess.CalledProcessError as e:
            show_held(((e.stdout, e.stderr),))
            raise
        show_held(run.held)
        return run


def cmd_check(measure_only: bool, only: list[str], shard: tuple[int, int] | None = None) -> int:
    unknown = [i for i in only if i not in {c.id for c in CASES} | {c.id for c in STATEMENT_CASES}]
    if unknown:
        print(f"  capability-cost: no such case: {unknown}", file=sys.stderr)
        return 2
    try:
        weights = census_shard_plan.read_weights(CASE_WEIGHTS.read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        print(f"  capability-cost: {CASE_WEIGHTS.relative_to(ROOT)}: {e}", file=sys.stderr)
        if shard is not None:
            return 2
        # Unsharded, the seconds only order the builds' start.
        weights = {}
    planned: set[str] | None = None
    if shard is not None:
        notes: list[str] = []
        ids = shard_cases(*shard, weights, notes)
        for note in notes:
            print(f"  capability-cost: {note}", file=sys.stderr)
        print(f"  capability-cost: shard {shard[1]} of {shard[0]} builds {len(ids)} case(s): "
              f"{', '.join(ids)}")
        planned = set(ids)

    def chosen(case_id: str) -> bool:
        return (not only or case_id in only) and (planned is None or case_id in planned)

    rc = 0
    try:
        env, prefixes = build_env()
    except ValueError as e:
        print(f"  capability-cost: {e}", file=sys.stderr)
        return 2
    sized = [case for case in CASES if chosen(case.id)]
    stating = [case for case in STATEMENT_CASES if chosen(case.id)]
    try:
        limits_of = {case.id: case_limits(case) for case in sized}
        # Resolved here, before any build, so that a profile that does not resolve ends the run
        # with its reason; a build's thread reads the list this resolved (`profile_features`).
        for case in sized:
            feature_list(case)
    except wz_config.PresetError as e:
        print(f"  capability-cost: the limits of an ABI's own preset, or the features of a case's "
              f"profile, did not resolve (scripts/provision-kconfiglib.sh provisions the "
              f"interpreter): {e}", file=sys.stderr)
        return 2
    try:
        linker = gnu_ld_version(env)
        strip_tool()
    except RuntimeError as e:
        print(f"  capability-cost: {e}", file=sys.stderr)
        return 2
    print(f"  capability-cost: every library and zenoh-pico reference is linked by {linker} "
          f"(cc {GNU_LD})")
    cores, memory, read_from = granted(os.environ, available_cpus(), available_mb())
    width, jobs = build_width(len(sized) + len(stating), cores, memory)
    print(f"  capability-cost: {len(sized) + len(stating)} build(s), {width} at a time with {jobs} "
          f"cargo job(s) each ({read_from}; {CASE_BUILD_MB} MB held for a build)")
    table = load_ceiling()
    rows = ceiling_rows(table)
    if not measure_only:
        for finding in table_findings(table, ceiling_cases()):
            print(f"  capability-cost FAIL: {finding}", file=sys.stderr)
            rc = 1
    today = datetime.datetime.now(datetime.timezone.utc).date().isoformat()
    measured_rows: dict[str, dict] = {}
    ceilinged = 0
    with Builds(width) as builds:
        starts: dict[str, Callable[[], SizeRun | StatementRun]] = {
            case.id: functools.partial(run_case, case, env, prefixes, limits_of[case.id], jobs)
            for case in sized}
        starts.update({case.id: functools.partial(run_statement, case, env, jobs)
                       for case in stating})
        for case_id in build_order(list(starts), weights):
            builds.start(case_id, starts[case_id])
        for case in sized:
            run: SizeRun = builds.result(case.id)
            got, ref = run.got, run.ref
            limits = limits_of[case.id]
            stated = stated_digest(case, case_features(case), limits)
            door = digest_door(case, case_features(case))
            print(f"  capability-cost: {case.id}: built under {len(limits)} limit and policy "
                  f"value(s) of its ABI's own preset")
            budget = (f"of no budget yet ({budget_for(got.text)} is the one it sets)"
                      if case.max_text is None
                      else f"of {case.max_text} ({100 * got.text // case.max_text}%)")
            print(f"  capability-cost: {case.id}: text {got.text} {budget}, {got.exports} "
                  f"exports, conformance digest "
                  f"{', '.join(got.digests) or 'none'} "
                  f"({f'statement {stated}' if door else f'no door: {DIGEST_CAPABILITY} is off'})")
            ref_findings = report_reference(case, got, ref)
            # The case's seconds, its build and its reference's: what c1cs_case_weights.tsv holds.
            print(f"  capability-cost: {case.id}: {run.seconds}s")
            # In either mode: a figure read from a library that holds a path is no figure, so it is
            # neither graded against a ceiling row nor printed as one.
            own = purity_findings(case.id, got.leaked) + link_findings(case.id, got)
            for finding in own + ref_findings:
                print(f"  capability-cost FAIL: {finding}", file=sys.stderr)
                rc = 1
            reading = case_reading(got, ref, today)
            row = rows.get(case.id)
            if reading is not None:
                debt = row.get("debt") if isinstance(row, dict) else None
                measured_rows[case.id] = ceiling_row(reading,
                                                     debt if isinstance(debt, str) else None)
            if measure_only:
                continue
            for finding in grade(case, got, stated, door):
                print(f"  capability-cost FAIL: {finding}", file=sys.stderr)
                rc = 1
            if reading is None:
                continue
            if row is None:
                print(f"  capability-cost: {case.id}: the row to add: "
                      f"{format_row(case.id, measured_rows[case.id])}")
                continue
            if row_findings(case.id, row):
                continue  # named by table_findings above
            ceilinged += 1
            findings, notes = grade_ceiling(case.id, row, reading, measure_command(case.id))
            for note in notes:
                print(f"  capability-cost: {note}")
            for finding in findings:
                print(f"  capability-cost FAIL: {finding}", file=sys.stderr)
                rc = 1
        for case in stating:
            stated_run: StatementRun = builds.result(case.id)
            features = case_features(case)
            digests = stated_run.digests
            print(f"  capability-cost: {case.id}: {stated_run.seconds}s")
            stated = stated_digest(case, features)
            unstated = wz_config.env_statement(wz_config.load_decl(), case_abi(case),
                                               sorted(features), {}, {})["digest"]
            print(f"  capability-cost: {case.id}: conformance digest {', '.join(digests) or 'none'} "
                  f"(statement {stated}, with nothing stated {unstated})")
            if measure_only:
                continue
            for finding in grade_statement(case, digests, stated, unstated,
                                           digest_door(case, features)):
                print(f"  capability-cost FAIL: {finding}", file=sys.stderr)
                rc = 1
    if measured_rows:
        print(f"  capability-cost: the rows this run reads for {HOST_CEILING.relative_to(ROOT)} "
              f"`cases` (each replaces the row of its case; a ratchet's `debt` is the open-debt "
              f"item the case is registered under):")
        for n, (case_id, row) in enumerate(measured_rows.items(), 1):
            print(f"    {format_row(case_id, row)}{',' if n < len(measured_rows) else ''}")
    if rc == 0 and not measure_only:
        print(f"  capability-cost: {len(sized)} case(s) within budget, absent where absent, present "
              f"where present, each carrying its statement's digest where it has the door and "
              f"none where it has not; {ceilinged} pico case(s) "
              f"under their zenoh-pico ceiling; {len(stating)} build(s) with stated limits, "
              f"policies or arm carrying theirs")
    return rc


def cmd_selftest() -> int:
    ok = 0
    bad = 0

    def expect(name: str, cond: bool) -> None:
        nonlocal ok, bad
        if cond:
            ok += 1
        else:
            bad += 1
            print(f"  capability-cost selftest FAIL: {name}", file=sys.stderr)

    case = Case("t", "p", "l", "", 1000, forbid=(ACCEPT,), require=(UDP,), exports=3)
    clean = Measured(text=900, symbols=["wz::udp_pipeline::wire", "wz::other"], exports=3)
    expect("a build inside every bound passes", grade(case, clean) == [])
    expect("a size over budget is a finding",
           len(grade(case, Measured(1001, clean.symbols, 3))) == 1)
    expect("a size AT the budget passes", grade(case, Measured(1000, clean.symbols, 3)) == [])
    leaked = Measured(900, clean.symbols + ["wz::accept_loop::accept_any"], 3)
    expect("a DialIntent a scouting build keeps is not the accept loop",
           grade(case, Measured(900, clean.symbols + ["wz::accept_loop::DialIntent"], 3)) == [])
    expect("a forbidden plane that is present is a finding", len(grade(case, leaked)) == 1)
    lost = Measured(900, ["wz::other"], 3)
    expect("a required plane that is absent is a finding", len(grade(case, lost)) == 1)
    expect("a wrong export count is a finding", len(grade(case, Measured(900, clean.symbols, 4))) == 1)
    personality = Case("t", "p", "l", "", 1000, forbid_undefined=(r"^rust_eh_personality$",))
    expect("a forbidden undefined symbol is a finding",
           len(grade(personality, Measured(900, [], 3, (), ("malloc", "rust_eh_personality"))))
           == 1)
    expect("the same name defined, or another left undefined, is not",
           grade(personality, Measured(900, ["rust_eh_personality"], 3, (), ("malloc",))) == [])
    resume = [p for p in {c.id: c for c in CASES}["pico-client-coop-nostd"].forbid_undefined
              if re.search(p, "_Unwind_Resume")]
    expect("the client without std refuses the unwinder's resume left undefined, by either spelling",
           len(resume) == 1 and re.search(resume[0], "_Unwind_Resume@GCC_3.0") is not None
           and re.search(resume[0], "_Unwind_Resume_or_Rethrow") is None)
    libc_named = Case("t", "p", "l", "", 1000, require_needed=(r"^libc\.so",))
    expect("a library that names no C library is a finding",
           len(grade(libc_named, Measured(900, [], 3, (), (), ()))) == 1)
    expect("one that names it is not",
           grade(libc_named, Measured(900, [], 3, (), (), ("libc.so.6",))) == [])
    moved = with_rustflags({"RUSTFLAGS": "-C a=b --remap-path-prefix=/x=/wz", "HOME": "/h"},
                           ["-C", "force-unwind-tables=no"])
    expect("a configured case's flags follow the environment's, in the encoded variable",
           moved == {"HOME": "/h", "CARGO_ENCODED_RUSTFLAGS":
                     "-C\x1fa=b\x1f--remap-path-prefix=/x=/wz\x1f-C\x1fforce-unwind-tables=no"})
    encoded = with_rustflags({"CARGO_ENCODED_RUSTFLAGS": "-C\x1fa b", "RUSTFLAGS": "-C c"}, ["x"])
    expect("the encoded flags, which cargo reads first, are the ones kept, spaces and all",
           encoded == {"CARGO_ENCODED_RUSTFLAGS": "-C\x1fa b\x1fx"})
    # The configuration files a case names: the tables that hold for the target, joined, and
    # every other shape refused rather than skipped.
    linux_gnu = {"unix", 'target_family="unix"', 'target_os="linux"', 'target_env="gnu"',
                 'target_arch="x86_64"'}
    linux_musl = {"unix", 'target_family="unix"', 'target_os="linux"', 'target_env="musl"',
                  'target_arch="x86_64"'}
    linux_arm64 = (linux_gnu - {'target_arch="x86_64"'}) | {'target_arch="aarch64"'}
    windows_msvc = {"windows", 'target_family="windows"', 'target_os="windows"',
                    'target_env="msvc"', 'target_arch="x86_64"'}
    windows_msvc_x86 = (windows_msvc - {'target_arch="x86_64"'}) | {'target_arch="x86"'}
    expect("a name, a key and value, and all, any and not of them are read",
           cfg_matches("unix", linux_gnu) and not cfg_matches("windows", linux_gnu)
           and cfg_matches('all(target_os = "linux", target_env = "gnu")', linux_gnu)
           and not cfg_matches('all(target_os = "linux", target_env = "gnu")', linux_musl)
           and cfg_matches('any(windows, target_env="musl")', linux_musl)
           and cfg_matches("not(windows)", linux_gnu) and not cfg_matches("not(unix)", linux_gnu)
           and cfg_matches("all()", linux_gnu) and not cfg_matches("any()", linux_gnu))
    for shape in ("unix windows", "all(unix", "not(unix, windows)", 'target_os = linux',
                  "feature(x)", "unix)", "", "all(unix,,windows)"):
        try:
            cfg_matches(shape, linux_gnu)
            expect(f"the predicate {shape!r} is refused", False)
        except ValueError:
            expect(f"the predicate {shape!r} is refused", True)
    sample = ("# a comment\n[target.x86_64-unknown-linux-gnu]\nrustflags = [\"-C\", \"t\"]\n\n"
              "[target.'cfg(windows)']\nrustflags = [\"w\"]\n"
              "[target.'cfg(unix)']\nrustflags = [\"u\"]\n")
    expect("the triple's table, then each cfg table that holds",
           config_rustflags(sample, "x86_64-unknown-linux-gnu", linux_gnu) == ["-C", "t", "u"]
           and config_rustflags(sample, "x86_64-pc-windows-msvc", windows_msvc) == ["w"])
    win = "x86_64-pc-windows-msvc"
    linked = (f'[target.{win}]\nlinker = "rust-lld"\nrustflags = ["-C", "linker-flavor=lld-link"]\n'
              "[target.'cfg(unix)']\nrustflags = [\"u\"]\n")
    expect("a triple's linker is that triple's alone, with its flags beside it",
           config_rustflags(linked, "x86_64-unknown-linux-gnu", linux_gnu) == ["u"]
           and config_linker(linked, "x86_64-unknown-linux-gnu") is None
           and config_rustflags(linked, win, windows_msvc) == ["-C", "linker-flavor=lld-link"]
           and config_linker(linked, win) == "rust-lld"
           and config_linker(sample, win) is None)
    for shape in ("[build]\nrustflags = [\"x\"]\n", "[target.'cfg(unix)']\nlinker = \"cc\"\n",
                  "rustflags = [\"x\"]\n", "[target.'cfg(unix)']\nrustflags = \"-C x\"\n",
                  "[target.'cfg(unix)']\nrustflags = [\"x\"]\nrustflags = [\"y\"]\n",
                  f'[target.{win}]\nrunner = "wine"\n', f'[target.{win}]\nlinker = "bin/lld"\n',
                  f'[target.{win}]\nlinker = 1\n', f'[target.{win}]\nlinker = ""\n',
                  '[env]\nX = "1"\n', '[target]\nrustflags = ["x"]\n',
                  '[[target]]\nrustflags = ["x"]\n', 'target = "x"\n',
                  "[target.'cfg(unix)']\nrustflags = [\n  \"x\",\n]\n"):
        try:
            read_config_tables(shape)
            expect(f"the configuration {shape!r} is refused", False)
        except ValueError:
            expect(f"the configuration {shape!r} is refused", True)
    try:
        read_config_tables(f'[target.{win}]\nlinker = "rust-lld"\nrunner = "wine"\n')
        unknown_key = ""
    except ValueError as e:
        unknown_key = str(e)
    expect("a key this gate does not pass on is refused by its name and its table's",
           "`runner`" in unknown_key and win in unknown_key)
    expect("cargo's variable of a triple's linker is named as cargo names it",
           target_linker_env(win) == "CARGO_TARGET_X86_64_PC_WINDOWS_MSVC_LINKER"
           and target_linker_env("thumbv8m.main-none-eabihf")
           == "CARGO_TARGET_THUMBV8M_MAIN_NONE_EABIHF_LINKER")
    expect("files merged join their flags in order, and the last linker named is the one",
           merged_config([("a", f'[target.{win}]\nlinker = "a-ld"\nrustflags = ["x"]\n'),
                          ("b", f'[target.{win}]\nlinker = "b-ld"\nrustflags = ["y"]\n')],
                         win, windows_msvc) == (["x", "y"], "b-ld")
           and merged_config([("a", f'[target.{win}]\nlinker = "a-ld"\n'),
                              ("b", "[target.'cfg(windows)']\nrustflags = [\"y\"]\n")],
                             win, windows_msvc) == (["y"], "a-ld")
           and merged_config([], win, windows_msvc) == ([], None))
    try:
        merged_config([("crates/x.toml", "[build]\n")], win, windows_msvc)
        refused_by = ""
    except ValueError as e:
        refused_by = str(e)
    expect("a file merged that cannot be read is refused by its name",
           refused_by.startswith("crates/x.toml: ") and "`build`" in refused_by)
    nostd = (CRATES / NOSTD_CONFIG).read_text(encoding="utf-8")
    expect("the configuration without std drops the unwind tables on a POSIX host only, and aligns "
           "no innermost loop of an x86 or x64 library",
           config_rustflags(nostd, "x86_64-unknown-linux-gnu", linux_gnu)
           == ["-C", "force-unwind-tables=no", "-C", NOSTD_LOOP_ALIGNMENT]
           and config_rustflags(nostd, "aarch64-unknown-linux-gnu", linux_arm64)
           == ["-C", "force-unwind-tables=no"]
           and config_linker(nostd, "x86_64-unknown-linux-gnu") is None)
    expect("the configuration without std links a Windows library by the toolchain's own linker",
           all(config_rustflags(nostd, t, cfg)
               == ["-C", "linker-flavor=lld-link", "-C", NOSTD_LOOP_ALIGNMENT]
               and config_linker(nostd, t) == "rust-lld"
               for t, cfg in ((win, windows_msvc), ("i686-pc-windows-msvc", windows_msvc_x86))))

    def readable(path: str) -> bool:
        try:
            read_config_tables((CRATES / path).read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return False
        return True

    named_configs = sorted({p for c in CASES for p in c.cargo_configs})
    expect("every configuration file a case names is one this gate reads",
           named_configs != [] and all(readable(p) for p in named_configs))
    # Where the interpreter has `tomllib` (3.11+; the hosted floor does not, so the import is by
    # name), the floor reader must read each such file as TOML does.
    try:
        stdlib_toml = importlib.import_module("tomllib")
    except ImportError:
        stdlib_toml = None
    if stdlib_toml is not None:
        for path in named_configs:
            text = (CRATES / path).read_text(encoding="utf-8")
            expect(f"crates/{path} reads as tomllib reads it",
                   wz_config.read_decl_toml(text) == stdlib_toml.loads(text))
    expect("the linker a library's .comment names is the one printed",
           comment_linker("String dump of section '.comment':\n  [     0]  rustc version 1.97.0\n"
                          "  [    2d]  Linker: LLD 22.1.6 (/checkout/src/llvm 08c84e)\n")
           == "Linker: LLD 22.1.6"
           and comment_linker("  [     0]  mold 2.30.0 (compatible with GNU ld)\n") == "mold 2.30.0"
           and comment_linker("  [     0]  GCC: (Ubuntu 13.3.0) 13.3.0\n").startswith("no linker"))
    # Packed relocations: the file's flag is the one the gate holds a library and its reference
    # to, on the Linux GNU target only, and a library linked with it must have DT_RELR and the
    # version need that makes an older loader refuse it.
    packed = (CRATES / PACKED_RELOCS_CONFIG).read_text(encoding="utf-8")
    expect("the packed-relocations file links a Linux GNU library with the flag, and no other",
           config_rustflags(packed, "x86_64-unknown-linux-gnu", linux_gnu)
           == ["-C", f"link-arg={PACKED_RELOCS_LINK}"]
           and config_rustflags(packed, "x86_64-unknown-linux-musl", linux_musl) == []
           and config_rustflags(packed, "x86_64-pc-windows-msvc", windows_msvc) == [])
    expect("the linker arguments among rustc flags are read in both spellings",
           link_args(["-C", "force-unwind-tables=no", "-C", "link-arg=-Wl,-z,x",
                      "-Clink-arg=-Wl,-y", "--cfg", "link-arg=z", "-C"]) == ["-Wl,-z,x", "-Wl,-y"])
    by_case = {c.id: c for c in CASES}
    expect("the Linux C ABI size case of the pico client is linked packed",
           by_case["pico-client-coop-nostd"].cargo_configs[:2] == (NOSTD_CONFIG, PACKED_RELOCS_CONFIG))
    expect("no pico case is built with std: each takes an aborting profile, and no ship one",
           all(c.profile in ("capi-nostd", "capi-small") for c in CASES if c.package == "wz-capi-pico")
           and all(NOSTD_CONFIG in c.cargo_configs for c in CASES
                   if c.package == "wz-capi-pico" and c.profile == "capi-nostd")
           and "pico-client-coop" not in by_case)
    asked_relr = Measured(900, [], 3, link_args=(PACKED_RELOCS_LINK,), relr=True, relr_need=True)
    expect("a library linked packed with DT_RELR and the version need is linked as asked",
           link_findings("t", asked_relr) == [])
    expect("one with no DT_RELR is a finding that names the linker",
           len(found := link_findings("t", Measured(900, [], 3, linker="GNU ld 2.37",
                                                    link_args=(PACKED_RELOCS_LINK,))))
           == 1 and "no DT_RELR" in found[0] and "GNU ld 2.37" in found[0])
    expect("one with DT_RELR and no version need is a finding",
           len(found := link_findings("t", Measured(900, [], 3, link_args=(PACKED_RELOCS_LINK,),
                                                    relr=True))) == 1
           and RELR_VERSION_NEED in found[0])
    expect("a library not asked to pack is not held to DT_RELR",
           link_findings("t", Measured(900, [], 3)) == [])
    discard = (CRATES / DISCARD_UNWIND_CONFIG).read_text(encoding="utf-8")
    expect("the discard file links a Linux library with the script by GNU ld, and nothing else",
           config_rustflags(discard, "x86_64-unknown-linux-gnu", linux_gnu)
           == ["-C", f"link-arg={GNU_LD}", "-C", f"link-arg={DISCARD_UNWIND_LINK}"]
           and config_rustflags(discard, "x86_64-pc-windows-msvc", windows_msvc) == [])
    expect("the script the discard names is in the tree, as the linker reads it from crates/",
           (CRATES / DISCARD_UNWIND_SCRIPT).is_file()
           and DISCARD_UNWIND_LINK.split(",")[-1] == DISCARD_UNWIND_SCRIPT)
    run_text = (CRATES / RUN_TEXT_CONFIG).read_text(encoding="utf-8")
    expect("the run-text file links a Linux library with its script and nothing else, and the "
           "script is in the tree",
           config_rustflags(run_text, "x86_64-unknown-linux-gnu", linux_gnu)
           == ["-C", f"link-arg={RUN_TEXT_LINK}"]
           and config_rustflags(run_text, "x86_64-pc-windows-msvc", windows_msvc) == []
           and (CRATES / RUN_TEXT_SCRIPT).is_file()
           and RUN_TEXT_LINK.split(",")[-1] == RUN_TEXT_SCRIPT)
    expect("a library linked with a run-text list that places functions and holding no laid-out "
           "run is a finding; one that holds it, an empty list and a library linked without the "
           "script are not",
           len(found := link_findings("t", Measured(900, [], 3, link_args=(RUN_TEXT_LINK,),
                                                    linker="GNU ld 2.42"),
                                      run_text_listed=4)) == 1
           and RUN_TEXT_SECTION in found[0] and "4 function(s)" in found[0]
           and link_findings("t", Measured(900, [], 3, link_args=(RUN_TEXT_LINK,), run_text=True),
                             run_text_listed=4) == []
           and link_findings("t", Measured(900, [], 3, link_args=(RUN_TEXT_LINK,)),
                             run_text_listed=0) == []
           and link_findings("t", Measured(900, [], 3), run_text_listed=4) == [])
    expect("a run-text list is counted by the lines of its statement and not of its head",
           run_text_lines("/*\n    *(.text.head)\n */\nSECTIONS\n{\n  .text.run :\n  {\n"
                          "    *(.text.a .text.unlikely.a)\n    *(.text.b .text.unlikely.b)\n"
                          "  }\n}\nINSERT BEFORE .text;\n") == 2
           and run_text_lines("SECTIONS\n{\n  .text.run :\n  {\n  }\n}\nINSERT BEFORE .text;\n") == 0
           and run_text_lines("") == 0)
    expect("only the library without std, which never unwinds, discards the unwind tables",
           all(c.profile == "capi-nostd" and NOSTD_CONFIG in c.cargo_configs
               for c in CASES if DISCARD_UNWIND_CONFIG in c.cargo_configs)
           and DISCARD_UNWIND_CONFIG in by_case["pico-client-coop-nostd"].cargo_configs)
    expect("a library linked with the discard and still holding tables is a finding",
           len(found := link_findings("t", Measured(900, [], 3, link_args=(DISCARD_UNWIND_LINK,),
                                                    eh_frame=True, linker="mold 2.30.0"))) == 1
           and "mold 2.30.0" in found[0]
           and link_findings("t", Measured(900, [], 3, link_args=(DISCARD_UNWIND_LINK,))) == []
           and link_findings("t", Measured(900, [], 3, eh_frame=True)) == [])
    expect("every library the gate builds is linked by GNU ld through cc",
           link_args(GATE_RUSTFLAGS) == [GNU_LD] and "linker=cc" in GATE_RUSTFLAGS)
    # The plan of a case's build, which the performance matrix builds its arm W by.
    here = build_normalization.Prefixes(str(ROOT), str(TARGET.parents[1]), "/opt/cargo")
    plain = case_build(Case("t", "wz-capi-pico", "libt.so", "a,b", 1), {}, limits={},
                       prefixes=here)
    stands = f"{CASE_TARGETS / 't'}={build_normalization.WORKSPACE_TO}/crates/target"
    expect("a case of no configuration file is built for the default target, by the gate's linker, "
           "in its own target directory read as the shared one",
           plain.cmd[:6] == ("cargo", "build", "--profile", SHIP_PROFILE, "-p", "wz-capi-pico-lib")
           and plain.cmd[-3:] == ("--no-default-features", "--features", "abi/a,abi/b")
           and plain.cmd[plain.cmd.index("--target-dir") + 1] == str(CASE_TARGETS / "t")
           and "--target" not in plain.cmd
           and plain.lib == CASE_TARGETS / "t" / SHIP_PROFILE / "libt.so"
           and plain.link_args == (GNU_LD,)
           and plain.env == {build_normalization.ENCODED_RUSTFLAGS:
                             "\x1f".join([f"--remap-path-prefix={stands}", *GATE_RUSTFLAGS]),
                             "CFLAGS": f"-ffile-prefix-map={stands}",
                             "CXXFLAGS": f"-ffile-prefix-map={stands}",
                             **wz_package.ship_debug_env(SHIP_PROFILE)})
    # A case that reads its features from a profile is planned only where the profile resolves
    # (the pinned Kconfig interpreter); its directory is its own all the same.
    planned_here = [c for c in CASES
                    if c.features_from is None or wz_config.kconfiglib_module() is not None]
    expect("two cases build in two target directories, and their libraries are apart",
           len({case_target(c) for c in CASES}) == len(CASES)
           and len({case_build(c, {}, "x86_64-unknown-linux-gnu", linux_gnu, limits={},
                               prefixes=here).lib for c in planned_here}) == len(planned_here))
    stepped = case_build(Case("t+c", "wz-capi-pico", "libt.so", "a,b,c", 1), {}, limits={},
                         prefixes=here, target_dir=CASE_TARGETS / "t")
    expect("a build given another case's directory is made there and read as that case's build is",
           stepped.cmd[stepped.cmd.index("--target-dir") + 1] == str(CASE_TARGETS / "t")
           and stepped.cmd[-1] == "abi/a,abi/b,abi/c"
           and stepped.lib == plain.lib and stepped.env == plain.env)
    expect("a package that is its own C library is built as it is named, its features as given",
           artifact_package("wz-capi-c") == "wz-capi-c"
           and artifact_features("wz-capi-c", "a, b") == "a,b"
           and artifact_package("wz-capi-pico") == "wz-capi-pico-lib"
           and artifact_features("wz-capi-pico", "") == "")
    pico_statement = next(s for s in STATEMENT_CASES if s.package == "wz-capi-pico")
    capic_statement = next(s for s in STATEMENT_CASES if s.package == "wz-capi-c")
    expect("the pico statement case builds the C library by the aborting profile, through the ABI",
           statement_cmd(pico_statement)[2:6] == ["--profile", "capi-nostd", "-p", "wz-capi-pico-lib"]
           and "abi/conformance-digest" in statement_cmd(pico_statement)[9].split(",")
           and statement_profile_dir(pico_statement) == "capi-nostd"
           and statement_cmd(capic_statement)[2:6] == ["--profile", "dev", "-p", "wz-capi-c"]
           and statement_profile_dir(capic_statement) == "debug")
    expect("each statement case builds in a target directory of its own",
           [statement_cmd(s)[-2:] for s in STATEMENT_CASES]
           == [["--target-dir", str(STATEMENT_TARGET / s.id)] for s in STATEMENT_CASES]
           and len({statement_target(s) for s in STATEMENT_CASES}) == len(STATEMENT_CASES))
    expect("a case of the crate's default features names none",
           "--features" not in case_build(Case("t", "p", "l", None, 1), {}).cmd
           and "--no-default-features" not in case_build(Case("t", "p", "l", None, 1), {}).cmd)
    shell = {"WZ_LIMIT_MAX_KEYEXPR_BYTES": "999", "WZ_POLICY_SN_RESOLUTION": "bits-8", "PATH": "/p"}
    under = case_build(Case("t", "wz-capi-pico", "libt.so", "a", 1), shell,
                       limits={"WZ_LIMIT_MAX_SUBSCRIPTIONS": "4"})
    expect("a case is built under the limits of its build and none the shell exported, and its "
           "plan names them",
           under.env.get("WZ_LIMIT_MAX_SUBSCRIPTIONS") == "4"
           and "WZ_LIMIT_MAX_KEYEXPR_BYTES" not in under.env
           and "WZ_POLICY_SN_RESOLUTION" not in under.env and under.env.get("PATH") == "/p"
           and under.limits == ("WZ_LIMIT_MAX_SUBSCRIPTIONS=4",))
    expect("a package that is no ABI's library has no preset, and a statement case's limits are "
           "its own",
           case_limits(Case("t", "p", "l", None, 1)) == {}
           and case_build(Case("t", "p", "l", None, 1), shell).limits == ()
           and "WZ_LIMIT_MAX_KEYEXPR_BYTES" not in case_build(Case("t", "p", "l", None, 1), shell).env
           and all(case_limits(s) == dict(s.env) for s in STATEMENT_CASES))
    bare_build = case_build(by_case["pico-client-coop-nostd"], {}, "x86_64-unknown-linux-gnu",
                            linux_gnu, limits={})
    expect("a case of configuration files is built for the target named, their flags the library's",
           bare_build.cmd[bare_build.cmd.index("--target") + 1] == "x86_64-unknown-linux-gnu"
           and bare_build.lib
           == CASE_TARGETS / "pico-client-coop-nostd" / "x86_64-unknown-linux-gnu" / "capi-nostd"
           / "libwz_capi_pico.so"
           and "force-unwind-tables=no"
           in bare_build.env[build_normalization.ENCODED_RUSTFLAGS].split("\x1f")
           and NOSTD_LOOP_ALIGNMENT
           in bare_build.env[build_normalization.ENCODED_RUSTFLAGS].split("\x1f")
           and discards_unwind_tables(bare_build.link_args)
           and PACKED_RELOCS_LINK in bare_build.link_args
           and not any(k.endswith("_LINKER") for k in bare_build.env))
    expect("the pico client without std is laid out by the run-text script, and its reference is not",
           RUN_TEXT_CONFIG in by_case["pico-client-coop-nostd"].cargo_configs
           and RUN_TEXT_LINK in bare_build.link_args
           and not any(RUN_TEXT_SCRIPT in arg for arg in reference_build(bare_build.link_args)[0])
           and discards_unwind_tables(reference_build(bare_build.link_args)[0]))
    win_build = case_build(by_case["pico-client-coop-nostd"],
                           {target_linker_env(win): "link.exe"}, win, windows_msvc, limits={})
    expect("a case built for a target its file names a linker for is linked by it, over the caller's",
           win_build.env[target_linker_env(win)] == "rust-lld"
           and "linker-flavor=lld-link"
           in win_build.env[build_normalization.ENCODED_RUSTFLAGS].split("\x1f")
           and NOSTD_LOOP_ALIGNMENT
           in win_build.env[build_normalization.ENCODED_RUSTFLAGS].split("\x1f")
           and "force-unwind-tables=no"
           not in win_build.env[build_normalization.ENCODED_RUSTFLAGS].split("\x1f"))
    gnu_linker = target_linker_env("x86_64-unknown-linux-gnu")
    expect("a caller's linker for a target no file names one for is left as cargo would leave it",
           case_build(by_case["pico-client-coop-nostd"], {gnu_linker: "clang"},
                      "x86_64-unknown-linux-gnu", linux_gnu, limits={}).env[gnu_linker] == "clang")
    expect("a case is built with its line tables by its own profile's variable, and no flag",
           bare_build.env["CARGO_PROFILE_CAPI_NOSTD_DEBUG"] == wz_package.SHIP_DEBUG
           and plain.env["CARGO_PROFILE_SHIP_DEBUG"] == wz_package.SHIP_DEBUG
           and not any("debuginfo" in f or "strip" in f for f in
                       bare_build.env[build_normalization.ENCODED_RUSTFLAGS].split("\x1f")))
    expect("a file whose strip moved its code is a finding naming the section, on either side",
           len(found := link_findings("t", Measured(900, [], 3, code_moved=(".text",)))) == 1
           and ".text" in found[0]
           and len(link_findings("t", Reference(text=1, pin="p", toolchain="cc", refused=(),
                                                code_moved=(".init",)))) == 1
           and link_findings("t", Measured(900, [], 3)) == [])
    expect("the GNU ld line of the C compiler's linker version is read, and none is None",
           gnu_ld_line("collect2 version 13\nGNU ld (GNU Binutils for Ubuntu) 2.38\nCopyright\n")
           == "GNU ld (GNU Binutils for Ubuntu) 2.38"
           and gnu_ld_line("LLD 18.1.3 (compatible with GNU linkers)\n") is None
           and gnu_ld_line("") is None)
    expect("a library asked for GNU ld whose .comment names another linker is a finding",
           len(found := link_findings("t", Measured(900, [], 3, link_args=(GNU_LD,),
                                                    linker="Linker: LLD 22.1.6"))) == 1
           and "Linker: LLD 22.1.6" in found[0]
           and link_findings("t", Measured(900, [], 3, link_args=(GNU_LD,),
                                           linker=comment_linker(""))) == []
           and link_findings("t", Measured(900, [], 3, linker="mold 2.30.0")) == [])
    absolute = f"-Wl,-T,{CRATES / DISCARD_UNWIND_SCRIPT}"
    expect("a reference is built as its case: packed as it is, without tables where it has none",
           reference_build(()) == ((), LINE_TABLES_CFLAGS)
           and reference_build((PACKED_RELOCS_LINK, "-Wl,-x"))
           == ((PACKED_RELOCS_LINK,), LINE_TABLES_CFLAGS)
           and reference_build((PACKED_RELOCS_LINK, DISCARD_UNWIND_LINK))
           == ((PACKED_RELOCS_LINK, absolute), LINE_TABLES_CFLAGS + NO_UNWIND_CFLAGS)
           and reference_build((GNU_LD, PACKED_RELOCS_LINK, GNU_LD))
           == ((GNU_LD, PACKED_RELOCS_LINK), LINE_TABLES_CFLAGS))
    expect("the discard is read by its path from crates/ and by its absolute path alike",
           discards_unwind_tables((DISCARD_UNWIND_LINK,)) and discards_unwind_tables((absolute,))
           and not discards_unwind_tables(("-Wl,-T,other.ld", PACKED_RELOCS_LINK)))
    expect("a reference linked with the discard and still holding tables is a finding",
           len(link_findings("t", Reference(text=1, pin="p", toolchain="cc", refused=(),
                                            link_args=(absolute,), eh_frame=True))) == 1
           and link_findings("t", Reference(text=1, pin="p", toolchain="cc", refused=(),
                                            link_args=(absolute,))) == [])
    expect("a reference is linked with its case's linker arguments, and keyed by them",
           reference_args({"Z_A": 1}) == ["-DZ_A=1"]
           and reference_args({"Z_A": 1}, (PACKED_RELOCS_LINK, "-Wl,-x"))
           == ["-DZ_A=1", f"-DCMAKE_SHARED_LINKER_FLAGS={PACKED_RELOCS_LINK} -Wl,-x"]
           and reference_key("pin", "cc", reference_args({"Z_A": 1}), {})
           != reference_key("pin", "cc", reference_args({"Z_A": 1}, (PACKED_RELOCS_LINK,)), {}))
    expect("an unpinned export count is not graded",
           grade(Case("t", "p", "l", "", 1000), Measured(900, [], 99)) == [])
    # The control that keeps ABSENCE honest: every pattern a case forbids is required by some
    # case in the table, so a forbidden pattern that no build can match cannot stay unnoticed.
    required = {p for c in CASES for p in c.require}
    forbidden = {p for c in CASES for p in c.forbid}
    expect("every forbidden pattern is required of a build that has the plane, or names why "
           "its control is not yet in the table",
           forbidden <= required | set(CONTROL_PENDING))
    expect("a pattern whose control is in the table no longer waits for one",
           not (set(CONTROL_PENDING) & required))
    expect("case ids are unique", len({c.id for c in CASES}) == len(CASES))
    expect("a patterned plane's own symbol matches its pattern",
           all(re.search(p, s) for p, s in (
               (ACCEPT, "wz_runtime_tokio::accept_loop::accept_loop_offering_spawned"),
               (RESPONDER, "ScoutingResponder::new"),
               (SCOUTING, "wz_runtime_tokio::scouting_glue::drive"),
               (GOSSIP, "wz_runtime_tokio::gossip_plane::GossipPlane"),
               (UDP, "wz_runtime_tokio::udp_pipeline::wire_udp_socket"),
               (CLOCK, "uhlc::HLC::new_timestamp"),
               (ADVANCED, "wz_runtime_tokio::advanced_publisher::put"),
               (UDP, "wz_runtime_coop::udp_link::UdpDriver<S> as Drop>::drop"),
               (TOKIO_ENGINE, "wz_capi_core::faces::SharedSession::publish_on_wire_all"),
               (COOP_ENGINE, "wz_capi_coop::engine::CoopEngine<L,C>::open"),
               (ACCEPT_HANDSHAKE, "wz_session_core::accept_cookie::encode_accept_cookie"),
               (CONFIG_VERDICT, "wz_capi_c_config_validate_topology_rows"),
               (CONFIG_VERDICT, "wz_capi_c_config_device_requires"),
               (LOG_FACADE, "<log::__private_api::GlobalLogger as log::Log>::log"),
               (LOG_FACADE, "log::__private_api::log_impl"),
               (HEAP_ABORT, "alloc::alloc::handle_alloc_error"))))
    expect("a module whose name ends in log is not the log facade",
           not any(re.search(LOG_FACADE, s) for s in (
               "wz_capi_pico::event_log::zext_event_emit",
               "wz_session_core::action_log::count")))
    expect("the doors an open reads its config through are not the verdict's",
           not any(re.search(CONFIG_VERDICT, s) for s in (
               "wz_capi_c_config_honoured", "wz_capi_c_config_disposition",
               "zc_config_insert_json5", "wz_capi_c::config::render_nested")))
    # The denominator's own check: a switch pico built otherwise than asked is named, both ways.
    asked = {"Z_FEATURE_MATCHING": 1, "Z_FEATURE_INTEREST": 0, "Z_FEATURE_QUERY": 0}
    expect("a reference built as asked differs nowhere",
           refused_switches(asked, "#define Z_FEATURE_MATCHING 1\n#define Z_FEATURE_INTEREST 0\n"
                                   "#define Z_FEATURE_QUERY 0\n") == [])
    expect("a switch pico turned off, or on, against the ask is named",
           refused_switches(asked, "#define Z_FEATURE_MATCHING 0\n#define Z_FEATURE_INTEREST 0\n"
                                   "#define Z_FEATURE_QUERY 1\n")
           == ["Z_FEATURE_MATCHING", "Z_FEATURE_QUERY"])
    # A reference build is found again by its key, and a key that ignored one of its three inputs
    # would hand a run the build of another switch set, pin or compiler.
    flags = ["-DZ_FEATURE_MATCHING=1", "-DZ_FEATURE_QUERY=0"]
    off = ["-DZ_FEATURE_MATCHING=0", "-DZ_FEATURE_QUERY=0"]
    rule = {"CFLAGS": "-ffile-prefix-map=/srv/tree=/wz", build_normalization.EPOCH: "1"}
    expect("the same build is the same key, and a switch, the pin or the toolchain moves it",
           reference_key("pin", "cc", flags, rule)
           == reference_key("pin", "cc", list(flags), dict(rule))
           and len({reference_key("pin", "cc", flags, rule),
                    reference_key("pin", "cc", off, rule),
                    reference_key("other", "cc", flags, rule),
                    reference_key("pin", "other", flags, rule)}) == 4)
    expect("a case's features are its package's as cargo resolves them",
           "os-host" in case_features(next(c for c in CASES if c.id == "pico-client"))
           and not {"engine-tokio", "serial-drive-own-thread", "rx-busy-poll"}
           & case_features(next(c for c in CASES if c.id == "pico-client"))
           and "peer" in case_features(next(c for c in CASES if c.id == "pico-default"))
           and "gossip" not in case_features(next(c for c in CASES if c.id == "pico-default")))
    # A profile is a compile property, not a capability: a case that differs from another only in
    # its profile must be divided by the same pico, or the ratio moves from both sides at once.
    by_id = {c.id: c for c in CASES}
    expect("a profile twin has its base case's features, and so its pico reference",
           all(case_features(by_id[small]) == case_features(by_id[base])
               for small, base in (("pico-client-small", "pico-client"),
                                   ("capic-client-small", "capic-client"))))
    # A case that reads its features from a profile: the twin of the Windows like-for-like library.
    twin, release = by_id["pico-api-coop-nostd"], by_id["pico-client-coop-nostd"]
    expect("the Linux twin of the Windows like-for-like library reads its features from that "
           "lane's profile and is built in the release client's form",
           twin.features is None and twin.features_from == pico_windows_package.LIKE_PROFILE
           and (twin.package, twin.lib, twin.profile, twin.cargo_configs)
           == (release.package, release.lib, release.profile, release.cargo_configs)
           and all(getattr(case, name) == value for case in (twin, release)
                   for name, value in NOSTD_RELEASE_FORM.items()))
    expect("only a pico case reads its features from a profile, and it states none of its own",
           all(c.package == "wz-capi-pico" and c.features is None
               for c in CASES if c.features_from is not None))
    expect("a case of its own features is built with them, one of the crate's default with none",
           feature_list(Case("t", "p", "l", "a,b", 1)) == "a,b"
           and feature_list(Case("t", "p", "l", None, 1)) is None
           and feature_list(STATEMENT_CASES[0]) == STATEMENT_CASES[0].features)
    if wz_config.kconfiglib_module() is not None:
        like = pico_windows_package.library_features(
            pico_windows_package.resolve_profile(
                wz_config.load_decl(), pico_windows_package.LIKE_PROFILE)["features"],
            wz_config.manifest_features(wz_config.MANIFESTS["pico"]))
        twin_build = case_build(twin, {}, "x86_64-unknown-linux-gnu", linux_gnu, limits={},
                                prefixes=here)
        release_build = case_build(release, {}, "x86_64-unknown-linux-gnu", linux_gnu, limits={},
                                   prefixes=here)
        expect("the twin is built with the features the Windows lane builds its library with, "
               "and linked as the release client is, in a directory of its own",
               feature_list(twin) == ",".join(like)
               and twin_build.link_args == bare_build.link_args == release_build.link_args
               and twin_build.env
               == {k: v.replace(str(case_target(release)), str(case_target(twin)))
                   for k, v in release_build.env.items()}
               and twin_build.lib
               == case_target(twin) / "x86_64-unknown-linux-gnu" / twin.profile / twin.lib
               and twin_build.cmd[-3:] == ("--no-default-features", "--features",
                                           artifact_features(twin.package, ",".join(like)))
               and {"os-host", "peer"} <= case_features(twin))
    # A case with no budget yet: refused with the budget its reading sets.
    expect("a budget is the reading and two percent, rounded up to the hundred",
           budget_for(1_000_000) == 1_020_000 and budget_for(1_049_123) == 1_070_200
           and budget_for(1) == 100)
    expect("a case with no budget yet fails, naming the budget its reading sets",
           len(found := grade(Case("t", "p", "l", "", None), Measured(900, [], 3))) == 1
           and "no budget" in found[0] and str(budget_for(900)) in found[0])
    # STATEMENT: the digest is read from the binary's bytes as the C string the library stores, and
    # graded against the statement's; none, two, or another one are each a finding.
    a, b = "sha256:" + "a" * 64, "sha256:" + "b" * 64
    expect("the digest is the NUL-terminated sha256 string, and only that",
           digests_in(b"\x00" + a.encode() + b"\x00junk" + a.encode() + b"\x00") == (a,)
           and digests_in(a.encode() + b"0\x00") == ()
           and digests_in(a.encode()) == ()
           and digests_in(b"sha256:" + b"A" * 64 + b"\x00") == ())
    with_digest = Measured(900, clean.symbols, 3, (a,))
    expect("a library carrying its statement's digest passes", grade(case, with_digest, a) == [])
    expect("a library carrying another digest, none, or two is a finding",
           len(grade(case, with_digest, b)) == 1 and len(grade(case, clean, a)) == 1
           and len(grade(case, Measured(900, clean.symbols, 3, (a, b)), a)) == 1)
    expect("a library without the digest's door passes carrying none, and carrying its "
           "statement's or any other digest is a finding",
           grade(case, clean, a, door=False) == []
           and len(grade(case, with_digest, a, door=False)) == 1
           and len(grade(case, Measured(900, clean.symbols, 3, (b,)), a, door=False)) == 1)
    digest_cap = wz_config.load_decl()["caps"].get(DIGEST_CAPABILITY, {})
    expect("the digest's door is a capability of the pico ABI and not of the zenoh-c one, so a "
           "pico case's features decide it and every zenoh-c case has it",
           "pico" in digest_cap.get("abis", []) and "c" not in digest_cap.get("abis", [])
           and digest_door(by_id["pico-default"], case_features(by_id["pico-default"]))
           and not digest_door(by_id["pico-client"], case_features(by_id["pico-client"]))
           and digest_door(by_id["capic-client"], case_features(by_id["capic-client"]))
           and all(digest_door(s, case_features(s)) for s in STATEMENT_CASES))
    expect("a case's statement follows its features and its ABI",
           stated_digest(by_id["pico-client"], case_features(by_id["pico-client"]), {})
           == stated_digest(by_id["pico-client-small"], case_features(by_id["pico-client-small"]), {})
           != stated_digest(by_id["pico-default"], case_features(by_id["pico-default"]), {})
           and stated_digest(by_id["capic-client"], case_features(by_id["capic-client"]), {})
           != stated_digest(by_id["pico-client"], case_features(by_id["pico-client"]), {}))
    nostd_case = by_id["pico-client-coop-nostd"]
    nostd_features = case_features(nostd_case)
    lim0 = wz_config.load_decl()["limits"][0]
    choice = next(p for p in wz_config.load_decl()["policies"] if p["kind"] == "choice")
    allowance = wz_config.policy_allows_symbol(choice, wz_config.policy_values(choice)[-1])
    expect("a case's statement follows the limits it is built under, and not a policy's allowance",
           stated_digest(nostd_case, nostd_features, {lim0["kconfig"]: str(lim0["default"] + 1)})
           != stated_digest(nostd_case, nostd_features, {})
           == stated_digest(nostd_case, nostd_features, {allowance: "off"}))
    if wz_config.kconfiglib_module() is not None:
        _, shipped = wz_config.build_of(wz_config.load_decl(), "pico", [])
        preset_limits = case_limits(nostd_case)
        expect("a pico size case is built under its ABI's own preset, the pico bounds among them",
               preset_limits == dict(line.partition("=")[::2] for line in shipped)
               and any(name.startswith("WZ_LIMIT_") for name in preset_limits)
               and all(case_build(nostd_case, {}, "x86_64-unknown-linux-gnu", linux_gnu).env.get(k) == v
                       for k, v in preset_limits.items()))
    # The statement cases: each states something the defaults do not, through names the build
    # script reads, and the grader tells their pass from each way of failing.
    expect("case ids are unique across the size and statement cases",
           len({c.id for c in CASES} | {c.id for c in STATEMENT_CASES})
           == len(CASES) + len(STATEMENT_CASES))
    decl = wz_config.load_decl()
    expect("every statement case states a limit and a policy the declaration reads, off its "
           "default, and the zenoh-c case turns a layout arm on",
           all({k for k, _ in s.env} & {x["kconfig"] for x in decl["limits"]}
               and {k for k, _ in s.env} & {p["kconfig"] for p in decl["policies"]}
               and stated_digest(s, case_features(s)) != wz_config.env_statement(
                   decl, case_abi(s), sorted(case_features(s)), {}, {})["digest"]
               for s in STATEMENT_CASES)
           and any(case_abi(s) == "c" and set(wz_config.arm_switches(decl, "c")) & case_features(s)
                   for s in STATEMENT_CASES))
    s0 = STATEMENT_CASES[0]
    expect("a statement case passes on its digest alone and fails on another, none, or a case "
           "that states nothing",
           grade_statement(s0, (a,), a, b) == [] and len(grade_statement(s0, (b,), a, b)) == 1
           and len(grade_statement(s0, (), a, b)) == 1
           and len(grade_statement(s0, (a,), a, a)) == 1
           and len(grade_statement(s0, (), a, b, door=False)) == 2)
    inherited = statement_env(s0, {"WZ_LIMIT_MAX_KEYEXPR_BYTES": "999", "RUSTFLAGS": "-Cx"})
    expect("a statement case builds with its own limits and policies, none of the shell's, in "
           "the environment it was handed",
           "WZ_LIMIT_MAX_KEYEXPR_BYTES" not in inherited and inherited["RUSTFLAGS"] == "-Cx"
           and all(inherited[k] == v for k, v in s0.env))
    # Where and when the build ran: a library that holds a build path is a finding, and a
    # reference built under other C flags or another epoch is never read back as this one.
    expect("a library holding a build path is a finding that names the prefix",
           purity_findings("t", ()) == []
           and len(purity_findings("t", ("/srv/tree",))) == 1
           and "/srv/tree" in purity_findings("t", ("/srv/tree",))[0])
    ref_env = {"CFLAGS": "-ffile-prefix-map=/srv/tree=/wz", build_normalization.EPOCH: "1"}
    key = reference_key("pin", "cc", ["-DZ=1"], ref_env)
    other_epoch = {**ref_env, build_normalization.EPOCH: "2"}
    expect("a pico reference is keyed by the C flags and the epoch it was built under",
           key != reference_key("pin", "cc", ["-DZ=1"], {**ref_env, "CFLAGS": ""})
           and key != reference_key("pin", "cc", ["-DZ=1"], other_epoch)
           and key == reference_key("pin", "cc", ["-DZ=1"], dict(ref_env)) and len(key) == 16)
    expect("every case's profile is one crates/Cargo.toml defines",
           {c.profile for c in CASES} <= {"release"} | set(
               re.findall(r"^\[profile\.([\w-]+)\]", (CRATES / "Cargo.toml").read_text(), re.M)))
    # THE SHIPPING PROFILE: a case reads the library a deployer receives, not the daily build.
    profiles = cargo_profiles((CRATES / "Cargo.toml").read_text(encoding="utf-8"))
    expect("the shipping profile links one program: fat LTO and one codegen unit",
           profiles.get(SHIP_PROFILE, {}).get("lto") == '"fat"'
           and profiles.get(SHIP_PROFILE, {}).get("codegen-units") == "1")
    expect("every size case is built with the shipping profile or one inheriting it",
           all(inherits_from(c.profile, SHIP_PROFILE, profiles) for c in CASES))
    chain = cargo_profiles('[profile.a]\nlto = "fat"\n[profile.b]\ninherits = "c"\n[profile.c]\n'
                           'inherits = "a"\n[profile.c.package.x]\nopt-level = "s"\n'
                           '[profile.d]\ninherits = "e"\n[profile.e]\ninherits = "d"\n')
    expect("a profile inherits through its chain, and a loop or another base is no inheritance",
           inherits_from("b", "a", chain) and inherits_from("a", "a", chain)
           and not inherits_from("d", "a", chain) and not inherits_from("release", "a", chain)
           and chain["c"] == {"inherits": '"a"'})
    expect("the Windows lane builds its packages and its client with the C library's configuration",
           pico_windows_package.NOSTD_CONFIG == NOSTD_CONFIG)
    # THE PICO CEILING (D9): synthetic readings against each kind of row, and the committed table.
    def rd(wz: int, pico: int, date: str = "2026-11-21", tc: str = "cc 1") -> dict:
        return ceiling_reading(wz, pico, "e1ab223a28aa", tc, date)

    debt = "debt-known"
    set_from = rd(2_520_000, 1_000_000, "2026-11-20")
    ratchet = ceiling_row(set_from, debt)
    expect("a reading that is no WIN sets a ratchet at its ratio, rounded up, under its debt",
           ratchet == {"ratio_at_most": 2.52, "debt": debt, "reading": set_from}
           and ceiling_row(rd(1_016_594, 403_086), debt)["ratio_at_most"] == 2.5221
           and ceil_ratio(3, 1) == 3.0 and ceil_ratio(1, 3) == 0.3334)
    expect("a reading with no registered debt sets the placeholder, which a grade refuses",
           ceiling_row(set_from, None)["debt"] == DEBT_PLACEHOLDER
           and ceiling_row(set_from, DEBT_PLACEHOLDER)["debt"] == DEBT_PLACEHOLDER
           and any("registered debt" in f
                   for f in grade_ceiling("t", ceiling_row(set_from, None), set_from)[0]))
    win = rd(990, 1000)
    locked = ceiling_row(win, debt)
    expect("a WIN reading sets a locked row",
           locked == {"verdict": "win", "debt": debt, "reading": win}
           and ceiling_row(win, DEBT_PLACEHOLDER) == {"verdict": "win", "reading": win})
    expect("a locked case that reads WIN passes", grade_ceiling("t", locked, rd(999, 1000)) == ([], []))
    expect("a locked case that reads LOSS or TIE fails, and no budget clears it",
           all(len(f) == 1 and "locked at WIN" in f[0] and n == []
               for f, n in (grade_ceiling("t", locked, rd(1001, 1000)),
                            grade_ceiling("t", locked, rd(1000, 1000)))))
    expect("a ratchet case at its ratio passes, and so does one inside the tolerance",
           grade_ceiling("t", ratchet, rd(2_520_000, 1_000_000)) == ([], [])
           and grade_ceiling("t", ratchet, rd(2_582_000, 1_000_000)) == ([], []))
    over, _ = grade_ceiling("t", ratchet, rd(2_584_000, 1_000_000))
    expect("a ratchet case over the tolerance fails, naming the reading it was set from",
           len(over) == 1 and "over its ratchet 2.52" in over[0] and "2026-11-20" in over[0]
           and "read with" not in over[0])
    expect("a ratchet failure on another toolchain names both",
           "the row was read with cc 1, this run with cc 2"
           in grade_ceiling("t", ratchet, rd(2_600_000, 1_000_000, tc="cc 2"))[0][0])
    expect("the tolerance is relative to the ratchet and is 2.5 percent, the measured host spread",
           RATIO_TOLERANCE == 0.025
           and grade_ceiling("t", ceiling_row(rd(10_000, 10_000), debt), rd(10_249, 10_000))[0] == []
           and grade_ceiling("t", ceiling_row(rd(10_000, 10_000), debt), rd(10_251, 10_000))[0] != [])
    lower, tighter = grade_ceiling("t", ratchet, rd(2_400_000, 1_000_000))
    expect("a ratchet case well under its ratio passes and prints the tighter row to commit",
           lower == [] and len(tighter) == 1 and '"ratio_at_most": 2.4' in tighter[0])
    won, _ = grade_ceiling("t", ratchet, rd(999_999, 1_000_000))
    expect("a ratchet case that reads WIN fails and prints the locked row to commit",
           len(won) == 1 and '"verdict": "win"' in won[0] and "close " + debt in won[0])
    unfilled = {"ratio_at_most": None, "debt": DEBT_PLACEHOLDER, "reading": None}
    blank, _ = grade_ceiling("t", unfilled, set_from, measure_command("t"))
    expect("an unfilled row fails, saying how to fill it with this run's row",
           len(blank) == 1 and "--measure t" in blank[0] and '"ratio_at_most": 2.52' in blank[0])
    # A ratio is read only from two libraries that hold no build path.
    clean_ref = Reference(text=1_000_000, pin="e1ab223a28aa", toolchain="cc 1", refused=())
    clean_got = Measured(text=2_520_000, symbols=[], exports=0)
    held_got = Measured(text=2_520_000, symbols=[], exports=0, leaked=("/srv/tree",))
    held_ref = Reference(text=1_000_000, pin="e1ab223a28aa", toolchain="cc 1", refused=(),
                         leaked=("/srv/tree",))
    expect("a case is read against its reference only when neither library holds a build path",
           case_reading(clean_got, clean_ref, "2026-11-20") == set_from
           and case_reading(clean_got, None, "2026-11-20") is None
           and case_reading(held_got, clean_ref, "2026-11-20") is None
           and case_reading(clean_got, held_ref, "2026-11-20") is None)
    unpacked_got = Measured(text=2_520_000, symbols=[], exports=0,
                            link_args=(PACKED_RELOCS_LINK,))
    unpacked_ref = Reference(text=1_000_000, pin="e1ab223a28aa", toolchain="cc 1", refused=(),
                             link_args=(PACKED_RELOCS_LINK,), relr=True)
    packed_got = Measured(text=2_520_000, symbols=[], exports=0,
                          link_args=(PACKED_RELOCS_LINK,), relr=True, relr_need=True)
    packed_ref = Reference(text=1_000_000, pin="e1ab223a28aa", toolchain="cc 1", refused=(),
                           link_args=(PACKED_RELOCS_LINK,), relr=True, relr_need=True)
    expect("a case is read against its reference only when both are linked as asked",
           case_reading(packed_got, packed_ref, "2026-11-20") == set_from
           and case_reading(unpacked_got, packed_ref, "2026-11-20") is None
           and case_reading(packed_got, unpacked_ref, "2026-11-20") is None)
    # The table's shape, static: the population, the two row forms and their readings.
    good = {"schema": HOST_CEILING_SCHEMA, "cases": {"a": ratchet, "b": locked, "c": unfilled}}
    expect("a table with one well-formed row per case passes",
           table_findings(good, ["a", "b", "c"]) == [])
    expect("a case with no row, and a row for no case, are findings",
           len(table_findings(good, ["a", "b", "c", "d"])) == 1
           and len(table_findings(good, ["a", "b"])) == 1
           and len(table_findings(None, ["a"])) == 1
           and len(table_findings({"schema": 0, "cases": {}}, [])) == 1)
    bad_rows = (
        {**ratchet, "verdict": "win"},  # both forms
        {"debt": debt, "reading": set_from},  # neither
        {**ratchet, "ratio_at_mots": 2.52},  # an unknown key
        {**ratchet, "ratio_at_most": 2.6},  # a bound no reading set
        {**locked, "verdict": "tie"},  # a lock on anything but WIN
        {**locked, "reading": set_from},  # a lock on a reading that is no WIN
        {**ratchet, "reading": {**set_from, "wz_text": "2520000"}},  # a reading that is no count
        {**unfilled, "reading": set_from},  # an unfilled row that states a reading
        {"ratio_at_most": 1.0, "debt": debt, "reading": rd(999_999, 1_000_000)},  # a WIN ratchet
    )
    expect("each malformed row is a finding",
           all(row_findings("t", r) for r in bad_rows))
    committed = load_ceiling()
    expect("the committed table holds every pico case of CASES and the release DLL of each width "
           "of Windows, one well-formed row each",
           table_findings(committed, ceiling_cases()) == []
           and set(ceiling_rows(committed)) == set(ceiling_cases())
           and {c.id for c in CASES if c.package == "wz-capi-pico"} <= set(ceiling_cases())
           and set(pico_windows_package.CEILING_CASES) <= set(ceiling_cases())
           and set(pico_windows_package.FEATURE_CASES) <= set(ceiling_cases())
           and len(pico_windows_package.CEILING_CASES) == len(pico_windows_package.ARCHES))
    expect("an unfilled row names no command when its lane gives none",
           "prints the same row" not in grade_ceiling("t", unfilled, set_from)[0][0])
    every = [c.id for c in CASES] + [c.id for c in STATEMENT_CASES]
    weights = census_shard_plan.read_weights(CASE_WEIGHTS.read_text(encoding="utf-8"))
    expect("the shards partition the cases, size and statement alike, for one to four shards",
           all(sorted(i for k in range(n) for i in shard_cases(n, k, weights, []))
               == sorted(every) for n in range(1, 5)))
    expect("an empty table still partitions them, each case planned at the fallback",
           sorted(i for k in range(2) for i in shard_cases(2, k, {}, [])) == sorted(every))
    stale: list[str] = []
    shard_cases(2, 0, {**weights, "no-such-case": 1}, stale)
    expect("a row for no case is named, not refused",
           any(n.startswith("no-such-case has a weight") for n in stale))
    expect("a shard builds its cases in the gate's order",
           all(ids == [i for i in every if i in set(ids)]
               for ids in (shard_cases(2, k, weights, []) for k in range(2))))
    # The parts of the fleet, and the builds at once.
    expect("the parts the planner is given are the shards, each read back as the shard it names",
           fleet_parts() == [f"shard-{k}-of-{FLEET_PARTS}" for k in range(FLEET_PARTS)]
           and [part_shard(p) for p in fleet_parts()]
           == [(FLEET_PARTS, k) for k in range(FLEET_PARTS)]
           and sorted(i for p in fleet_parts() for i in shard_cases(*part_shard(p), weights, []))
           == sorted(every))

    def no_part(name: str) -> bool:
        try:
            part_shard(name)
        except ValueError as e:
            return "shard-0-of-" in str(e)
        return False

    expect("a name that is no part is refused, naming the parts",
           all(no_part(n) for n in ("shard-2-of-2", "shard-0-of-0", "shard-01-of-2", "shard-0",
                                    "part-0-of-2", "shard-0-of-2 ")))
    expect("the builds run as many at once as there are builds, cores and memory for, and one at "
           "least, the cores shared among them",
           build_width(24, 22, 32768, 4096) == (8, 3)
           and build_width(24, 22, None, 4096) == (22, 1)
           and build_width(3, 22, None, 4096) == (3, 8)
           and build_width(24, 4, 14000, 4096) == (3, 2)
           and build_width(24, 22, 1000, 4096) == (1, 22)
           and build_width(0, 4, None, 4096) == (1, 4))
    expect("the cores and the memory are bx's grant, else the affinity and the available memory",
           granted({"BX_GRANT_CORES": "22", "BX_GRANT_MEM_MB": "32768"}, 64, 100000)[:2]
           == (22, 32768)
           and granted({}, 6, 12000)[:2] == (6, 12000)
           and granted({}, 0, None)[:2] == (1, None)
           and granted({"BX_GRANT_CORES": "0", "BX_GRANT_MEM_MB": "4G"}, 6, 900)[:2] == (6, 900)
           and "BX_GRANT_CORES" in granted({"BX_GRANT_CORES": "2"}, 6, None)[2]
           and "the memory unknown" in granted({"BX_GRANT_CORES": "2"}, 6, None)[2])
    with tempfile.TemporaryDirectory() as tmp:
        meminfo = pathlib.Path(tmp) / "meminfo"
        meminfo.write_text("MemTotal:       65536000 kB\nMemAvailable:   32768000 kB\n",
                           encoding="ascii")
        read = available_mb(meminfo)
        meminfo.write_text("MemTotal:       65536000 kB\n", encoding="ascii")
        expect("the available memory is read from the kernel's line, and is unknown without it",
               read == 32000 and available_mb(meminfo) is None
               and available_mb(pathlib.Path(tmp) / "absent") is None)
    expect("the builds start heaviest first, the rest in the order given",
           build_order(["a", "b", "c", "d"], {"b": 5, "c": 9, "d": 5}) == ["c", "b", "d", "a"])
    print(f"  capability-cost selftest: {ok}/{ok + bad} arm(s) pass")
    return 0 if bad == 0 else 1


def main(argv: list[str]) -> int:
    if len(argv) < 2 or argv[1] not in ("--check", "--measure", "--selftest", "--parts") or (
        argv[1] in ("--selftest", "--parts") and len(argv) != 2
    ):
        print(__doc__, file=sys.stderr)
        return 2
    if argv[1] == "--selftest":
        return cmd_selftest()
    if argv[1] == "--parts":
        print("\n".join(fleet_parts()))
        return 0
    parser = argparse.ArgumentParser(prog=f"capability_cost_gate.py {argv[1]}", add_help=False)
    parser.add_argument("--shards", type=int)
    parser.add_argument("--shard", type=int)
    parser.add_argument("--part")
    parser.add_argument("ids", nargs="*")
    try:
        args = parser.parse_intermixed_args(argv[2:])
    except SystemExit:
        return 2
    shard = None
    if args.part is not None:
        if args.shards is not None or args.shard is not None:
            print("  capability-cost: give a part or --shards N --shard K, not both",
                  file=sys.stderr)
            return 2
        try:
            shard = part_shard(args.part)
        except ValueError as e:
            print(f"  capability-cost: {e}", file=sys.stderr)
            return 2
    elif args.shards is not None or args.shard is not None:
        if args.shards is None or args.shard is None or not 0 <= args.shard < args.shards:
            print("  capability-cost: give --shards N and --shard K with 0 <= K < N",
                  file=sys.stderr)
            return 2
        shard = (args.shards, args.shard)
    # A line at a time, so the hosted log stamps each case when it ends, not when a buffer fills.
    sys.stdout.reconfigure(line_buffering=True)
    return cmd_check(measure_only=argv[1] == "--measure", only=args.ids, shard=shard)


if __name__ == "__main__":
    sys.exit(main(sys.argv))
