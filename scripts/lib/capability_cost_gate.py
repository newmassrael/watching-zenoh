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
                 with, read from its own bytes). Every case is a build
                 whose configuration is known, so each is also the end-to-end witness that a
                 library states the build it is.

The size cases state no limit or policy and turn no zenoh-c layout arm on. [`STATEMENT_CASES`]
are the builds that do, graded on fact 5 alone: a limit and a policy stated through the build's
environment, on each ABI, and the shared-memory arm of the zenoh-c drop-in.

PRESENCE is what makes ABSENCE mean something. A forbidden pattern that no build can match is a
check that cannot fail (`--selftest` pins the matcher, and the full builds here are the live
control: every pattern a client build is forbidden is REQUIRED of a build that has the plane).

## What a budget is, and is not

A budget is a ceiling a measured size sits under with a small margin, not a target. It moves in
the commit that moves the size, with the new measurement stated; a size that grew without anyone
choosing it is what this gate exists to refuse. The sizes are `size` text on the pinned toolchain
(`rust-toolchain.toml`) and are comparable only to themselves: a different compiler moves them,
which is why the margin is a percentage and not a byte count.

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
table. The workspace's own configuration has flags for windows-msvc only. What the rule does not
remove is the toolchain: a host with another C compiler or linker builds other bytes from the
same tree, and its reading is comparable only to readings made with that toolchain, so each pico
case prints the linker of both of its libraries as each library's `.comment` names it
(`linker_of`).

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

Usage:
    capability_cost_gate.py --check [ID...]    build every case (or the named ones), grade it
    capability_cost_gate.py --measure [ID...]  build the same and print what was measured,
                                               with each pico case's ceiling row to commit
    capability_cost_gate.py --selftest     grade the grader on synthetic input
"""

from __future__ import annotations

import datetime
import hashlib
import io
import json
import math
import os
import pathlib
import re
import subprocess
import sys
import tarfile
from collections.abc import Mapping
from dataclasses import dataclass, field
from fractions import Fraction

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import wz_config  # noqa: E402  (the one declaration, and its resolver)
import build_normalization  # noqa: E402  (the one rule that keeps paths and time out of bytes)
from artifact_root import artifact  # noqa: E402  (a sibling: where products are)
from kit_compare import verdict_size  # noqa: E402  (decision D1's size verdict, one copy)

ROOT = pathlib.Path(__file__).resolve().parents[2]
CRATES = ROOT / "crates"
PICO_SOURCE = ROOT / "vendor" / "zenoh-pico"
# The reference builds, one directory per (pin, switches, toolchain), so a run that asks for the
# same build again reads it instead of building it. Products, so under the artifact root when one
# is set (scripts/lib/artifact-root.sh), like the cargo target directory below.
PICO_BUILDS = artifact("crates/target/pico-reference")
# A case's library is under the directory of the cargo profile it was built with. The size cases
# name it to cargo rather than inherit one: a target directory outside the checkout and the
# artifact root would put paths no mapping covers into the library, and the gate would read a
# library from here that cargo wrote elsewhere.
TARGET = artifact("crates/target")

# The features every pico build has, read from the one place that states them, the declaration's
# `[base] pico`, so a feature the crate's default gains (or loses) reaches the cases from there
# and not from a second copy here; `wz_config --selftest` holds the cases to the empty selection.
PICO_BASE = ",".join(
    wz_config.read_decl_toml(wz_config.DECL.read_text(encoding="utf-8"))["base"]["pico"]
)

# The configuration of the library without `std` (`crates/.cargo/capi-nostd.toml`), which a case
# composes with the profile of the same name.
NOSTD_CONFIG = ".cargo/capi-nostd.toml"

# Planes a build without the capability must not carry, as demangled-symbol patterns. The same
# patterns are REQUIRED of a build that has the capability.
ACCEPT = r"accept_loop::(accept_any|accept_loop_|AcceptEvent|SpawnedFaces|next_spawned)"
RESPONDER = r"scouting_responder|ScoutingResponder"
SCOUTING = r"scouting_glue|scouting_fanout|ScoutFanOut"
GOSSIP = r"gossip_plane|GossipPlane"
UDP = r"udp_pipeline|UdpDriver|udp_writer"
CLOCK = r"uhlc|NodeClock"
ADVANCED = r"advanced_publisher|AdvancedPublisher"
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
# panic strategy, and one built without it (`os-posix`, docs/c-abi-engine-and-memory.md P4) has none
# of.
STD_RUNTIME = r"std::backtrace_rs::|rustc_demangle::|addr2line::"
# The Keccak permutation of zenoh's SHAKE128 derivation of a session's initial sequence number,
# which the tokio engine announces by and the cooperative pico client does not
# (`wz-session-core`'s `initial-sn-compact`, zenoh-pico drawing that origin at random).
KECCAK = r"keccak::"
# The engine a pico build runs its sessions on (`engine-tokio` / `engine-coop`,
# docs/capi-pico-on-coop-engine.md): a build of one links none of the other.
TOKIO_ENGINE = r"wz_capi_core::|wz_runtime_tokio::"
COOP_ENGINE = r"wz_capi_coop::"
# The cooperative engine's listening role: the ports it holds and the faces it makes of what they
# accept (`wz-capi-coop`'s `listen`).
COOP_LISTEN = r"wz_capi_coop::engine::Listening<"
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
    max_text: int
    forbid: tuple[str, ...] = ()
    require: tuple[str, ...] = ()
    exports: int | None = None
    # The cargo profile (`crates/Cargo.toml`). It is not a capability, so it leaves the pico
    # reference alone: that is derived from the features only.
    profile: str = "release"
    # Patterns no symbol the library leaves UNDEFINED may match (`nm -u`): a name the library
    # expects whoever loads it to define, which no C program linking it does.
    forbid_undefined: tuple[str, ...] = ()
    # Patterns each of which some library the library names as needed (DT_NEEDED) must match: a
    # library that names no C library leaves its calls unversioned, and the loader binds an
    # unversioned call to the oldest version of the symbol.
    require_needed: tuple[str, ...] = ()
    # The cargo configuration files whose flags the build takes (paths from `crates/`, read by
    # `config_rustflags`), with the host's own target named (`--target`), so that what a file
    # gives the library's crates does not reach the build scripts. Empty: the profile alone.
    cargo_configs: tuple[str, ...] = ()
    note: str = field(default="", compare=False)


# Budgets are the measured text plus about two percent. See the module doc.
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
    # document layer of step 4a (`policy_document::{read_wz, compose, resolve_document}`, the
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
    # `wz_ext_config_policy` +1,359 and `wz_ext_config_profile` +862, the composition
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
    # document's `wz/limits` read with named refusals, and the three doors that open under it.
    # +12,802 here, both trees (`b58b71c19` and the round's head) built on one machine. The
    # symbol diff of pico-client-small (+6,580 of text symbols; .text +6,864, .data.rel.ro
    # +4,904, .rodata +1,920, .eh_frame +1,512): the reader of `wz/limits` (`compose_limits`
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
         forbid=(ACCEPT, RESPONDER, SCOUTING, GOSSIP, UDP, CLOCK, ADVANCED, THREADED,
                 CONNECTIVITY, MULTICAST, COOP_ENGINE),
         require=(SINGLE_THREADED, TOKIO_ENGINE, KECCAK),
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
         forbid=(ACCEPT, RESPONDER, SCOUTING, GOSSIP, UDP, CLOCK, ADVANCED, THREADED,
                 CONNECTIVITY, MULTICAST),
         require=(SINGLE_THREADED,), profile="capi-small",
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
         forbid=(ACCEPT, RESPONDER, SCOUTING, GOSSIP, CLOCK, ADVANCED, THREADED, CONNECTIVITY,
                 MULTICAST),
         require=(UDP, SINGLE_THREADED),
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
    # 109,800 bytes more on pc2 once `wz_ext_config_device_requires` (`device_requires.rs`, a
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
    Case("pico-client-coop", "wz-capi-pico", "libwz_capi_pico.so", "engine-coop,link-udp",
         # 2026-11-21 -- the fifth PoC set: +8,732 on one host against main b58b71c19, by symbol:
         # a droppable publish behind a held session is dropped per face and owed to the other faces
         # (`fan_out` 1,667, `publish` +1,558, `send_handed` 735, `for_held` +507, the owed leg's
         # clone 761), the ABI object pools' slot release and registry (about 800); the owed queue is
         # taken whole rather than drained, which kept 3,700 of a drain's code out.
         # 2026-11-22 -- the step 4b carry and run 44895098050's reading:
         # 1,047,506 hosted, +9,488 on one machine.
         1_060_500,
         forbid=(ACCEPT, RESPONDER, SCOUTING, GOSSIP, CLOCK, ADVANCED, THREADED, CONNECTIVITY,
                 MULTICAST, TOKIO_ENGINE, COOP_LISTEN, KECCAK),
         require=(UDP, SINGLE_THREADED, COOP_ENGINE, STD_RUNTIME),
         exports=444,
         note="444 exports with the config doors of the open's policies "
              "(`wz_ext_config_policy`, `wz_ext_config_profile`, in every build); "
              "442 with the conformance digest's door (`wz_ext_conformance_digest`, "
              "decision C15, in every build), 441 before. "
              "The single-threaded client of pico-client-udp on the cooperative engine: "
              "888,223 measured, 2.20 times the same pico, against pico-client-udp's 4.63. It "
              "grew from 867,811 by what pico's client has by default and it lacked: the "
              "KeepAlive and Close codecs, a lost link dialled again with the session's "
              "declarations sent again over it (881,043), and a read that waits on its link "
              "outside the session's lock. 897,831 on 2026-10-25 (budget 895,000 before), "
              "read bisected on the commits of that day: 893,251 with the timestamp policy "
              "(`d6d659a10`), 894,515 with the faces the port reports on both engines "
              "(`944fad43c`), 895,491 with a Push's frame sized from its message "
              "(`77df225a7`, the commit that crossed the old budget); the 2,340 bytes between "
              "that and the head are one commit: 895,531 before and 897,795 with the "
              "per-link replay cursor over the six declaration lists (`5024d4e0f`, +2,264); "
              "905,204 on hosted CI on 2026-10-26, +204 over the old budget of 905,000, with the "
              "key set's gate and the engine port's advanced plane (pico-client's note above). Its "
              "exports are pico-client's 441: the runtime's critical "
              "sections are a lock of the process (`host-lock`), so no `critical-section` "
              "implementation is linked, whose two symbols a cdylib exported beside the C ABI "
              "(443 before). 912,823 on pc2 on 2026-10-26 against 899,119 at the commit before "
              "the engine held its session on the slot observer and one link's peer tables "
              "(+13,704, the budget moved over it): on the build machine the text grew 12,696 "
              "(965,003 to 977,699 in the scout build), the symbols gained or lost netting "
              "+4,472 (the observer's dispatch, 11,831 for the application observer's 11,951, "
              "the peer tables' construction and drop and the subscriber reconcile, which the "
              "application observer did as it was told) and those kept growing 5,802 (the "
              "subscriber table's owned dispatch +4,402 and the Put's owned form +3,567, less "
              "what shrank), which is where the compiler placed code it had inlined elsewhere. "
              "930,067 on pc2 on 2026-10-27 against 912,823 before the engine held its links as a "
              "table of faces (+17,244, the budget moved over it; 928,843 with the observer's "
              "dispatch reading the other faces through a trait object, 1,224 less, and "
              "monomorphic over them it is the slot images' for free, whose other faces are none): "
              "+15,585 in the scout build on "
              "the build machine (978,075 to 993,660) before that choice, whose symbols say what a "
              "second face costs: "
              "the observer's dispatch that counts the other faces' declarations is 11,962 "
              "against 11,831, the polling of every link 4,163 against the one link's 3,487, the "
              "face tables' drop 1,814 against the peer tables' 886, the two matching-listener "
              "declarations that were inline 1,674, the filter's read over every face's peer "
              "+1,369, the loss flush +1,621, and the removal of a face and of the accepted ones "
              "about 1,000. 931,511 on pc2 after the policy that states the width of the sequence "
              "numbers (`1549a936f`) read the width where the handshake had a literal: 1,444 more "
              "in this case (the next seven cases read +1,200 to +1,500), and every cooperative "
              "budget keeps about 1,200 over its reading since. 934,883 on pc2 on 2026-10-27, "
              "2,183 over the old budget of 932,700, the day the listening role came: the "
              "engine's shared entropy, the handshake run in either role and the wait on "
              "several links are in a build that listens to nothing, with the main of that day "
              "merged; the two are not measured apart. The budget follows the hosted reading, "
              "which reads 3,300 to 4,400 over pc2, so it is moved to the pc2 reading and "
              "5,500, an estimate the first hosted run replaces; the listening build's own "
              "text is a case of the step that gives pico a listener"),
    # The same client built as the host library without `std` (`os-posix`, phase P4 of
    # docs/c-abi-engine-and-memory.md): the same capabilities and C symbols, no standard library,
    # the C library's heap and `abort` in its place, and no unwinding (`capi-nostd`, whose
    # configuration drops the unwind tables). The budget is pico-client-coop's, a ceiling the
    # form sits under by construction until its first reading sets its own; its ceiling row is
    # unfilled until then (`--measure pico-client-coop-nostd` prints both).
    Case("pico-client-coop-nostd", "wz-capi-pico", "libwz_capi_pico.so", "os-posix,link-udp",
         1_049_200,
         forbid=(ACCEPT, RESPONDER, SCOUTING, GOSSIP, CLOCK, ADVANCED, THREADED, CONNECTIVITY,
                 MULTICAST, TOKIO_ENGINE, COOP_LISTEN, STD_RUNTIME, KECCAK),
         require=(UDP, SINGLE_THREADED, COOP_ENGINE),
         forbid_undefined=(r"^rust_eh_personality$",),
         require_needed=(r"^libc\.so",),
         exports=445, profile="capi-nostd", cargo_configs=(NOSTD_CONFIG,),
         note="pico-client-coop's capabilities and its 444 C exports, and `rust_eh_personality`: "
              "the prebuilt `core`'s unwind tables name it and LTO keeps the reference "
              "(measured: undefined in the first build, so no C program linked), so the library "
              "defines it, as an abort that nothing reaches (`src/os/no_std_host.rs`), and a "
              "`#[no_mangle]` item of a cdylib is exported. No `critical-section` "
              "implementation: the locks are the host's own calls through `wz-host-sync`"),
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
         "engine-coop,link-udp,unstable-api", 1_172_500,
         forbid=(ACCEPT, RESPONDER, SCOUTING, GOSSIP, CLOCK, ADVANCED, THREADED, CONNECTIVITY,
                 MULTICAST, TOKIO_ENGINE, COOP_LISTEN),
         require=(UDP, SINGLE_THREADED, COOP_ENGINE),
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
         "engine-coop,link-udp,local-subscriber", 1_067_300,
         forbid=(ACCEPT, RESPONDER, SCOUTING, GOSSIP, CLOCK, ADVANCED, THREADED, CONNECTIVITY,
                 MULTICAST, TOKIO_ENGINE, COOP_LISTEN),
         require=(UDP, SINGLE_THREADED, COOP_ENGINE),
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
         "engine-coop,link-udp,unstable-api,connectivity", 1_242_400,
         forbid=(ACCEPT, RESPONDER, SCOUTING, GOSSIP, CLOCK, ADVANCED, THREADED, MULTICAST,
                 TOKIO_ENGINE, COOP_LISTEN),
         require=(UDP, SINGLE_THREADED, COOP_ENGINE, CONNECTIVITY),
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
         "engine-coop,link-udp,admin-space", 1_433_800,
         forbid=(ACCEPT, RESPONDER, SCOUTING, GOSSIP, CLOCK, ADVANCED, THREADED, CONNECTIVITY,
                 MULTICAST, TOKIO_ENGINE, COOP_LISTEN),
         require=(UDP, SINGLE_THREADED, COOP_ENGINE),
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
    # `wz_ext_get_to_peer` +314, the leg reply moved out of `fan_get` (+2,934 / -2,917).
    # 2026-11-21 -- step 4b rounds 2 to 4, as pico-client's note of this day says: +16,320 on
    # one machine.
    Case("pico-client-coop-query", "wz-capi-pico", "libwz_capi_pico.so",
         # 2026-11-20 -- step 4b round 2a, as pico-client-coop's note says: +492 on pc2.
         # 2026-11-20 -- step 4b round 2b, as pico-client-coop's note says: +136 on pc2.
         # 2026-11-21 -- the fifth PoC set, as pico-client-coop's note says: +8,868 on one host.
         # 2026-11-22 -- the step 4b carry and run 44895098050's reading:
         # 1,373,248 hosted, +10,300 on one machine.
         "engine-coop,link-udp,query,queryable", 1_387_100,
         forbid=(ACCEPT, RESPONDER, SCOUTING, GOSSIP, CLOCK, ADVANCED, THREADED, CONNECTIVITY,
                 MULTICAST, TOKIO_ENGINE, COOP_LISTEN),
         require=(UDP, SINGLE_THREADED, COOP_ENGINE),
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
         "engine-coop,link-udp,query,queryable,local-queryable", 1_403_300,
         forbid=(ACCEPT, RESPONDER, SCOUTING, GOSSIP, CLOCK, ADVANCED, THREADED, CONNECTIVITY,
                 MULTICAST, TOKIO_ENGINE, COOP_LISTEN),
         require=(UDP, SINGLE_THREADED, COOP_ENGINE),
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
         "engine-coop,link-udp,scout", 1_144_700,
         forbid=(ACCEPT, RESPONDER, SCOUTING, GOSSIP, CLOCK, ADVANCED, THREADED, CONNECTIVITY,
                 MULTICAST, TOKIO_ENGINE, COOP_LISTEN),
         require=(UDP, SINGLE_THREADED, COOP_ENGINE, COOP_SCOUT),
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
         "engine-coop,link-udp,peer", 1_208_400,
         forbid=(ACCEPT, RESPONDER, SCOUTING, GOSSIP, CLOCK, ADVANCED, THREADED, CONNECTIVITY,
                 MULTICAST, TOKIO_ENGINE),
         require=(UDP, SINGLE_THREADED, COOP_ENGINE, COOP_SCOUT, COOP_LISTEN),
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
         forbid=(GOSSIP, CLOCK, ADVANCED, THREADED, CONNECTIVITY, MULTICAST),
         require=(ACCEPT, RESPONDER, SCOUTING, UDP, SINGLE_THREADED),
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
         forbid=(SINGLE_THREADED,),
         require=(ACCEPT, RESPONDER, SCOUTING, GOSSIP, UDP, CLOCK, ADVANCED, THREADED,
                  CONNECTIVITY, MULTICAST),
         exports=811,
         note="every capability on: the symbol count is the drop-in's. 811 with the three pico "
              "internals clang emits calls to into every program of the unstable arm "
              "(`header_internals`: `_z_cancellation_token_clear`, "
              "`_z_cancellation_token_remove_on_cancel_handler`, `_z_sync_group_notifier_drop`). "
              "808 with the config "
              "doors of the open's policies (`wz_ext_config_policy`, `wz_ext_config_profile`; "
              "`wz_ext_config_document` is behind `config-document`, off). 806 with the door that "
              "tells a session's peers its declarations again (`wz_ext_redeclare`, unstable "
              "surface). 809 -> 802 when the "
              "seven single-threaded entry points left the multi-threaded arm; 804 with the "
              "conformance digest's door (`wz_ext_conformance_digest`, decision C15); 803 with the "
              "door that answers what a configuration asks of the operating system "
              "(`wz_ext_config_device_requires`); 805 with the get addressed to one node "
              "(`wz_ext_get_to_peer`, in every build with the query plane). 4,216,542 "
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
                 ROUTER_NODE, ACCEPT_HANDSHAKE, CONFIG_VERDICT)),
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
    Case("capic-default", "wz-capi-c", "libwz_capi_c.so", None, 11_252_900,
         require=(ROUTER_NODE, ACCEPT, RESPONDER, SCOUTING, GOSSIP, UDP, CLOCK, ADVANCED,
                  MULTICAST, ACCEPT_HANDSHAKE, CONFIG_VERDICT),
         exports=837,
         note="837 exports with the conformance digest's door (`wz_capi_c_conformance_digest`, "
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
         9_454_348,
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


# The conformance digest as the library stores it: a C string, so the NUL is part of the match and
# a longer hex run or an unterminated one is not taken for it.
DIGEST_IN_BINARY = re.compile(rb"sha256:[0-9a-f]{64}\x00")


def digests_in(data: bytes) -> tuple[str, ...]:
    return tuple(sorted({m.group(0)[:-1].decode("ascii") for m in DIGEST_IN_BINARY.finditer(data)}))


def case_abi(case: Case) -> str:
    return {"wz-capi-pico": "pico", "wz-capi-c": "c"}[case.package]


def stated_digest(case: Case | StatementCase, features: set[str]) -> str:
    """The digest the conformance statement gives the case's build: its ABI and features, and the
    limits and policies its environment states (none for a size case, so every limit is at its
    default and every policy at upstream's)."""
    return wz_config.env_statement(wz_config.load_decl(), case_abi(case), sorted(features),
                                   dict(getattr(case, "env", ())), {})["digest"]


# The fifth fact for the builds the size cases do not make: the build script reads limits and
# policies from the environment and the zenoh-c layout arm from a feature, and every size case
# builds with none of them stated and no arm on. Without these, that reading is held only by unit
# tests that hand the reader its answers (`wz-conformance-build`, and the statement vectors both
# writers reproduce). These cases make real libraries with a non-default limit, a non-default
# policy and the arm upstream's published zenoh-c archive has. Each must carry the digest its
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
    note: str = field(default="", compare=False)


STATEMENT_CASES: tuple[StatementCase, ...] = (
    StatementCase("statement-pico-stated", "wz-capi-pico", "libwz_capi_pico.so",
                  "engine-coop,link-udp",
                  (("WZ_LIMIT_MAX_SUBSCRIPTIONS", "32"), ("WZ_POLICY_SN_RESOLUTION", "bits-16")),
                  note="the pico client on the cooperative engine (pico-client-coop's features) "
                       "with a limit and a policy stated off their defaults"),
    StatementCase("statement-capic-shm-arm", "wz-capi-c", "libwz_capi_c.so",
                  "default,zenoh-c-shared-memory",
                  (("WZ_LIMIT_MAX_QUERYABLES", "24"), ("WZ_POLICY_MULTICAST_LOOPBACK", "off")),
                  note="the zenoh-c default with the shared-memory arm on, the arm upstream's "
                       "published archive is built with, and a limit and a policy stated"),
)


def statement_env(case: StatementCase, base: Mapping[str, str]) -> dict[str, str]:
    """The environment a statement case builds in: `base` (the gate's, see `build_env`), with
    every limit and policy it states removed, and the case's added. Otherwise a value the shell
    happened to export would build another library than the case names, and the statement would
    still match it."""
    env = {k: v for k, v in base.items()
           if not k.startswith(("WZ_LIMIT_", "WZ_POLICY_"))}
    return {**env, **dict(case.env)}


def build_statement_case(case: StatementCase, base: Mapping[str, str]) -> tuple[str, ...]:
    """Build a statement case and return the conformance digests its library carries."""
    subprocess.run(["cargo", "build", "-p", case.package, "--quiet", "--no-default-features",
                    "--features", case.features, "--target-dir", str(STATEMENT_TARGET)],
                   cwd=CRATES, env=statement_env(case, base), check=True)
    return digests_in((STATEMENT_TARGET / "debug" / case.lib).read_bytes())


def grade_statement(case: StatementCase, got: tuple[str, ...], stated: str,
                    unstated: str) -> list[str]:
    """The findings for a statement case; empty when it passes. `unstated` is the digest of the
    same features with nothing stated. A case equal to it would state nothing the size cases do
    not, and its pass would hold nothing."""
    findings: list[str] = []
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


def grade(case: Case, got: Measured, stated: str | None = None) -> list[str]:
    """The findings for one case; empty when it passes. Pure, so the selftest can drive it.
    `stated` is the digest the case's conformance statement gives; None skips that fact (the
    selftest's synthetic cases have no statement)."""
    findings: list[str] = []
    if stated is not None and got.digests != (stated,):
        findings.append(
            f"{case.id}: the library carries the conformance digest(s) {list(got.digests) or 'none'}, "
            f"and the statement of its feature set is {stated}. The build script "
            f"(wz-conformance-build) read another build than the one this case made, or the two "
            f"writers of the canonical form disagree (their fixture tests say which)."
        )
    if got.text > case.max_text:
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
                f"loads it to define; no C program that links it does, so the program's link fails."
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


# A table header of a configuration file a case names: `[target.<triple>]` or
# `[target.'cfg(...)']`, and the one line of flags each holds.
CONFIG_TABLE = re.compile(r"\[target\.(?:'([^']+)'|([A-Za-z0-9_.-]+))\]")
CONFIG_FLAGS = re.compile(r"rustflags\s*=\s*(\[.*\])")
# The words of a `cfg(...)` predicate: a name, a string, or one of `( ) , =`.
CFG_TOKEN = re.compile(r'\s*(?:([A-Za-z_][A-Za-z0-9_]*)|("[^"\\]*")|([(),=]))')


def read_config_rustflags(text: str) -> list[tuple[str, list[str]]]:
    """The `rustflags` of each `[target.<key>]` table of a cargo configuration file, in file
    order. The files a case names hold those tables and nothing else; any other line is refused by
    number rather than skipped, so a setting this gate would not pass on cannot sit in one
    unnoticed."""
    tables: list[tuple[str, list[str]]] = []
    key: str | None = None
    for number, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        header = CONFIG_TABLE.fullmatch(line)
        if header:
            key = header.group(1) or header.group(2)
            continue
        flags = CONFIG_FLAGS.fullmatch(line)
        if key is None or not flags:
            raise ValueError(f"line {number}: not a `[target.<key>]` header or the one-line "
                             f"`rustflags` array of one: {line!r}")
        try:
            value = json.loads(flags.group(1))
        except ValueError:
            value = None
        if not isinstance(value, list) or not all(isinstance(f, str) for f in value):
            raise ValueError(f"line {number}: `rustflags` is not a one-line array of strings")
        tables.append((key, value))
        key = None
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
    tables = read_config_rustflags(text)
    flags = [f for key, table in tables if key == triple for f in table]
    for key, table in tables:
        if key.startswith("cfg(") and key.endswith(")") and cfg_matches(key[4:-1], cfg):
            flags += table
    return flags


def target_cfg(triple: str) -> set[str]:
    """The `rustc --print cfg` lines of `triple`: `unix`, `target_os="linux"`, ..."""
    out = subprocess.run(["rustc", "--print", "cfg", "--target", triple], cwd=CRATES,
                         capture_output=True, text=True, check=True).stdout
    return {line.strip() for line in out.splitlines() if line.strip()}


def case_config_flags(case: Case, triple: str, cfg: set[str]) -> list[str]:
    """The flags the case's configuration files give its library's crates, in the order it names
    the files."""
    flags: list[str] = []
    for path in case.cargo_configs:
        try:
            flags += config_rustflags((CRATES / path).read_text(encoding="utf-8"), triple, cfg)
        except ValueError as e:
            raise ValueError(f"crates/{path}: {e}") from e
    return flags


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
    return "no linker named in .comment (GNU ld names none)"


def build(case: Case, env: Mapping[str, str], prefixes: build_normalization.Prefixes) -> Measured:
    cmd = ["cargo", "build", "--profile", case.profile, "-p", case.package, "--quiet",
           "--target-dir", str(TARGET)]
    lib_dir = TARGET / case.profile
    if case.cargo_configs:
        triple = host_triple()
        env = with_rustflags(env, case_config_flags(case, triple, target_cfg(triple)))
        cmd += ["--target", triple]
        lib_dir = TARGET / triple / case.profile
    if case.features is not None:
        cmd += ["--no-default-features"]
        if case.features:
            cmd += ["--features", case.features]
    subprocess.run(cmd, cwd=CRATES, env=env, check=True)
    lib = lib_dir / case.lib
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
                    needed=needed, linker=linker_of(lib))


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


def case_features(case: Case) -> set[str]:
    """The features of the case's package its build turns on, as cargo resolves them."""
    feats = wz_config.manifest_features(CRATES / case.package / "Cargo.toml")
    start = ["default"] if case.features is None else [f for f in case.features.split(",") if f]
    return wz_config.enabled_features(feats, start)


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


def pico_reference_tree(asked: dict[str, int],
                        env: Mapping[str, str]) -> tuple[pathlib.Path, str, str]:
    """Build zenoh-pico with `asked` set, from an export of the pinned submodule (pico's CMake
    writes a header into its source tree, which must not dirty the submodule), in `env` (the
    gate's, `build_env`), unless that build is there already. Returns its directory (`src` the
    export, `build` the CMake tree), the full pin and the toolchain. The host performance matrix
    (`scripts/host-bench/perf_matrix.py`) links this same build, asked for in the environment of
    `build_env` too, so the library it times is the one whose size this gate prints."""
    pin = subprocess.run(["git", "-C", str(PICO_SOURCE), "rev-parse", "HEAD"], capture_output=True,
                         text=True, check=True).stdout.strip()
    toolchain = f"{first_line(['cc', '--version'])}; {first_line(['cmake', '--version'])}"
    flags = [f"-D{s}={v}" for s, v in sorted(asked.items())]
    work = PICO_BUILDS / reference_key(pin, toolchain, flags, env)
    lib = work / "build" / "lib" / "libzenohpico.so"
    if not lib.exists():
        archive = subprocess.run(["git", "-C", str(PICO_SOURCE), "archive", "--format=tar", "HEAD"],
                                 capture_output=True, check=True).stdout
        with tarfile.open(fileobj=io.BytesIO(archive)) as tar:
            tar.extractall(work / "src", filter="data")
        run_quiet(["cmake", "-S", str(work / "src"), "-B", str(work / "build"),
                   "-DCMAKE_BUILD_TYPE=Release", "-DBUILD_SHARED_LIBS=ON",
                   "-DBUILD_EXAMPLES=OFF", "-DBUILD_TESTING=OFF", *flags], env)
        run_quiet(["cmake", "--build", str(work / "build"), "--parallel", str(os.cpu_count() or 1)],
                  env)
    return work, pin, toolchain


def pico_reference_build(asked: dict[str, int], env: Mapping[str, str],
                         prefixes: build_normalization.Prefixes) -> Reference:
    """zenoh-pico built with `asked` set under `env` ([`pico_reference_tree`]), measured, and
    searched for the build path prefixes `env` maps."""
    work, pin, toolchain = pico_reference_tree(asked, env)
    lib = work / "build" / "lib" / "libzenohpico.so"
    header = (work / "build" / "include" / "zenoh-pico" / "config.h").read_text()
    size_out = subprocess.run(["size", str(lib)], capture_output=True, text=True, check=True).stdout
    return Reference(text=int(size_out.splitlines()[1].split()[0]), pin=pin[:12],
                     toolchain=toolchain, refused=tuple(refused_switches(asked, header)),
                     leaked=tuple(build_normalization.leaked(lib.read_bytes(), prefixes)),
                     linker=linker_of(lib))


def report_reference(case: Case, got: Measured, env: Mapping[str, str],
                     prefixes: build_normalization.Prefixes) -> tuple[Reference | None, list[str]]:
    """Print the case's size against zenoh-pico built as the same build, and return that build
    with the finding for it when it holds a build path. Only the pico ABI's cases have one here:
    zenoh-c's original is a Rust build of its own the lanes that install the oracle provision, and
    this lane does not."""
    if case.package != "wz-capi-pico":
        print(f"  capability-cost: {case.id}: no same-build reference in this lane (zenoh-c's is "
              f"provisioned only where the oracle is installed)")
        return None, []
    asked = wz_config.pico_reference(wz_config.load_decl(), case_features(case))
    ref = pico_reference_build(asked, env, prefixes)
    print(f"  capability-cost: {case.id}: zenoh-pico {ref.pin} as the same build: text "
          f"{ref.text}; wz is {got.text / ref.text:.2f} times it ({ref.toolchain})")
    print(f"  capability-cost: {case.id}: wz linked by {got.linker}, zenoh-pico by {ref.linker}")
    if ref.refused:
        print(f"  capability-cost: {case.id}: pico built {', '.join(ref.refused)} otherwise than "
              f"asked, so the two builds differ there")
    return ref, purity_findings(f"{case.id} (its zenoh-pico reference)", ref.leaked)


# ── the pico ceiling of the host libraries (docs/upstream-parity.md D9) ────────────────────────

# The committed table: per pico case, the ratio it may not exceed, or its lock at WIN.
HOST_CEILING = ROOT / "deploy" / "pico_host_ceiling.json"
HOST_CEILING_SCHEMA = 1
# How far over its ratchet a ratio may read before the case fails, relative to the ratchet. Two
# readings of one tree on one host are equal (both builds are deterministic), so this is only the
# spread between hosts, and it is MEASURED, not assumed: on 2026-11-21 one tree read
# pico-client-coop at 1,012,762 bytes on the coordinating host and 1,030,646 on a build host
# (1.77 percent), while zenoh-pico read 403,086 on both, so the ratio does NOT cancel what a host
# does to wz's own build (its Rust toolchain's linking, not the C compiler). 2.5 percent covers that
# spread with a margin. It narrows to the spread of one image when every host builds in the image
# the tree declares (the same-build-environment work); until then a row is filled from the hosts
# that grade it. It bounds only what the ratio forgives: the case's byte budget still holds it.
RATIO_TOLERANCE = 0.025
# A ratchet is the reading's ratio rounded UP to four places, so the bound never sits under the
# reading it was set from.
RATIO_PLACES = 10_000
# A debt is an entry of the store's inventory (`debt-<id>`, status active), as every new open
# debt is since 2026-11-13; `cmd_check` also holds the id to the inventory.
DEBT_ID = re.compile(r"debt-[a-z0-9][a-z0-9-]*")
DEBT_PLACEHOLDER = "debt-TBD"
READING_KEYS = ("date", "wz_text", "pico_text", "pico_pin", "toolchain")
ROW_KEYS = frozenset(("verdict", "ratio_at_most", "debt", "reading"))
CEILING_NO_BUDGET = ("no budget or row move clears it: take the bytes back, or the owner "
                     "decides (docs/upstream-parity.md D9)")


def ceiling_cases() -> list[str]:
    """The cases the ceiling holds: every pico case, the ones `report_reference` builds a
    reference for."""
    return [c.id for c in CASES if c.package == "wz-capi-pico"]


def load_ceiling(path: pathlib.Path = HOST_CEILING) -> dict | None:
    if not path.is_file():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def ceiling_rows(table: dict | None) -> dict:
    rows = table.get("cases") if isinstance(table, dict) else None
    return rows if isinstance(rows, dict) else {}


def ceil_ratio(wz_text: int, pico_text: int) -> float:
    """wz text over pico text, rounded up to four places in exact arithmetic."""
    return math.ceil(Fraction(wz_text * RATIO_PLACES, pico_text)) / RATIO_PLACES


def ceiling_reading(wz_text: int, pico_text: int, pin: str, toolchain: str, date: str) -> dict:
    return {"date": date, "wz_text": wz_text, "pico_text": pico_text, "pico_pin": pin,
            "toolchain": toolchain}


def case_reading(got: Measured, ref: Reference | None, date: str) -> dict | None:
    """The reading a case is held to its row by, or None when it has none: no reference, or a
    library on either side that holds a build path, whose text is no figure (its purity finding
    fails the run instead)."""
    if ref is None or got.leaked or ref.leaked:
        return None
    return ceiling_reading(got.text, ref.text, ref.pin, ref.toolchain, date)


def ceiling_row(reading: dict, debt: str | None) -> dict:
    """The row a reading sets: locked when it is a WIN (D1), a ratchet at its ratio otherwise,
    under the debt item the case is registered with (a placeholder while it has none)."""
    row: dict = {}
    if verdict_size(reading["wz_text"], reading["pico_text"]) == "WIN":
        row["verdict"] = "win"
        if debt and DEBT_ID.fullmatch(debt):
            row["debt"] = debt
    else:
        row["ratio_at_most"] = ceil_ratio(reading["wz_text"], reading["pico_text"])
        row["debt"] = debt if debt and DEBT_ID.fullmatch(debt) else DEBT_PLACEHOLDER
    row["reading"] = reading
    return row


def format_row(case_id: str, row: dict) -> str:
    return f"{json.dumps(case_id)}: {json.dumps(row)}"


def reading_findings(case_id: str, reading: object) -> list[str]:
    if not isinstance(reading, dict) or set(reading) != set(READING_KEYS):
        return [f"{case_id}: its reading must state exactly {', '.join(READING_KEYS)}"]
    out: list[str] = []
    for key in ("wz_text", "pico_text"):
        if type(reading[key]) is not int or reading[key] <= 0:
            out.append(f"{case_id}: its reading's {key} is not a positive byte count")
    for key in ("date", "pico_pin", "toolchain"):
        if not isinstance(reading[key], str) or not reading[key]:
            out.append(f"{case_id}: its reading's {key} is empty")
    return out


def row_findings(case_id: str, row: object) -> list[str]:
    """What makes a row of the table no row of the ceiling. A row whose `ratio_at_most` is null
    is well formed here (the unfilled form) and refused by `grade_ceiling`."""
    if not isinstance(row, dict):
        return [f"{case_id}: its row is not an object"]
    out = [f"{case_id}: its row has the unknown key {key!r}" for key in sorted(set(row) - ROW_KEYS)]
    locked = "verdict" in row
    if locked == ("ratio_at_most" in row):
        return out + [f"{case_id}: its row must state either `verdict` (locked) or "
                      f"`ratio_at_most` (ratchet), and states {'both' if locked else 'neither'}"]
    if locked:
        if row["verdict"] != "win":
            out.append(f"{case_id}: a locked row's verdict is \"win\" and nothing else (D1: only "
                       f"WIN counts), not {row['verdict']!r}")
        found = reading_findings(case_id, row.get("reading"))
        out += found
        if not found and verdict_size(row["reading"]["wz_text"], row["reading"]["pico_text"]) != "WIN":
            out.append(f"{case_id}: the row is locked at WIN on a reading that is no WIN")
        if "debt" in row and not (isinstance(row["debt"], str) and DEBT_ID.fullmatch(row["debt"])):
            out.append(f"{case_id}: a locked row's debt, when stated, is the item its WIN closed "
                       f"(`debt-<id>`, an entry of the store's inventory)")
        return out
    if not isinstance(row.get("debt"), str):
        out.append(f"{case_id}: a ratchet row states the debt item it is registered under")
    at_most = row["ratio_at_most"]
    if at_most is None:
        if row.get("reading") is not None:
            out.append(f"{case_id}: an unfilled row (`ratio_at_most` null) states no reading")
        return out
    if isinstance(at_most, bool) or not isinstance(at_most, (int, float)) or at_most <= 0:
        return out + [f"{case_id}: its ratio_at_most is not a positive number"]
    found = reading_findings(case_id, row.get("reading"))
    if found:
        return out + found
    reading = row["reading"]
    if at_most != ceil_ratio(reading["wz_text"], reading["pico_text"]):
        out.append(f"{case_id}: its ratio_at_most {at_most} is not its reading's ratio rounded up "
                   f"to four places ({ceil_ratio(reading['wz_text'], reading['pico_text'])}): the "
                   f"ratchet is set from a stated reading and from nothing else")
    if verdict_size(reading["wz_text"], reading["pico_text"]) == "WIN":
        out.append(f"{case_id}: a ratchet row set from a WIN; lock it: "
                   f"{format_row(case_id, ceiling_row(reading, row.get('debt')))}")
    return out


def table_findings(table: dict | None, case_ids: list[str]) -> list[str]:
    """What keeps the table from holding each of `case_ids` with one well-formed row. Static: it
    needs no build, so a run of some cases still grades the whole table."""
    where = HOST_CEILING.relative_to(ROOT)
    if table is None:
        return [f"{where} is missing: every pico case is held under zenoh-pico by its row there"]
    if not isinstance(table, dict) or table.get("schema") != HOST_CEILING_SCHEMA:
        return [f"{where} is not schema {HOST_CEILING_SCHEMA}"]
    rows = table.get("cases")
    if not isinstance(rows, dict):
        return [f"{where} has no `cases` object"]
    out: list[str] = []
    for case_id in case_ids:
        if case_id not in rows:
            out.append(f"{case_id}: no row in {where}: a pico case is held under zenoh-pico from "
                       f"the commit that adds it, so the population cannot grow past the ceiling; "
                       f"`--measure {case_id}` prints its row")
    for case_id, row in rows.items():
        if case_id not in case_ids:
            out.append(f"{case_id}: a row in {where} for no pico case of CASES")
        else:
            out += row_findings(case_id, row)
    return out


def grade_ceiling(case_id: str, row: dict, reading: dict) -> tuple[list[str], list[str]]:
    """The findings and the notes for one case's reading against its well-formed row. Pure, so
    the selftest can drive it."""
    wz_text, pico_text = reading["wz_text"], reading["pico_text"]
    ratio = wz_text / pico_text
    verdict = verdict_size(wz_text, pico_text)
    said = (f"{case_id}: wz text {wz_text} against zenoh-pico {pico_text} as the same build, "
            f"ratio {ratio:.4f}, {verdict}")
    if "verdict" in row:
        if verdict != "WIN":
            return [f"{said}. The case is locked at WIN (since {row['reading']['date']}); "
                    f"{CEILING_NO_BUDGET}"], []
        return [], []
    debt = row.get("debt")
    at_most = row["ratio_at_most"]
    if at_most is None:
        return [f"{said}. Its row in {HOST_CEILING.relative_to(ROOT)} states no ratio_at_most, so "
                f"the case is held to nothing. Fill it from the host that grades it: paste "
                f"{format_row(case_id, ceiling_row(reading, debt))} over the row, with `debt` the "
                f"store inventory entry (`debt-<id>`) the case is registered under (D5); "
                f"`python3 scripts/lib/capability_cost_gate.py --measure {case_id}` prints the "
                f"same row"], []
    findings: list[str] = []
    notes: list[str] = []
    if not (isinstance(debt, str) and DEBT_ID.fullmatch(debt)):
        findings.append(f"{case_id}: its row names no registered debt ({debt!r}): a case that is no "
                        f"WIN is an open-debt item, paid largest ratio first (D5), and its row "
                        f"says which (`debt-<id>`, an entry of the store's inventory)")
    if verdict == "WIN":
        findings.append(f"{said}. A case that reached WIN is locked at WIN from now on: replace its "
                        f"row with {format_row(case_id, ceiling_row(reading, debt))} and close "
                        f"{debt}")
        return findings, notes
    limit = at_most * (1 + RATIO_TOLERANCE)
    if ratio > limit:
        then = row["reading"]
        host = ("" if then["toolchain"] == reading["toolchain"] else
                f"; the row was read with {then['toolchain']}, this run with {reading['toolchain']}")
        findings.append(f"{said}, over its ratchet {at_most} (with the {RATIO_TOLERANCE:.1%} "
                        f"tolerance, {limit:.4f}; set {then['date']} from {then['wz_text']} against "
                        f"{then['pico_text']}){host}. A ratchet only moves down: {CEILING_NO_BUDGET}")
    elif ratio * (1 + RATIO_TOLERANCE) < at_most:
        notes.append(f"{case_id}: ratio {ratio:.4f} is under its ratchet {at_most} by more than the "
                     f"tolerance; commit the tighter row: {format_row(case_id, ceiling_row(reading, debt))}")
    return findings, notes


def cmd_check(measure_only: bool, only: list[str]) -> int:
    unknown = [i for i in only if i not in {c.id for c in CASES} | {c.id for c in STATEMENT_CASES}]
    if unknown:
        print(f"  capability-cost: no such case: {unknown}", file=sys.stderr)
        return 2
    rc = 0
    try:
        env, prefixes = build_env()
    except ValueError as e:
        print(f"  capability-cost: {e}", file=sys.stderr)
        return 2
    table = load_ceiling()
    rows = ceiling_rows(table)
    if not measure_only:
        for finding in table_findings(table, ceiling_cases()):
            print(f"  capability-cost FAIL: {finding}", file=sys.stderr)
            rc = 1
    today = datetime.datetime.now(datetime.timezone.utc).date().isoformat()
    measured_rows: dict[str, dict] = {}
    ceilinged = 0
    for case in CASES:
        if only and case.id not in only:
            continue
        got = build(case, env, prefixes)
        stated = stated_digest(case, case_features(case))
        print(f"  capability-cost: {case.id}: text {got.text} of {case.max_text} "
              f"({100 * got.text // case.max_text}%), {got.exports} exports, conformance digest "
              f"{', '.join(got.digests) or 'none'} (statement {stated})")
        ref, ref_findings = report_reference(case, got, env, prefixes)
        # In either mode: a figure read from a library that holds a path is no figure, so it is
        # neither graded against a ceiling row nor printed as one.
        for finding in purity_findings(case.id, got.leaked) + ref_findings:
            print(f"  capability-cost FAIL: {finding}", file=sys.stderr)
            rc = 1
        reading = case_reading(got, ref, today)
        row = rows.get(case.id)
        if reading is not None:
            debt = row.get("debt") if isinstance(row, dict) else None
            measured_rows[case.id] = ceiling_row(reading, debt if isinstance(debt, str) else None)
        if measure_only:
            continue
        for finding in grade(case, got, stated):
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
        findings, notes = grade_ceiling(case.id, row, reading)
        for note in notes:
            print(f"  capability-cost: {note}")
        for finding in findings:
            print(f"  capability-cost FAIL: {finding}", file=sys.stderr)
            rc = 1
    statements = 0
    for case in STATEMENT_CASES:
        if only and case.id not in only:
            continue
        statements += 1
        features = case_features(case)
        got = build_statement_case(case, env)
        stated = stated_digest(case, features)
        unstated = wz_config.env_statement(wz_config.load_decl(), case_abi(case), sorted(features),
                                           {}, {})["digest"]
        print(f"  capability-cost: {case.id}: conformance digest {', '.join(got) or 'none'} "
              f"(statement {stated}, with nothing stated {unstated})")
        if measure_only:
            continue
        for finding in grade_statement(case, got, stated, unstated):
            print(f"  capability-cost FAIL: {finding}", file=sys.stderr)
            rc = 1
    sized = sum(1 for c in CASES if not only or c.id in only)
    if measured_rows:
        print(f"  capability-cost: the rows this run reads for {HOST_CEILING.relative_to(ROOT)} "
              f"`cases` (each replaces the row of its case; a ratchet's `debt` is the open-debt "
              f"item the case is registered under):")
        for n, (case_id, row) in enumerate(measured_rows.items(), 1):
            print(f"    {format_row(case_id, row)}{',' if n < len(measured_rows) else ''}")
    if rc == 0 and not measure_only:
        print(f"  capability-cost: {sized} case(s) within budget, absent where absent, present "
              f"where present, each carrying its statement's digest; {ceilinged} pico case(s) "
              f"under their zenoh-pico ceiling; {statements} build(s) with stated limits, "
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
    linux_gnu = {"unix", 'target_family="unix"', 'target_os="linux"', 'target_env="gnu"'}
    linux_musl = {"unix", 'target_family="unix"', 'target_os="linux"', 'target_env="musl"'}
    windows_msvc = {"windows", 'target_family="windows"', 'target_os="windows"',
                    'target_env="msvc"'}
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
    for shape in ("[build]\nrustflags = [\"x\"]\n", "[target.'cfg(unix)']\nlinker = \"cc\"\n",
                  "rustflags = [\"x\"]\n", "[target.'cfg(unix)']\nrustflags = \"-C x\"\n",
                  "[target.'cfg(unix)']\nrustflags = [\"x\"]\nrustflags = [\"y\"]\n"):
        try:
            read_config_rustflags(shape)
            expect(f"the configuration {shape!r} is refused", False)
        except ValueError:
            expect(f"the configuration {shape!r} is refused", True)
    nostd = (CRATES / NOSTD_CONFIG).read_text(encoding="utf-8")
    expect("the configuration without std drops the unwind tables on a POSIX host only",
           config_rustflags(nostd, "x86_64-unknown-linux-gnu", linux_gnu)
           == ["-C", "force-unwind-tables=no"]
           and config_rustflags(nostd, "x86_64-pc-windows-msvc", windows_msvc) == [])

    def readable(path: str) -> bool:
        try:
            read_config_rustflags((CRATES / path).read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return False
        return True

    expect("every configuration file a case names is one this gate reads",
           all(readable(p) for c in CASES for p in c.cargo_configs))
    expect("the linker a library's .comment names is the one printed",
           comment_linker("String dump of section '.comment':\n  [     0]  rustc version 1.97.0\n"
                          "  [    2d]  Linker: LLD 22.1.6 (/checkout/src/llvm 08c84e)\n")
           == "Linker: LLD 22.1.6"
           and comment_linker("  [     0]  mold 2.30.0 (compatible with GNU ld)\n") == "mold 2.30.0"
           and comment_linker("  [     0]  GCC: (Ubuntu 13.3.0) 13.3.0\n").startswith("no linker"))
    expect("an unpinned export count is not graded",
           grade(Case("t", "p", "l", "", 1000), Measured(900, [], 99)) == [])
    # The control that keeps ABSENCE honest: every pattern a case forbids is required by some
    # case in the table, so a forbidden pattern that no build can match cannot stay unnoticed.
    required = {p for c in CASES for p in c.require}
    forbidden = {p for c in CASES for p in c.forbid}
    expect("every forbidden pattern is required of a build that has the plane",
           forbidden <= required)
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
               (CONFIG_VERDICT, "wz_capi_c_config_device_requires"))))
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
           {"serial-drive-own-thread", "rx-busy-poll"}
           <= case_features(next(c for c in CASES if c.id == "pico-client"))
           and "peer" in case_features(next(c for c in CASES if c.id == "pico-default")))
    # A profile is a compile property, not a capability: a case that differs from another only in
    # its profile must be divided by the same pico, or the ratio moves from both sides at once.
    by_id = {c.id: c for c in CASES}
    expect("a profile twin has its base case's features, and so its pico reference",
           all(case_features(by_id[small]) == case_features(by_id[base])
               for small, base in (("pico-client-small", "pico-client"),
                                   ("capic-client-small", "capic-client"))))
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
    expect("a case's statement follows its features and its ABI",
           stated_digest(by_id["pico-client"], case_features(by_id["pico-client"]))
           == stated_digest(by_id["pico-client-small"], case_features(by_id["pico-client-small"]))
           != stated_digest(by_id["pico-default"], case_features(by_id["pico-default"]))
           and stated_digest(by_id["capic-client"], case_features(by_id["capic-client"]))
           != stated_digest(by_id["pico-client"], case_features(by_id["pico-client"])))
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
           and len(grade_statement(s0, (a,), a, a)) == 1)
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
    blank, _ = grade_ceiling("t", unfilled, set_from)
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
    expect("the committed table holds every pico case of CASES, one well-formed row each",
           table_findings(committed, ceiling_cases()) == []
           and set(ceiling_rows(committed)) == {c.id for c in CASES if c.package == "wz-capi-pico"}
           and len(ceiling_cases()) >= 1)
    print(f"  capability-cost selftest: {ok}/{ok + bad} arm(s) pass")
    return 0 if bad == 0 else 1


def main(argv: list[str]) -> int:
    if len(argv) < 2 or argv[1] not in ("--check", "--measure", "--selftest") or (
        argv[1] == "--selftest" and len(argv) != 2
    ):
        print(__doc__, file=sys.stderr)
        return 2
    if argv[1] == "--selftest":
        return cmd_selftest()
    return cmd_check(measure_only=argv[1] == "--measure", only=argv[2:])


if __name__ == "__main__":
    sys.exit(main(sys.argv))
