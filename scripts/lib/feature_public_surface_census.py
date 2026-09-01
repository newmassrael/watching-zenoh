#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

"""R2193 (no register item) — HOW MANY OF THIS WORKSPACE'S NON-DEFAULT
FEATURES GATE A PUBLIC ITEM, DERIVED RATHER THAN ESTIMATED.

## Why the citation says no item while the file answers for one

The debt this answers, 532, lives in the half of the register that is not the
store, so there is no `debt-` id to cite and the convention's explicit
declaration is the only true one. Its siblings `prose_feature_gate.py` and
`prose_dep_graph_gate.py` stand in the same place for the same reason. The item
is named in full below, which is what a reader grepping for it will find.

## The item, and the half of it this is

Item 532: `feature_gate_diagnostic.py` (R2115) makes rustc an oracle for "a
consumer who reaches for a feature-gated path is told WHICH feature" -- but it
is scoped to ONE package, and its banner ends "N other workspace package(s) are
NOT covered". That is an impression, not a fraction: nobody knew how many of
the 521 non-default features carry the same trap, so nobody could say what
widening the axis would cost or when it would be done.

The item is explicit that the HARD HALF is deciding the population, and that
counting it by hand is exactly what must not happen. So this file derives it.

## What "gates a public path" is derived FROM, and why not rustdoc

The item's own suggestion was to diff the public API across a feature ON/OFF
pair, which needs `rustdoc --output-format json` -- nightly-only, re-measured
this round on rustc 1.97.0 and still true. That is the wrong instrument here
for a reason that has nothing to do with nightly: it would need one rustdoc
build PER FEATURE, and the population is in the hundreds.

The BINDING side is cheaper and exact. R2115's own docstring records the
property that makes its probe work: rustc emits the note only when the
`#[cfg(feature = ...)]` sits ON the item it configured out. So the sites that
can carry the trap are exactly the sites where such an attribute is attached to
a publicly-visible item -- and that is a fact about the source, not about a
rendered API.

## EVERY attribute site is classified, and unclassified is RED

The population is every `#[cfg(...)]` carrying a `feature = "..."`, and each
one lands in exactly one class:

  * `public-item`      -- strictly `pub`, then an item keyword. THE DENOMINATOR.
  * `macro-invocation` -- a macro call, which can EXPAND to a public item.
                          Counted IN, because over-reporting is the safe
                          direction and a macro's expansion is not readable
                          from here.
  * `restricted-item`  -- `pub(crate)` / `pub(super)`; not reachable from
                          outside the crate, so not this trap.
  * `private-item`     -- an item with no visibility.
  * `not-an-item`      -- a block, statement, expression, match arm, struct
                          field or assertion. The item's own prose says most
                          sites are these, and the measurement agrees.

A site matching none of them is a FINDING. It has to be declared with the
reason, and a declaration whose site no longer occurs is a FINDING too, so the
list cannot rot into a permission slip.

## The denominator is a SET, pinned, not a count

A count moves for two reasons and names neither. What is pinned is the SET of
`(package, feature)` pairs that gate a public item and are outside the
package's default closure. Every pair must be one of:

  * PROBED           -- derived by importing `feature_gate_diagnostic`, both
                        its hand-written probes and the ones it reads off each
                        crate root, so widening that axis moves this fraction
                        automatically rather than needing a second edit;
  * NO_PUBLIC_PATH   -- that module's declaration, which this file DOES NOT
                        BELIEVE: a name declared to gate no public path and
                        found here attached to a publicly visible item is a
                        FINDING. Otherwise a reason-string table would be an
                        escape hatch from the very derivation it sits beside;
  * DEFERRED         -- that module's waiting list, for packages the axis HAS
                        taken: gates a public item, not probed yet, reason
                        given per feature;
  * OFF_AXIS         -- named HERE, per package, for packages the axis has not
                        taken at all. One reason for the whole package.

A pair in none of the four is a FINDING, so the population cannot grow in
silence: a feature added tomorrow that gates a public item reds this until
somebody decides which it is. A name in the waiting lists that no longer gates
a public item is a FINDING too, and so is a package listed BOTH on the axis and
in `OFF_AXIS` -- one fact, one place.

## What this deliberately does NOT decide

Whether a `pub` item is reachable from OUTSIDE its crate. A `pub fn` inside a
private module is not, and this counts it anyway -- over-reporting, which
inflates the work remaining rather than hiding it, and each such pair can be
retired into NO_PUBLIC_PATH with that as its reason. Narrowing it needs module
reachability, which is the rustdoc-shaped question this file avoided; the
retirement path exists so the number can still reach zero.
"""

from __future__ import annotations

import collections
import functools
import json
import pathlib
import re
import subprocess
import sys
import tempfile
import typing

ROOT = pathlib.Path(__file__).resolve().parents[2]
CRATES = ROOT / "crates"
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

import feature_gate_diagnostic as fgd  # noqa: E402 -- after the path insert

FEATURE = re.compile(r'feature\s*=\s*"([^"]+)"')

# An item keyword, after any leading qualifier.
_KW = (
    r"(?:fn|mod|struct|enum|trait|impl|use|type|const|static|union"
    r"|macro_rules!|macro|extern\s+crate)"
)
_QUAL = r"(?:async\s+|unsafe\s+|extern\s+\"[^\"]*\"\s+|const\s+|default\s+)*"

PUBLIC_ITEM = re.compile(r"^\s*pub\s+" + _QUAL + _KW + r"\b")
RESTRICTED_ITEM = re.compile(r"^\s*pub\s*\([^)]*\)\s+" + _QUAL + _KW + r"\b")
PRIVATE_ITEM = re.compile(r"^\s*" + _QUAL + _KW + r"\b")
# An assertion is a macro too, and it is never an item; checked FIRST so the
# macro class stays the genuinely ambiguous one.
ASSERTION = re.compile(r"^\s*(?:debug_)?assert(?:_eq|_ne|_matches)?!\s*\(")
MACRO_CALL = re.compile(r"^\s*[A-Za-z_][A-Za-z0-9_]*!\s*[({\[]")
FIELD = re.compile(r"^\s*(?:pub\s*(?:\([^)]*\)\s*)?)?[A-Za-z_][A-Za-z0-9_]*\s*:")
BLOCK_OR_STMT = re.compile(
    r"^\s*(?:[{}()\[\]]|let\b|if\b|for\b|while\b|loop\b|match\b|return\b"
    r"|break\b|continue\b|else\b|\.|\||\"|\d|_\b)"
)
CALL_OR_PATH = re.compile(
    r"^\s*[A-Za-z_][A-Za-z0-9_:<>\.]*\s*(?:[({,]|=>|=[^=]|\.|::<)"
)
BARE_NAME = re.compile(r"^\s*[A-Za-z_][A-Za-z0-9_:.]*\s*,?\s*$")

DENOMINATOR_CLASSES = ("public-item", "macro-invocation")

# R2207 — a cfg that is not a bare `feature = "x"`. MEASURED on rustc 1.97.0
# and recorded in `feature_gate_diagnostic`'s own DEFERRED prose: when the
# attribute is a compound, the note reads "the item is gated here" and NAMES NO
# FEATURE, so such an item cannot witness the property the axis holds down.
COMPOUND = re.compile(r"\b(?:any|all|not)\s*\(")


class Shape(typing.NamedTuple):
    """Where one denominator site is, and the two facts a deferral turns on."""

    where: str
    #: the attribute is an `any(...)` / `all(...)` / `not(...)`
    compound: bool
    #: the gated item's indentation. Zero is a module-level item, which a
    #: consumer names as `module::thing`; anything deeper is inside an `impl`
    #: or a nested block, and a method there is spelled `Type::thing`.
    column: int


# R2207 — the CLOSED vocabulary a `DEFERRED` reason must carry, and what each
# word OBLIGES. Marker spelling: `@defer <word>` anywhere in the reason.
#
# ## Why a reason string needed a marker at all
#
# `feature_gate_diagnostic.DEFERRED` is the axis's waiting list: gates a public
# item, not probed yet, reason given. Until this existed the reason was PROSE,
# and prose is what this workspace keeps paying for -- `NO_PUBLIC_PATH` one
# table up already carries the warning in capitals ("THIS TABLE IS NOT
# BELIEVED") precisely because a reason nobody measures is an escape hatch from
# the derivation it sits beside. The waiting list had no such check: a feature
# whose public item is a plain module-level `pub fn` under a simple cfg -- one
# a probe could be written for this afternoon -- could sit there forever under
# any sentence at all.
#
# So each word implies something DERIVED FROM THE SITES, and the check below
# holds it:
#
#   * `compound-cfg`  -- EVERY public-item site of that feature is compound.
#                        A single simple-cfg site refutes it: that one could
#                        carry the probe.
#   * `impl-method`   -- no public-item site under a SIMPLE cfg is at column
#                        zero. A module-level item under a simple cfg is
#                        exactly the shape the axis probes, so the deferral
#                        would be declining work that is already possible.
#   * `cfg-not-twin`  -- the package writes `cfg(not(feature = "x"))` for it,
#                        so the feature swaps an implementation rather than
#                        removing a path and there is no resolution error to
#                        annotate. Its module-level site is expected, which is
#                        why it cannot be folded into `impl-method`.
#
# A reason carrying no marker, or a word outside this set, is a FINDING --
# unclassified is not a pass. And a marker whose obligation the sites refute is
# a FINDING, which is the direction that matters: it turns "somebody wrote a
# sentence" into "the tree still agrees with it".
DEFER_POLICY = ("compound-cfg", "impl-method", "cfg-not-twin")
DEFER_MARKER = re.compile(r"@defer\s+([a-z-]+)")

# path -> why this gate cannot classify the site there. BOTH DIRECTIONS: an
# undeclared unclassified site FAILS, and a declaration with no site FAILS.
UNCLASSIFIED_DECLARED: dict[str, str] = {
    "crates/wz-runtime-tokio/tests/multicast_pubsub_loopback.rs": (
        "the attribute is followed by the continuation of a multi-line string "
        "literal belonging to an earlier attribute, so the next source line is "
        "not the item this one is attached to"
    ),
}

# Packages the diagnostic axis has NOT taken yet -> (why, the features that
# gate a public item there).
#
# R2194 split the waiting list in two, because the two halves are answered by
# different tables. Once a package JOINS the axis, every one of its non-default
# features has to be decided over there -- probed, declared to gate no public
# path, or deferred with a reason -- and this table must not name it any more.
# What stays here is the packages nobody has taken.
#
# A SET, not a count, in both halves. A feature that gates a public item and is
# in none of the tables FAILS; a name here that no longer gates one FAILS; and
# a package that has joined the axis while still listed here FAILS.
OFF_AXIS: dict[str, tuple[str, frozenset[str]]] = {
    "wz": (
        "the facade: each of these re-exports a whole runtime or platform "
        "subtree, so one probe per feature is a probe of somebody else's "
        "public surface and belongs to that crate's row instead",
        frozenset(
            {
                "api-compat-c",
                "api-compat-pico",
                "platform-freertos",
                "platform-zephyr",
                "rest-http-bridge",
                "runtime-coop",
                "runtime-tokio",
                "session-lwip",
            }
        ),
    ),
    "wz-capi-c": (
        "a C ABI crate: its public contract is the SYMBOL SET a C program "
        "links against, not a Rust path a consumer names, and that contract "
        "is already measured against upstream's own library on all four ABI "
        "arms. Held to `ABI_CONTRACT` below rather than to this sentence",
        frozenset({"zenoh-c-no-unstable-api", "zenoh-c-shared-memory"}),
    ),
    "wz-codecs-test-support": (
        "a test-support crate: `publish = false`, and NO workspace library "
        "consumes it -- every edge into it is a `dev-dependency`, so the only "
        "Rust sites that can name its gated paths are this workspace's own "
        "test targets. Held to `TEST_ONLY_REACH` below rather than to this "
        "sentence",
        frozenset(
            {
                "codec-declare",
                "codec-push",
                "codec-request",
                "codec-response",
                "codec-response-final",
            }
        ),
    ),
    "wz-link-lwip": (
        "an MCU link crate whose consumers are the deploy probes, not an "
        "external caller reaching for a path",
        frozenset({"buffer-pool-session-rx-slim", "test-support"}),
    ),
    "wz-packet-socket": (
        "one feature, gating a Linux-only capture path",
        frozenset({"tap"}),
    ),
    "wz-runtime-coop": (
        "the no_std runtime: reached through the facade's `runtime-coop`, so "
        "the facade row above is where a consumer-facing probe would sit",
        frozenset({"alloc", "reassembly", "scouting-static", "session-unicast"}),
    ),
    "wz-runtime-core": (
        "the trait skeleton; its one non-default feature gates the alloc-only "
        "half of that skeleton",
        frozenset({"alloc"}),
    ),
    # `wz-runtime-tokio` used to sit here, carrying all 62 of its
    # public-gating features. R2194 put it ON the axis, so its features are
    # decided in `feature_gate_diagnostic`'s own tables now -- 44 probed from
    # the crate root, 18 deferred with a reason. Listing it in both places
    # would be the second copy of one fact that this file exists to refuse
    # elsewhere, and the check below fails if a package on the axis reappears
    # here.
    "wz-runtime-tokio-test-support": (
        "a test-support crate: `publish = false`, and the one workspace "
        "library consuming it outside a `dev-dependency` (`wz-e2e-harness`) "
        "is itself consumed only by packages with no library target, so no "
        "library a Rust consumer could name reaches its gated paths. NOT "
        "\"same reason as the other one\", which is what this row used to say "
        "and which the graph refuted. Held to `TEST_ONLY_REACH` below",
        frozenset({"tls-fixtures"}),
    ),
    # `wz-session-core` used to sit here with all 65 of its public-gating
    # features -- 65 of the 90 pairs no axis had taken, the longest row this
    # table ever held. R2207 put it ON the axis, so its features are decided in
    # `feature_gate_diagnostic`'s own tables now; listing it in both places
    # would be the second copy of one fact this file refuses elsewhere, and the
    # check below fails if a package on the axis reappears here.
    #
    # ⛔ ITS REASON WAS REFUTED, not outgrown, and that is worth the sentence.
    # It read "probing here and at the runtime would ask the same question
    # twice". MEASURED when the axis came to take it: of the 65, only 23 are
    # probed at `wz-runtime-tokio` at all and 31 exist there under no name. And
    # even where the NAME is shared the two are not one question -- rustc
    # attaches its "gated behind the `x` feature" note to the ITEM it configured
    # out, so a probe spelling `wz_runtime_tokio::…` says nothing whatever about
    # a consumer who types `wz_session_core::…`. A reason that sounds structural
    # can still be a guess, and this table is where such a guess goes to live
    # for months.
    "wz-session-lwip": (
        "one feature, on the lwip session glue; consumers are deploy probes",
        frozenset({"transport-multicast"}),
    ),
    "wz-tls-record": (
        "`publish = false`, and the only workspace edge that turns `fixtures` "
        "on is a `dev-dependency`; no feature definition anywhere in this "
        "workspace enables it either, so the only sites that can name its "
        "gated paths are test targets. The CRATE is not test-only -- "
        "`wz-analyze` takes it as a normal dependency -- which is why this is "
        "held to `TEST_ONLY_FEATURE` below and not to `TEST_ONLY_REACH`",
        frozenset({"fixtures"}),
    ),
}

# R2260 (open-debt item 593's residue) — the packages whose `OFF_AXIS` reason is
# the claim "this crate's public contract is a C ABI symbol set, not a Rust
# path", MEASURED instead of asserted.
#
# ## Why this exists, and what refuted the sentence it replaces
#
# `OFF_AXIS` reasons are PROSE, which is the shape this file already warns
# about one table up: "a reason nobody measures is an escape hatch from the very
# derivation it sits beside". `wz-capi-c`'s reason was "one feature, and it
# selects between two ABI spellings rather than adding or removing a Rust path a
# consumer names", and BOTH halves were false when re-measured:
#
#   * "one feature" — R2259 made it two, which is how this row was found at all.
#   * "rather than adding or removing a Rust path" — the row's own feature gates
#     FIVE `pub mod` declarations (`advanced`, `cancellation`, `events`,
#     `source_info`, `zenoh_ext`). A gated `pub mod` is exactly a Rust path
#     appearing and disappearing.
#
# The row is still RIGHT to be off the axis; the reason for it was wrong. So the
# reason becomes a predicate, and the predicate is the narrow true one: what the
# crate exposes under these features is the C ABI, so a Rust consumer has no
# non-`extern` function to reach for and the missing-feature diagnostic R2115
# probes for has no subject here.
#
# ## The predicate
#
# For every `(package, feature)` in this table's `OFF_AXIS` row, every
# public-item site it gates must be one of:
#
#   * an `fn` carrying `#[no_mangle]` — a C entry point;
#   * a `pub mod` whose every STRICTLY-`pub` `fn` carries `#[no_mangle]` — an
#     ABI module, checked by opening the module's own file;
#   * a `const` / `struct` / `enum` / `type` / `union` — what a C header
#     declares, and not something a Rust caller can call.
#
# A `use` is a FINDING even though there is none today: a gated re-export IS a
# Rust path, and the whole point of writing this down is that the population
# must not be able to grow in silence. So is any item shape this does not know —
# unclassified is RED, never a pass.
#
# ## What this deliberately does NOT claim
#
# That the OTHER `OFF_AXIS` rows are measured. Some are not; their reasons are
# still prose, and that residue is filed (open-debt item 606) rather than
# hidden. ⛔ R2266 struck the number that used to stand in this sentence: it
# said "the other seven" while the table held ten rows and nine of them were
# prose. A residue named by a hand-typed count is a count nobody re-derives, so
# `PROSE_ONLY` below carries the residue as a SET and `check` refuses a row
# that is in neither the predicates nor that set.
ABI_CONTRACT: dict[str, str] = {
    "wz-capi-c": (
        "the zenoh-c drop-in cdylib; its symbol set is graded against "
        "upstream's own libzenohc.so on all four ABI arms by "
        "`crates/wz-integration-tests/tests/zenoh_c_abi_symbol_census.rs`"
    ),
}

#: A strictly-`pub` `fn`, at any depth — the shape that would be a Rust caller's
#: entry point if it were not an `extern "C"` one. `pub(crate)` is deliberately
#: NOT matched: it is unreachable from outside the crate, the same line
#: `classify` draws with `restricted-item`.
ABI_PUB_FN = re.compile(r"^\s*pub\s+(?:unsafe\s+|const\s+|async\s+)*(?:extern\s+\"[^\"]*\"\s+)?fn\b")

#: `pub mod name;` — a gated Rust path whose contents decide whether it is one.
ABI_PUB_MOD = re.compile(r"^\s*pub\s+mod\s+([A-Za-z_][A-Za-z0-9_]*)\s*;")

#: The item keywords a C header declares and a Rust caller cannot call.
ABI_DECLARATION = re.compile(r"^\s*pub\s+(?:const|static|struct|enum|type|union)\b")

#: A gated re-export. Not present today; a FINDING if it ever is.
ABI_USE = re.compile(r"^\s*pub\s+use\b")


# R2266 (open-debt item 606) — the packages whose `OFF_AXIS` reason is the claim
# "this crate's consumers are this workspace's own test targets", MEASURED
# instead of asserted.
#
# ## What refuted the sentence this replaces
#
# `wz-runtime-tokio-test-support` read "a test-support crate; same reason as the
# other one", and the other one reads "its consumers are this workspace's own
# test targets, which the lanes already compile under every combination". The
# first half is FALSE and the graph says so: `wz-e2e-harness` consumes it as a
# NORMAL dependency, from a `lib` target, and its own manifest argues the case
# in a comment nobody could reach from here. A `lib` is not a test target; it is
# exactly the shape whose public paths a Rust consumer names.
#
# The row is still RIGHT to be off the axis, and the reason for it was wrong --
# the same shape R2260 found one row over. So the reason becomes a predicate,
# and the predicate is the narrow true one below.
#
# ## The predicate
#
# For each package here, BOTH of these must hold:
#
#   * `publish = false` in its own manifest. `cargo` refuses to publish a crate
#     that carries an unpublishable path dependency, so this closes the whole
#     library closure below it against a registry consumer, not just this
#     crate. It is the "outside the workspace" half, and it is a fact in the
#     metadata rather than a habit.
#   * every workspace package that consumes it through a NON-dev edge is a
#     library, and walking those edges upward terminates only at packages with
#     no library target at all -- a `bin` or a test-only crate, which nothing
#     can name a path through. That transitive set of libraries is PINNED here
#     as a SET, and it is checked in BOTH directions: a library that starts
#     consuming one of these reds because the set grew, and a name left behind
#     after its edge is deleted reds because the set shrank.
#
# A `build`-dependency edge is a FINDING: a build script is not a test target,
# and its code names paths like any other consumer. There is none today, which
# is the point -- the population must not be able to grow in silence.
#
# An empty population is a FINDING too, per package and overall: a crate no
# workspace edge reaches at all is one this row excuses without measuring, and
# "nobody consumes it" is the shape that makes every check below vacuous.
#
# ## What this does NOT claim
#
# The second half of the old sentence, "which the lanes already compile under
# every combination". That is a claim about lane coverage, it is `OFF_AXIS`'s
# weakest link, and NOTHING here measures it. It is deliberately dropped from
# both reasons rather than carried unmeasured -- feature COMBINATIONS have no
# instrument in this workspace at all (open-debt item 374), so a reason that
# leaned on them was leaning on nothing.
#
#: package -> the transitive set of workspace LIBRARIES that consume it through
#: non-dev edges. Empty means no library consumes it at all.
TEST_ONLY_REACH: dict[str, frozenset[str]] = {
    "wz-codecs-test-support": frozenset(),
    "wz-runtime-tokio-test-support": frozenset({"wz-e2e-harness"}),
}


# R2266 (open-debt item 606) — the FEATURE-level form of the same claim, for a
# crate that is NOT test-only but whose gated feature is.
#
# `wz-tls-record` read "one feature, and it gates test fixtures". The crate is
# ordinary -- `wz-analyze` consumes it as a normal dependency and `wz-replay`
# reaches it transitively -- so `TEST_ONLY_REACH` above cannot hold it: its
# library closure is real. What IS test-only is the FEATURE, and that is a
# different predicate rather than a looser one:
#
#   * `publish = false`, as above and for the same reason;
#   * every workspace edge that turns the named feature ON is a
#     `dev-dependency`, and at least one does -- a feature nothing enables is a
#     population of zero, which reports green by construction;
#   * NO feature definition anywhere in the workspace enables it, in this
#     package or another. That is the escape route: `wz-session-lwip`'s
#     `buffer-pool-session-rx-slim` enables `wz-link-lwip`'s feature of the
#     same name, so this shape is real in this tree and an edges-only check
#     would miss it;
#   * the `OFF_AXIS` row is covered ENTIRELY. A predicate holding part of a row
#     leaves the rest excused by prose while the row reads as measured, which
#     is worse than prose that admits what it is.
#: package -> the features of its `OFF_AXIS` row that are test-only
TEST_ONLY_FEATURE: dict[str, frozenset[str]] = {
    "wz-tls-record": frozenset({"fixtures"}),
}

# The residue of item 606, as a SET so that it is derived rather than recounted.
# Every `OFF_AXIS` row is in exactly one of three places: `ABI_CONTRACT`,
# `TEST_ONLY_REACH`, or here -- meaning its reason is still prose that nothing
# measures. A row in none of them, or in two, is a FINDING, so a row added
# tomorrow cannot land unclassified and this residue cannot drift.
#
# ⛔ These are NOT one kind of claim, which is why one predicate does not take
# them: `wz` re-exports whole subtrees, `wz-runtime-coop` points at the facade
# row, `wz-link-lwip` / `wz-session-lwip` point at deploy probes, and
# `wz-packet-socket` / `wz-runtime-core` / `wz-tls-record` each assert what
# their one feature gates. Retiring one is a round's work, and the round that
# does it moves the name out of this set in the same edit.
PROSE_ONLY: frozenset[str] = frozenset(
    {
        "wz",
        "wz-link-lwip",
        "wz-packet-socket",
        "wz-runtime-coop",
        "wz-runtime-core",
        "wz-session-lwip",
    }
)


class Dep(typing.NamedTuple):
    """One workspace dependency edge, seen from the package depended UPON."""

    consumer: str
    #: `cargo metadata` spells a normal edge as `null`; normalised here.
    kind: str
    #: the features this edge turns on explicitly. `TEST_ONLY_FEATURE` asks
    #: WHICH edge enables a name, which a crate-level walk cannot answer.
    features: frozenset[str] = frozenset()


#: The target kinds that make a package nameable by a Rust consumer. A `bin`,
#: a `test`, a `bench` and an `example` are NOT here on purpose: nothing can
#: take a dependency on them, so a path cannot be named through one.
LIB_KINDS = frozenset({"lib", "rlib", "dylib", "cdylib", "staticlib", "proc-macro"})


def dep_graph() -> tuple[dict[str, list[Dep]], set[str], set[str]]:
    """(package -> the workspace edges INTO it, libraries, unpublishables).

    The direction is deliberately reversed from a manifest's. The question
    `TEST_ONLY_REACH` asks is "who can name a path into this crate", and that
    is answered by CONSUMERS; a dependency list answers the other question.

    `publish` arrives as `[]` when a manifest says `publish = false` and as
    `null` when it says nothing at all, and `null` means "any registry". So the
    unpublishable set is the one carrying an EMPTY registry list, and reading
    it as a boolean would put every silent package in it.
    """
    meta = _metadata()
    into: dict[str, list[Dep]] = collections.defaultdict(list)
    libs: set[str] = set()
    unpublishable: set[str] = set()
    names = {p["name"] for p in meta["packages"]}
    for p in meta["packages"]:
        if any(set(t["kind"]) & LIB_KINDS for t in p["targets"]):
            libs.add(p["name"])
        if p.get("publish") == []:
            unpublishable.add(p["name"])
        for d in p["dependencies"]:
            if d["name"] in names:
                into[d["name"]].append(
                    Dep(
                        p["name"],
                        d.get("kind") or "normal",
                        frozenset(d.get("features") or ()),
                    )
                )
    return dict(into), libs, unpublishable


def feature_defs() -> dict[str, dict[str, list[str]]]:
    """package -> its feature table, exactly as `cargo metadata` reports it.

    Needed because an edge is not the only way a feature comes on: one
    package's feature can name another's (`wz-session-lwip`'s
    `buffer-pool-session-rx-slim` names `wz-link-lwip`'s, and that is a real
    row in this workspace), and a check that only read edges would call such a
    name unreachable.
    """
    return {p["name"]: p["features"] for p in _metadata()["packages"]}


class Reach(typing.NamedTuple):
    """What walking the consumer edges upward from one package found."""

    #: the transitive workspace LIBRARIES consuming it through non-dev edges
    libs: set[str]
    #: the packages the walk terminated at, which have no library target
    terminals: set[str]
    #: `(subject, consumer, kind)` for every edge that was not `normal`
    other: list[tuple[str, str, str]]
    #: how many edges were examined at all -- zero is a finding, never a pass
    edges: int


def reach_of(pkg: str, into: dict[str, list[Dep]], libs: set[str]) -> Reach:
    """Walk consumer edges upward from `pkg`, following libraries only.

    A non-library consumer ENDS the walk rather than continuing it, and that is
    the whole predicate: a `bin` cannot be depended on, so no path runs through
    one and the missing-feature diagnostic has no site to fire at beyond it.
    """
    seen: set[str] = set()
    terminals: set[str] = set()
    other: list[tuple[str, str, str]] = []
    edges = 0
    walked = {pkg}
    work = [pkg]
    while work:
        subject = work.pop()
        for dep in into.get(subject, []):
            edges += 1
            if dep.kind != "normal":
                other.append((subject, dep.consumer, dep.kind))
                continue
            if dep.consumer in libs:
                if dep.consumer not in walked:
                    walked.add(dep.consumer)
                    seen.add(dep.consumer)
                    work.append(dep.consumer)
            else:
                terminals.add(dep.consumer)
    return Reach(seen, terminals, other, edges)


@functools.lru_cache(maxsize=1)
def _metadata() -> dict:
    """`cargo metadata` for this workspace, read ONCE.

    Two derivations need it now -- the non-default feature lists below, and the
    dependency graph `TEST_ONLY_REACH` is decided from. Two subprocess runs
    could disagree about a tree edited between them, and that disagreement
    would surface as an unexplained finding rather than as itself.
    """
    out = subprocess.run(
        ["cargo", "metadata", "--no-deps", "--format-version", "1"],
        cwd=CRATES,
        capture_output=True,
        text=True,
    )
    if out.returncode != 0:
        raise RuntimeError(f"cargo metadata failed: {out.stderr[:400]}")
    return json.loads(out.stdout)


def workspace() -> tuple[dict[str, str], dict[str, set[str]]]:
    """(manifest dir -> package, package -> its NON-DEFAULT features)."""
    meta = _metadata()
    dirs: dict[str, str] = {}
    nondefault: dict[str, set[str]] = {}
    for p in meta["packages"]:
        d = pathlib.Path(p["manifest_path"]).parent
        try:
            dirs[str(d.relative_to(ROOT))] = p["name"]
        except ValueError:
            continue
        feats = p["features"]
        nondefault[p["name"]] = set(feats) - {"default"} - fgd.default_closure(feats)
    return dirs, nondefault


def owner(path: str, dirs: dict[str, str]) -> str | None:
    best: tuple[str, str] | None = None
    for d, name in dirs.items():
        if path.startswith(d + "/") and (best is None or len(d) > len(best[0])):
            best = (d, name)
    return best[1] if best else None


def classify(following: str) -> str:
    """Which class the item an attribute is attached to belongs to."""
    if PUBLIC_ITEM.match(following):
        return "public-item"
    if RESTRICTED_ITEM.match(following):
        return "restricted-item"
    if PRIVATE_ITEM.match(following):
        return "private-item"
    if ASSERTION.match(following):
        return "not-an-item"
    if MACRO_CALL.match(following):
        return "macro-invocation"
    if FIELD.match(following) or BLOCK_OR_STMT.match(following):
        return "not-an-item"
    if CALL_OR_PATH.match(following) or BARE_NAME.match(following):
        return "not-an-item"
    return "UNCLASSIFIED"


def attached(lines: list[str], start: int) -> str | None:
    """The source line the attribute at `start` is attached to.

    Attributes, blank lines and `//` comments stack in front of the item, so
    the first line that is none of those IS the item. The window runs to the
    end of the file on purpose: a bounded one reported 31 sites as having no
    following line when they simply had a long attribute stack.
    """
    for j in range(start + 1, len(lines)):
        s = lines[j].strip()
        if s == "" or s.startswith("//") or s.startswith("#["):
            continue
        return lines[j]
    return None


def scan(
    root: pathlib.Path, files: list[str], dirs: dict[str, str], nondefault: dict[str, set[str]]
) -> tuple[
    collections.Counter,
    set[tuple[str, str]],
    list[tuple[str, int, str]],
    dict[tuple[str, str], list["Shape"]],
]:
    """(class counts, denominator pairs, unclassified sites, site shapes)."""
    counts: collections.Counter = collections.Counter()
    denom: set[tuple[str, str]] = set()
    unclassified: list[tuple[str, int, str]] = []
    sites: dict[tuple[str, str], list[Shape]] = collections.defaultdict(list)
    for rel in files:
        if not rel.endswith(".rs"):
            continue
        path = root / rel
        if not path.is_file():
            continue
        pkg = owner(rel, dirs)
        try:
            lines = path.read_text(encoding="utf-8").split("\n")
        except (UnicodeDecodeError, OSError):
            continue
        for i, line in enumerate(lines):
            if not line.strip().startswith("#[cfg") or "feature" not in line:
                continue
            feats = FEATURE.findall(line)
            if not feats:
                continue
            following = attached(lines, i)
            if following is None:
                counts["UNCLASSIFIED"] += 1
                unclassified.append((rel, i + 1, "<no line after the attribute>"))
                continue
            kind = classify(following)
            counts[kind] += 1
            if kind == "UNCLASSIFIED":
                unclassified.append((rel, i + 1, following.strip()[:60]))
            elif kind in DENOMINATOR_CLASSES and pkg is not None:
                # R2207 — the SHAPE of the site, kept so a deferral's stated
                # reason can be held to it. See `DEFER_POLICY`.
                shape = Shape(
                    where=f"{rel}:{i + 1}",
                    compound=bool(COMPOUND.search(line)),
                    column=len(following) - len(following.lstrip()),
                )
                for f in feats:
                    if f in nondefault.get(pkg, ()):
                        denom.add((pkg, f))
                        sites[(pkg, f)].append(shape)
    return counts, denom, unclassified, sites


def probed_pairs() -> set[tuple[str, str]]:
    """DERIVED from the diagnostic axis, so widening it moves this fraction.

    MEASURED, because the first version of this was a dead probe: it read a
    single-package constant, so adding a probe for any OTHER package moved
    nothing here and the "widening moves the fraction" claim was prose. R2193
    made that axis a per-package table for this reason.

    R2194: the hand-written table is no longer the whole answer -- that axis
    now also READS probes off each crate root, and a fraction that counted only
    the typed ones would under-report the coverage it exists to report.
    """
    pairs = {(pkg, f) for pkg, feats in fgd.PROBES.items() for f in feats}
    for pkg, crate_path in fgd.AXIS.items():
        # BOTH derivations. R2195 added the submodule walk, and reading only
        # the crate-root one here made this file report features as decided
        # nowhere while the axis was probing every one of them -- the R2193
        # dead-probe shape again, caught this time by the gate rather than by
        # a mutation.
        #
        # R2197 re-ran that mutation before landing the round and it is TEN
        # findings, not the seventeen first written here: nineteen features
        # reach a public path through a submodule and nine of those are
        # derivable at the crate root as well. The GUARD is this union; the
        # count is only what the mutation printed on the day.
        pairs |= {(pkg, f) for f in fgd.derived_probes(pkg, crate_path)}
        pairs |= {(pkg, f) for f in fgd.submodule_probes(pkg, crate_path)}
    # A crate root gates DEFAULT features too, and the axis filters those out
    # before probing. Leaving them in here would credit coverage for probes
    # that are never built.
    return {(p, f) for p, f in pairs if f in nondefault_of(p)}


@functools.lru_cache(maxsize=None)
def nondefault_of(package: str) -> frozenset[str]:
    _dirs, nd = workspace()
    return frozenset(nd.get(package, ()))


def declared_pairs() -> set[tuple[str, str]]:
    return {(pkg, f) for pkg, feats in fgd.NO_PUBLIC_PATH.items() for f in feats}


def unprobed_pairs() -> set[tuple[str, str]]:
    """The waiting list: deferred ON the axis, plus the packages not on it.

    R2194 split it. A package the axis has taken keeps its per-feature reasons
    over there, because joining forces a decision on every one of its features;
    a package nobody has taken keeps one reason here for the whole package.
    Listing a package in both would be the second copy of one fact that this
    file exists to refuse elsewhere, and `check` fails on exactly that.
    """
    deferred = {(pkg, f) for pkg, feats in fgd.DEFERRED.items() for f in feats}
    off = {(pkg, f) for pkg, (_why, fs) in OFF_AXIS.items() for f in fs}
    return deferred | off


@functools.lru_cache(maxsize=None)
def negated_in(package: str) -> frozenset[str]:
    """Features this package writes a `cfg(not(feature = "x"))` for.

    The obligation behind `@defer cfg-not-twin`: such a feature SWAPS an
    implementation rather than removing a path, so turning it off leaves the
    path resolvable and there is no error for rustc to annotate. Read out of the
    package's own sources, so the claim ages with them.
    """
    out: set[str] = set()
    listed = subprocess.run(
        ["git", "ls-files", f"crates/{package}"],
        cwd=ROOT,
        capture_output=True,
        text=True,
    ).stdout.split()
    for rel in listed:
        if not rel.endswith(".rs"):
            continue
        try:
            text = (ROOT / rel).read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        for line in text.split("\n"):
            if "not(" in line and "feature" in line:
                out.update(FEATURE.findall(line))
    return frozenset(out)


def abi_module_is_abi(root: pathlib.Path, rel: str, module: str) -> str | None:
    """Why `module`, declared in `rel`, is not an ABI module — or `None`.

    Opens the module's own file, which is the whole point: a gated `pub mod` is
    a Rust path, and the only thing that makes it an ABI path instead is what is
    inside it. Reads the SIBLING file (`src/x.rs`) and the directory form
    (`src/x/mod.rs`), because either spelling is a module.

    A module whose file cannot be found is a finding, not a pass — the same rule
    the rest of this file follows for anything it could not read.
    """
    src = (root / rel).parent
    for candidate in (src / f"{module}.rs", src / module / "mod.rs"):
        if not candidate.is_file():
            continue
        lines = candidate.read_text(encoding="utf-8", errors="replace").split("\n")
        for i, line in enumerate(lines):
            if not ABI_PUB_FN.match(line):
                continue
            # Walk BACK over the attribute / doc stack in front of the fn. The
            # attributes are what carry `#[no_mangle]`, and they sit above the
            # signature rather than on it.
            j = i - 1
            marked = False
            while j >= 0:
                s = lines[j].strip()
                if s.startswith("#["):
                    marked = marked or "no_mangle" in s
                elif s.startswith("//") or s == "":
                    pass
                else:
                    break
                j -= 1
            if not marked:
                rel_c = candidate.relative_to(root).as_posix()
                return (
                    f"`{rel_c}:{i + 1}` is a strictly-`pub` fn with no "
                    f"`#[no_mangle]`, so `{module}` is a Rust path a caller can "
                    f"reach, not a C ABI module"
                )
        return None
    return f"the file for `pub mod {module}` was not found beside `{rel}`"


def abi_contract_findings(root: pathlib.Path, sites: dict[tuple[str, str], list[Shape]]) -> list[str]:
    """R2260 — hold every `ABI_CONTRACT` package's `OFF_AXIS` reason to the source.

    The reason claims the crate's feature-gated public surface is a C ABI. This
    reads every site that surface actually has and refuses anything a Rust
    caller could name.
    """
    findings: list[str] = []
    reached = 0
    for pkg in sorted(ABI_CONTRACT):
        if pkg not in OFF_AXIS:
            findings.append(
                f"`{pkg}` claims an ABI contract in `ABI_CONTRACT` but has no "
                f"`OFF_AXIS` row, so the claim excuses nothing and is unread"
            )
            continue
        _why, feats = OFF_AXIS[pkg]
        for feat in sorted(feats):
            for shape in sites.get((pkg, feat), []):
                rel, ln = shape.where.rsplit(":", 1)
                path = root / rel
                if not path.is_file():
                    findings.append(f"`{shape.where}` no longer exists")
                    continue
                lines = path.read_text(encoding="utf-8", errors="replace").split("\n")
                item = attached(lines, int(ln) - 1)
                if item is None:
                    findings.append(f"`{shape.where}` has no item after its attribute")
                    continue
                reached += 1
                mod = ABI_PUB_MOD.match(item)
                if mod:
                    why = abi_module_is_abi(root, rel, mod.group(1))
                    if why:
                        findings.append(
                            f"`{pkg}` / `{feat}` is excused as a C ABI contract, but {why} "
                            f"(`{shape.where}`)"
                        )
                    continue
                if ABI_PUB_FN.match(item):
                    stack = []
                    j = int(ln)
                    while j < len(lines) and lines[j].strip().startswith("#["):
                        stack.append(lines[j])
                        j += 1
                    if not any("no_mangle" in a for a in stack):
                        findings.append(
                            f"`{pkg}` / `{feat}` is excused as a C ABI contract, but "
                            f"`{shape.where}` gates a strictly-`pub` fn with no "
                            f"`#[no_mangle]` — a Rust caller can name it"
                        )
                    continue
                if ABI_USE.match(item):
                    findings.append(
                        f"`{pkg}` / `{feat}` is excused as a C ABI contract, but "
                        f"`{shape.where}` gates a `pub use` — a re-export IS a Rust path"
                    )
                    continue
                if ABI_DECLARATION.match(item):
                    continue
                findings.append(
                    f"`{pkg}` / `{feat}` is excused as a C ABI contract, but "
                    f"`{shape.where}` gates an item shape this check does not know "
                    f"(`{item.strip()[:60]}`) — unclassified is RED, not a pass"
                )
    # An excuse held to an EMPTY population excuses everything. The packages in
    # `ABI_CONTRACT` are there because they gate a public surface; a run that
    # reached none of it has measured nothing and must say so.
    if ABI_CONTRACT and reached == 0:
        findings.append(
            "no `ABI_CONTRACT` package has a single public-item site to hold its "
            "reason to, so this arm graded nothing while reporting clean"
        )
    return findings


def test_only_reach_findings(
    graph: tuple[dict[str, list[Dep]], set[str], set[str]] | None = None,
) -> list[str]:
    """R2266 — hold every `TEST_ONLY_REACH` row to the dependency graph.

    `graph` is injectable so the selftest can drive the FAIL paths the real
    tree cannot produce while it is clean, which is the half of any check here
    that nobody would otherwise exercise.
    """
    into, libs, unpublishable = graph if graph is not None else dep_graph()
    findings: list[str] = []
    examined = 0
    for pkg in sorted(TEST_ONLY_REACH):
        pinned = set(TEST_ONLY_REACH[pkg])
        if pkg not in OFF_AXIS:
            findings.append(
                f"`{pkg}` pins a test-only closure in `TEST_ONLY_REACH` but has "
                f"no `OFF_AXIS` row, so the claim excuses nothing and is unread"
            )
            continue
        if pkg not in libs:
            findings.append(
                f"`{pkg}` is excused as a test-support LIBRARY and has no "
                f"library target, so there is no public Rust surface for this "
                f"row to be about"
            )
            continue
        if pkg not in unpublishable:
            findings.append(
                f"`{pkg}` is excused because its consumers are this "
                f"workspace's own test targets, and its manifest does not say "
                f"`publish = false` -- a registry consumer outside this "
                f"workspace would be one this row never counted"
            )
        reach = reach_of(pkg, into, libs)
        examined += reach.edges
        if reach.edges == 0:
            findings.append(
                f"`{pkg}` is excused as test-support and NO workspace package "
                f"consumes it, by any kind of edge. An excuse held to an empty "
                f"population excuses everything: either something depends on "
                f"it and this walk is wrong, or the crate is dead and the row "
                f"is about nothing"
            )
        for subject, consumer, kind in sorted(reach.other):
            if kind == "dev":
                continue
            findings.append(
                f"`{consumer}` consumes `{subject}` as a `{kind}`-dependency, "
                f"and `{pkg}`'s row is excused on the claim that only test "
                f"targets name it. A build script is not a test target"
            )
        grew = reach.libs - pinned
        shrank = pinned - reach.libs
        for name in sorted(grew):
            findings.append(
                f"`{name}` is a workspace LIBRARY that now reaches `{pkg}` "
                f"through non-dev dependency edges, and `TEST_ONLY_REACH` does "
                f"not list it. A library is exactly the shape whose public "
                f"paths a Rust consumer names, so either the pin grows with a "
                f"reason or the row leaves this table"
            )
        for name in sorted(shrank):
            findings.append(
                f"`TEST_ONLY_REACH` pins `{name}` in `{pkg}`'s closure and no "
                f"chain of non-dev edges reaches it any more. A pin that "
                f"outlives its subject reports a closure nobody has; delete "
                f"the name in the commit that deleted the edge"
            )
    if TEST_ONLY_REACH and examined == 0:
        findings.append(
            "no `TEST_ONLY_REACH` package has a single workspace dependency "
            "edge to hold its reason to, so this arm graded nothing while "
            "reporting clean"
        )
    # THE RESIDUE, DERIVED. Every `OFF_AXIS` row is measured by one of the
    # predicates or declared prose-only; a row in neither is unclassified, and
    # unclassified is RED here for the same reason it is in `classify`.
    measured = set(ABI_CONTRACT) | set(TEST_ONLY_REACH) | set(TEST_ONLY_FEATURE)
    for pkg in sorted(set(OFF_AXIS) - measured - PROSE_ONLY):
        findings.append(
            f"`{pkg}` has an `OFF_AXIS` row and is in neither predicate table "
            f"nor `PROSE_ONLY`. A row nothing measures and nothing admits to "
            f"be prose is an escape hatch from the derivation it sits beside "
            f"-- name it in `PROSE_ONLY` with item 606, or measure it"
        )
    for pkg in sorted(measured & PROSE_ONLY):
        findings.append(
            f"`{pkg}` is held to a predicate AND declared prose-only, and "
            f"those cannot both be true -- one fact, one place"
        )
    for pkg in sorted(PROSE_ONLY - set(OFF_AXIS)):
        findings.append(
            f"`{pkg}` is declared prose-only and has no `OFF_AXIS` row, so the "
            f"residue it reports is work nobody has. Delete the name"
        )
    tables = (ABI_CONTRACT, TEST_ONLY_REACH, TEST_ONLY_FEATURE)
    for i, first in enumerate(tables):
        for second in tables[i + 1 :]:
            for pkg in sorted(set(first) & set(second)):
                findings.append(
                    f"`{pkg}` is held to two predicate tables, and each was "
                    f"written for a different kind of claim -- pick the one "
                    f"its row makes"
                )
    return findings


def test_only_feature_findings(
    graph: tuple[dict[str, list[Dep]], set[str], set[str]] | None = None,
    defs: dict[str, dict[str, list[str]]] | None = None,
) -> list[str]:
    """R2266 — hold every `TEST_ONLY_FEATURE` row to the graph AND the feature
    tables. Both inputs are injectable, for the reason the sibling arm gives.
    """
    into, _libs, unpublishable = graph if graph is not None else dep_graph()
    tables = defs if defs is not None else feature_defs()
    findings: list[str] = []
    examined = 0
    for pkg in sorted(TEST_ONLY_FEATURE):
        feats = set(TEST_ONLY_FEATURE[pkg])
        if pkg not in OFF_AXIS:
            findings.append(
                f"`{pkg}` names test-only features in `TEST_ONLY_FEATURE` but "
                f"has no `OFF_AXIS` row, so the claim excuses nothing and is "
                f"unread"
            )
            continue
        _why, row = OFF_AXIS[pkg]
        if feats != set(row):
            findings.append(
                f"`{pkg}`'s `OFF_AXIS` row names {sorted(row)} and "
                f"`TEST_ONLY_FEATURE` holds {sorted(feats)}. A predicate "
                f"covering PART of a row leaves the rest excused by prose "
                f"while the row reads as measured, which is worse than prose "
                f"that admits what it is"
            )
            continue
        if pkg not in unpublishable:
            findings.append(
                f"`{pkg}` has a test-only feature row and its manifest does "
                f"not say `publish = false`, so a registry consumer could "
                f"enable that feature from outside this workspace"
            )
        for feat in sorted(feats):
            enabling = [d for d in into.get(pkg, []) if feat in d.features]
            examined += len(enabling)
            if not enabling:
                findings.append(
                    f"nothing in this workspace turns `{pkg}`'s `{feat}` on, "
                    f"so the claim that only test targets do is held to an "
                    f"empty population -- either the feature is dead or this "
                    f"read of the edges is wrong"
                )
            for dep in sorted(enabling):
                if dep.kind != "dev":
                    findings.append(
                        f"`{dep.consumer}` turns `{pkg}`'s `{feat}` on through "
                        f"a `{dep.kind}` edge, and the row is excused on the "
                        f"claim that only test targets enable it"
                    )
            for other_pkg, table in sorted(tables.items()):
                for other_feat, enables in sorted(table.items()):
                    if other_pkg == pkg and other_feat == feat:
                        continue
                    for token in enables:
                        base = token.split("?/")[0].split("/")[0]
                        base = base[4:] if base.startswith("dep:") else base
                        named = token.split("/", 1)[1] if "/" in token else token
                        if (base == pkg or other_pkg == pkg) and named == feat:
                            findings.append(
                                f"`{other_pkg}`'s `{other_feat}` feature "
                                f"enables `{pkg}`'s `{feat}` (`{token}`), so "
                                f"an edge that never names `{feat}` can still "
                                f"turn it on. A check that only read edges "
                                f"would call this unreachable"
                            )
    if TEST_ONLY_FEATURE and examined == 0:
        findings.append(
            "no `TEST_ONLY_FEATURE` row has a single edge enabling it, so this "
            "arm graded nothing while reporting clean"
        )
    return findings


def defer_findings(sites: dict[tuple[str, str], list[Shape]]) -> list[str]:
    """R2207 — hold every `DEFERRED` reason to what its marker obliges.

    See `DEFER_POLICY` for the vocabulary and why prose alone was not enough.
    Only pairs the scan actually found sites for are judged: a name whose sites
    have gone is a different finding, already raised above, and reporting both
    for one edit would say the same thing twice.
    """
    out: list[str] = []
    for pkg, feats in sorted(fgd.DEFERRED.items()):
        for feat, why in sorted(feats.items()):
            marks = DEFER_MARKER.findall(why)
            if len(marks) != 1 or marks[0] not in DEFER_POLICY:
                out.append(
                    f"`{pkg}` / `{feat}` is deferred with a reason carrying "
                    f"{'no' if not marks else 'the'} `@defer` marker"
                    f"{'' if not marks else ' ' + repr(marks)}. Exactly one is "
                    f"required, from {DEFER_POLICY}: a waiting-list reason "
                    f"nothing can check is the escape hatch this file refuses "
                    f"one table up."
                )
                continue
            found = sites.get((pkg, feat))
            if not found:
                continue
            word = marks[0]
            if word == "compound-cfg":
                simple = [s for s in found if not s.compound]
                if simple:
                    out.append(
                        f"`{pkg}` / `{feat}` is deferred as `compound-cfg` -- "
                        f"every public item it gates behind an `any`/`all`/"
                        f"`not`, which rustc cannot name a feature for. It has "
                        f"{len(simple)} site(s) under a SIMPLE cfg "
                        f"({', '.join(s.where for s in simple[:3])}), and one "
                        f"of those can carry the probe."
                    )
            elif word == "impl-method":
                bare = [s for s in found if not s.compound and s.column == 0]
                if bare:
                    out.append(
                        f"`{pkg}` / `{feat}` is deferred as `impl-method` -- "
                        f"reachable only as `Type::name`, which removing makes "
                        f"an E0599 rather than the E0432/E0433 this axis "
                        f"adjudicates. It has {len(bare)} MODULE-LEVEL site(s) "
                        f"under a simple cfg "
                        f"({', '.join(s.where for s in bare[:3])}), which is "
                        f"the shape the axis probes."
                    )
            elif word == "cfg-not-twin" and feat not in negated_in(pkg):
                out.append(
                    f"`{pkg}` / `{feat}` is deferred as `cfg-not-twin` -- an "
                    f"implementation swap with no resolution error to "
                    f"annotate -- and no `cfg(not(feature = \"{feat}\"))` "
                    f"occurs in that package. The twin the reason turns on is "
                    f"not there."
                )
    return out


def check() -> int:
    dirs, nondefault = workspace()
    files = subprocess.run(
        ["git", "ls-files", "crates"], cwd=ROOT, capture_output=True, text=True
    ).stdout.split()
    counts, denom, unclassified, sites = scan(ROOT, files, dirs, nondefault)

    findings: list[str] = []

    total_sites = sum(counts.values())
    if total_sites == 0:
        print(
            "feature-public-surface: FAIL -- no `#[cfg(feature = ...)]` site in "
            "this workspace, so every arm below would report clean over an "
            "empty population"
        )
        return 1
    if not denom:
        print(
            "feature-public-surface: FAIL -- no non-default feature gates a "
            "public item, which would make the diagnostic axis's coverage a "
            "fraction with no denominator. If that is genuinely true now, this "
            "floor comes down in the same commit that made it true."
        )
        return 1

    seen_paths = {rel for rel, _line, _what in unclassified}
    for rel, line, what in unclassified:
        if rel not in UNCLASSIFIED_DECLARED:
            findings.append(
                f"{rel}:{line}: a `#[cfg(feature = ...)]` whose item this gate "
                f"cannot classify -- it is attached to `{what}`. Unclassified "
                f"is not a pass: it decides whether the feature belongs in the "
                f"denominator, so either the shape belongs in `classify`, or "
                f"the file belongs in `UNCLASSIFIED_DECLARED` with the reason."
            )
    for rel, why in sorted(UNCLASSIFIED_DECLARED.items()):
        if rel not in seen_paths:
            findings.append(
                f"{rel}: declared to hold an unclassifiable site ({why}) and it "
                f"no longer does. A declaration that outlives its subject is a "
                f"permission slip nobody re-reads; delete the entry."
            )

    probed, declared, unprobed = probed_pairs(), declared_pairs(), unprobed_pairs()
    accounted = probed | declared | unprobed
    for pkg in sorted(set(OFF_AXIS) & set(fgd.AXIS)):
        findings.append(
            f"`{pkg}` is on the diagnostic axis AND still listed as off it. "
            f"Joining the axis forces a decision on every one of that "
            f"package's non-default features over there, so the whole-package "
            f"row here has to go -- one fact, one place."
        )
    for pkg, feat in sorted(denom - accounted):
        findings.append(
            f"`{pkg}` / `{feat}` is a non-default feature gating a public item "
            f"and nothing says what is being done about it. If its package is "
            f"on the diagnostic axis, give it a probe, a `NO_PUBLIC_PATH` "
            f"entry or a `DEFERRED` row there; if it is not, name the feature "
            f"in this file's `OFF_AXIS` row for that package -- the population "
            f"must not be able to grow in silence, which is the whole of item "
            f"532."
        )
    for pkg, feat in sorted(unprobed - denom):
        findings.append(
            f"`{pkg}` / `{feat}` is listed as an unprobed public-surface "
            f"feature and no `#[cfg]` in that package attaches it to a public "
            f"item any more. Delete the name: a waiting list that keeps names "
            f"nothing is waiting for reports work that does not exist."
        )
    # THE OTHER DIRECTION ON `NO_PUBLIC_PATH`, and it is the one that stops a
    # reason-string table being an escape hatch: the diagnostic axis accepts
    # "this gates no public path" as a decision, and nothing over there can
    # check it. Here it is a DERIVED claim, and a false one fails.
    for pkg, feat in sorted(declared & denom):
        findings.append(
            f"`{pkg}` / `{feat}` is declared to gate no public path, and this "
            f"scan finds a `#[cfg]` in that package attaching it to a publicly "
            f"visible item. A declaration is not a decision the derivation has "
            f"to accept: probe it, defer it with a reason, or correct the "
            f"claim."
        )
    overlap = (probed | declared) & unprobed
    for pkg, feat in sorted(overlap):
        findings.append(
            f"`{pkg}` / `{feat}` is both handled by the diagnostic axis and "
            f"listed as unprobed, and those cannot both be true"
        )
    findings.extend(defer_findings(sites))
    findings.extend(abi_contract_findings(ROOT, sites))
    findings.extend(test_only_reach_findings())
    findings.extend(test_only_feature_findings())

    if findings:
        print(f"feature-public-surface: FAIL -- {len(findings)} finding(s)")
        for f in findings:
            print(f"  {f}")
        return 1

    nd_total = sum(len(v) for v in nondefault.values())
    deferred_on_axis = {
        (pkg, f) for pkg, feats in fgd.DEFERRED.items() for f in feats
    }
    print(
        f"  feature-public-surface: {total_sites} `#[cfg(feature)]` site(s) all "
        f"classified; of {nd_total} non-default feature(s) in this workspace, "
        f"{len(denom)} gate a public item -- "
        f"{len(denom & probed)} probed, {len(denom & declared)} declared to "
        f"gate no public path, {len(denom & deferred_on_axis)} deferred on the "
        f"axis, {len(denom & unprobed) - len(denom & deferred_on_axis)} in "
        f"{len(OFF_AXIS)} package(s) the axis has not taken"
    )
    # The residue of item 606, DERIVED. It used to be a number in a comment,
    # and that number was wrong by two for as long as it stood.
    print(
        f"    off-axis reasons: {len(set(ABI_CONTRACT) & set(OFF_AXIS))} held to "
        f"`ABI_CONTRACT`, {len(set(TEST_ONLY_REACH) & set(OFF_AXIS))} to "
        f"`TEST_ONLY_REACH`, {len(set(TEST_ONLY_FEATURE) & set(OFF_AXIS))} to "
        f"`TEST_ONLY_FEATURE`, {len(PROSE_ONLY)} still prose (item 606)"
    )
    for kind in (
        "public-item",
        "macro-invocation",
        "restricted-item",
        "private-item",
        "not-an-item",
    ):
        print(f"    {counts[kind]:5}  {kind}")
    return 0


# ASSEMBLED, NEVER SPELLED. The production scan reads `crates/**`, not this
# file, so a fixture here could not be mistaken for a real site -- but the
# sibling gates in this directory learned the same lesson the expensive way and
# the habit costs nothing.
_ATTR = "#[cfg(fea" + 'ture = "{f}")]'


def _fixture() -> dict[str, str]:
    """One file per class, plus the shapes an earlier scanner got WRONG."""
    a = _ATTR.format(f="alpha")
    b = _ATTR.format(f="beta")

    return {
        "demo/src/pub_item.rs": f"{a}\npub fn reach() {{}}\n",
        "demo/src/macro_item.rs": f"{b}\nmake_public_thing!(one, two);\n",
        "demo/src/restricted.rs": f"{a}\npub(crate) fn hidden() {{}}\n",
        "demo/src/private.rs": f"{a}\nfn internal() {{}}\n",
        "demo/src/expr.rs": f"fn f() {{\n    {a}\n    let x = 1;\n}}\n",
        "demo/src/field.rs": f"pub struct S {{\n    {a}\n    pub n: usize,\n}}\n",
        # an assertion is a macro call and must NOT reach the denominator
        "demo/src/assertion.rs": f"fn t() {{\n    {a}\n    assert!(true);\n}}\n",
        # a long attribute stack: the item is several lines down, and a bounded
        # window reported these as having no following line at all
        "demo/src/stacked.rs": (
            f"{a}\n#[allow(dead_code)]\n// a comment\n\npub struct Late;\n"
        ),
        # attached to nothing this gate can name
        "demo/src/weird.rs": f"{a}\n@@@ not rust @@@\n",
    }


def abi_selftest() -> int:
    """R2260 — drive `abi_contract_findings` through every way it refuses.

    Two of these are CONTROLS that must PASS, and they are the half that makes
    the rest mean anything: a predicate that refused an `extern "C"` fn or a C
    constant would be refusing exactly what an ABI crate is made of, and the row
    would have to come back out.
    """
    nm = '#[no_mangle]\npub unsafe extern "C" fn ok() {}\n'
    bare = "pub fn a_rust_caller_can_name() {}\n"
    files = {
        "demo/src/lib.rs": (
            '#[cfg(feature = "abi")]\n#[no_mangle]\npub extern "C" fn direct() {}\n'
            '#[cfg(feature = "abi")]\npub const Z_THING: u32 = 1;\n'
            '#[cfg(feature = "abi")]\npub mod good;\n'
            '#[cfg(feature = "abi")]\npub mod bad;\n'
            '#[cfg(feature = "abi")]\npub fn loose() {}\n'
            '#[cfg(feature = "abi")]\npub use crate::good::ok as Alias;\n'
            '#[cfg(feature = "abi")]\npub mod missing;\n'
            # a public item shape the predicate has no rule for. It must be a
            # FINDING rather than fall through the bottom as a pass — the
            # unclassified-is-RED rule this file applies to its own scanner,
            # applied to this arm too.
            '#[cfg(feature = "abi")]\npub trait NotAnAbiThing {}\n'
        ),
        "demo/src/good.rs": nm,
        # the shape the whole predicate exists for: a module that LOOKS like an
        # ABI module from `lib.rs` and is a Rust path once opened
        "demo/src/bad.rs": nm + bare,
    }
    dirs = {"demo": "demo"}
    nondefault = {"demo": {"abi"}}
    real_off, real_abi = OFF_AXIS.get("demo"), ABI_CONTRACT.get("demo")
    with tempfile.TemporaryDirectory() as tmp:
        home = pathlib.Path(tmp)
        for rel, body in files.items():
            (home / rel).parent.mkdir(parents=True, exist_ok=True)
            (home / rel).write_text(body, encoding="utf-8")
        _c, _d, _u, sites = scan(home, sorted(files), dirs, nondefault)
        try:
            OFF_AXIS["demo"] = ("fixture", frozenset({"abi"}))
            ABI_CONTRACT["demo"] = "fixture"
            findings = abi_contract_findings(home, sites)
            # An `ABI_CONTRACT` package with no `OFF_AXIS` row excuses nothing.
            del OFF_AXIS["demo"]
            orphan = abi_contract_findings(home, {})
        finally:
            OFF_AXIS.pop("demo", None)
            ABI_CONTRACT.pop("demo", None)
            if real_off is not None:
                OFF_AXIS["demo"] = real_off
            if real_abi is not None:
                ABI_CONTRACT["demo"] = real_abi

    got = set()
    for f in findings:
        if "gates a strictly-`pub` fn" in f:
            got.add("loose-fn")
        elif "is a strictly-`pub` fn with no" in f:
            got.add("bad-module")
        elif "`pub use`" in f:
            got.add("reexport")
        elif "was not found beside" in f:
            got.add("missing-module")
        elif "does not know" in f:
            got.add("unknown-shape")
    want = {"loose-fn", "bad-module", "reexport", "missing-module", "unknown-shape"}
    if got != want:
        print(
            f"feature-public-surface: SELFTEST FAIL -- the ABI-contract "
            f"predicate must refuse exactly {sorted(want)} and it refused "
            f"{sorted(got)} (from {findings}). The `extern \"C\"` fn, the "
            f"`pub const` and the module whose every `pub fn` is `#[no_mangle]` "
            f"are the CONTROLS: refusing those would refuse what an ABI crate "
            f"is made of."
        )
        return 1
    if not any("has no `OFF_AXIS` row" in f for f in orphan):
        print(
            "feature-public-surface: SELFTEST FAIL -- an `ABI_CONTRACT` entry "
            "whose package has no `OFF_AXIS` row excuses nothing and must be "
            "reported, or the two tables can drift apart unread"
        )
        return 1
    if not any("graded nothing" in f for f in abi_contract_findings(pathlib.Path("/"), {})):
        print(
            "feature-public-surface: SELFTEST FAIL -- an empty population must "
            "FAIL rather than report clean; a reason held to nothing excuses "
            "everything"
        )
        return 1
    return 0


def test_only_selftest() -> int:
    """R2266 — drive `test_only_reach_findings` through every way it refuses.

    An INJECTED graph rather than the tree, for the reason the sibling arms
    give: the tree is (and must stay) clean, so every FAIL path here is one the
    real run never takes. Two of the rows are CONTROLS that must PASS, and they
    are what stops the predicate being one that refuses test-support crates in
    general -- `ts_dev` is the dev-edges-only shape and `ts_chain` is the one
    the refuted `wz-runtime-tokio-test-support` row actually has: a library
    consumer, terminating at a package with no library target.
    """
    libs = {
        "ts_dev",
        "ts_chain",
        "h_lib",
        "ts_grown",
        "new_lib",
        "ts_shrunk",
        "ts_orphan",
        "ts_pub",
        "ts_build",
        "ts_noff",
        "px_dual",
    }
    unpublishable = libs - {"ts_pub"} | {"ts_nolib"}
    into: dict[str, list[Dep]] = {
        "ts_dev": [Dep("t_tests", "dev")],
        "ts_chain": [Dep("h_lib", "normal")],
        "h_lib": [Dep("b_bin", "normal")],
        "ts_grown": [Dep("new_lib", "normal")],
        "ts_shrunk": [Dep("t_tests", "dev")],
        "ts_pub": [Dep("t_tests", "dev")],
        "ts_build": [Dep("bs", "build")],
        "ts_nolib": [Dep("t_tests", "dev")],
        "ts_noff": [Dep("t_tests", "dev")],
        "px_dual": [Dep("t_tests", "dev")],
    }
    reach = {
        "ts_dev": frozenset(),
        "ts_chain": frozenset({"h_lib"}),
        "ts_grown": frozenset(),
        "ts_shrunk": frozenset({"vanished"}),
        "ts_orphan": frozenset(),
        "ts_pub": frozenset(),
        "ts_build": frozenset(),
        "ts_nolib": frozenset(),
        "ts_noff": frozenset(),
        "px_dual": frozenset(),
    }
    off = {
        name: ("fixture", frozenset({"f"}))
        for name in list(reach) + ["px_prose", "px_unclassified", "px_both"]
        if name != "ts_noff"
    }
    real = (OFF_AXIS.copy(), TEST_ONLY_REACH.copy(), ABI_CONTRACT.copy(), PROSE_ONLY)
    try:
        OFF_AXIS.clear()
        OFF_AXIS.update(off)
        TEST_ONLY_REACH.clear()
        TEST_ONLY_REACH.update(reach)
        ABI_CONTRACT.clear()
        ABI_CONTRACT.update({"px_both": "fixture", "px_dual": "fixture"})
        globals()["PROSE_ONLY"] = frozenset({"px_prose", "px_both", "px_ghost"})
        findings = test_only_reach_findings((into, libs, unpublishable))
        empty = test_only_reach_findings(({}, libs, unpublishable))
    finally:
        OFF_AXIS.clear()
        OFF_AXIS.update(real[0])
        TEST_ONLY_REACH.clear()
        TEST_ONLY_REACH.update(real[1])
        ABI_CONTRACT.clear()
        ABI_CONTRACT.update(real[2])
        globals()["PROSE_ONLY"] = real[3]

    marks = (
        ("excuses nothing and is unread", "no-off-axis-row"),
        ("has no library target", "not-a-library"),
        ("`publish = false`", "publishable"),
        ("NO workspace package consumes it", "empty-population"),
        ("-dependency, and", "build-edge"),
        ("does not list it", "closure-grew"),
        ("outlives its subject", "closure-shrank"),
        ("nor `PROSE_ONLY`", "unclassified-row"),
        ("AND declared prose-only", "measured-and-prose"),
        ("the residue it reports is work nobody has", "prose-only-ghost"),
        ("held to two predicate tables", "two-predicates"),
    )
    got = {mark for needle, mark in marks if any(needle in f for f in findings)}
    want = {mark for _needle, mark in marks}
    if got != want:
        print(
            f"feature-public-surface: SELFTEST FAIL -- the test-only-reach "
            f"predicate must refuse exactly {sorted(want)} and it refused "
            f"{sorted(got)} (from {findings}). `ts_dev`, `ts_chain` and "
            f"`px_prose` are the CONTROLS: refusing a crate whose only edges "
            f"are dev ones, or one whose library consumer terminates at a "
            f"package with no library target, would refuse exactly what a "
            f"test-support crate is."
        )
        return 1
    for control in ("ts_dev", "ts_chain", "px_prose"):
        if any(f"`{control}`" in f for f in findings):
            print(
                f"feature-public-surface: SELFTEST FAIL -- `{control}` is a "
                f"CONTROL and the predicate reported it: {findings}"
            )
            return 1
    if not any("graded nothing" in f for f in empty):
        print(
            "feature-public-surface: SELFTEST FAIL -- a graph with no edge at "
            "all must FAIL rather than report clean; a closure held to nothing "
            "excuses everything"
        )
        return 1
    return 0


def test_only_feature_selftest() -> int:
    """R2266 — drive `test_only_feature_findings` through every way it refuses.

    `tf_ok` is the CONTROL: a `publish = false` crate with one feature that a
    single `dev-dependency` edge enables and no feature definition names. That
    is exactly `wz-tls-record`'s shape, and a predicate refusing it would be
    refusing what a test-fixture feature IS.
    """
    unpublishable = {"tf_ok", "tf_normal", "tf_dead", "tf_indirect", "tf_partial", "tf_noff"}
    into: dict[str, list[Dep]] = {
        "tf_ok": [Dep("t_tests", "dev", frozenset({"fx"}))],
        "tf_normal": [Dep("prod", "normal", frozenset({"fx"}))],
        "tf_pub": [Dep("t_tests", "dev", frozenset({"fx"}))],
        "tf_dead": [Dep("t_tests", "dev", frozenset())],
        "tf_indirect": [Dep("t_tests", "dev", frozenset({"fx"}))],
        "tf_partial": [Dep("t_tests", "dev", frozenset({"fx"}))],
        "tf_noff": [Dep("t_tests", "dev", frozenset({"fx"}))],
    }
    rows = {
        "tf_ok": frozenset({"fx"}),
        "tf_normal": frozenset({"fx"}),
        "tf_pub": frozenset({"fx"}),
        "tf_dead": frozenset({"fx"}),
        "tf_indirect": frozenset({"fx"}),
        "tf_partial": frozenset({"fx"}),
        "tf_noff": frozenset({"fx"}),
    }
    off = {
        name: ("fixture", frozenset({"fx", "other"}) if name == "tf_partial" else frozenset({"fx"}))
        for name in rows
        if name != "tf_noff"
    }
    defs = {
        "tf_ok": {"fx": []},
        "tf_normal": {"fx": []},
        "tf_pub": {"fx": []},
        "tf_dead": {"fx": []},
        # the escape route: another package's feature turns it on, so no edge
        # has to name it
        "tf_indirect": {"fx": []},
        "neighbour": {"bundle": ["tf_indirect/fx"]},
        "tf_partial": {"fx": [], "other": []},
        "tf_noff": {"fx": []},
    }
    real_off, real_rows = OFF_AXIS.copy(), TEST_ONLY_FEATURE.copy()
    try:
        OFF_AXIS.clear()
        OFF_AXIS.update(off)
        TEST_ONLY_FEATURE.clear()
        TEST_ONLY_FEATURE.update(rows)
        findings = test_only_feature_findings((into, set(), unpublishable), defs)
        empty = test_only_feature_findings(({}, set(), unpublishable), defs)
    finally:
        OFF_AXIS.clear()
        OFF_AXIS.update(real_off)
        TEST_ONLY_FEATURE.clear()
        TEST_ONLY_FEATURE.update(real_rows)

    marks = (
        ("excuses nothing and is unread", "no-off-axis-row"),
        ("covering PART of a row", "partial-row"),
        ("does not say `publish = false`", "publishable"),
        ("nothing in this workspace turns", "dead-feature"),
        ("edge, and the row is excused", "normal-edge"),
        ("would call this unreachable", "feature-enables-it"),
    )
    got = {mark for needle, mark in marks if any(needle in f for f in findings)}
    want = {mark for _needle, mark in marks}
    if got != want:
        print(
            f"feature-public-surface: SELFTEST FAIL -- the test-only-feature "
            f"predicate must refuse exactly {sorted(want)} and it refused "
            f"{sorted(got)} (from {findings}). `tf_ok` is the CONTROL."
        )
        return 1
    if any("`tf_ok`" in f for f in findings):
        print(
            f"feature-public-surface: SELFTEST FAIL -- `tf_ok` is the CONTROL "
            f"and the predicate reported it: {findings}"
        )
        return 1
    if not any("graded nothing" in f for f in empty):
        print(
            "feature-public-surface: SELFTEST FAIL -- a graph with no enabling "
            "edge at all must FAIL rather than report clean"
        )
        return 1
    return 0


def selftest() -> int:
    """Every class, both denominator members, and the two late repairs."""
    dirs = {"demo": "demo"}
    nondefault = {"demo": {"alpha", "beta"}}
    with tempfile.TemporaryDirectory() as tmp:
        home = pathlib.Path(tmp)
        fixture = _fixture()
        for rel, body in fixture.items():
            (home / rel).parent.mkdir(parents=True, exist_ok=True)
            (home / rel).write_text(body, encoding="utf-8")
        counts, denom, unclassified, sites = scan(
            home, sorted(fixture), dirs, nondefault
        )

    want_counts = {
        "public-item": 2,
        "macro-invocation": 1,
        "restricted-item": 1,
        "private-item": 1,
        "not-an-item": 3,
        "UNCLASSIFIED": 1,
    }
    if dict(counts) != want_counts:
        print(
            f"feature-public-surface: SELFTEST FAIL -- expected {want_counts} "
            f"and the scan produced {dict(counts)}. An assertion must not count "
            f"as a macro invocation, and a stacked attribute must still find "
            f"its item."
        )
        return 1
    if denom != {("demo", "alpha"), ("demo", "beta")}:
        print(
            f"feature-public-surface: SELFTEST FAIL -- the denominator must "
            f"hold the public item's feature AND the macro invocation's, and "
            f"it held {sorted(denom)}. A macro can expand to a public item, so "
            f"leaving it out is the under-reporting direction."
        )
        return 1
    if [rel for rel, _l, _w in unclassified] != ["demo/src/weird.rs"]:
        print(
            f"feature-public-surface: SELFTEST FAIL -- exactly the "
            f"unrecognisable site must be unclassified, and the scan said "
            f"{unclassified}"
        )
        return 1
    # R2207 — AND THE DEFERRAL POLICY, driven through every way it refuses.
    #
    # A fixture rather than the tree, for the reason this whole function
    # exists: the tree is (and must stay) clean, so the FAIL paths of a check
    # that only ever sees clean input are the half nobody exercises. Each probe
    # below is a shape the OLD prose-only waiting list would have swallowed
    # without a word.
    shapes = {
        ("demo", "compound_ok"): [Shape("a.rs:1", True, 0)],
        ("demo", "compound_bad"): [Shape("a.rs:2", True, 0), Shape("a.rs:3", False, 0)],
        ("demo", "method_ok"): [Shape("b.rs:1", False, 4)],
        ("demo", "method_bad"): [Shape("b.rs:2", False, 0)],
        ("demo", "marker_missing"): [Shape("c.rs:1", True, 0)],
        ("demo", "marker_unknown"): [Shape("c.rs:2", True, 0)],
        ("demo", "gone"): [],
    }
    probes = {
        "compound_ok": "@defer compound-cfg",
        "compound_bad": "@defer compound-cfg",
        "method_ok": "@defer impl-method",
        "method_bad": "@defer impl-method",
        "marker_missing": "no marker at all",
        "marker_unknown": "@defer someday",
        "gone": "@defer compound-cfg",
    }
    real = fgd.DEFERRED
    try:
        fgd.DEFERRED = {"demo": probes}
        got = {f.split("`")[3] for f in defer_findings(shapes)}
    finally:
        fgd.DEFERRED = real
    want = {"compound_bad", "method_bad", "marker_missing", "marker_unknown"}
    if got != want:
        print(
            f"feature-public-surface: SELFTEST FAIL -- the deferral policy must "
            f"refuse exactly {sorted(want)} and it refused {sorted(got)}. "
            f"`compound_ok` and `method_ok` are the CONTROLS: a check that "
            f"refused those would be refusing the shapes the markers exist to "
            f"describe, and `gone` is the one whose sites have vanished, which "
            f"a different arm already reports."
        )
        return 1

    # R2260 — AND THE ABI-CONTRACT PREDICATE, driven the same way and for the
    # same reason: the tree is clean, so every FAIL path here is one the real
    # run never takes. Each shape below is one the OLD prose-only `OFF_AXIS`
    # reason swallowed in silence — which is not hypothetical, because the row
    # this predicate replaces asserted "rather than adding or removing a Rust
    # path" while gating five `pub mod` declarations.
    if abi_selftest() != 0:
        return 1

    # R2266 — AND THE TEST-ONLY-REACH PREDICATE, on an injected dependency
    # graph and for the same reason. The row this one replaces said "same
    # reason as the other one" while a `lib` target consumed it as a normal
    # dependency, so the shapes below are not hypothetical either.
    if test_only_selftest() != 0:
        return 1
    if test_only_feature_selftest() != 0:
        return 1

    print(
        "feature-public-surface: selftest OK -- separates a public item, a "
        "macro call, a restricted item, a private item, a field, a statement "
        "and an assertion; finds an item behind a stacked attribute; refuses "
        "to guess at a shape it does not know; and holds each `@defer` marker "
        "to what its sites say, refusing a simple-cfg site under "
        "`compound-cfg`, a module-level one under `impl-method`, a missing "
        "marker and an unknown word -- past two clean controls; and holds "
        "each `ABI_CONTRACT` row to the source, refusing a loose `pub fn`, a "
        "module that is one once opened, a `pub use`, a module file that is "
        "not there, a shape it has no rule for, a row with no `OFF_AXIS` "
        "entry and an empty population -- past three clean controls; and "
        "holds each `TEST_ONLY_REACH` row to the dependency graph, refusing a "
        "publishable crate, one with no library target, a build-dependency "
        "edge, a library consumer the pin does not list, a pinned name no "
        "edge reaches, a crate nothing consumes, a row with no `OFF_AXIS` "
        "entry, an `OFF_AXIS` row in neither predicate nor `PROSE_ONLY`, a "
        "row in both, a prose-only name with no row, and an empty graph -- "
        "past three clean controls; and holds each `TEST_ONLY_FEATURE` row to "
        "the graph AND the feature tables, refusing a publishable crate, a "
        "non-dev edge that enables the feature, a feature no edge enables, a "
        "feature another package's feature turns on, a row covered only in "
        "part, a row with no `OFF_AXIS` entry and an empty graph -- past one "
        "clean control"
    )
    return 0


def main(argv: list[str]) -> int:
    if len(argv) != 1 or argv[0] not in {"--check", "--selftest"}:
        print("usage: feature_public_surface_census.py --check | --selftest")
        return 2
    return selftest() if argv[0] == "--selftest" else check()


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
