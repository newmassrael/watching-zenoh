#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

"""R3573 (no register item) -- the node declaration of `docs/target-build-contract.md` section 5b:
one file per node that says which endpoints it dials, which entities it declares and which budgets
it runs on, held to what the target profile can build.

    wz_node.py --check                  every deploy/nodes/*.toml validates for its target and its
                                        deploy/nodes/generated/<id>.rs is current
    wz_node.py --write                  write those generated files
    wz_node.py --emit ID                print the generated `declared.rs` of the node ID
    wz_node.py --env ID                 print `WZ_LIMIT_<NAME>=<value>` for the budgets the node states
                                        and `WZ_POLICY_<NAME>=<value>` for the policies it states
    wz_node.py --validate FILE          validate a declaration that is not in the registry (`<id>.toml`)
    wz_node.py --vocabulary TARGET      print, as JSON, what the target builds: the declaration schema,
                                        each word's keys and bounds, the budgets and the policies
    wz_node.py --selftest

A node is a declaration and not an argument vector. This module is the first half of turning one
into an executable: it reads the file, refuses what it cannot hold to the target, and generates the
constants the node's code reads. `--emit` prints them; `--write` writes the copy the tree tracks
under `deploy/nodes/generated/`, which the image gates build and `--check` holds current. It does
not build the node.

## What a declaration may say

    [node]                     id (the file's name), help, target
    [[endpoint]]               role = "dial", locator = "<scheme>/<a.b.c.d>:<port>" (a router it dials);
                               role = "listen", locator = "tcp/<a.b.c.d>:<port>" and accepts = N (the
                               port it takes connections on, and how many sessions of them it holds
                               at once; a node that listens presents itself to them as a peer);
                               role = "multicast", locator = "udp/<group>:<port>", members = N and
                               an optional ttl (a group the node is a member of, which carries
                               publishers and subscriptions: the literal Put is all its outbound
                               vocabulary has without an allocator);
                               role = "peer", zid = "<lowercase hex>" and locator = "tls/<a.b.c.d>:<port>"
                               (a node it holds by its zid from its first tick, decision D7 of
                               docs/session-lifecycle-intent.md: the third transport, where the
                               build declares the peers and no verb asks for them; the locator is a
                               hint, every dial is made for the zid, and only a secure channel proves
                               the answer is the node, so it is `tls`; each peer raises MAX_PEER_NODES
                               when the declaration states none)
    [[entity]]               kind = "queryable", key, and document_bytes (a fixed document) or
                               from = "<subscriber key>" (the latest sample of that subscription);
                               kind = "subscriber", key, sample_bytes (the payload bytes it keeps);
                               kind = "publisher", key, WHEN and WHAT (a stream of puts on that key,
                               the workload of docs/target-build-contract.md 5c in the driver's own
                               words): WHEN is period_ms or rate_per_s (a decimal written as a
                               string) under arrivals = "periodic" (the default), "poisson" (with
                               an arrival_seed) or "burst" (with burst, the puts of each); WHAT is
                               document_bytes (the same document every put) or payload_bytes with
                               a fill ("counter", the default, "zero" or "seeded" with a seed),
                               made for each put from its sequence number;
                               kind = "querier", key, period_ms, timeout_ms, reply_bytes (it asks
                               that key every period and keeps the latest reply; a queryable's
                               from may name its key);
                               kind = "liveliness-token", key (a literal, declared on every
                               session and kept by the router for as long as it lasts);
                               kind = "replay", key, and the driver's timing ("declared", the
                               default, or "capture"), gap_ms, speed (a decimal written as a string)
                               and max_gap_ms (a recorded sequence put on each session from the
                               moment it is established)
    [[sample]]               replay = "<replay key>", text or hex (the bytes as recorded), an
                               optional key (the replay's when none), captured_at_ms, and a mutation
                               ("none", the default; "flip_bit" with at_bit; "truncate" with keep;
                               "extend" with count and seed; "scramble" with seed)
    [limits]                   <LIMIT_ID> = <integer>, any limit `deploy/wz-config.toml` declares
    [policy]                   <policy-id> = "<value>", any policy `deploy/wz-config.toml` declares
                               (`"on"` or `"off"` for a bool, one of its choices otherwise): the
                               behaviour the node is built with where upstream's is not the one it
                               wants; a policy left out is upstream's

## What it refuses, and why that is an exit and not a skip

The vocabulary is wider than any one target can build: a declaration may name a listening endpoint
over a scheme a target has no listener for, a group over a scheme that is not UDP, a publisher, a
subscriber, a liveliness token or a querier on a node that has a group. A target states which
of those it builds (`TARGETS`), and a word it does not build is REFUSED with the target's reason,
never dropped: a node that silently lost its subscriber would run and be wrong. A word outside the
vocabulary is refused as a typo. A budget the target cannot give, a key longer than the key limit,
more queryables than the registry holds and a document longer than the node's storage are refused
by name.

## The registry and a declaration given as a file

A declaration states `schema = 1` at its top: the number of this contract, which a reader refuses
when it does not know it. `deploy/nodes/` is the registry: the declarations this tree builds on every
round (the image gates, the lanes), each with its generated file tracked and held current. A
declaration need not be registered to be built: a consumer that makes one node per graph gives the
file (`wz_package.py --node-file`), which is validated exactly as a registered one and generated into
the build's own directory (`resolve_file`). What makes either correct is the vocabulary, not the
registry: each word is a behaviour with its generator rule, its `const` assertions, its link-gate
proof and its witness, and a declaration is a combination the validator and the node's assertions
hold. `--vocabulary` prints what a target builds from the same tables `validate` reads.

## What it does not do

It does not build the node: `wz_package.py --node ID` (or `--node-file`) does (section 5b), through `resolve`, which
hands it the validated declaration, the generated file that is current, the features and budgets
the build takes and what the endpoints ask of a device. A declaration is held to the budgets of the
image the node is built in (`image_limits`: the `WZ_LIMIT_*` of that package's cargo config), and
what it states overrides them. The digest in the generated file is the SHA-256 of the declaration's
bytes, so any edit of the file, a comment included, makes the generated copy stale until `--write`.
The only target is `slot`, the per-session fixed-memory profile (`wz_session_mcu::slot_node`), whose
node holds one dialled session and up to its `accepts` sessions a peer opened, and answers queries
from documents; the heap runtime is not a target here.
"""

from __future__ import annotations

import hashlib
import json
import pathlib
import re
import sys
import tempfile

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import wz_config  # noqa: E402
import wz_key_set  # noqa: E402

# `key_problem` and `rust_string` moved to `wz_keyexpr.py`, which `wz_key_set.py` shares; they stay
# names of this module, which its selftest and `wz_package.py` read.
from wz_keyexpr import ZID_RE, key_problem, rust_string  # noqa: E402,F401

ROOT = pathlib.Path(__file__).resolve().parents[2]
NODES = ROOT / "deploy" / "nodes"

# The schema of a declaration: the number a declaration states as its top-level `schema`. A reader
# refuses a number it does not know; a key is never given another meaning within one number, and a
# change a declaration written for the previous number cannot survive moves it.
DECLARATION_SCHEMA = 1

# The shape of what `--vocabulary` prints, as `vocabulary_schema`: a number apart from the
# declaration's, because the JSON a consumer parses can change shape while the declarations it
# describes stay readable. It moves when a reader of the previous shape would misread the new one
# (a field that changes type or meaning, or goes); a field added beside the others does not move it.
# A reader refuses a number it does not know, so a mismatch stops and names both numbers.
#   1: the first shape (`one_of` a list of keys; integer, key and locator values).
#   2: Round 3729: `one_of` a list of groups of keys, values `word` (`choices`, `default`) and
#      `rate` (`min_gap_ns`, `max_gap_ns`), a key's `with` condition, a kind's `group_refused_keys`.
#      Added beside it since (the number stays): the `replay` kind, the `samples` section, the values
#      `decimal`, `text` and `hex`, and a `with` that lists its values (`in`).
VOCABULARY_SCHEMA = 2

# The shape of each word of the vocabulary: the keys it takes and the value of each. An integer's
# bounds are numbers or the name of the target's field that holds the number, so the shape is stated
# once and each target states its own numbers. `validate` reads this table for which keys a word may
# have and the range of each integer, and `vocabulary` prints it resolved against a target, so what a
# consumer is told a target builds and what the target accepts are one statement.
#   value: `locator` (<scheme>/<a.b.c.d>:<port>), `zid` (lowercase hex), `key-expression` (a key or a
#   pattern, held to MAX_KEYEXPR_BYTES), `key` (a literal key: no `*`, no `$`), `cell-key` (the key
#   of a subscriber or a querier of the same node), `integer` (from `min` to `max`), `word` (one of
#   `choices`), `rate` (a positive decimal of puts a second written as a string, whose gap is from
#   `min_gap_ns` to `max_gap_ns`).
#   with: a key read only when another key of the word is stated (`{"key": K}`) or has a value
#   (`{"key": K, "value": V}`, a word's default counting as stated); `required` is then "required
#   exactly when that holds", and the key stated when it does not hold is refused.
#   one_of: groups of keys of which a word states exactly one each.
def _key(value: str, required: bool = True) -> dict:
    return {"value": value, "required": required}


def _int(low: int, high: int | str, required: bool = True, default: int | None = None) -> dict:
    spec = {"value": "integer", "required": required, "min": low, "max": high}
    if default is not None:
        spec["default"] = default
    return spec


def _word(choices: tuple[str, ...], default: str) -> dict:
    return {"value": "word", "required": False, "choices": list(choices), "default": default}


def _rate(min_gap: int | str, max_gap: int | str) -> dict:
    return {"value": "rate", "required": False, "min_gap_ns": min_gap, "max_gap_ns": max_gap}


def _decimal() -> dict:
    return {"value": "decimal", "required": False}


def _when(spec: dict, key: str, value: str | tuple[str, ...] | None = None) -> dict:
    """`spec`, read only when `key` is stated (`value` None), has `value`, or has one of the values
    of a tuple (`in`)."""
    if isinstance(value, tuple):
        return {**spec, "with": {"key": key, "in": list(value)}}
    return {**spec, "with": {"key": key, **({"value": value} if value is not None else {})}}


# The words of a stream, as the traffic driver of `wz-ap-demo` names them (`sessions_driver/stream.rs`,
# `PROCESSES` and `FILLS`), so a declared publisher and a driven one are written alike.
PROCESSES = ("periodic", "poisson", "burst")
FILLS = ("zero", "counter", "seeded")
# The words of a replay, as the driver's `replay` role names them (`roles/replay.rs`, `TIMINGS` and
# `MUTATIONS`; a mutation's parameters keep its names, `at_bit`, `keep`, `count`, `seed`).
TIMINGS = ("declared", "capture")
MUTATIONS = ("none", "flip_bit", "truncate", "extend", "scramble")


ENDPOINT_SHAPES = {
    "dial": {"keys": {"locator": _key("locator")}},
    "listen": {"keys": {"locator": _key("locator"), "accepts": _int(1, "max_accepts")}},
    "multicast": {"keys": {"locator": _key("locator"), "members": _int(1, "max_members"),
                           "ttl": _int(1, 255, required=False, default=1)}},
    "peer": {"keys": {"locator": _key("locator"), "zid": _key("zid")}},
}
# `count` is how many of a kind one node holds: a target's field, or the budget (`limit`) a declaration
# may raise.
ENTITY_SHAPES = {
    "publisher": {"is": "puts a stream of its own", "count": {"max": "max_publishers"},
                  "keys": {"key": _key("key"), "period_ms": _int(1, "period_max", required=False),
                           "rate_per_s": _rate("gap_min_ns", "gap_max_ns"),
                           "arrivals": _word(PROCESSES, "periodic"),
                           "arrival_seed": _when(_int(0, "seed_max"), "arrivals", "poisson"),
                           "burst": _when(_int(1, "burst_max"), "arrivals", "burst"),
                           "document_bytes": _int(0, "publish_max", required=False),
                           "payload_bytes": _int(1, "publish_max", required=False),
                           "fill": _when(_word(FILLS, "counter"), "payload_bytes"),
                           "seed": _when(_int(0, "seed_max"), "fill", "seeded")},
                  "one_of": [["period_ms", "rate_per_s"], ["document_bytes", "payload_bytes"]]},
    "subscriber": {"is": "keeps what it receives", "count": {"limit": "MAX_SUBSCRIPTIONS"},
                   "keys": {"key": _key("key-expression"), "sample_bytes": _int(1, "sample_max")}},
    "queryable": {"is": "answers from a document or from what a subscriber or querier keeps",
                  "count": {"limit": "MAX_QUERYABLES"},
                  "keys": {"key": _key("key-expression"), "document_bytes": _int(0, "document_max", required=False),
                           "from": _key("cell-key", required=False)},
                  "one_of": [["document_bytes", "from"]]},
    "querier": {"is": "asks and keeps what comes back", "count": {"max": "max_queriers"},
                "keys": {"key": _key("key-expression"), "period_ms": _int(1, "period_max"),
                         "timeout_ms": _int(1, "timeout_max"), "reply_bytes": _int(1, "sample_max")}},
    "liveliness-token": {"is": "is only its key", "count": {"max": "max_tokens"}, "keys": {"key": _key("key")}},
    "replay": {"is": "puts a recorded sequence of samples on each session", "count": {"max": "max_replays"},
               "keys": {"key": _key("key"), "timing": _word(TIMINGS, "declared"),
                        "gap_ms": _int(0, "period_max", required=False, default=100),
                        "speed": _decimal(),
                        "max_gap_ms": _int(0, "period_max", required=False, default=10_000)}},
}

# A replay's samples are tables of their own (`[[sample]]`), since a declaration's tables do not
# nest: each names the replay it belongs to by that replay's key (as a queryable's `from` names a
# cell), and is put on its own `key` or, when it states none, on the replay's.
SAMPLE_SHAPE = {
    "keys": {"replay": _key("replay-key"), "key": _key("key", required=False),
             "text": _key("text", required=False), "hex": _key("hex", required=False),
             "captured_at_ms": _int(0, "seed_max", required=False),
             "mutation": _word(MUTATIONS, "none"),
             "at_bit": _when(_int(0, "bit_max"), "mutation", "flip_bit"),
             "keep": _when(_int(0, "publish_max"), "mutation", "truncate"),
             "count": _when(_int(0, "publish_max"), "mutation", "extend"),
             "seed": _when(_int(0, "seed_max"), "mutation", ("extend", "scramble"))},
    "one_of": [["text", "hex"]],
}
SAMPLE_KEYS = set(SAMPLE_SHAPE["keys"])

# The words a declaration may use. A word outside these is a typo; one inside them that a target does
# not build is a refusal with the target's own reason.
ENDPOINT_ROLES = tuple(ENDPOINT_SHAPES)
ENTITY_KINDS = tuple(ENTITY_SHAPES)
NODE_KEYS = {"id", "help", "target"}
ENDPOINT_KEYS = {"role"} | {k for shape in ENDPOINT_SHAPES.values() for k in shape["keys"]}
ENTITY_KEYS = {"kind"} | {k for shape in ENTITY_SHAPES.values() for k in shape["keys"]}
TOP_KEYS = {"schema", "node", "endpoint", "entity", "sample", "limits", "policy", "allow"}


def bound(target: dict, value: int | str) -> int:
    """A bound of the shape table: a number, or the target's field that holds it."""
    return target[value] if isinstance(value, str) else value


def owners(shapes: dict, key: str) -> list[str]:
    """The words whose shape has `key`, in the table's order."""
    return [word for word, shape in shapes.items() if key in shape["keys"]]


DECIMAL_RE = re.compile(r"([0-9]+)(?:\.([0-9]+))?")


def decimal_parts(text: object) -> tuple[tuple[int, int] | None, str | None]:
    """The (mantissa, scale) of a positive decimal written as `text`, or why it is not one:
    `wz_workload::arrivals::Decimal::parse` (digits, and a point and digits if any; at most 18
    significant digits; greater than zero)."""
    match = DECIMAL_RE.fullmatch(text) if isinstance(text, str) else None
    if match is None:
        return None, "not a positive decimal written as a string: digits, and a point and digits if any"
    whole, fraction = match[1], (match[2] or "").rstrip("0")
    if len(whole.lstrip("0")) + len(fraction) > 18:
        return None, "has more than 18 significant digits"
    mantissa = int(whole + fraction)
    if mantissa == 0:
        return None, "must be greater than zero"
    return (mantissa, len(fraction)), None


def rate_gap_ns(text: object) -> tuple[int | None, str | None]:
    """The gap between two puts of a rate written as `text`, in nanoseconds rounded down, or why
    `text` is not a rate: `wz_workload::arrivals::Decimal::parse` and `gap_nanos` (exactly
    10^9 x 10^scale / mantissa), so a declared rate and a driven one give one gap to the nanosecond."""
    parts, why = decimal_parts(text)
    if parts is None:
        return None, why
    mantissa, scale = parts
    return 10**9 * 10**scale // mantissa, None


HEX_RE = re.compile(r"(?:[0-9a-fA-F]{2})*")


def holds(item: dict, keys: dict, condition: dict) -> bool:
    """Whether the `with` condition of a key holds for `item`: the key it names is stated, or has
    the value it names, or one of the values it lists (a word's default counting as stated)."""
    if "value" not in condition and "in" not in condition:
        return condition["key"] in item
    value = item.get(condition["key"], keys[condition["key"]].get("default"))
    return value in condition["in"] if "in" in condition else value == condition["value"]


def value_problems(who: str, item: dict, keys: dict, target: dict) -> list[str]:
    """Each integer, word, rate, decimal, text or hex key of a word's shape that is missing (when
    required) or outside its bounds, and each key stated where its `with` condition does not hold."""
    out = []
    for key, spec in keys.items():
        condition = spec.get("with")
        if condition is not None and not holds(item, keys, condition):
            if key in item:
                if "in" in condition:
                    when = f"`{condition['key']}` is one of {', '.join(map(repr, condition['in']))}"
                elif "value" in condition:
                    when = f"`{condition['key']}` is {condition['value']!r}"
                else:
                    when = f"`{condition['key']}` is stated"
                out.append(f"{who}: `{key}` is read only when {when}")
            continue
        kinds = ("integer", "word", "rate", "decimal", "text", "hex")
        if spec["value"] not in kinds or (key not in item and not spec["required"]):
            continue
        value = item.get(key)
        if spec["value"] == "integer":
            low, high = bound(target, spec["min"]), bound(target, spec["max"])
            if isinstance(value, bool) or not isinstance(value, int) or not low <= value <= high:
                out.append(f"{who}: {key} is {value!r}, not an integer from {low} to {high}")
        elif spec["value"] == "word":
            if value not in spec["choices"]:
                out.append(f"{who}: {key} is {value!r}, not one of {', '.join(spec['choices'])}")
        elif spec["value"] == "decimal":
            _, why = decimal_parts(value)
            if why is not None:
                out.append(f"{who}: {key} is {value!r}, {why}")
        elif spec["value"] == "text":
            if not isinstance(value, str):
                out.append(f"{who}: {key} is {value!r}, not a string")
        elif spec["value"] == "hex":
            if not isinstance(value, str) or HEX_RE.fullmatch(value) is None:
                out.append(f"{who}: {key} is {value!r}, not hex: two digits a byte")
        else:
            gap, why = rate_gap_ns(value)
            low, high = bound(target, spec["min_gap_ns"]), bound(target, spec["max_gap_ns"])
            if why is not None:
                out.append(f"{who}: {key} is {value!r}, {why}")
            elif not low <= gap <= high:
                out.append(f"{who}: {key} is {value!r}, a gap of {gap} ns between two puts, not from "
                           f"{low} to {high} ns")
    return out

# What each target builds. `slot` is the per-session fixed-memory profile of the cooperative runtime:
# one dialled session, no allocator, queries answered from documents that are prefixes of one static.
TARGETS = {
    "slot": {
        # The package the node is built in, whose cargo config states the budgets it holds.
        "image": "deploy/host-slot-node",
        # The endpoints of each role a node holds: the one router it dials (the connect manager's
        # row, `MAX_STATIC_CONNECT`), the one port it listens on and the peers it holds by their zid
        # (each a connection machine of some 930 bytes and two rows of the locator directory,
        # `MAX_PEER_NODES`, which a declaration's peers set when it states none). The sessions of the node are
        # the dialled one and `accepts` more, which is the size of its session table.
        "endpoint_limits": {"dial": 1, "listen": 1, "multicast": 1, "peer": 4},
        "schemes": ("tcp", "udp", "tls"),
        # A group is UDP: a member's datagrams are the group's, with no connection to hold.
        "multicast_schemes": ("udp",),
        # The members of the group the node tracks at once, each a row of its peer table.
        "max_members": 8,
        # What a group carries with no allocator: the literal Put is the whole of its outbound
        # vocabulary, so a node that has a group publishes and subscribes. A kind the group cannot
        # carry is refused for the node as a whole, since every entity is carried by every plane the
        # node has, and one the group silently dropped would be a node that lost it.
        "group_kinds": {"publisher", "subscriber"},
        "group_refused": {
            "queryable": "the reply a queryable writes (Response and ResponseFinal) has no form "
            "without an allocator in the group's emit yet",
            "querier": "the Request a querier asks with has no form without an allocator in the "
            "group's emit yet",
            "liveliness-token": "the answer a token gives to an interest (DeclareReply) has no form "
            "without an allocator in the group's emit yet",
            "replay": "a replay's sample is mutated into the node's one buffer, which a put on the "
            "group cannot borrow for as long as the group's pump holds it",
        },
        # A key of a kind the group carries that the group cannot carry, by kind and key.
        "group_refused_keys": {
            "publisher": {
                "payload_bytes": "a put on the group borrows its bytes for as long as the group's "
                "pump holds it, which a body made for each put in the node's one buffer cannot "
                "give; a group's publisher puts a document",
            },
        },
        # A listener is a stream's: a `tcp/` connection is a link the moment it is accepted, with no
        # handshake of the transport's own to read first.
        "listen_schemes": ("tcp",),
        # A peer held by its zid is dialled over a secure channel: only that proves the node that
        # answered is the one the zid names (decision D4 of docs/session-lifecycle-intent.md).
        "peer_schemes": ("tls",),
        # The sessions a peer opened that the node holds at once; each is a session slot, a pump
        # cell and a task cell of the node's tables, and a pair of link buffers.
        "max_accepts": 4,
        "entity_kinds": {"queryable", "subscriber", "publisher", "querier", "liveliness-token", "replay"},
        # `DOC_MAX` of the same file: the static every document is a prefix of.
        "document_max": 4096,
        # The bytes of a payload a subscription keeps (`LatestCells` of `wz_session_mcu::latest`).
        "sample_max": 4096,
        # What a publisher puts: one document or a body made for each put (in the node's one
        # `MadeBuffer`, sized by the longest), at most what a frame carries with room to spare, and
        # the schedules of at most `max_publishers` in the session's task cell.
        "publish_max": 1024,
        "max_publishers": 4,
        # A replay's samples are read-only data of the image and its state is in the session's task
        # cell beside the publishers'; a sample is put as written or mutated into the same buffer, so
        # it and its mutated form are held to `publish_max`, and a flipped bit to the bits of that.
        "max_replays": 2,
        "max_samples": 64,
        "bit_max": 1024 * 8 - 1,
        # The gaps of a publisher's arrivals: its clock is the millisecond, so a gap shorter than one
        # would be puts the node makes in the same tick (a rate of at most 1000 a second), and the
        # longest is `period_max`'s. A Poisson process draws gaps shorter than its mean; those are made
        # at once and how late they were is counted, never thinned (`wz_session_mcu::slot_publisher`).
        "gap_min_ns": 1_000_000,
        "gap_max_ns": 3_600_000 * 1_000_000,
        # A burst is made at most `CATCH_UP` puts a round (`slot_publisher`), the rest in rounds the
        # node wakes for at once; the bound is a batch a frame-sized put of each fits a link with.
        "burst_max": 1024,
        # A seed is a TOML integer, which is signed 64-bit; the generators take its bits.
        "seed_max": 2**63 - 1,
        # A querier keeps its latest reply in a cell, so it is held to the cell's size (`sample_max`),
        # and its schedule is in the same task cell.
        "max_queriers": 4,
        "timeout_max": 60_000,
        "period_max": 3_600_000,
        # A token is only a declaration, so the bound is what the declarations of a session establishing
        # can carry: a node of four tokens and a document is what the witness runs, and every one of
        # the five is seen by the router (`wz_declared_token_zenohd_interop.rs`).
        "max_tokens": 4,
        "refused": {},
        # Why a listener over this scheme is not built, by scheme.
        "listen_refused": {
            "udp": "a datagram listener answers the sender of an InitSyn and the slot node's "
            "accept loop is a stream's",
            "tls": "the secure channel of the slot node is one it dials; it has no server side yet",
        },
    },
}

LOCATOR_RE = re.compile(r"(?P<scheme>[a-z]+)/(?P<a>\d{1,3})\.(?P<b>\d{1,3})\.(?P<c>\d{1,3})\.(?P<d>\d{1,3}):(?P<port>\d{1,5})")


def image_limits(target: dict) -> dict[str, int]:
    """The budgets the target's image states in its own cargo config (`[env]` of
    `<image>/.cargo/config.toml`, `WZ_LIMIT_<NAME>`): what a node of that target holds when its
    declaration says nothing, because the build runs in the image's directory and cargo applies the
    file there. Read from the file and not copied, so the generator and the build cannot disagree
    about the size of a table."""
    text = (ROOT / target["image"] / ".cargo" / "config.toml").read_text(encoding="utf-8")
    env = wz_config.read_decl_toml(text).get("env", {})
    return {
        name.removeprefix("WZ_LIMIT_"): int(value)
        for name, value in env.items()
        if name.startswith("WZ_LIMIT_")
    }


def limit_values(decl: dict, stated: dict, image: dict[str, int]) -> tuple[dict[str, int], list[str]]:
    """The effective value of every declared limit: the node's, else the image's, else the
    declaration's default."""
    known = {lim["id"]: lim["default"] for lim in decl["limits"]}
    known.update({k: v for k, v in image.items() if k in known})
    problems = []
    for name, value in stated.items():
        if name not in known:
            problems.append(f"limits: `{name}` is not a limit deploy/wz-config.toml declares")
        elif isinstance(value, bool) or not isinstance(value, int) or value < 1:
            problems.append(f"limits: `{name}` is {value!r}, not a positive integer")
    return ({**known, **{k: v for k, v in stated.items() if k in known and isinstance(v, int)}}, problems)


def policy_problems(decl: dict, stated: dict) -> list[str]:
    """Why a node's `[policy]` table is not a build a policy catalogue can give: a policy the
    declaration does not have, a value that is not one the policy takes (`on` or `off` for a bool,
    one of its choices otherwise)."""
    known = {pol["id"]: pol for pol in decl["policies"]}
    problems = []
    for name, value in stated.items():
        pol = known.get(name)
        if pol is None:
            problems.append(f"policy: `{name}` is not a policy deploy/wz-config.toml declares")
            continue
        allowed = ["on", "off"] if pol["kind"] == "bool" else list(pol["choices"])
        if not isinstance(value, str) or value not in allowed:
            problems.append(f"policy: `{name}` is {value!r}, one of {', '.join(allowed)}")
    return problems


def validate(name: str, data: dict, decl: dict) -> list[str]:
    """Every reason `data` (the file `name`, read) is not a node its target can build."""
    out = []
    for extra in sorted(set(data) - TOP_KEYS):
        out.append(f"`{extra}` is not a table a node declaration has")
    if data.get("schema") != DECLARATION_SCHEMA:
        return out + [f"schema is {data.get('schema')!r}; this reader reads node declarations of schema "
                      f"{DECLARATION_SCHEMA} (state `schema = {DECLARATION_SCHEMA}` at the top)"]
    node = data.get("node")
    if not isinstance(node, dict):
        return out + ["there is no [node] table"]
    for extra in sorted(set(node) - NODE_KEYS):
        out.append(f"node: `{extra}` is not a key of [node]")
    if node.get("id") != name:
        out.append(f"node: id is {node.get('id')!r}, the file is named {name!r}")
    if not isinstance(node.get("help"), str) or not node["help"].strip():
        out.append("node: help is missing")
    target = TARGETS.get(node.get("target"))
    if target is None:
        return out + [f"node: target is {node.get('target')!r}, not one of {', '.join(sorted(TARGETS))}"]

    values, problems = limit_values(decl, data.get("limits", {}), image_limits(target))
    out += problems
    stated_policy = data.get("policy", {})
    if not isinstance(stated_policy, dict):
        out.append("policy: [policy] is a table of <policy-id> = \"<value>\"")
    else:
        out += policy_problems(decl, stated_policy)

    endpoints = data.get("endpoint", [])
    if not endpoints:
        out.append("a node with no endpoint neither reaches anything nor is reached: declare one [[endpoint]]")
    held: dict[str, int] = {}
    peer_zids: set[str] = set()
    for n, ep in enumerate(endpoints, 1):
        who = f"endpoint {n}"
        for extra in sorted(set(ep) - ENDPOINT_KEYS):
            out.append(f"{who}: `{extra}` is not a key of [[endpoint]]")
        role = ep.get("role")
        if role not in ENDPOINT_ROLES:
            out.append(f"{who}: role is {role!r}, not one of {', '.join(ENDPOINT_ROLES)}")
        elif role not in target["endpoint_limits"]:
            out.append(f"{who}: a `{role}` endpoint is not built on {node['target']}: {target['refused'][role]}")
        else:
            held[role] = held.get(role, 0) + 1
            if held[role] == target["endpoint_limits"][role] + 1:
                out.append(f"{who}: more than {target['endpoint_limits'][role]} `{role}` endpoint(s); the "
                           f"{node['target']} target holds {target['endpoint_limits'][role]}")
        if role in ENDPOINT_SHAPES:
            keys = ENDPOINT_SHAPES[role]["keys"]
            for extra in sorted((set(ep) & ENDPOINT_KEYS) - set(keys) - {"role"}):
                out.append(f"{who}: only a {' or a '.join(f'`{r}`' for r in owners(ENDPOINT_SHAPES, extra))} "
                           f"endpoint has `{extra}`")
            out += value_problems(who, ep, keys, target)
        zid = ep.get("zid")
        if role == "peer":
            if not isinstance(zid, str) or ZID_RE.fullmatch(zid) is None:
                out.append(f"{who}: zid is {zid!r}, not the lowercase hex of a zid (no leading 0, at most "
                           "32 digits)")
            elif zid in peer_zids:
                out.append(f"{who}: zid {zid} is declared twice")
            else:
                peer_zids.add(zid)
        match = LOCATOR_RE.fullmatch(ep.get("locator", "")) if isinstance(ep.get("locator"), str) else None
        if match is None:
            out.append(f"{who}: locator {ep.get('locator')!r} is not <scheme>/<a.b.c.d>:<port>")
        else:
            if match["scheme"] not in target["schemes"]:
                out.append(f"{who}: scheme `{match['scheme']}` is not one of {', '.join(target['schemes'])}")
            elif role == "listen" and match["scheme"] not in target["listen_schemes"]:
                out.append(f"{who}: a `{match['scheme']}` listener is not built on {node['target']}: "
                           f"{target['listen_refused'][match['scheme']]}")
            elif role == "multicast" and match["scheme"] not in target["multicast_schemes"]:
                out.append(f"{who}: a group is `{'`, `'.join(target['multicast_schemes'])}`, not `{match['scheme']}`")
            elif role == "peer" and match["scheme"] not in target["peer_schemes"]:
                out.append(f"{who}: a peer held by its zid is dialled over "
                           f"`{'`, `'.join(target['peer_schemes'])}`, not `{match['scheme']}`: only "
                           "a secure channel proves the node that answered is the one the zid names "
                           "(decision D4 of docs/session-lifecycle-intent.md)")
            if any(int(match[o]) > 255 for o in "abcd") or not 1 <= int(match["port"]) <= 65535:
                out.append(f"{who}: locator {ep['locator']!r} has an octet above 255 or a port outside 1..65535")
            elif role == "multicast" and not 224 <= int(match["a"]) <= 239:
                out.append(f"{who}: locator {ep['locator']!r} is not a group: a multicast address is "
                           "224.0.0.0 to 239.255.255.255")
    if "MAX_PEER_NODES" in data.get("limits", {}) and held.get("peer", 0) > values["MAX_PEER_NODES"]:
        out.append(f"limits: MAX_PEER_NODES is {values['MAX_PEER_NODES']}, the declaration holds "
                   f"{held['peer']} peers by their zid")
    has_group = "multicast" in held

    seen: dict[str, set[str]] = {kind: set() for kind in ENTITY_KINDS}
    sample_sizes: dict[str, int] = {}
    mirrors: list[tuple[str, object]] = []
    queryables = subscribers = publishers = queriers = tokens = replays = 0
    for n, ent in enumerate(data.get("entity", []), 1):
        who = f"entity {n}"
        for extra in sorted(set(ent) - ENTITY_KEYS):
            out.append(f"{who}: `{extra}` is not a key of [[entity]]")
        kind = ent.get("kind")
        if kind not in ENTITY_KINDS:
            out.append(f"{who}: kind is {kind!r}, not one of {', '.join(ENTITY_KINDS)}")
            continue
        if kind not in target["entity_kinds"]:
            why_not = target["refused"].get(kind, "the target has no behaviour for it yet")
            out.append(f"{who}: a `{kind}` is not built on {node['target']}: {why_not}")
            continue
        if has_group and kind not in target["group_kinds"]:
            out.append(f"{who}: a `{kind}` is not carried by the group this node is a member of: "
                       f"{target['group_refused'][kind]}")
            continue
        tokens += kind == "liveliness-token"
        queryables += kind == "queryable"
        subscribers += kind == "subscriber"
        publishers += kind == "publisher"
        queriers += kind == "querier"
        replays += kind == "replay"
        shape = ENTITY_SHAPES[kind]
        for extra in sorted((set(ent) & ENTITY_KEYS) - set(shape["keys"]) - {"kind"}):
            out.append(f"{who}: a {kind} {shape['is']} and has no `{extra}` (only "
                       f"{' or '.join(f'a {k}' for k in owners(ENTITY_SHAPES, extra))} has `{extra}`)")
        for group in shape.get("one_of", []):
            stated = [k for k in group if k in ent]
            if len(stated) != 1:
                out.append(f"{who}: a {kind} {shape['is']}: state exactly one of "
                           f"{', '.join(f'`{k}`' for k in group)}" + (", not both" if stated else ""))
        out += value_problems(who, ent, shape["keys"], target)
        if has_group:
            for refused, why_not in target["group_refused_keys"].get(kind, {}).items():
                if refused in ent:
                    out.append(f"{who}: a {kind}'s `{refused}` is not carried by the group this node is "
                               f"a member of: {why_not}")
        key = ent.get("key")
        why = key_problem(key, values["MAX_KEYEXPR_BYTES"]) if isinstance(key, str) else "is missing"
        # A subscription and a querier each keep their latest in a cell named by the key.
        cell_twin = {"subscriber": "querier", "querier": "subscriber"}.get(kind)
        if why:
            out.append(f"{who}: key {key!r} {why}")
        elif key in seen[kind]:
            out.append(f"{who}: key {key!r} is declared twice")
        elif cell_twin and key in seen[cell_twin]:
            out.append(f"{who}: key {key!r} names the cell of a {cell_twin} too, and a cell is named by one")
        else:
            seen[kind].add(key)
        if shape["keys"]["key"]["value"] == "key" and isinstance(key, str) and ("*" in key or "$" in key):
            out.append(f"{who}: a {kind} is on one key, and {key!r} is a pattern (`*` or `$`)")
        # What a cell keeps, by the key that names it, for the queryables that answer from it.
        kept = {"subscriber": "sample_bytes", "querier": "reply_bytes"}.get(kind)
        size = ent.get(kept) if kept else None
        if kept and isinstance(key, str) and isinstance(size, int) and not isinstance(size, bool):
            sample_sizes[key] = size
        if "from" in shape["keys"] and "from" in ent:
            mirrors.append((who, ent["from"]))
    for who, source in mirrors:
        if not isinstance(source, str) or source not in seen["subscriber"] | seen["querier"]:
            out.append(f"{who}: `from` is {source!r}, which is not the key of a subscription or a querier "
                       "of this node")
        elif sample_sizes.get(source, 0) > values["MAX_REPLY_PAYLOAD_BYTES"]:
            out.append(f"{who}: what {source!r} keeps is {sample_sizes[source]} bytes, more than a "
                       f"reply holds (MAX_REPLY_PAYLOAD_BYTES is {values['MAX_REPLY_PAYLOAD_BYTES']})")
    if publishers > target["max_publishers"]:
        out.append(f"{publishers} publishers; the {node['target']} target keeps the schedule of "
                   f"{target['max_publishers']} in the session's task cell")
    if replays > target["max_replays"]:
        out.append(f"{replays} replays; the {node['target']} target keeps the state of "
                   f"{target['max_replays']} in the session's task cell")
    out += sample_problems(data.get("sample", []), seen["replay"], target, values)
    if tokens > target["max_tokens"]:
        out.append(f"{tokens} liveliness tokens; the {node['target']} target declares at most "
                   f"{target['max_tokens']} in the declarations of a session establishing")
    if queriers > target["max_queriers"]:
        out.append(f"{queriers} queriers; the {node['target']} target keeps the schedule of "
                   f"{target['max_queriers']} in the session's task cell")
    stated = data.get("limits", {})
    pending = pending_need(data.get("entity", []))
    if "MAX_PENDING_QUERIES" in stated and isinstance(stated["MAX_PENDING_QUERIES"], int) \
            and stated["MAX_PENDING_QUERIES"] < pending:
        out.append(f"its queriers can have {pending} queries pending; the declaration states "
                   f"MAX_PENDING_QUERIES = {stated['MAX_PENDING_QUERIES']} (state at least {pending}, or "
                   "nothing, and it follows from the entities)")
    for name, need, what in (("MAX_QUERYABLES", queryables, "queryables"),
                             ("MAX_SUBSCRIPTIONS", subscribers, "subscriptions")):
        if name in stated and isinstance(stated[name], int) and stated[name] < need:
            out.append(f"{need} {what}; the declaration states {name} = {stated[name]} (state at least "
                       f"{need}, or nothing, and it follows from the entities)")
    # A node that states a closed key set is held to what the table can carry: canonical keys, concrete
    # publishers and tokens, no wildcard that nothing concrete meets, no entity twice.
    if states_closed_key_set(data):
        found = wz_key_set.validate(key_set_entities(data), values["MAX_KEYEXPR_BYTES"])
        if not found and "allow" in data:
            found = wz_key_set.validate_allows(
                data["allow"], key_set_entities(data), values["MAX_KEYEXPR_BYTES"], peer_zids_of(data)
            )
        out += [f"key set: {why}" for why in found]
    elif "allow" in data:
        out.append("allow: an allowance is over a closed key set; the node states `key-set = \"closed\"` "
                   "in [policy] or declares no [[allow]]")
    return out


def sample_body(sample: dict) -> bytes | None:
    """The bytes a valid sample records: its text's UTF-8, or its hex. `None` for neither."""
    if isinstance(sample.get("text"), str):
        return sample["text"].encode("utf-8")
    if isinstance(sample.get("hex"), str) and HEX_RE.fullmatch(sample["hex"]):
        return bytes.fromhex(sample["hex"])
    return None


def mutated_len(sample: dict, body_len: int) -> int:
    """How long a sample is once mutated: `wz_workload::mutation::Mutation::output_len`."""
    mutation = sample.get("mutation", "none")
    if mutation == "truncate" and isinstance(sample.get("keep"), int):
        return min(body_len, sample["keep"])
    if mutation == "extend" and isinstance(sample.get("count"), int):
        return body_len + sample["count"]
    return body_len


def sample_problems(samples: list, replays: set[str], target: dict, values: dict) -> list[str]:
    """Every reason the `[[sample]]` tables are not the samples of this node's replays: a key the
    shape does not have, a value outside its bounds, a sample of no replay or one put on a pattern,
    a sample or its mutated form longer than a put carries, a replay with no sample, more samples
    than the target holds."""
    out = []
    per_replay = {key: 0 for key in replays}
    for n, sample in enumerate(samples, 1):
        who = f"sample {n}"
        for extra in sorted(set(sample) - SAMPLE_KEYS):
            out.append(f"{who}: `{extra}` is not a key of [[sample]]")
        for group in SAMPLE_SHAPE["one_of"]:
            stated = [k for k in group if k in sample]
            if len(stated) != 1:
                out.append(f"{who}: a sample is recorded bytes: state exactly one of "
                           f"{', '.join(f'`{k}`' for k in group)}" + (", not both" if stated else ""))
        out += value_problems(who, sample, SAMPLE_SHAPE["keys"], target)
        replay = sample.get("replay")
        if replay not in per_replay:
            out.append(f"{who}: `replay` is {replay!r}, which is not the key of a replay of this node")
        else:
            per_replay[replay] += 1
        if "key" in sample:
            key = sample["key"]
            why = key_problem(key, values["MAX_KEYEXPR_BYTES"]) if isinstance(key, str) else "is not a string"
            if why:
                out.append(f"{who}: key {key!r} {why}")
            elif "*" in key or "$" in key:
                out.append(f"{who}: a sample is put on one key, and {key!r} is a pattern (`*` or `$`)")
        body = sample_body(sample)
        if body is not None:
            most = target["publish_max"]
            if len(body) > most:
                out.append(f"{who}: its bytes are {len(body)}, more than a put carries ({most})")
            elif mutated_len(sample, len(body)) > most:
                out.append(f"{who}: mutated, its bytes are {mutated_len(sample, len(body))}, more than a "
                           f"put carries ({most})")
    for key, count in sorted(per_replay.items()):
        if count == 0:
            out.append(f"replay {key!r} has no sample: give it [[sample]] tables with replay = {key!r}")
    if len(samples) > target["max_samples"]:
        out.append(f"{len(samples)} samples; the target holds {target['max_samples']} in the image")
    return out


def pending_need(entities: list) -> int:
    """The queries a node's queriers can have pending at once: each is asked every period and stays
    until its final or its deadline, so a querier holds the periods that fit in its timeout, and the
    row a late final of the last still holds. Entities that do not validate count for nothing."""
    total = 0
    for ent in entities:
        if ent.get("kind") != "querier":
            continue
        period, timeout = ent.get("period_ms"), ent.get("timeout_ms")
        if all(isinstance(v, int) and not isinstance(v, bool) and v >= 1 for v in (period, timeout)):
            total += -(-timeout // period) + 1
    return total


def budgets(data: dict, decl: dict) -> dict[str, int]:
    """The budgets a node's build is given: what the declaration states, and the three its entities
    decide (`MAX_QUERYABLES`, `MAX_SUBSCRIPTIONS`, `MAX_PENDING_QUERIES`) when the image's own is
    below what they need and the declaration does not state one. Valid input only: `validate` ran
    first."""
    target = TARGETS[data["node"]["target"]]
    stated = dict(data.get("limits", {}))
    values, _ = limit_values(decl, stated, image_limits(target))
    entities = data.get("entity", [])
    needs = {
        "MAX_QUERYABLES": sum(1 for e in entities if e["kind"] == "queryable"),
        "MAX_SUBSCRIPTIONS": sum(1 for e in entities if e["kind"] == "subscriber"),
        "MAX_PENDING_QUERIES": pending_need(entities),
        "MAX_PEER_NODES": sum(1 for ep in data["endpoint"] if ep["role"] == "peer"),
    }
    for name, need in needs.items():
        if name not in stated and need > values[name]:
            stated[name] = need
    return dict(sorted(stated.items()))


def digest(name: str, directory: pathlib.Path = NODES) -> str:
    """The SHA-256 of the declaration file's bytes, lower-case hex: what a built node says it was
    built from, so a declaration edited after the build is a difference a tool can see."""
    return hashlib.sha256((directory / f"{name}.toml").read_bytes()).hexdigest()


def states_closed_key_set(data: dict) -> bool:
    """Whether the node states the `key-set` policy as `closed`."""
    stated = data.get("policy", {})
    return isinstance(stated, dict) and stated.get("key-set") == "closed"


def peer_zids_of(data: dict) -> set[str]:
    """The zids the node declares as `peer` endpoints: the peers it may allow something."""
    return {ep.get("zid") for ep in data.get("endpoint", []) if isinstance(ep, dict) and ep.get("role") == "peer"}


def key_set_entities(data: dict) -> list[dict]:
    """The node's entities as the key set sees them: a kind and a key. An entity that is not a table
    counts for nothing here; `validate` has already said so. A replay is not a declaration: what the
    key set sees of it is the keys its samples put on, each a publisher's (once, and not again where
    a publisher of the node already puts on it)."""
    entities = [e for e in data.get("entity", []) if isinstance(e, dict)]
    rows = [{"kind": e.get("kind"), "key": e.get("key")} for e in entities if e.get("kind") != "replay"]
    put = {row["key"] for row in rows if row["kind"] == "publisher"}
    for sample in data.get("sample", []):
        if not isinstance(sample, dict):
            continue
        key = sample.get("key", sample.get("replay"))
        if isinstance(key, str) and key not in put:
            put.add(key)
            rows.append({"kind": "publisher", "key": key})
    return rows


def key_set_lines(data: dict) -> list[str]:
    """The module `key_set` of the node's `declared.rs`: its table when it states a closed key set
    (`docs/closed-key-set.md`, the entities it declares are the keys), and nothing when it does not.
    A node that is open has no table to adopt, and the closed key set is code a build has only with
    the `key-set-closed` feature of `wz-session-core`, so a module that names it would not compile
    in the open build. Valid input only."""
    if not states_closed_key_set(data):
        return []
    entities = key_set_entities(data)
    allows = data.get("allow", [])
    allowance = wz_key_set.build_allowance(entities, allows) if allows else None
    return wz_key_set.table_lines(wz_key_set.build(entities), closed=True, allowance=allowance)


# The module the generated publisher constants are written in: `wz_session_mcu::slot_publisher`
# re-exports the workload's `Process` and `Fill`, so a node's image names one crate for them.
PUBLISHER = "wz_session_mcu::slot_publisher"


def gap_of(publisher: dict) -> int:
    """The gap of a valid publisher's arrivals, in nanoseconds: its period, or its rate's gap."""
    if "period_ms" in publisher:
        return publisher["period_ms"] * 1_000_000
    gap, _ = rate_gap_ns(publisher["rate_per_s"])
    return gap


def process_literal(publisher: dict) -> str:
    """The `Process` of a valid publisher, as Rust: the gap is the periodic gap, the Poisson mean
    or the gap between bursts, as the driver's `stream::schedule` reads the same keys."""
    gap = gap_of(publisher)
    arrivals = publisher.get("arrivals", "periodic")
    if arrivals == "poisson":
        return f"{PUBLISHER}::Process::Poisson {{ mean_gap_nanos: {gap}, seed: {publisher['arrival_seed']} }}"
    if arrivals == "burst":
        return f"{PUBLISHER}::Process::Burst {{ size: {publisher['burst']}, gap_nanos: {gap} }}"
    return f"{PUBLISHER}::Process::Periodic {{ gap_nanos: {gap} }}"


def body_literal(publisher: dict) -> str:
    """The bytes of each put of a valid publisher and the fill they are made with, as Rust: `None`
    for a document, whose bytes the image takes from its body pool."""
    if "document_bytes" in publisher:
        return f"{publisher['document_bytes']}, None"
    fill = publisher.get("fill", "counter")
    made = {"zero": "Zero", "counter": "Counter"}.get(fill) or f"Seeded {{ seed: {publisher['seed']} }}"
    return f"{publisher['payload_bytes']}, Some({PUBLISHER}::Fill::{made})"


# The module the generated replay constants are written in: `wz_session_mcu::slot_replay`
# re-exports the workload's `Timing` and `Mutation`.
REPLAY = "wz_session_mcu::slot_replay"


def mutation_literal(sample: dict) -> str:
    """The `Mutation` of a valid sample, as Rust, from the driver's words."""
    mutation = sample.get("mutation", "none")
    if mutation == "flip_bit":
        return f"{REPLAY}::Mutation::FlipBit {{ at: {sample['at_bit']} }}"
    if mutation == "truncate":
        return f"{REPLAY}::Mutation::Truncate {{ to: {sample['keep']} }}"
    if mutation == "extend":
        return f"{REPLAY}::Mutation::Extend {{ count: {sample['count']}, seed: {sample['seed']} }}"
    if mutation == "scramble":
        return f"{REPLAY}::Mutation::Scramble {{ seed: {sample['seed']} }}"
    return f"{REPLAY}::Mutation::None"


def replay_rows(data: dict) -> tuple[list[str], list[str]]:
    """The generated rows of a valid node's replays and of their samples, every replay's samples
    together and in the order written, so a replay is a range of the samples."""
    replays, samples = [], []
    for replay in (e for e in data.get("entity", []) if e["kind"] == "replay"):
        own = [s for s in data.get("sample", []) if s["replay"] == replay["key"]]
        timing = "Capture" if replay.get("timing", "declared") == "capture" else "Declared"
        replays.append(
            f"({rust_string(replay['key'])}, {REPLAY}::Timing::{timing}, {replay.get('gap_ms', 100)}, "
            f"{rust_string(replay.get('speed', '1'))}, {replay.get('max_gap_ms', 10_000)}, "
            f"{len(samples)}, {len(own)})")
        for sample in own:
            at = sample.get("captured_at_ms")
            body = ", ".join(str(b) for b in sample_body(sample))
            samples.append(
                f"({rust_string(sample.get('key', replay['key']))}, &[{body}], "
                f"{'None' if at is None else f'Some({at})'}, {mutation_literal(sample)})")
    return replays, samples


def emit(name: str, data: dict, declaration_sha256: str) -> str:
    """The `declared.rs` the node's code includes. Valid input only: `validate` ran first."""
    dialed = [ep["locator"] for ep in data["endpoint"] if ep["role"] == "dial"]
    dials = ", ".join(rust_string(locator) for locator in dialed)
    peers = [(ep["zid"], ep["locator"]) for ep in data["endpoint"] if ep["role"] == "peer"]
    peer_nodes = ", ".join(
        f"([{', '.join(str(b) for b in int(zid, 16).to_bytes(16, 'little'))}], {rust_string(locator)})"
        for zid, locator in peers
    )
    secure = any(d.startswith("tls/") for d in dialed) or bool(peers)
    listens = [ep for ep in data["endpoint"] if ep["role"] == "listen"]
    listen_at = listens[0]["locator"] if listens else ""
    accepts = listens[0]["accepts"] if listens else 0
    at = LOCATOR_RE.fullmatch(listen_at) if listens else None
    listen_addr = ", ".join(at[o] for o in "abcd") if at else "0, 0, 0, 0"
    listen_port = int(at["port"]) if at else 0
    groups = [ep for ep in data["endpoint"] if ep["role"] == "multicast"]
    group_at = groups[0]["locator"] if groups else ""
    members = groups[0]["members"] if groups else 0
    group_ttl = groups[0].get("ttl", 1) if groups else 1
    gat = LOCATOR_RE.fullmatch(group_at) if groups else None
    group_addr = ", ".join(gat[o] for o in "abcd") if gat else "0, 0, 0, 0"
    group_port = int(gat["port"]) if gat else 0
    every = data.get("entity", [])
    entities = [(e["key"], e["document_bytes"]) for e in every if e["kind"] == "queryable" and "from" not in e]
    docs = ", ".join(f"({rust_string(k)}, {b})" for k, b in entities)
    subscribed = [(e["key"], e["sample_bytes"]) for e in every if e["kind"] == "subscriber"]
    cells = ", ".join(f"({rust_string(k)}, {b})" for k, b in subscribed)
    queried = [(e["key"], e["period_ms"], e["timeout_ms"], e["reply_bytes"]) for e in every
               if e["kind"] == "querier"]
    asks = ", ".join(f"({rust_string(k)}, {p}, {t}, {b})" for k, p, t, b in queried)
    # The cells are the subscriptions' and then the queriers', in the order the declaration has them.
    place = {k: at for at, k in enumerate([k for k, _ in subscribed] + [k for k, _, _, _ in queried])}
    mirrored = [(e["key"], place[e["from"]]) for e in every if e["kind"] == "queryable" and "from" in e]
    mirrors = ", ".join(f"({rust_string(k)}, {at})" for k, at in mirrored)
    published = [e for e in every if e["kind"] == "publisher"]
    pubs = ", ".join(f"({rust_string(e['key'])}, {process_literal(e)}, {body_literal(e)})" for e in published)
    replayed, samples = replay_rows(data)
    alive = [e["key"] for e in every if e["kind"] == "liveliness-token"]
    token_keys = ", ".join(rust_string(k) for k in alive)
    # The constants of a plane the node does not have are not generated: the node's code reads them
    # only under the feature that plane is built with, which is on exactly when the declaration has
    # it, so a constant generated without it would be one the build never reads.
    listener = [
        "/// The address and port the listening locator names.",
        f"pub const LISTEN_ADDR: [u8; 4] = [{listen_addr}];",
        f"pub const LISTEN_PORT: u16 = {listen_port};",
    ] if listens else []
    group = [
        "/// The locator of the group, the address and port it names, the hop limit of what the node",
        "/// sends and how many members of the group it tracks at once.",
        f"pub const GROUP: &str = {rust_string(group_at)};",
        f"pub const GROUP_ADDR: [u8; 4] = [{group_addr}];",
        f"pub const GROUP_PORT: u16 = {group_port};",
        f"pub const GROUP_TTL: u8 = {group_ttl};",
        f"pub const MEMBERS: usize = {members};",
    ] if groups else []
    querier = [
        "/// The queriers: (key, the period and the timeout in milliseconds, the bytes of a reply each",
        "/// keeps).",
        f"pub const QUERIED: [(&str, u32, u32, usize); {len(queried)}] = [{asks}];",
    ] if queried else []
    return "\n".join(
        [
            f"// {wz_config.SPDX}",
            f"// {wz_config.COPYRIGHT}",
            "",
            f"// GENERATED from the node declaration {name}.toml (DECLARATION_SHA256 below) by",
            "// scripts/lib/wz_node.py. Do not edit: a change is made in the declaration and generated again.",
            "",
            f"pub const NODE_ID: &str = {rust_string(name)};",
            "/// The digest of the declaration file this was generated from; the node's facts note carries it.",
            f"pub const DECLARATION_SHA256: &str = {rust_string(declaration_sha256)};",
            "/// The routers the node dials, as locators.",
            f"pub const DIALS: usize = {len(dialed)};",
            f"pub const DIALED: [&str; {len(dialed)}] = [{dials}];",
            "/// The peers the node holds by their zid beside the router it dials, each as the sixteen bytes",
            "/// of the zid and the locator it may be found at (decision D7, the third transport).",
            f"pub const PEERS: usize = {len(peers)};",
            f"pub const PEER_NODES: [([u8; 16], &str); {len(peers)}] = [{peer_nodes}];",
            "/// Whether a dialled endpoint or a peer is `tls/`, which the node's `tls` feature must be built for.",
            f"pub const TLS: bool = {'true' if secure else 'false'};",
            "/// Whether the node listens, the locator it listens on (empty when it does not) and how many",
            "/// sessions a peer opened it holds at once.",
            f"pub const LISTENS: bool = {'true' if listens else 'false'};",
            f"pub const LISTEN: &str = {rust_string(listen_at)};",
            f"pub const ACCEPTS: usize = {accepts};",
            *listener,
            "/// The sessions the node holds at most: the ones it dials, the peers it holds by their zid and",
            "/// the ones a peer opened.",
            "pub const SESSIONS: usize = DIALS + PEERS + ACCEPTS;",
            "/// Whether the node is a member of a multicast group.",
            f"pub const GROUPS: usize = {len(groups)};",
            *group,
            "/// The queryables the node declares, and the documents they answer with: (key, bytes).",
            f"pub const DOCS: usize = {len(entities)};",
            f"pub const DOCUMENTS: [(&str, usize); {len(entities)}] = [{docs}];",
            "/// The subscriptions the node declares, and the bytes of a payload each keeps: (key, bytes).",
            f"pub const SUBSCRIBERS: usize = {len(subscribed)};",
            f"pub const SUBSCRIPTIONS: [(&str, usize); {len(subscribed)}] = [{cells}];",
            "/// The liveliness tokens the node declares on every session, by key.",
            f"pub const TOKENS: usize = {len(alive)};",
            f"pub const TOKEN_KEYS: [&str; {len(alive)}] = [{token_keys}];",
            "/// The queriers the node runs.",
            f"pub const QUERIERS: usize = {len(queried)};",
            *querier,
            "/// The cells that keep a latest value: the subscriptions' and then the queriers'.",
            f"pub const CELLS: usize = {len(subscribed) + len(queried)};",
            "/// The most bytes any cell keeps: the size of every cell the node holds.",
            f"pub const SAMPLE_MAX: usize = {max([b for _, b in subscribed] + [b for _, _, _, b in queried], default=1)};",
            "/// The queryables that answer from a cell: (key, index into the cells).",
            f"pub const MIRRORS: usize = {len(mirrored)};",
            f"pub const MIRRORED: [(&str, usize); {len(mirrored)}] = [{mirrors}];",
            "/// The publishers: (key, when its puts are due, the bytes of each put and the fill they are",
            "/// made with, or `None` for a document of that many bytes).",
            f"pub const PUBLISHERS: usize = {len(published)};",
            f"pub const PUBLISHED: [(&str, {PUBLISHER}::Process, usize, Option<{PUBLISHER}::Fill>); "
            f"{len(published)}] = [{pubs}];",
            "/// The replays: (key, timing, the declared gap in milliseconds, the speed as written, the",
            "/// ceiling of a gap in milliseconds, the first of its samples, how many).",
            f"pub const REPLAYS: usize = {len(replayed)};",
            f"pub const REPLAYED: [(&str, {REPLAY}::Timing, u64, &str, u64, usize, usize); {len(replayed)}] = "
            f"[{', '.join(replayed)}];",
            "/// The replays' samples, each replay's together: (key, bytes, capture time in milliseconds,",
            "/// mutation).",
            f"pub const REPLAY_SAMPLES: [(&str, &[u8], Option<u64>, {REPLAY}::Mutation); {len(samples)}] = "
            f"[{', '.join(samples)}];",
            "",
            *([*key_set_lines(data), ""] if states_closed_key_set(data) else []),
        ]
    )


def load(name: str, decl: dict, directory: pathlib.Path = NODES) -> dict:
    data = wz_config.read_decl_toml((directory / f"{name}.toml").read_text(encoding="utf-8"))
    problems = validate(name, data, decl)
    if problems:
        raise ValueError(f"{name}: " + "; ".join(problems))
    return data


def env_lines(data: dict, decl: dict) -> list[str]:
    return [f"WZ_LIMIT_{k}={v}" for k, v in budgets(data, decl).items()]


def policy_lines(data: dict, decl: dict) -> list[str]:
    """The policies a node states, as the environment its build reads (`WZ_POLICY_<NAME>`), in the
    catalogue's order. A policy it does not state is left out, which is upstream's. Valid input
    only: `validate` ran first."""
    stated = data.get("policy", {})
    return [
        f"{pol['kconfig']}={stated[pol['id']]}" for pol in decl["policies"] if pol["id"] in stated
    ]


# What a dialled endpoint's scheme asks of the device, by name from the facilities of
# `deploy/wz-config.toml`. `tls` rides a TCP stream, so it asks for the same socket.
SCHEME_FACILITIES = {"tcp": "sockets-tcp", "tls": "sockets-tcp", "udp": "sockets-udp"}


def features_of(data: dict) -> list[str]:
    """The cargo features a node is built with: `declared`, `tls` exactly when a dialled endpoint is
    `tls/` (which the node's own `const` assertion holds again), `get` for a node that asks (and
    only such a node: the layer's queries and the pending table are not in any other), `token` for a
    node that declares a liveliness token and `listen` for a node that has a port to listen on."""
    tls = any(ep["locator"].startswith("tls/") for ep in data["endpoint"] if ep["role"] in ("dial", "peer"))
    asks = any(e["kind"] == "querier" for e in data.get("entity", []))
    alive = any(e["kind"] == "liveliness-token" for e in data.get("entity", []))
    listens = any(ep["role"] == "listen" for ep in data["endpoint"])
    grouped = any(ep["role"] == "multicast" for ep in data["endpoint"])
    return (["declared"] + (["tls"] if tls else []) + (["get"] if asks else [])
            + (["token"] if alive else []) + (["listen"] if listens else [])
            + (["multicast"] if grouped else []))


def resolve(name: str, decl: dict, directory: pathlib.Path = NODES) -> dict:
    """What the entry needs of one registered node, or the reason it cannot have it: the
    declaration validates for its target, and the tracked generated file is the one this
    declaration generates now (a build that read a stale one would build what the file said and
    not what the declaration says).

    `features` are the cargo features the node is built with (`tls` exactly when its endpoint is
    `tls/`, which the node's own `const` assertion holds again), `limits` the budgets it states as
    the environment the build reads, and `facilities` what its endpoints ask of the device beyond
    the base every executable asks.
    """
    data = load(name, decl, directory)
    sha = digest(name, directory)
    generated = generated_path(name, directory)
    if not generated.is_file() or generated.read_text(encoding="utf-8") != emit(name, data, sha):
        raise ValueError(f"{name}: {generated.name} is missing or stale: regenerate it with --write")
    source = (directory / f"{name}.toml").read_bytes()
    if hashlib.sha256(source).hexdigest() != sha:
        raise ValueError(f"{name}: the declaration changed while it was read")
    return {**view_of(name, data, sha, generated, decl), "source": source}


def read_file(path: pathlib.Path, decl: dict) -> tuple[str, dict, bytes]:
    """A declaration that is not in the registry: its bytes, read once, and what they say, validated
    exactly as a registered one is. Its name is the file's (`<id>.toml`, which `[node] id` must
    match), so a node is named by what it declares and not by where it was put."""
    blob = path.read_bytes()
    name = path.stem
    try:
        data = wz_config.read_decl_toml(blob.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as err:
        raise ValueError(f"{name}: not a TOML declaration: {err}") from err
    problems = validate(name, data, decl)
    if problems:
        raise ValueError(f"{name}: " + "; ".join(problems))
    return name, data, blob


def resolve_file(path: pathlib.Path, decl: dict, work: pathlib.Path) -> dict:
    """What the entry needs of a declaration given as a file, the registry's twin: the same
    validation, and the generated constants written into `work` (a directory the caller owns for
    the build) instead of being held to a tracked copy. The node is identified by the SHA-256 of
    the bytes read, which is what the built file carries and the package holds the declaration to.
    `source` is those bytes, which the package carries beside the node."""
    name, data, blob = read_file(path, decl)
    sha = hashlib.sha256(blob).hexdigest()
    generated = work / f"{name}.rs"
    generated.write_text(emit(name, data, sha), encoding="utf-8")
    return {**view_of(name, data, sha, generated, decl), "source": blob}


def view_of(name: str, data: dict, sha: str, generated: pathlib.Path, decl: dict) -> dict:
    """The build's view of a validated declaration, however it was given."""
    schemes = [LOCATOR_RE.fullmatch(ep["locator"])["scheme"] for ep in data["endpoint"]]
    facilities = {SCHEME_FACILITIES[s] for s in schemes}
    if any(ep["role"] == "multicast" for ep in data["endpoint"]):
        # A group is a UDP socket that has joined it: the socket option is a facility of its own.
        facilities.add("multicast")
    facilities = sorted(facilities)
    unknown = [f for f in facilities if f not in wz_config.OS_FACILITIES]
    if unknown:
        raise ValueError(f"{name}: the facilities {', '.join(unknown)} that its endpoints ask for are not "
                         "in the facility vocabulary of scripts/lib/wz_config.py")
    return {
        "id": name,
        "target": data["node"]["target"],
        "declaration_sha256": sha,
        "generated": generated,
        "features": features_of(data),
        "limits": dict(line.split("=", 1) for line in env_lines(data, decl)),
        "policies": dict(line.split("=", 1) for line in policy_lines(data, decl)),
        "facilities": facilities,
    }


def vocabulary(target_id: str, decl: dict) -> dict:
    """What a target builds, as data a consumer reads before it writes a declaration: the schema
    number, each endpoint role and entity kind with its keys and their bounds resolved to this
    target's numbers (a word the target does not build carries the reason instead), the groups of
    keys a word states exactly one of each (`one_of`, a list of lists), what a group carries (and
    the keys of a kind it carries that it does not), and the budgets and policies a declaration may state with the values a node gets when it
    states none. Made from the tables `validate` reads, so it cannot say a target builds what the
    target refuses."""
    target = TARGETS[target_id]
    bounds = {"integer": ("min", "max"), "rate": ("min_gap_ns", "max_gap_ns")}

    def resolved(keys: dict) -> dict:
        return {key: {**spec, **{name: bound(target, spec[name]) for name in bounds.get(spec["value"], ())}}
                for key, spec in keys.items()}

    schemes = {"dial": target["schemes"], "listen": target["listen_schemes"],
               "multicast": target["multicast_schemes"], "peer": target["peer_schemes"]}
    endpoints = {}
    for role, shape in ENDPOINT_SHAPES.items():
        if role not in target["endpoint_limits"]:
            endpoints[role] = {"built": False, "reason": target["refused"][role]}
            continue
        entry = {"built": True, "max": target["endpoint_limits"][role], "schemes": list(schemes[role]),
                 "keys": resolved(shape["keys"])}
        if role == "listen":
            entry["refused_schemes"] = dict(target["listen_refused"])
        endpoints[role] = entry
    limits, _ = limit_values(decl, {}, image_limits(target))
    entities = {}
    for kind, shape in ENTITY_SHAPES.items():
        if kind not in target["entity_kinds"]:
            entities[kind] = {"built": False,
                              "reason": target["refused"].get(kind, "the target has no behaviour for it yet")}
            continue
        count = ({"max": target[shape["count"]["max"]]} if "max" in shape["count"]
                 else {"limit": shape["count"]["limit"], "default": limits[shape["count"]["limit"]]})
        entry = {"built": True, "is": shape["is"], "count": count, "keys": resolved(shape["keys"])}
        if "one_of" in shape:
            entry["one_of"] = [list(group) for group in shape["one_of"]]
        if kind in target["group_refused_keys"]:
            entry["group_refused_keys"] = dict(target["group_refused_keys"][kind])
        entities[kind] = entry
    policies = {pol["id"]: ["on", "off"] if pol["kind"] == "bool" else list(pol["choices"])
                for pol in decl["policies"]}
    return {
        "vocabulary_schema": VOCABULARY_SCHEMA,
        "schema": DECLARATION_SCHEMA,
        "target": target_id,
        "endpoints": endpoints,
        "entities": entities,
        "samples": {"of": "replay", "is": "the tables `[[sample]]`, each naming its replay by its key",
                    "count": {"max": target["max_samples"]}, "keys": resolved(SAMPLE_SHAPE["keys"]),
                    "one_of": [list(group) for group in SAMPLE_SHAPE["one_of"]]},
        "group": {"carries": sorted(target["group_kinds"]), "refused": dict(sorted(target["group_refused"].items()))},
        "limits": dict(sorted(limits.items())),
        "policies": policies,
    }


def generated_path(name: str, directory: pathlib.Path = NODES) -> pathlib.Path:
    return directory / "generated" / f"{name}.rs"


def check(decl: dict, directory: pathlib.Path = NODES) -> int:
    """Every declaration validates and its generated file, which the image gates build, is current."""
    files = sorted(directory.glob("*.toml")) if directory.is_dir() else []
    bad = 0
    for path in files:
        try:
            data = load(path.stem, decl, directory)
        except (ValueError, OSError) as err:
            print(f"  wz-node FAIL: {err}", file=sys.stderr)
            bad += 1
            continue
        out = generated_path(path.stem, directory)
        if not out.is_file() or out.read_text(encoding="utf-8") != emit(path.stem, data, digest(path.stem, directory)):
            print(f"  wz-node FAIL: {out.name} is missing or stale: regenerate it with --write", file=sys.stderr)
            bad += 1
    expected = {generated_path(p.stem, directory).name for p in files}
    gen = directory / "generated"
    for stray in sorted(p.name for p in gen.glob("*.rs")) if gen.is_dir() else []:
        if stray not in expected:
            print(f"  wz-node FAIL: generated/{stray} has no declaration", file=sys.stderr)
            bad += 1
    print(f"wz-node: {len(files)} node declaration(s), {len(files) - bad} valid and current")
    return 1 if bad else 0


def write(decl: dict, directory: pathlib.Path = NODES) -> int:
    """Generate every declaration's file; a declaration that does not validate writes nothing."""
    files = sorted(directory.glob("*.toml")) if directory.is_dir() else []
    for path in files:
        try:
            data = load(path.stem, decl, directory)
        except (ValueError, OSError) as err:
            print(f"  wz-node FAIL: {err}", file=sys.stderr)
            return 1
        out = generated_path(path.stem, directory)
        out.parent.mkdir(exist_ok=True)
        out.write_text(emit(path.stem, data, digest(path.stem, directory)), encoding="utf-8")
    print(f"wz-node: wrote {len(files)} generated file(s)")
    return 0


# ---------------------------------------------------------------------------
# Selftest
# ---------------------------------------------------------------------------

SAMPLE = """schema = 1

[node]
id = "n"
help = "A node."
target = "slot"

[[endpoint]]
role = "dial"
locator = "tcp/10.0.0.1:7447"

[[entity]]
kind = "queryable"
key = "lab/doc/a"
document_bytes = 512

[limits]
MAX_QUERYABLES = 2
"""


def _selftest() -> int:
    decl = wz_config.load_decl()

    def expect(what: str, ok: bool) -> None:
        if not ok:
            raise AssertionError(what)

    def problems(text: str, name: str = "n") -> list[str]:
        return validate(name, wz_config.read_decl_toml(text), decl)

    def refuses(what: str, text: str, needle: str, name: str = "n") -> None:
        found = problems(text, name)
        expect(f"{what}: expected a finding naming {needle!r}, got {found}", any(needle in p for p in found))

    expect("the sample is a valid node", problems(SAMPLE) == [])
    data = wz_config.read_decl_toml(SAMPLE)
    sha = "0" * 64
    rs = emit("n", data, sha)
    expect("the endpoint is the generated router",
           'pub const DIALED: [&str; 1] = ["tcp/10.0.0.1:7447"];' in rs and "pub const DIALS: usize = 1;" in rs)
    expect("the declaration's digest is a constant of the generated file",
           f'pub const DECLARATION_SHA256: &str = "{sha}";' in rs)
    expect("a tcp endpoint is not tls", "pub const TLS: bool = false;" in rs)
    expect("the documents are the queryables", 'pub const DOCUMENTS: [(&str, usize); 1] = [("lab/doc/a", 512)];' in rs)
    expect("a tls endpoint sets the flag", "pub const TLS: bool = true;" in emit(
        "n", wz_config.read_decl_toml(SAMPLE.replace("tcp/", "tls/")), sha))
    expect("the file names its source and says it is generated",
           "GENERATED from the node declaration n.toml" in rs and "deploy/nodes" not in rs)
    expect("the budgets become the limit environment",
           env_lines(data, decl) == ["WZ_LIMIT_MAX_QUERYABLES=2"])
    expect("a node with no subscription declares none and holds cells of one byte nowhere",
           "pub const SUBSCRIBERS: usize = 0;" in rs and "pub const MIRRORS: usize = 0;" in rs
           and "pub const SAMPLE_MAX: usize = 1;" in rs)

    # A subscription keeps what it receives; a queryable may answer from one.
    sub = '\n[[entity]]\nkind = "subscriber"\nkey = "lab/in/a"\nsample_bytes = 64\n'
    mirror = '\n[[entity]]\nkind = "queryable"\nkey = "lab/in/a"\nfrom = "lab/in/a"\n'
    expect("a subscription is a valid entity", problems(SAMPLE + sub) == [])
    expect("a queryable that answers from it is valid, under the key it subscribes to",
           problems(SAMPLE + sub + mirror) == [])
    both = emit("n", wz_config.read_decl_toml(SAMPLE + sub + mirror), sha)
    expect("the subscription and its size are generated",
           'pub const SUBSCRIPTIONS: [(&str, usize); 1] = [("lab/in/a", 64)];' in both
           and "pub const SUBSCRIBERS: usize = 1;" in both and "pub const SAMPLE_MAX: usize = 64;" in both)
    expect("the mirror names the subscription it answers from, by place",
           'pub const MIRRORED: [(&str, usize); 1] = [("lab/in/a", 0)];' in both
           and "pub const MIRRORS: usize = 1;" in both)
    expect("the mirror is not a document",
           'pub const DOCUMENTS: [(&str, usize); 1] = [("lab/doc/a", 512)];' in both)
    expect("every cell is as large as the largest subscription",
           "pub const SAMPLE_MAX: usize = 100;" in emit("n", wz_config.read_decl_toml(
               SAMPLE + sub + '\n[[entity]]\nkind = "subscriber"\nkey = "lab/in/b"\nsample_bytes = 100\n'), sha))
    two = wz_config.read_decl_toml(SAMPLE + sub + '\n[[entity]]\nkind = "subscriber"\nkey = "lab/in/b"\n'
                                   'sample_bytes = 8\n' + '\n[[entity]]\nkind = "queryable"\nkey = "lab/in/b"\n'
                                   'from = "lab/in/b"\n')
    expect("a mirror points at the place of its own subscription, not the first",
           'pub const MIRRORED: [(&str, usize); 1] = [("lab/in/b", 1)];' in emit("n", two, sha))
    expect("the budgets a subscription decides follow from it when the declaration states none",
           budgets(wz_config.read_decl_toml(SAMPLE + sub), decl)["MAX_SUBSCRIPTIONS"] >= 1)
    many = SAMPLE.replace("MAX_QUERYABLES = 2", "") + "".join(
        f'\n[[entity]]\nkind = "queryable"\nkey = "lab/q/{i}"\ndocument_bytes = 1\n' for i in range(4))
    expect("the queryables of a node decide MAX_QUERYABLES where the image's is too small",
           budgets(wz_config.read_decl_toml(many), decl)["MAX_QUERYABLES"] == 5)
    expect("and the registry holds what they need", problems(many) == [])

    refuses("a file named otherwise than its id", SAMPLE, "the file is named", "other")
    refuses("an unknown target", SAMPLE.replace('"slot"', '"heap"'), "target is 'heap'")
    # A listening endpoint: the port a node takes connections on and how many sessions of them it holds.
    listening = SAMPLE.replace(
        "[[entity]]", '[[endpoint]]\nrole = "listen"\nlocator = "tcp/0.0.0.0:17475"\naccepts = 2\n\n[[entity]]', 1)
    expect("a node that dials a router and listens is valid", problems(listening) == [])
    lrs = emit("n", wz_config.read_decl_toml(listening), sha)
    expect("the listener is a constant of the generated file",
           'pub const LISTENS: bool = true;' in lrs and 'pub const LISTEN: &str = "tcp/0.0.0.0:17475";' in lrs
           and "pub const LISTEN_ADDR: [u8; 4] = [0, 0, 0, 0];" in lrs and "pub const LISTEN_PORT: u16 = 17475;" in lrs
           and "pub const ACCEPTS: usize = 2;" in lrs)
    expect("its sessions are the dialled one and the accepted ones",
           'pub const DIALED: [&str; 1] = ["tcp/10.0.0.1:7447"];' in lrs and "pub const SESSIONS: usize = DIALS + PEERS + ACCEPTS;" in lrs)
    expect("a node that listens on nothing accepts nothing",
           "pub const LISTENS: bool = false;" in rs and "pub const ACCEPTS: usize = 0;" in rs
           and 'pub const LISTEN: &str = "";' in rs and "LISTEN_ADDR" not in rs and "LISTEN_PORT" not in rs)
    expect("a listener is a feature of the build, and the others are unchanged",
           features_of(wz_config.read_decl_toml(listening)) == ["declared", "listen"]
           and features_of(data) == ["declared"])
    listen_only = listening.replace('[[endpoint]]\nrole = "dial"\nlocator = "tcp/10.0.0.1:7447"\n\n', "")
    expect("a node that only listens is valid, and dials nothing",
           problems(listen_only) == [] and 'pub const DIALED: [&str; 0] = [];' in emit(
               "n", wz_config.read_decl_toml(listen_only), sha))
    expect("a tls endpoint it dials is not the listener's scheme",
           features_of(wz_config.read_decl_toml(listening.replace("tcp/10.0.0.1", "tls/10.0.0.1"))) ==
           ["declared", "tls", "listen"])
    refuses("a listener with no accepts", listening.replace("accepts = 2\n", ""), "accepts is None")
    refuses("a listener that accepts none", listening.replace("accepts = 2", "accepts = 0"), "accepts is 0")
    refuses("a listener that accepts more than the node holds",
            listening.replace("accepts = 2", "accepts = 5"), "from 1 to 4")
    refuses("accepts on a dialled endpoint", SAMPLE.replace('role = "dial"', 'role = "dial"\naccepts = 1'),
            "only a `listen` endpoint has `accepts`")
    refuses("a second listener", listening + '\n[[endpoint]]\nrole = "listen"\nlocator = "tcp/0.0.0.0:17476"\n'
            "accepts = 1\n", "more than 1 `listen`")
    refuses("a datagram listener is refused with the target's reason",
            listening.replace("tcp/0.0.0.0", "udp/0.0.0.0"), "a `udp` listener is not built on slot")
    refuses("a secure listener is refused with the target's reason",
            listening.replace("tcp/0.0.0.0", "tls/0.0.0.0"), "a `tls` listener is not built on slot")
    # A multicast group: a member of it publishes and subscribes, and the rest is refused by name.
    group_node = """schema = 1

[node]
id = "n"
help = "A node."
target = "slot"

[[endpoint]]
role = "multicast"
locator = "udp/224.0.0.224:7447"
members = 4

[[entity]]
kind = "subscriber"
key = "lab/in"
sample_bytes = 64

[[entity]]
kind = "publisher"
key = "lab/out"
period_ms = 200
document_bytes = 8
"""
    expect("a node that is a member of a group, publishes and subscribes is valid", problems(group_node) == [])
    grs = emit("n", wz_config.read_decl_toml(group_node), sha)
    expect("the group is a set of constants of the generated file",
           "pub const GROUPS: usize = 1;" in grs and 'pub const GROUP: &str = "udp/224.0.0.224:7447";' in grs
           and "pub const GROUP_ADDR: [u8; 4] = [224, 0, 0, 224];" in grs and "pub const GROUP_PORT: u16 = 7447;" in grs
           and "pub const GROUP_TTL: u8 = 1;" in grs and "pub const MEMBERS: usize = 4;" in grs
           and "pub const DIALS: usize = 0;" in grs and "pub const SESSIONS: usize = DIALS + PEERS + ACCEPTS;" in grs)
    expect("a node with no group is a member of none, and none of a group's constants is generated",
           "pub const GROUPS: usize = 0;" in rs and "MEMBERS" not in rs and "GROUP_TTL" not in rs
           and "GROUP_ADDR" not in rs)
    expect("a group is a feature of the build",
           features_of(wz_config.read_decl_toml(group_node)) == ["declared", "multicast"])
    expect("a group's publisher puts at a rate and under any arrival process",
           problems(group_node.replace("period_ms = 200", 'rate_per_s = "20"\narrivals = "poisson"\n'
                                       "arrival_seed = 1")) == [])
    refuses("a body made for each put on a node with a group",
            group_node.replace("document_bytes = 8", "payload_bytes = 8"),
            "`payload_bytes` is not carried by the group")
    refuses("a replay on a node with a group",
            group_node + '\n[[entity]]\nkind = "replay"\nkey = "lab/r"\n'
            '\n[[sample]]\nreplay = "lab/r"\ntext = "a"\n', "a `replay` is not carried by the group")

    # A replay: its samples in the driver's words, each naming the replay by its key.
    replay = ('\n[[entity]]\nkind = "replay"\nkey = "lab/r"\ntiming = "capture"\nspeed = "2.5"\n'
              '\n[[sample]]\nreplay = "lab/r"\ntext = "ab"\ncaptured_at_ms = 1000\n'
              '\n[[sample]]\nreplay = "lab/r"\nkey = "lab/r/other"\nhex = "00ff"\nmutation = "flip_bit"\n'
              'at_bit = 9\n'
              '\n[[sample]]\nreplay = "lab/r"\ntext = "xyz"\nmutation = "extend"\ncount = 2\nseed = 5\n')
    expect("a replay and its samples are valid", problems(SAMPLE + replay) == [])
    rrs = emit("n", wz_config.read_decl_toml(SAMPLE + replay), sha)
    expect("the replay is a row of its schedule and a range of the samples",
           'pub const REPLAYED: [(&str, wz_session_mcu::slot_replay::Timing, u64, &str, u64, usize, usize); 1] = '
           '[("lab/r", wz_session_mcu::slot_replay::Timing::Capture, 100, "2.5", 10000, 0, 3)];' in rrs)
    expect("each sample is its key, its bytes, its time and its mutation",
           '("lab/r", &[97, 98], Some(1000), wz_session_mcu::slot_replay::Mutation::None)' in rrs
           and '("lab/r/other", &[0, 255], None, wz_session_mcu::slot_replay::Mutation::FlipBit { at: 9 })' in rrs
           and 'Mutation::Extend { count: 2, seed: 5 })' in rrs)
    expect("a node with no replay declares none",
           "pub const REPLAYS: usize = 0;" in rs and "REPLAY_SAMPLES: [(&str, &[u8], Option<u64>, "
           "wz_session_mcu::slot_replay::Mutation); 0] = [];" in rs)
    refuses("a replay with no sample", SAMPLE + '\n[[entity]]\nkind = "replay"\nkey = "lab/r"\n', "has no sample")
    refuses("a sample of no replay", SAMPLE + '\n[[sample]]\nreplay = "lab/r"\ntext = "a"\n',
            "not the key of a replay")
    refuses("a sample with text and hex", SAMPLE + replay + '\n[[sample]]\nreplay = "lab/r"\ntext = "a"\nhex = "00"\n',
            "not both")
    refuses("a sample put on a pattern", SAMPLE + replay.replace("lab/r/other", "lab/r/*"), "is a pattern")
    refuses("a sample mutated past what a put carries",
            SAMPLE + replay.replace("count = 2", "count = 1024"), "mutated, its bytes are 1027")
    refuses("a seed of a flipped bit", SAMPLE + replay.replace("at_bit = 9", "at_bit = 9\nseed = 1"),
            "`seed` is read only when `mutation` is one of 'extend', 'scramble'")
    refuses("a speed that is not a decimal", SAMPLE + replay.replace('"2.5"', '"fast"'), "speed is 'fast'")
    refuses("more replays than the task cell keeps", SAMPLE + "".join(
        f'\n[[entity]]\nkind = "replay"\nkey = "lab/r{i}"\n\n[[sample]]\nreplay = "lab/r{i}"\ntext = "a"\n'
        for i in range(3)), "3 replays")
    expect("a closed key set sees a replay's sample keys as publishers",
           key_set_entities(wz_config.read_decl_toml(SAMPLE + replay))[-2:]
           == [{"kind": "publisher", "key": "lab/r"}, {"kind": "publisher", "key": "lab/r/other"}])
    expect("a ttl the declaration states is the one generated",
           "pub const GROUP_TTL: u8 = 8;" in emit(
               "n", wz_config.read_decl_toml(group_node.replace("members = 4", "members = 4\nttl = 8")), sha))
    both = group_node.replace("[[entity]]", '[[endpoint]]\nrole = "dial"\nlocator = "tcp/10.0.0.1:7447"\n\n[[entity]]', 1)
    expect("a node may dial a router and be a member of a group", problems(both) == []
           and features_of(wz_config.read_decl_toml(both)) == ["declared", "multicast"])
    refuses("a group with no members", group_node.replace("members = 4\n", ""), "members is None")
    refuses("a group of more members than the node tracks", group_node.replace("members = 4", "members = 9"), "from 1 to 8")
    refuses("a hop limit of zero", group_node.replace("members = 4", "members = 4\nttl = 0"), "ttl is 0")
    refuses("a hop limit past a byte", group_node.replace("members = 4", "members = 4\nttl = 256"), "ttl is 256")
    refuses("a group that is not a multicast address", group_node.replace("224.0.0.224", "10.0.0.1"), "is not a group")
    refuses("a group over TCP", group_node.replace("udp/", "tcp/"), "a group is `udp`, not `tcp`")
    refuses("members on a dialled endpoint", SAMPLE.replace('role = "dial"', 'role = "dial"\nmembers = 2'),
            "only a `multicast` endpoint has `members`")
    refuses("a second group", group_node + '\n[[endpoint]]\nrole = "multicast"\nlocator = "udp/224.0.0.225:7447"\n'
            "members = 2\n", "more than 1 `multicast`")
    for kind, extra in (("queryable", 'document_bytes = 16'),
                        ("querier", 'period_ms = 100\ntimeout_ms = 500\nreply_bytes = 16'),
                        ("liveliness-token", "")):
        refuses(f"a {kind} on a node that is a member of a group",
                group_node + f'\n[[entity]]\nkind = "{kind}"\nkey = "lab/x"\n{extra}\n',
                f"a `{kind}` is not carried by the group")
    refuses("a role outside the vocabulary", SAMPLE.replace('role = "dial"', 'role = "dail"'), "not one of dial")
    # A kind a target does not build is refused with the target's own words, or with a default when it
    # states none. The slot target builds every kind now, so the branch is driven on a target that
    # does not, for the length of the call.
    built = TARGETS["slot"]["entity_kinds"]
    TARGETS["slot"]["entity_kinds"] = built - {"publisher"}
    try:
        refuses("a kind the target does not build is refused, never dropped",
                SAMPLE + '\n[[entity]]\nkind = "publisher"\nkey = "p"\nperiod_ms = 1\ndocument_bytes = 1\n',
                "not built on slot: the target has no behaviour for it yet")
        TARGETS["slot"]["refused"]["publisher"] = "the target has no clock"
        refuses("and with the target's reason when it states one",
                SAMPLE + '\n[[entity]]\nkind = "publisher"\nkey = "p"\nperiod_ms = 1\ndocument_bytes = 1\n',
                "the target has no clock")
    finally:
        TARGETS["slot"]["entity_kinds"] = built
        TARGETS["slot"]["refused"].pop("publisher", None)

    # A liveliness token is a key, declared on every session, that the router drops with the session.
    tok = '\n[[entity]]\nkind = "liveliness-token"\nkey = "lab/alive/a"\n'
    expect("a token is a valid entity", problems(SAMPLE + tok) == [])
    toks = emit("n", wz_config.read_decl_toml(SAMPLE + tok + tok.replace("lab/alive/a", "lab/alive/b")), sha)
    expect("the tokens are generated by key, in the order they are declared",
           'pub const TOKEN_KEYS: [&str; 2] = ["lab/alive/a", "lab/alive/b"];' in toks
           and "pub const TOKENS: usize = 2;" in toks)
    expect("a node with no token declares none",
           "pub const TOKENS: usize = 0;" in rs and "pub const TOKEN_KEYS: [&str; 0] = [];" in rs)
    expect("a token decides no budget and no cell",
           budgets(wz_config.read_decl_toml(SAMPLE + tok), decl) == budgets(data, decl)
           and "pub const CELLS: usize = 0;" in emit("n", wz_config.read_decl_toml(SAMPLE + tok), sha))
    expect("a node with a token is built with the token feature, and no other is",
           features_of(wz_config.read_decl_toml(SAMPLE + tok)) == ["declared", "token"]
           and features_of(data) == ["declared"])
    expect("the features are the ones each kind asks for, in a fixed order",
           features_of(wz_config.read_decl_toml((
               SAMPLE + tok + '\n[[entity]]\nkind = "querier"\nkey = "lab/ask/val"\nperiod_ms = 500\n'
               "timeout_ms = 1000\nreply_bytes = 32\n").replace("tcp/", "tls/")))
           == ["declared", "tls", "get", "token"])
    refuses("a token with no key", SAMPLE + '\n[[entity]]\nkind = "liveliness-token"\n', "key")
    refuses("a token that is a pattern", SAMPLE + tok.replace("lab/alive/a", "lab/alive/*"), "is a pattern")
    refuses("a token that is a pattern with $", SAMPLE + tok.replace("lab/alive/a", "lab/$*"), "is a pattern")
    refuses("a token with a document", SAMPLE + tok + "document_bytes = 4\n", "has no `document_bytes`")
    refuses("a token with a sample size", SAMPLE + tok + "sample_bytes = 4\n", "has no `sample_bytes`")
    refuses("a token with a source", SAMPLE + tok + 'from = "x"\n', "has no `from`")
    refuses("a token with a period", SAMPLE + tok + "period_ms = 4\n", "only a publisher or a querier has `period_ms`")
    refuses("two tokens of one key", SAMPLE + tok + tok, "declared twice")
    expect("a token and a publisher of one key are not a duplicate",
           problems(SAMPLE + tok + '\n[[entity]]\nkind = "publisher"\nkey = "lab/alive/a"\nperiod_ms = 5\n'
                    "document_bytes = 1\n") == [])
    refuses("more tokens than a session establishing declares",
            SAMPLE + "".join(tok.replace("lab/alive/a", f"lab/alive/{i}") for i in range(5)),
            "5 liveliness tokens")

    # A querier asks a key every period and keeps the latest reply in a cell.
    ask = ('\n[[entity]]\nkind = "querier"\nkey = "lab/ask/val"\nperiod_ms = 500\ntimeout_ms = 1000\n'
           "reply_bytes = 32\n")
    expect("a querier is a valid entity", problems(SAMPLE + ask) == [])
    asked = emit("n", wz_config.read_decl_toml(SAMPLE + ask), sha)
    expect("the querier, its period, its timeout and its reply size are generated",
           'pub const QUERIED: [(&str, u32, u32, usize); 1] = [("lab/ask/val", 500, 1000, 32)];' in asked
           and "pub const QUERIERS: usize = 1;" in asked and "pub const CELLS: usize = 1;" in asked)
    expect("the cell of a querier is as large as it asks, and no node with none has a querier",
           "pub const SAMPLE_MAX: usize = 32;" in asked and "pub const QUERIERS: usize = 0;" in rs)
    expect("a querier is a pattern-able key: it asks for everything under it",
           problems(SAMPLE + ask.replace("lab/ask/val", "lab/ask/**")) == [])
    expect("a node that asks is built with get, and no other is",
           features_of(wz_config.read_decl_toml(SAMPLE + ask)) == ["declared", "get"]
           and features_of(data) == ["declared"]
           and features_of(wz_config.read_decl_toml((SAMPLE + ask).replace("tcp/", "tls/"))) == ["declared", "tls", "get"])
    expect("the pending rows its queries can fill are counted from the periods that fit in a timeout",
           pending_need(wz_config.read_decl_toml(SAMPLE + ask)["entity"]) == 3)
    expect("an image whose table holds them is left as it is",
           "MAX_PENDING_QUERIES" not in budgets(wz_config.read_decl_toml(SAMPLE + ask), decl))
    slow = SAMPLE + ask.replace("period_ms = 500", "period_ms = 1000").replace("timeout_ms = 1000", "timeout_ms = 60000")
    expect("one whose table is too small gets the rows the querier needs",
           budgets(wz_config.read_decl_toml(slow), decl)["MAX_PENDING_QUERIES"] == 61)
    both = SAMPLE + sub + ask
    expect("the cells are the subscriptions' and then the queriers', and a mirror may answer from a querier",
           problems(both + '\n[[entity]]\nkind = "queryable"\nkey = "lab/ask/val"\nfrom = "lab/ask/val"\n') == []
           and 'pub const MIRRORED: [(&str, usize); 1] = [("lab/ask/val", 1)];' in emit(
               "n", wz_config.read_decl_toml(both + '\n[[entity]]\nkind = "queryable"\nkey = "lab/ask/val"\n'
                                             'from = "lab/ask/val"\n'), sha)
           and "pub const CELLS: usize = 2;" in emit("n", wz_config.read_decl_toml(both), sha))
    refuses("a querier with no period", SAMPLE + ask.replace("period_ms = 500\n", ""), "period_ms is None")
    refuses("a querier with no timeout", SAMPLE + ask.replace("timeout_ms = 1000\n", ""), "timeout_ms is None")
    refuses("a timeout above the target's", SAMPLE + ask.replace("1000", "60001"), "timeout_ms is 60001")
    refuses("a querier that keeps nothing", SAMPLE + ask.replace("reply_bytes = 32", "reply_bytes = 0"),
            "reply_bytes is 0")
    refuses("a querier that keeps more than a cell", SAMPLE + ask.replace("= 32", "= 4097"), "reply_bytes is 4097")
    refuses("a querier with a document", SAMPLE + ask + "document_bytes = 4\n", "has no `document_bytes`")
    refuses("a querier with a source", SAMPLE + ask + 'from = "lab/in/a"\n', "has no `from`")
    refuses("a timeout on a publisher", SAMPLE + "\n[[entity]]\nkind = \"publisher\"\nkey = \"lab/o\"\n"
            "period_ms = 5\ndocument_bytes = 1\ntimeout_ms = 5\n", "only a querier has `timeout_ms`")
    refuses("a reply size on a subscriber", SAMPLE + sub + "reply_bytes = 5\n", "only a querier has `reply_bytes`")
    refuses("two queriers of one key", SAMPLE + ask + ask, "declared twice")
    refuses("a subscription and a querier of one key", SAMPLE + sub + ask.replace("lab/ask/val", "lab/in/a"),
            "names the cell of a subscriber too")
    refuses("more queriers than the task cell keeps",
            SAMPLE + "".join(ask.replace("lab/ask/val", f"lab/ask/{i}") for i in range(5)), "5 queriers")
    refuses("a mirror of a querier that keeps more than a reply holds",
            SAMPLE + ask.replace("= 32", "= 2048") + '\n[[entity]]\nkind = "queryable"\nkey = "m"\n'
            'from = "lab/ask/val"\n', "more than a reply holds")
    refuses("a limit stated below the pending rows the querier needs",
            SAMPLE.replace("MAX_QUERYABLES = 2", "MAX_QUERYABLES = 2\nMAX_PENDING_QUERIES = 2") + ask,
            "states MAX_PENDING_QUERIES = 2")

    # A publisher puts a stream of its own on one key: a document every period, at its least.
    pub = '\n[[entity]]\nkind = "publisher"\nkey = "lab/out/beat"\nperiod_ms = 200\ndocument_bytes = 8\n'
    expect("a publisher is a valid entity", problems(SAMPLE + pub) == [])
    puts = emit("n", wz_config.read_decl_toml(SAMPLE + pub), sha)
    published = f"pub const PUBLISHED: [(&str, {PUBLISHER}::Process, usize, Option<{PUBLISHER}::Fill>); "
    expect("the publisher, its period and its document are generated",
           published + '1] = [("lab/out/beat", ' + f"{PUBLISHER}::Process::Periodic {{ gap_nanos: 200000000 }}, "
           "8, None)];" in puts and "pub const PUBLISHERS: usize = 1;" in puts)
    expect("a node with no publisher declares none",
           "pub const PUBLISHERS: usize = 0;" in rs and published + "0] = [];" in rs)
    expect("a publisher decides no budget", budgets(wz_config.read_decl_toml(SAMPLE + pub), decl)
           == budgets(data, decl))
    refuses("a publisher with no period", SAMPLE + pub.replace("period_ms = 200\n", ""),
            "state exactly one of `period_ms`, `rate_per_s`")
    refuses("a period of zero", SAMPLE + pub.replace("200", "0"), "period_ms is 0")
    refuses("a period above the target's", SAMPLE + pub.replace("200", "3600001"), "period_ms is 3600001")
    refuses("a publisher with no document", SAMPLE + pub.replace("document_bytes = 8\n", ""),
            "state exactly one of `document_bytes`, `payload_bytes`")
    refuses("a document above what a put carries", SAMPLE + pub.replace("= 8\n", "= 1025\n"), "document_bytes is 1025")

    # The stream's words are the traffic driver's, and a rate is its digits: the gaps below are the
    # ones `wz_workload::arrivals` holds in `a_rate_gives_its_gap_exactly`.
    for text, gap in (("100", 10_000_000), ("0.5", 2_000_000_000), ("3", 333_333_333), ("0.1", 10_000_000_000),
                      ("1000000", 1_000), ("007.250", 137_931_034)):
        expect(f"the rate {text} gives the workload's gap", rate_gap_ns(text) == (gap, None))
    for bad in ("", ".5", "5.", "-1", "+1", "1e3", "1.2.3", " 1", "0x10", "١", 2.5, 3):
        expect(f"{bad!r} is not a rate", rate_gap_ns(bad)[0] is None)
    expect("a rate of nothing is refused as zero", rate_gap_ns("0.000")[1] == "must be greater than zero")
    expect("a rate of more digits than a mantissa holds is refused",
           rate_gap_ns("1234567890.123456789")[1] == "has more than 18 significant digits")
    rated = pub.replace("period_ms = 200", 'rate_per_s = "3"')
    expect("a publisher at a rate is valid", problems(SAMPLE + rated) == [])
    expect("and its gap is the rate's",
           f"{PUBLISHER}::Process::Periodic {{ gap_nanos: 333333333 }}"
           in emit("n", wz_config.read_decl_toml(SAMPLE + rated), sha))
    refuses("a period and a rate", SAMPLE + pub + 'rate_per_s = "3"\n', "not both")
    refuses("a rate above the millisecond's", SAMPLE + rated.replace('"3"', '"1001"'), "a gap of 999000 ns")
    expect("a rate of a thousand a second is the slot clock's floor",
           problems(SAMPLE + rated.replace('"3"', '"1000"')) == [])
    try:
        wz_config.read_decl_toml(SAMPLE + rated.replace('"3"', "2.5"))
    except ValueError as err:
        expect(f"a rate written as a float is not read at all ({err})", "not a string, integer" in str(err))
    else:
        expect("a rate written as a float is not read at all", False)
    refuses("a rate written as an integer", SAMPLE + rated.replace('"3"', "3"), "not a positive decimal")
    poisson = rated + 'arrivals = "poisson"\narrival_seed = 7\n'
    expect("a Poisson publisher is valid, its mean the rate's gap and its seed the declaration's",
           f"{PUBLISHER}::Process::Poisson {{ mean_gap_nanos: 333333333, seed: 7 }}"
           in emit("n", wz_config.read_decl_toml(SAMPLE + poisson), sha) and problems(SAMPLE + poisson) == [])
    refuses("a Poisson publisher with no seed", SAMPLE + rated + 'arrivals = "poisson"\n', "arrival_seed is None")
    refuses("a seed of periodic arrivals", SAMPLE + rated + "arrival_seed = 7\n",
            "`arrival_seed` is read only when `arrivals` is 'poisson'")
    burst = pub + 'arrivals = "burst"\nburst = 4\n'
    expect("a burst publisher is valid, its size and gap the declaration's",
           f"{PUBLISHER}::Process::Burst {{ size: 4, gap_nanos: 200000000 }}"
           in emit("n", wz_config.read_decl_toml(SAMPLE + burst), sha) and problems(SAMPLE + burst) == [])
    refuses("a burst of periodic arrivals", SAMPLE + pub + "burst = 4\n", "`burst` is read only when")
    refuses("an arrival process the driver does not have", SAMPLE + pub + 'arrivals = "steady"\n',
            "not one of periodic, poisson, burst")
    made = pub.replace("document_bytes = 8", "payload_bytes = 16")
    expect("a publisher of a made body is valid, the counter its fill when it names none",
           f"16, Some({PUBLISHER}::Fill::Counter))" in emit("n", wz_config.read_decl_toml(SAMPLE + made), sha)
           and problems(SAMPLE + made) == [])
    seeded = made + 'fill = "seeded"\nseed = 9\n'
    expect("a seeded fill carries its seed",
           f"16, Some({PUBLISHER}::Fill::Seeded {{ seed: 9 }}))"
           in emit("n", wz_config.read_decl_toml(SAMPLE + seeded), sha))
    refuses("a seeded fill with no seed", SAMPLE + made + 'fill = "seeded"\n', "seed is None")
    refuses("a seed of a counter", SAMPLE + made + "seed = 9\n", "`seed` is read only when `fill` is 'seeded'")
    refuses("a fill of a document", SAMPLE + pub + 'fill = "zero"\n', "`fill` is read only when `payload_bytes` is stated")
    refuses("a document and a made body", SAMPLE + made + "document_bytes = 8\n", "not both")
    refuses("a made body above what a put carries", SAMPLE + made.replace("= 16", "= 1025"), "payload_bytes is 1025")
    refuses("a publisher of a pattern", SAMPLE + pub.replace("lab/out/beat", "lab/out/*"), "is a pattern")
    refuses("a publisher of a pattern with $", SAMPLE + pub.replace("lab/out/beat", "lab/out/$*"), "is a pattern")
    refuses("a publisher with a source", SAMPLE + pub + 'from = "lab/in/a"\n', "has no `from`")
    refuses("a publisher with a sample size", SAMPLE + pub + "sample_bytes = 4\n", "has no `sample_bytes`")
    refuses("a period on a queryable", SAMPLE.replace("512", "512\nperiod_ms = 5"),
            "only a publisher or a querier has `period_ms`")
    refuses("a period on a subscriber", SAMPLE + sub + "period_ms = 5\n",
            "only a publisher or a querier has `period_ms`")
    refuses("two publishers of one key", SAMPLE + pub + pub, "declared twice")
    refuses("more publishers than the task cell keeps",
            SAMPLE + "".join(pub.replace("lab/out/beat", f"lab/out/{i}") for i in range(5)), "5 publishers")
    expect("a publisher and a subscriber of one key are not a duplicate",
           problems(SAMPLE + sub + pub.replace("lab/out/beat", "lab/in/a")) == [])
    refuses("a subscription with no size", SAMPLE + '\n[[entity]]\nkind = "subscriber"\nkey = "lab/in/a"\n',
            "sample_bytes is None")
    refuses("a subscription of no bytes", SAMPLE + sub.replace("64", "0"), "sample_bytes is 0")
    refuses("a subscription above the target's cell", SAMPLE + sub.replace("64", "4097"), "sample_bytes is 4097")
    refuses("a subscription with a document", SAMPLE + sub + "document_bytes = 4\n", "has no `document_bytes`")
    refuses("a subscription with a source", SAMPLE + sub + 'from = "lab/in/a"\n', "has no `from`")
    refuses("a queryable with a sample size", SAMPLE.replace("512", "512\nsample_bytes = 4"), "has no `sample_bytes`")
    refuses("a mirror of a subscription nobody declared", SAMPLE + sub + mirror.replace('from = "lab/in/a"',
            'from = "lab/in/zzz"'), "not the key of a subscription")
    refuses("a mirror that is also a document", SAMPLE + sub + mirror + "document_bytes = 4\n", "not both")
    refuses("a mirror of a subscription that keeps more than a reply holds",
            SAMPLE + sub.replace("64", "2048") + mirror, "more than a reply holds")
    refuses("two subscriptions of one key", SAMPLE + sub + sub, "declared twice")
    expect("a subscription and a queryable of one key are not a duplicate",
           problems(SAMPLE + sub + mirror) == [])
    refuses("a limit stated below what the entities need",
            SAMPLE.replace("MAX_QUERYABLES = 2", "MAX_QUERYABLES = 2\nMAX_SUBSCRIPTIONS = 1") + sub
            + '\n[[entity]]\nkind = "subscriber"\nkey = "lab/in/b"\nsample_bytes = 4\n',
            "states MAX_SUBSCRIPTIONS = 1")
    refuses("a kind outside the vocabulary", SAMPLE.replace('kind = "queryable"', 'kind = "queryble"'),
            "not one of publisher")
    refuses("a locator with no scheme", SAMPLE.replace("tcp/10.0.0.1:7447", "10.0.0.1:7447"), "locator")
    refuses("a scheme the target does not dial", SAMPLE.replace("tcp/", "quic/"), "scheme `quic`")
    refuses("an octet above 255", SAMPLE.replace("10.0.0.1", "10.0.0.256"), "octet above 255")
    refuses("port zero", SAMPLE.replace(":7447", ":0"), "port outside")
    refuses("a second endpoint", SAMPLE + '\n[[endpoint]]\nrole = "dial"\nlocator = "tcp/10.0.0.2:7447"\n',
            "more than 1 `dial`")
    refuses("no endpoint", SAMPLE.replace('[[endpoint]]\nrole = "dial"\nlocator = "tcp/10.0.0.1:7447"\n', ""),
            "no endpoint")
    # Decision D7, the third transport: the peers a build declares and holds by their zid.
    peer = '\n[[endpoint]]\nrole = "peer"\nzid = "a1b2c3"\nlocator = "tls/10.0.0.9:7447"\n'
    expect("a declared peer is a valid declaration", problems(SAMPLE + peer) == [])
    peered = emit("n", wz_config.read_decl_toml(SAMPLE + peer), sha)
    expect("a peer is generated as its zid's sixteen bytes (the u128's little-endian) and its locator",
           "pub const PEERS: usize = 1;" in peered
           and 'pub const PEER_NODES: [([u8; 16], &str); 1] = [([195, 178, 161, 0, 0, 0, 0, 0, 0, 0, 0, 0, '
           '0, 0, 0, 0], "tls/10.0.0.9:7447")];' in peered)
    expect("a peer holds a session of its own", "pub const SESSIONS: usize = DIALS + PEERS + ACCEPTS;" in peered)
    expect("a peer is secure whatever the router is", "pub const TLS: bool = true;" in peered)
    expect("a node with no peer declares none", "pub const PEERS: usize = 0;" in rs
           and "pub const PEER_NODES: [([u8; 16], &str); 0] = [];" in rs)
    expect("a peer is built with the secure channel", "tls" in features_of(wz_config.read_decl_toml(SAMPLE + peer)))
    expect("a peer raises the budget of nodes held by their zid when none is stated",
           "WZ_LIMIT_MAX_PEER_NODES=1" in env_lines(wz_config.read_decl_toml(SAMPLE + peer), decl))
    refuses("a peer named by a zid with a leading zero", SAMPLE + peer.replace("a1b2c3", "0a1b2c3"), "lowercase hex")
    refuses("a peer named by an uppercase zid", SAMPLE + peer.replace("a1b2c3", "A1B2C3"), "lowercase hex")
    refuses("a peer with no zid", SAMPLE + peer.replace('zid = "a1b2c3"\n', ""), "lowercase hex")
    refuses("a peer over a stream with no secure channel", SAMPLE + peer.replace("tls/", "tcp/"), "dialled over `tls`")
    refuses("a zid declared twice", SAMPLE + peer + peer, "declared twice")
    refuses("a zid on a router", SAMPLE.replace('role = "dial"', 'role = "dial"\nzid = "a1"'), "only a `peer`")
    refuses("more peers than the declaration's own budget",
            SAMPLE.replace("MAX_QUERYABLES = 2", "MAX_QUERYABLES = 2\nMAX_PEER_NODES = 1")
            + peer + peer.replace("a1b2c3", "d4e5f6"), "MAX_PEER_NODES is 1")
    refuses("a key with an empty chunk", SAMPLE.replace("lab/doc/a", "lab//a"), "empty chunk")
    refuses("a key with a space", SAMPLE.replace("lab/doc/a", "lab doc"), "character a key expression does not")
    refuses("a key longer than the limit", SAMPLE.replace("lab/doc/a", "k" * 300), "MAX_KEYEXPR_BYTES")
    expect("the image's own budget is the baseline, read from its cargo config",
           image_limits(TARGETS["slot"])["MAX_KEYEXPR_BYTES"] == 64)
    refuses("a key over the image's budget, which is below the registry's default",
            SAMPLE.replace("lab/doc/a", "k" * 65), "MAX_KEYEXPR_BYTES (64)")
    expect("a node that states a larger budget holds that key",
           problems(SAMPLE.replace("lab/doc/a", "k" * 65).replace("MAX_QUERYABLES = 2", "MAX_QUERYABLES = 2\nMAX_KEYEXPR_BYTES = 128"))
           == [])
    refuses("a duplicate key", SAMPLE +'\n[[entity]]\nkind = "queryable"\nkey = "lab/doc/a"\ndocument_bytes = 1\n',
            "declared twice")
    refuses("a document above the node's storage", SAMPLE.replace("512", "4097"), "document_bytes")
    refuses("more queryables than the registry holds",
            SAMPLE + '\n[[entity]]\nkind = "queryable"\nkey = "lab/b"\ndocument_bytes = 1\n'
            '\n[[entity]]\nkind = "queryable"\nkey = "lab/c"\ndocument_bytes = 1\n', "MAX_QUERYABLES")
    refuses("a budget no limit has", SAMPLE.replace("MAX_QUERYABLES = 2", "MAX_NOTHING = 2"), "not a limit")
    refuses("a budget of zero", SAMPLE.replace("MAX_QUERYABLES = 2", "MAX_QUERYABLES = 0"), "positive integer")
    refuses("a key the table does not have", SAMPLE.replace('help = "A node."', 'help = "A node."\ncolour = "red"'),
            "not a key of [node]")
    refuses("a table the declaration does not have", SAMPLE + "\n[extra]\nx = 1\n", "not a table")
    refuses("a policy no catalogue has", SAMPLE + '\n[policy]\nno-such-policy = "on"\n', "not a policy")
    refuses("a bool policy that is not on or off",
            SAMPLE + '\n[policy]\ndeclaration-sync-pacing = "yes"\n', "one of on, off")
    refuses("a bool policy stated as a number",
            SAMPLE + "\n[policy]\ndeclaration-sync-pacing = 1\n", "one of on, off")
    refuses("a choice policy outside its choices",
            SAMPLE + '\n[policy]\nmulticast-loopback = "sometimes"\n', "one of os-default, on, off")
    expect("a bool policy and a choice policy state their values",
           problems(SAMPLE + '\n[policy]\ndeclaration-sync-pacing = "on"\nmulticast-loopback = "off"\n') == [])

    # A node that states a closed key set carries its table, and is held to what the table can carry;
    # one that does not has no key set module and is held to nothing new.
    closed = SAMPLE + '\n[policy]\nkey-set = "closed"\n'
    expect("a node that states a closed key set is valid", problems(closed) == [])
    closed_rs = emit("n", wz_config.read_decl_toml(closed), sha)
    expect("it carries its table, and `CLOSED` is `Some` of it",
           "pub const CATALOGUE: KeyCatalogue<'static>" in closed_rs
           and "pub const CLOSED: Option<&'static KeyCatalogue<'static>> = Some(&CATALOGUE);" in closed_rs
           and '"lab/doc/a",' in closed_rs)
    expect("a node that states none has no key set module at all, so it compiles without the feature",
           "key_set" not in rs and "CATALOGUE" not in rs and "CLOSED" not in rs)
    refuses("a closed node's key that is not canonical",
            closed.replace("lab/doc/a", "lab/**/*"), "key set: ")
    refuses("a closed node's wildcard that nothing concrete meets",
            closed.replace("lab/doc/a", "lab/doc/*"), "no concrete key")
    expect("the same keys in an open node are not held to it",
           problems(SAMPLE.replace("lab/doc/a", "lab/doc/*")) == [])

    # An allowance: what a peer the node declares may publish, over its closed key set.
    allow = '\n[[allow]]\npeer = "a1b2c3"\nops = ["publish"]\nkeys = ["lab/doc/a"]\n'
    expect("a closed node may allow a peer it declares", problems(closed + peer + allow) == [])
    allowed_rs = emit("n", wz_config.read_decl_toml(closed + peer + allow), sha)
    expect("its table carries the allowance, and `ALLOWED_PEERS` is `Some` of it",
           "pub const PEER_ALLOWANCE" in allowed_rs and "Some(&PEER_ALLOWANCE)" in allowed_rs)
    expect("a closed node with no allowance has `ALLOWED_PEERS = None`",
           "ALLOWED_PEERS" in closed_rs and "PEER_ALLOWANCE" not in closed_rs)
    refuses("an allowance for a peer the node does not declare", closed + allow, "not a peer endpoint")
    refuses("an allowance in a node that states no closed key set", SAMPLE + peer + allow, "over a closed key set")
    refuses("an allowance of a key nothing concrete meets",
            closed + peer + allow.replace("lab/doc/a", "zzz/**"), "allows nothing")
    refuses("no help", SAMPLE.replace('help = "A node."\n', ""), "help is missing")
    refuses("no node table", "schema = 1\n[limits]\nMAX_QUERYABLES = 2\n", "no [node] table")
    refuses("a declaration that states no schema", SAMPLE.replace("schema = 1\n", ""), "schema is None")
    refuses("a declaration of a schema this reader does not know", SAMPLE.replace("schema = 1", "schema = 2"),
            "schema is 2")

    # The generated copy is held to the declaration: missing, stale and stray are each a finding.
    with tempfile.TemporaryDirectory(prefix="wz-node-") as tmp:
        directory = pathlib.Path(tmp)
        (directory / "n.toml").write_text(SAMPLE, encoding="utf-8")
        expect("a declaration with no generated file fails the check", check(decl, directory) == 1)
        expect("writing generates the file", write(decl, directory) == 0)
        expect("the generated file is current", check(decl, directory) == 0)
        generated_path("n", directory).write_text("// edited by hand\n", encoding="utf-8")
        expect("a hand-edited generated file is stale", check(decl, directory) == 1)
        write(decl, directory)
        view = resolve("n", decl, directory)
        expect("a node resolves to the digest of its file", view["declaration_sha256"] == digest("n", directory))
        expect("a tcp node is built with the declared feature alone and asks for a tcp socket",
               view["features"] == ["declared"] and view["facilities"] == ["sockets-tcp"])
        expect("a stated budget is the environment of the build", view["limits"] == {"WZ_LIMIT_MAX_QUERYABLES": "2"})
        expect("a node that states no policy is built with upstream's", view["policies"] == {})
        (directory / "n.toml").write_text(
            SAMPLE + '\n[policy]\nmulticast-loopback = "off"\ndeclaration-sync-pacing = "on"\n',
            encoding="utf-8",
        )
        write(decl, directory)
        expect("a stated policy is the environment of the build, in the catalogue's order",
               list(resolve("n", decl, directory)["policies"].items())
               == [("WZ_POLICY_MULTICAST_LOOPBACK", "off"), ("WZ_POLICY_DECLARATION_SYNC_PACING", "on")])
        (directory / "n.toml").write_text(SAMPLE, encoding="utf-8")
        write(decl, directory)
        (directory / "n.toml").write_text(SAMPLE.replace("tcp/", "tls/"), encoding="utf-8")
        try:
            resolve("n", decl, directory)
        except ValueError as err:
            expect("an edited declaration is stale until it is generated again", "stale" in str(err))
        else:
            raise AssertionError("an edited declaration resolved against its old generated file")
        write(decl, directory)
        tls = resolve("n", decl, directory)
        expect("a tls node adds the tls feature and still asks only for a stream socket",
               tls["features"] == ["declared", "tls"] and tls["facilities"] == ["sockets-tcp"])
        (directory / "n.toml").write_text(SAMPLE.replace("tcp/", "udp/"), encoding="utf-8")
        write(decl, directory)
        expect("a udp node asks for a datagram socket", resolve("n", decl, directory)["facilities"] == ["sockets-udp"])
        (directory / "n.toml").write_text(SAMPLE, encoding="utf-8")
        write(decl, directory)
        (directory / "generated" / "gone.rs").write_text("", encoding="utf-8")
        expect("a generated file with no declaration is a finding", check(decl, directory) == 1)
        (directory / "generated" / "gone.rs").unlink()
        (directory / "n.toml").write_text(SAMPLE.replace('"slot"', '"heap"'), encoding="utf-8")
        before = generated_path("n", directory).read_text(encoding="utf-8")
        expect("a declaration that does not validate is not written", write(decl, directory) == 1)
        expect("and leaves the file as it was", generated_path("n", directory).read_text(encoding="utf-8") == before)

    # Every registered declaration validates and its tracked file is current.
    expect("every registered declaration validates and is current", check(decl) == 0)

    # The vocabulary a consumer reads is what the validator holds: every integer of every word the
    # target builds is accepted at the bound the vocabulary states and refused, by its name, one past.
    vocab = vocabulary("slot", decl)
    expect("the vocabulary states its own shape's number, this reader's schema and its target",
           vocab["vocabulary_schema"] == VOCABULARY_SCHEMA and vocab["schema"] == DECLARATION_SCHEMA
           and vocab["target"] == "slot")
    # The number names the shape it states: a shape-2 field is what each new field of shape 2 is.
    expect("the shape the vocabulary_schema names is the one printed",
           VOCABULARY_SCHEMA == 2
           and all(isinstance(group, list) for e in vocab["entities"].values() for group in e.get("one_of", []))
           and vocab["entities"]["publisher"]["keys"]["arrivals"]["value"] == "word"
           and vocab["entities"]["publisher"]["keys"]["rate_per_s"]["value"] == "rate"
           and "with" in vocab["entities"]["publisher"]["keys"]["seed"]
           and "group_refused_keys" in vocab["entities"]["publisher"])
    head = 'schema = 1\n\n[node]\nid = "n"\nhelp = "A node."\ntarget = "slot"\n'
    dial = '\n[[endpoint]]\nrole = "dial"\nlocator = "tcp/10.0.0.1:7447"\n'

    def toml_item(table: str, values: dict) -> str:
        return f"\n[[{table}]]\n" + "".join(
            f"{k} = {v!r}\n".replace("'", '"') if isinstance(v, str) else f"{k} = {v}\n" for k, v in values.items())

    def at_least(spec: dict, kind: str) -> object:
        return {"integer": spec.get("min"), "key": f"lab/v/{kind}", "key-expression": f"lab/v/{kind}",
                "word": spec.get("default"), "rate": "1", "decimal": "1", "text": "t", "hex": "00",
                "replay-key": "lab/v/replay"}[spec["value"]]

    def stating(entry: dict, item: dict, key: str, value: object) -> dict:
        """`item` with `key` stated as `value`: the other keys of its `one_of` group left out, and
        what its `with` condition names stated so that it holds."""
        groups = [g for g in entry.get("one_of", []) if key in g]
        out = {k: v for k, v in item.items() if not any(k in g and k != key for g in groups)}
        condition = entry["keys"][key].get("with")
        if condition is not None and not holds(out, entry["keys"], condition):
            need = condition["key"]
            wanted = condition["in"][0] if "in" in condition else condition.get("value")
            out = stating(entry, out, need, wanted if wanted is not None else at_least(entry["keys"][need], kind))
        return {**out, key: value}

    # A replay holds a sample, and a sample belongs to a replay: each word is judged beside the least
    # of the other, so the arms below judge one word at a time.
    least_sample = toml_item("sample", {"replay": "lab/v/replay", "text": "t"})
    least_replay = toml_item("entity", {"kind": "replay", "key": "lab/v/replay"})

    def judge_word(kind: str, entry: dict, render) -> None:
        """Hold one word of the vocabulary to the validator: its least valid, each condition, word,
        rate and integer bound accepted where the vocabulary says and refused by name past it."""
        base = {k: at_least(s, kind) for k, s in entry["keys"].items() if s["required"] and "with" not in s}
        base = {"kind": kind, **base} if kind != "sample" else base
        for group in entry.get("one_of", []):
            base = stating(entry, base, group[0], at_least(entry["keys"][group[0]], kind))
        expect(f"a {kind} with the keys the vocabulary requires, at their least, is valid",
               problems(render(base)) == [])
        for key, spec in entry["keys"].items():
            if "with" in spec:
                stray = problems(render({**base, key: at_least(spec, kind)}))
                expect(f"a {kind}'s {key} where its condition does not hold is refused ({stray})",
                       any(f"`{key}` is read only when" in p for p in stray))
            if spec["value"] == "word":
                odd = problems(render(stating(entry, base, key, "odd")))
                expect(f"a {kind}'s {key} outside the vocabulary's words is refused by name ({odd})",
                       any(f"{key} is 'odd', not one of {', '.join(spec['choices'])}" in p for p in odd))
            if spec["value"] in ("decimal", "hex"):
                odd = problems(render(stating(entry, base, key, "1.")))
                expect(f"a {kind}'s {key} that is not one is refused by name ({odd})",
                       any(f"{key} is '1.'" in p for p in odd))
            if spec["value"] == "rate":
                fastest = 10**9 // spec["min_gap_ns"]
                expect(f"the vocabulary's shortest gap of a {kind}'s {key} is a whole rate",
                       rate_gap_ns(str(fastest)) == (spec["min_gap_ns"], None))
                at_max = problems(render(stating(entry, base, key, str(fastest))))
                past = problems(render(stating(entry, base, key, str(fastest + 1))))
                expect(f"a {kind}'s {key} at the vocabulary's shortest gap is valid ({at_max})", at_max == [])
                expect(f"a {kind}'s {key} past it is refused by name ({past})",
                       any(f"{key} is '{fastest + 1}'" in p for p in past))
            if spec["value"] != "integer":
                continue
            at_max = problems(render(stating(entry, base, key, spec["max"])))
            past = problems(render(stating(entry, base, key, spec["max"] + 1)))
            expect(f"a {kind}'s {key} at the vocabulary's bound {spec['max']} is valid ({at_max})",
                   not any(f"{key} is" in p for p in at_max))
            expect(f"a {kind}'s {key} one past the vocabulary's bound is refused by name ({past})",
                   any(f"{key} is {spec['max'] + 1}" in p for p in past))
        if kind == "sample":
            return
        foreign = sorted(ENTITY_KEYS - set(entry["keys"]) - {"kind"})
        if foreign:
            expect(f"a key the vocabulary does not give a {kind} is refused",
                   any(f"has no `{foreign[0]}`" in p for p in problems(render({**base, foreign[0]: 1}))))

    for kind, entry in vocab["entities"].items():
        expect(f"the slot target builds a {kind}", entry["built"])
        sample_of = (lambda item: toml_item("sample", {"replay": item["key"], "text": "t"})) \
            if kind == "replay" else (lambda item: "")
        judge_word(kind, entry, lambda item, tail=sample_of: head + dial + toml_item("entity", item) + tail(item))
    judge_word("sample", vocab["samples"], lambda item: head + dial + least_replay + toml_item("sample", item))
    expect("the least sample and the least replay are each other's",
           problems(head + dial + least_replay + least_sample) == [])
    endpoint_base = {"listen": {"role": "listen", "locator": "tcp/127.0.0.1:7500"},
                     "multicast": {"role": "multicast", "locator": "udp/224.0.0.224:7490"}}
    for role, base in endpoint_base.items():
        entry = vocab["endpoints"][role]
        base = {**base, **{k: s["min"] for k, s in entry["keys"].items() if s["value"] == "integer" and s["required"]}}
        expect(f"a {role} endpoint with the integers the vocabulary requires, at their least, is valid",
               problems(head + toml_item("endpoint", base)) == [])
        for key, spec in entry["keys"].items():
            if spec["value"] != "integer":
                continue
            at_max = problems(head + toml_item("endpoint", {**base, key: spec["max"]}))
            past = problems(head + toml_item("endpoint", {**base, key: spec["max"] + 1}))
            expect(f"a {role} endpoint's {key} at the vocabulary's bound is valid ({at_max})",
                   not any(f"{key} is" in p for p in at_max))
            expect(f"a {role} endpoint's {key} one past the bound is refused by name ({past})",
                   any(f"{key} is {spec['max'] + 1}" in p for p in past))
    expect("the vocabulary's listener schemes are the ones a listener is accepted over",
           vocab["endpoints"]["listen"]["schemes"] == ["tcp"]
           and any("listener is not built" in p for p in problems(
               head + toml_item("endpoint", {"role": "listen", "locator": "udp/127.0.0.1:7500", "accepts": 1}))))
    expect("the vocabulary names the budgets and their values when a node states none",
           vocab["entities"]["queryable"]["count"]["limit"] == "MAX_QUERYABLES"
           and vocab["limits"]["MAX_QUERYABLES"] == vocab["entities"]["queryable"]["count"]["default"])

    # A declaration given as a file is the registry's twin: the same declaration copied out of the
    # registry resolves to the same node, its generated constants are the tracked file's bytes, and
    # it is identified by the digest of what was read.
    with tempfile.TemporaryDirectory(prefix="wz-node-file-") as work:
        outside = pathlib.Path(work) / "decl"
        build = pathlib.Path(work) / "build"
        outside.mkdir()
        build.mkdir()
        registered = resolve("slot-answerer", decl)
        copy = outside / "slot-answerer.toml"
        copy.write_bytes((NODES / "slot-answerer.toml").read_bytes())
        given = resolve_file(copy, decl, build)
        expect("a registered declaration given as a file resolves to the same node",
               {k: v for k, v in given.items() if k != "generated"}
               == {k: v for k, v in registered.items() if k != "generated"})
        expect("and generates the tracked file's bytes into the build's directory",
               given["generated"].parent == build
               and given["generated"].read_bytes() == registered["generated"].read_bytes())
        expect("the digest is of the bytes the package carries",
               given["declaration_sha256"] == hashlib.sha256(given["source"]).hexdigest())
        misnamed = outside / "other.toml"
        misnamed.write_bytes(copy.read_bytes())
        try:
            resolve_file(misnamed, decl, build)
        except ValueError as err:
            expect(f"a file whose name is not its node's id is refused ({err})", "the file is named" in str(err))
        else:
            expect("a file whose name is not its node's id is refused", False)
        broken = outside / "n.toml"
        broken.write_text("schema = 1\n[node\n")
        try:
            read_file(broken, decl)
        except ValueError as err:
            expect(f"a file that is not TOML is refused as such ({err})", "not a TOML declaration" in str(err))
        else:
            expect("a file that is not TOML is refused", False)
    print("wz-node: selftest OK")
    return 0


def main(argv: list[str]) -> int:
    if argv == ["--selftest"]:
        try:
            return _selftest()
        except AssertionError as err:
            print(f"wz-node: FAIL -- {err}", file=sys.stderr)
            return 1
    decl = wz_config.load_decl()
    if argv == ["--check"]:
        return check(decl)
    if argv == ["--write"]:
        return write(decl)
    if len(argv) == 2 and argv[0] == "--validate":
        try:
            name, data, blob = read_file(pathlib.Path(argv[1]), decl)
        except (ValueError, OSError) as err:
            print(f"wz-node: REFUSED -- {err}", file=sys.stderr)
            return 1
        print(f"wz-node: {name} is a valid {data['node']['target']} node (declaration "
              f"{hashlib.sha256(blob).hexdigest()})")
        return 0
    if len(argv) == 2 and argv[0] == "--vocabulary":
        if argv[1] not in TARGETS:
            print(f"wz-node: no target `{argv[1]}` (known: {', '.join(sorted(TARGETS))})", file=sys.stderr)
            return 2
        print(json.dumps(vocabulary(argv[1], decl), indent=2))
        return 0
    if len(argv) == 2 and argv[0] in ("--emit", "--env"):
        try:
            data = load(argv[1], decl)
        except (ValueError, OSError) as err:
            print(f"wz-node: REFUSED -- {err}", file=sys.stderr)
            return 1
        print(
            emit(argv[1], data, digest(argv[1]))
            if argv[0] == "--emit"
            else "\n".join(env_lines(data, decl) + policy_lines(data, decl))
        )
        return 0
    print(__doc__, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
