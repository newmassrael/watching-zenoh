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
                               at once; a node that listens presents itself to them as a peer)
    [[entity]]               kind = "queryable", key, and document_bytes (a fixed document) or
                               from = "<subscriber key>" (the latest sample of that subscription);
                               kind = "subscriber", key, sample_bytes (the payload bytes it keeps);
                               kind = "publisher", key, period_ms, document_bytes (the document it
                               puts on that key every period);
                               kind = "querier", key, period_ms, timeout_ms, reply_bytes (it asks
                               that key every period and keeps the latest reply; a queryable's
                               from may name its key);
                               kind = "liveliness-token", key (a literal, declared on every
                               session and kept by the router for as long as it lasts)
    [limits]                   <LIMIT_ID> = <integer>, any limit `deploy/wz-config.toml` declares

## What it refuses, and why that is an exit and not a skip

The vocabulary is wider than any one target can build: a declaration may name a listening endpoint
over a scheme a target has no listener for, a multicast group, a publisher, a subscriber, a
liveliness token or a querier. A target states which
of those it builds (`TARGETS`), and a word it does not build is REFUSED with the target's reason,
never dropped: a node that silently lost its subscriber would run and be wrong. A word outside the
vocabulary is refused as a typo. A budget the target cannot give, a key longer than the key limit,
more queryables than the registry holds and a document longer than the node's storage are refused
by name.

## What it does not do

It does not build the node: `wz_package.py --node ID` does (section 5b), through `resolve`, which
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
import pathlib
import re
import sys
import tempfile

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import wz_config  # noqa: E402

ROOT = pathlib.Path(__file__).resolve().parents[2]
NODES = ROOT / "deploy" / "nodes"

# The words a declaration may use. A word outside these is a typo; one inside them that a target does
# not build is a refusal with the target's own reason.
ENDPOINT_ROLES = ("dial", "listen", "multicast")
ENTITY_KINDS = ("publisher", "subscriber", "queryable", "querier", "liveliness-token")
NODE_KEYS = {"id", "help", "target"}
ENDPOINT_KEYS = {"role", "locator", "accepts"}
ENTITY_KEYS = {"kind", "key", "document_bytes", "sample_bytes", "from", "period_ms", "timeout_ms", "reply_bytes"}
TOP_KEYS = {"node", "endpoint", "entity", "limits"}

# What each target builds. `slot` is the per-session fixed-memory profile of the cooperative runtime:
# one dialled session, no allocator, queries answered from documents that are prefixes of one static.
TARGETS = {
    "slot": {
        # The package the node is built in, whose cargo config states the budgets it holds.
        "image": "deploy/host-slot-node",
        # The endpoints of each role a node holds: the one router it dials (the connect manager's
        # row, `MAX_STATIC_CONNECT`) and the one port it listens on. The sessions of the node are
        # the dialled one and `accepts` more, which is the size of its session table.
        "endpoint_limits": {"dial": 1, "listen": 1},
        "schemes": ("tcp", "udp", "tls"),
        # A listener is a stream's: a `tcp/` connection is a link the moment it is accepted, with no
        # handshake of the transport's own to read first.
        "listen_schemes": ("tcp",),
        # The sessions a peer opened that the node holds at once; each is a session slot, a pump
        # cell and a task cell of the node's tables, and a pair of link buffers.
        "max_accepts": 4,
        "entity_kinds": {"queryable", "subscriber", "publisher", "querier", "liveliness-token"},
        # `DOC_MAX` of the same file: the static every document is a prefix of.
        "document_max": 4096,
        # The bytes of a payload a subscription keeps (`LatestCells` of `wz_session_mcu::latest`).
        "sample_max": 4096,
        # What a publisher puts: one document, at most what a frame carries with room to spare, and
        # the schedules of at most `max_publishers` in the session's task cell.
        "publish_max": 1024,
        "max_publishers": 4,
        # A querier keeps its latest reply in a cell, so it is held to the cell's size (`sample_max`),
        # and its schedule is in the same task cell.
        "max_queriers": 4,
        "timeout_max": 60_000,
        "period_max": 3_600_000,
        # A token is only a declaration, so the bound is what the declarations of a session establishing
        # can carry: a node of four tokens and a document is what the witness runs, and every one of
        # the five is seen by the router (`wz_declared_token_zenohd_interop.rs`).
        "max_tokens": 4,
        "refused": {
            "multicast": "the multicast group session has a slot table but no node that joins "
            "one yet",
        },
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


def key_problem(key: str, limit: int) -> str | None:
    """Why `key` is not a key expression a node can declare, or None."""
    if not key:
        return "is empty"
    if len(key.encode("utf-8")) > limit:
        return f"is longer than MAX_KEYEXPR_BYTES ({limit})"
    if key.startswith("/") or key.endswith("/") or "//" in key:
        return "has an empty chunk"
    if any(c in key for c in "?#") or any(ord(c) < 0x21 or ord(c) == 0x7F for c in key):
        return "has a character a key expression does not (`?`, `#`, a space or a control)"
    return None


def validate(name: str, data: dict, decl: dict) -> list[str]:
    """Every reason `data` (the file `name`, read) is not a node its target can build."""
    out = []
    for extra in sorted(set(data) - TOP_KEYS):
        out.append(f"`{extra}` is not a table a node declaration has")
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

    endpoints = data.get("endpoint", [])
    if not endpoints:
        out.append("a node with no endpoint neither reaches anything nor is reached: declare one [[endpoint]]")
    held: dict[str, int] = {}
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
        accepts = ep.get("accepts")
        if role == "listen":
            if isinstance(accepts, bool) or not isinstance(accepts, int) or not 1 <= accepts <= target["max_accepts"]:
                out.append(f"{who}: accepts is {accepts!r}, not an integer from 1 to {target['max_accepts']}")
        elif "accepts" in ep:
            out.append(f"{who}: only a `listen` endpoint has `accepts`")
        match = LOCATOR_RE.fullmatch(ep.get("locator", "")) if isinstance(ep.get("locator"), str) else None
        if match is None:
            out.append(f"{who}: locator {ep.get('locator')!r} is not <scheme>/<a.b.c.d>:<port>")
        else:
            if match["scheme"] not in target["schemes"]:
                out.append(f"{who}: scheme `{match['scheme']}` is not one of {', '.join(target['schemes'])}")
            elif role == "listen" and match["scheme"] not in target["listen_schemes"]:
                out.append(f"{who}: a `{match['scheme']}` listener is not built on {node['target']}: "
                           f"{target['listen_refused'][match['scheme']]}")
            if any(int(match[o]) > 255 for o in "abcd") or not 1 <= int(match["port"]) <= 65535:
                out.append(f"{who}: locator {ep['locator']!r} has an octet above 255 or a port outside 1..65535")

    seen: dict[str, set[str]] = {"queryable": set(), "subscriber": set(), "publisher": set(),
                                 "querier": set(), "liveliness-token": set()}
    sample_sizes: dict[str, int] = {}
    mirrors: list[tuple[str, object]] = []
    queryables = subscribers = publishers = queriers = tokens = 0
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
        tokens += kind == "liveliness-token"
        queryables += kind == "queryable"
        subscribers += kind == "subscriber"
        publishers += kind == "publisher"
        queriers += kind == "querier"
        if kind not in ("publisher", "querier") and "period_ms" in ent:
            out.append(f"{who}: only a publisher or a querier has a `period_ms`")
        for extra in ("timeout_ms", "reply_bytes"):
            if kind != "querier" and extra in ent:
                out.append(f"{who}: only a querier has `{extra}`")
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
        if kind == "subscriber":
            for extra in ("document_bytes", "from"):
                if extra in ent:
                    out.append(f"{who}: a subscriber keeps what it receives and has no `{extra}`")
            size = ent.get("sample_bytes")
            if isinstance(size, bool) or not isinstance(size, int) or not 1 <= size <= target["sample_max"]:
                out.append(f"{who}: sample_bytes is {size!r}, not an integer from 1 to {target['sample_max']}")
            elif isinstance(key, str):
                sample_sizes[key] = size
            continue
        if kind == "liveliness-token":
            for extra in ("document_bytes", "sample_bytes", "from"):
                if extra in ent:
                    out.append(f"{who}: a liveliness token is only its key and has no `{extra}`")
            if isinstance(key, str) and ("*" in key or "$" in key):
                out.append(f"{who}: a token is the liveliness of one key, and {key!r} is a pattern (`*` or `$`)")
            continue
        if kind == "publisher":
            for extra in ("sample_bytes", "from"):
                if extra in ent:
                    out.append(f"{who}: a publisher puts a document of its own and has no `{extra}`")
            if isinstance(key, str) and ("*" in key or "$" in key):
                out.append(f"{who}: a publisher puts on one key, and {key!r} is a pattern (`*` or `$`)")
            period = ent.get("period_ms")
            if isinstance(period, bool) or not isinstance(period, int) or not 1 <= period <= target["period_max"]:
                out.append(f"{who}: period_ms is {period!r}, not an integer from 1 to {target['period_max']}")
            size = ent.get("document_bytes")
            if isinstance(size, bool) or not isinstance(size, int) or not 0 <= size <= target["publish_max"]:
                out.append(f"{who}: document_bytes is {size!r}, not an integer from 0 to {target['publish_max']}")
            continue
        if kind == "querier":
            for extra in ("document_bytes", "sample_bytes", "from"):
                if extra in ent:
                    out.append(f"{who}: a querier asks and keeps what comes back and has no `{extra}`")
            for name, low, high in (("period_ms", 1, target["period_max"]),
                                    ("timeout_ms", 1, target["timeout_max"]),
                                    ("reply_bytes", 1, target["sample_max"])):
                value = ent.get(name)
                if isinstance(value, bool) or not isinstance(value, int) or not low <= value <= high:
                    out.append(f"{who}: {name} is {value!r}, not an integer from {low} to {high}")
                elif name == "reply_bytes" and isinstance(key, str):
                    sample_sizes[key] = value
            continue
        if "sample_bytes" in ent:
            out.append(f"{who}: a queryable has no `sample_bytes`; the subscription it answers from has")
        if "from" in ent:
            if "document_bytes" in ent:
                out.append(f"{who}: a queryable answers from a subscription (`from`) or from a document "
                           "(`document_bytes`), not both")
            mirrors.append((who, ent["from"]))
            continue
        size = ent.get("document_bytes")
        if isinstance(size, bool) or not isinstance(size, int) or not 0 <= size <= target["document_max"]:
            out.append(f"{who}: document_bytes is {size!r}, not an integer from 0 to {target['document_max']}")
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
    }
    for name, need in needs.items():
        if name not in stated and need > values[name]:
            stated[name] = need
    return dict(sorted(stated.items()))


def rust_string(text: str) -> str:
    return '"' + text.replace("\\", "\\\\").replace('"', '\\"') + '"'


def digest(name: str, directory: pathlib.Path = NODES) -> str:
    """The SHA-256 of the declaration file's bytes, lower-case hex: what a built node says it was
    built from, so a declaration edited after the build is a difference a tool can see."""
    return hashlib.sha256((directory / f"{name}.toml").read_bytes()).hexdigest()


def emit(name: str, data: dict, declaration_sha256: str) -> str:
    """The `declared.rs` the node's code includes. Valid input only: `validate` ran first."""
    dialed = [ep["locator"] for ep in data["endpoint"] if ep["role"] == "dial"]
    dials = ", ".join(rust_string(locator) for locator in dialed)
    listens = [ep for ep in data["endpoint"] if ep["role"] == "listen"]
    listen_at = listens[0]["locator"] if listens else ""
    accepts = listens[0]["accepts"] if listens else 0
    at = LOCATOR_RE.fullmatch(listen_at) if listens else None
    listen_addr = ", ".join(at[o] for o in "abcd") if at else "0, 0, 0, 0"
    listen_port = int(at["port"]) if at else 0
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
    published = [(e["key"], e["period_ms"], e["document_bytes"]) for e in every if e["kind"] == "publisher"]
    pubs = ", ".join(f"({rust_string(k)}, {p}, {b})" for k, p, b in published)
    alive = [e["key"] for e in every if e["kind"] == "liveliness-token"]
    token_keys = ", ".join(rust_string(k) for k in alive)
    return "\n".join(
        [
            f"// {wz_config.SPDX}",
            f"// {wz_config.COPYRIGHT}",
            "",
            f"// GENERATED from deploy/nodes/{name}.toml by scripts/lib/wz_node.py --emit {name}.",
            "// Do not edit: a change is made in the declaration and generated again.",
            "",
            f"pub const NODE_ID: &str = {rust_string(name)};",
            "/// The digest of the declaration file this was generated from; the node's facts note carries it.",
            f"pub const DECLARATION_SHA256: &str = {rust_string(declaration_sha256)};",
            "/// The routers the node dials, as locators.",
            f"pub const DIALS: usize = {len(dialed)};",
            f"pub const DIALED: [&str; {len(dialed)}] = [{dials}];",
            "/// Whether a dialled endpoint is `tls/`, which the node's `tls` feature must be built for.",
            f"pub const TLS: bool = {'true' if any(d.startswith('tls/') for d in dialed) else 'false'};",
            "/// Whether the node listens, the locator it listens on (empty when it does not), the address",
            "/// and port that locator names, and how many sessions a peer opened it holds at once.",
            f"pub const LISTENS: bool = {'true' if listens else 'false'};",
            f"pub const LISTEN: &str = {rust_string(listen_at)};",
            f"pub const LISTEN_ADDR: [u8; 4] = [{listen_addr}];",
            f"pub const LISTEN_PORT: u16 = {listen_port};",
            f"pub const ACCEPTS: usize = {accepts};",
            "/// The sessions the node holds at most: the ones it dials and the ones a peer opened.",
            "pub const SESSIONS: usize = DIALS + ACCEPTS;",
            "/// The queryables the node declares, and the documents they answer with: (key, bytes).",
            f"pub const DOCS: usize = {len(entities)};",
            f"pub const DOCUMENTS: [(&str, usize); {len(entities)}] = [{docs}];",
            "/// The subscriptions the node declares, and the bytes of a payload each keeps: (key, bytes).",
            f"pub const SUBSCRIBERS: usize = {len(subscribed)};",
            f"pub const SUBSCRIPTIONS: [(&str, usize); {len(subscribed)}] = [{cells}];",
            "/// The queriers the node runs: (key, the period and the timeout in milliseconds, the bytes of a",
            "/// reply each keeps).",
            "/// The liveliness tokens the node declares on every session, by key.",
            f"pub const TOKENS: usize = {len(alive)};",
            f"pub const TOKEN_KEYS: [&str; {len(alive)}] = [{token_keys}];",
            f"pub const QUERIERS: usize = {len(queried)};",
            f"pub const QUERIED: [(&str, u32, u32, usize); {len(queried)}] = [{asks}];",
            "/// The cells that keep a latest value: the subscriptions' and then the queriers'.",
            f"pub const CELLS: usize = {len(subscribed) + len(queried)};",
            "/// The most bytes any cell keeps: the size of every cell the node holds.",
            f"pub const SAMPLE_MAX: usize = {max([b for _, b in subscribed] + [b for _, _, _, b in queried], default=1)};",
            "/// The queryables that answer from a cell: (key, index into the cells).",
            f"pub const MIRRORS: usize = {len(mirrored)};",
            f"pub const MIRRORED: [(&str, usize); {len(mirrored)}] = [{mirrors}];",
            "/// The publishers: (key, the period in milliseconds, the bytes of the document it puts).",
            f"pub const PUBLISHERS: usize = {len(published)};",
            f"pub const PUBLISHED: [(&str, u32, usize); {len(published)}] = [{pubs}];",
            "",
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


# What a dialled endpoint's scheme asks of the device, by name from the facilities of
# `deploy/wz-config.toml`. `tls` rides a TCP stream, so it asks for the same socket.
SCHEME_FACILITIES = {"tcp": "sockets-tcp", "tls": "sockets-tcp", "udp": "sockets-udp"}


def features_of(data: dict) -> list[str]:
    """The cargo features a node is built with: `declared`, `tls` exactly when a dialled endpoint is
    `tls/` (which the node's own `const` assertion holds again), `get` for a node that asks (and
    only such a node: the layer's queries and the pending table are not in any other), `token` for a
    node that declares a liveliness token and `listen` for a node that has a port to listen on."""
    tls = any(ep["locator"].startswith("tls/") for ep in data["endpoint"] if ep["role"] == "dial")
    asks = any(e["kind"] == "querier" for e in data.get("entity", []))
    alive = any(e["kind"] == "liveliness-token" for e in data.get("entity", []))
    listens = any(ep["role"] == "listen" for ep in data["endpoint"])
    return (["declared"] + (["tls"] if tls else []) + (["get"] if asks else [])
            + (["token"] if alive else []) + (["listen"] if listens else []))


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
    schemes = [LOCATOR_RE.fullmatch(ep["locator"])["scheme"] for ep in data["endpoint"]]
    facilities = sorted({SCHEME_FACILITIES[s] for s in schemes})
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
        "facilities": facilities,
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

SAMPLE = """[node]
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
    expect("the file names its source and says it is generated", "GENERATED from deploy/nodes/n.toml" in rs)
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
           'pub const DIALED: [&str; 1] = ["tcp/10.0.0.1:7447"];' in lrs and "pub const SESSIONS: usize = DIALS + ACCEPTS;" in lrs)
    expect("a node that listens on nothing accepts nothing",
           "pub const LISTENS: bool = false;" in rs and "pub const ACCEPTS: usize = 0;" in rs
           and 'pub const LISTEN: &str = "";' in rs)
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
    refuses("a multicast endpoint", SAMPLE.replace('role = "dial"', 'role = "multicast"'), "not built on slot")
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
    refuses("a token with a period", SAMPLE + tok + "period_ms = 4\n", "only a publisher or a querier has a `period_ms`")
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

    # A publisher puts a document of its own on one key, every period.
    pub = '\n[[entity]]\nkind = "publisher"\nkey = "lab/out/beat"\nperiod_ms = 200\ndocument_bytes = 8\n'
    expect("a publisher is a valid entity", problems(SAMPLE + pub) == [])
    puts = emit("n", wz_config.read_decl_toml(SAMPLE + pub), sha)
    expect("the publisher, its period and its document are generated",
           'pub const PUBLISHED: [(&str, u32, usize); 1] = [("lab/out/beat", 200, 8)];' in puts
           and "pub const PUBLISHERS: usize = 1;" in puts)
    expect("a node with no publisher declares none",
           "pub const PUBLISHERS: usize = 0;" in rs and "pub const PUBLISHED: [(&str, u32, usize); 0] = [];" in rs)
    expect("a publisher decides no budget", budgets(wz_config.read_decl_toml(SAMPLE + pub), decl)
           == budgets(data, decl))
    refuses("a publisher with no period", SAMPLE + pub.replace("period_ms = 200\n", ""), "period_ms is None")
    refuses("a period of zero", SAMPLE + pub.replace("200", "0"), "period_ms is 0")
    refuses("a period above the target's", SAMPLE + pub.replace("200", "3600001"), "period_ms is 3600001")
    refuses("a publisher with no document", SAMPLE + pub.replace("document_bytes = 8\n", ""), "document_bytes is None")
    refuses("a document above what a put carries", SAMPLE + pub.replace("= 8\n", "= 1025\n"), "document_bytes is 1025")
    refuses("a publisher of a pattern", SAMPLE + pub.replace("lab/out/beat", "lab/out/*"), "is a pattern")
    refuses("a publisher of a pattern with $", SAMPLE + pub.replace("lab/out/beat", "lab/out/$*"), "is a pattern")
    refuses("a publisher with a source", SAMPLE + pub + 'from = "lab/in/a"\n', "has no `from`")
    refuses("a publisher with a sample size", SAMPLE + pub + "sample_bytes = 4\n", "has no `sample_bytes`")
    refuses("a period on a queryable", SAMPLE.replace("512", "512\nperiod_ms = 5"),
            "only a publisher or a querier has a `period_ms`")
    refuses("a period on a subscriber", SAMPLE + sub + "period_ms = 5\n",
            "only a publisher or a querier has a `period_ms`")
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
    refuses("no help", SAMPLE.replace('help = "A node."\n', ""), "help is missing")
    refuses("no node table", "[limits]\nMAX_QUERYABLES = 2\n", "no [node] table")

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
    if len(argv) == 2 and argv[0] in ("--emit", "--env"):
        try:
            data = load(argv[1], decl)
        except (ValueError, OSError) as err:
            print(f"wz-node: REFUSED -- {err}", file=sys.stderr)
            return 1
        print(emit(argv[1], data, digest(argv[1])) if argv[0] == "--emit" else "\n".join(env_lines(data, decl)))
        return 0
    print(__doc__, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
