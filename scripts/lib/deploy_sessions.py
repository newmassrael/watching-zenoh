#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
"""R3221 (no register item) -- the `sessions:` list of a deploy machine.

The citation names no item because the request this answers, open-debt item
900, lives in the agent-memory register, which has no store id to resolve.

One program may hold SEVERAL local sessions: a client session towards a router
and a peer session in a multicast group, for one. A machine declares them as a
list, one entry per session, in start order. A machine with no `sessions:` key
is a single-session machine exactly as before, and nothing here reads it.

`scripts/validate-deploy.sh` calls `validate_machine` for every machine of every
`deploy/*.yaml`; a refusal names the key it refuses, as a dotted path from the
top of the document (`machines.mcu_node.sessions[1].group.endpoint`).

## The keys

machines.<m>.zid
    The machine's default zenoh id, which every session inherits. Optional;
    without it (and without a session's own) a session draws a random id.
    Spelled as upstream parses one: lowercase hex, no leading zero, at most 32
    digits, not zero. Upstream refuses uppercase first:
    `commons/zenoh-protocol/src/core/mod.rs` @ `uppercase hexadecimal is not accepted, use lowercase`
    and then hands the text to uhlc 0.8.2's `ID::from_str` (the version its
    lock pins), which refuses an empty string, a leading 0, more than 128
    bits and zero.

machines.<m>.sessions[i]
    name        required; unique within the machine; `[a-z][a-z0-9_]*`.
    mode        required; `client` or `peer`. A multicast session is a peer.
    transport   required; `unicast` or `multicast`. One transport per session.
    link        required; a key of `machines.<m>.links`. One session per link.
    zid         optional; overrides the machine's. Two sessions of one machine
                may share an id ONLY when their transports differ (a unicast
                session and a multicast one); two sessions of the same
                transport with equal ids are refused, naming both.
    connect.endpoints   unicast only; locators this session dials.
    listen.endpoints    unicast only; locators this session accepts on.
    accept.max_sessions unicast only, with `listen`; how many accepted
                sessions it holds at once. On an MCU or Zephyr machine only 1
                is accepted unless the machine declares a `session_pool`: the
                heap profiles' acceptor there holds one accepted session at a
                time and listens again when it ends, while the acceptor of the
                pool profile is one listener over one socket that claims a slot,
                a pump cell and a task cell for each peer before it answers it
                (and answers nothing when one is missing), so it holds as many
                as the pool has slots for. Each claims a slot of the pool (the
                count check below).
    group.endpoint      multicast only, required; `udp/<group>:<port>`, with the
                interface only as the `#iface=<name|addr>` tail, the metadata
                key upstream's UDP multicast locator reads:
                `io/zenoh-links/zenoh-link-udp/src/lib.rs` @ `pub const UDP_MULTICAST_IFACE: &str = "iface";`
                No tail means upstream's default, the first non-loopback
                multicast interface:
                `io/zenoh-links/zenoh-link-udp/src/multicast.rs` @ `.join_multicast_v4(&dst_ip4, &src_ip4)`
                `auto` is not a word on a locator. On an MCU machine
                the tail is honoured only when the session's link declares the
                same `netif:`; lwIP joins on every IGMP interface and cannot be
                told one otherwise, so any other tail is refused.
    group.join_interval_ms, group.lease_ms   multicast only; positive integers.
    limits      a per-session override of `machines.<m>.limits`; every key must
                be one the machine declares.
    buffer_pools  the session's own static pools: `session_rx_pool`,
                `session_tx_pool`, `reassembly_pool`, each `{ ref: <pool> }`
                naming a `sources/**/<pool>.scxml` buffer-pool document, or an
                inline `{ slot_count, slot_size, ... }`. Omitted, the profile's
                default pools stand, ONE INSTANCE PER SESSION: two sessions
                double that SRAM, and the multicast receive pool alone is
                32 x 1536 bytes (its queue holds 31 datagrams).
    heap_budget_bytes   RESERVED and refused. The heap profiles have no
                per-session heap budget: every session allocates from the one
                image heap. The per-session budget's shape is the session's
                static pools above, which is what the fixed-memory profiles
                keep, and on an image with a session table the `session_pool`
                (`max_sessions` x `slot_bytes`) that bounds every session by
                construction. The allocator is not split: a byte cap on a
                shared `#[global_allocator]` cannot be enforced per session
                without a per-session arena, so the key is not built as a cap.

Any other key in a session is refused by name.

## The session pool (Round 3278): how many sessions, and the one RAM number

A fixed-memory machine holds its sessions in a static table of N slots, each
big enough for ONE session whatever its transport. A machine with no
`session_pool:` key is read exactly as above and nothing below applies.

machines.<m>.session_pool
    ref         the SSOT document of the table, a `sources/**/<name>.scxml`
                buffer-pool: its `slot-count` is MAX_SESSIONS and its
                `slot-size` is the byte CEILING of one session slot (the typed
                slot, its link socket and its reassembly staging together).
                SCE emits both as `SLOT_COUNT` / `SLOT_SIZE`, and the numbers
                live ONLY in that document, as every other pool's do.
    max_sessions, slot_bytes
                the inline form of the same two numbers, positive integers,
                for a machine whose document does not exist yet. It is read and
                budgeted here and generates nothing; `ref` and the inline pair
                together are refused.
    process     numbers that belong to no session: `max_tasks`, `max_timers`,
                `admin_reply_bytes`, `admin_locators`, `admin_session_links`,
                `connect_endpoints`, `multicast_replies`, each a positive
                integer. `admin_reply_bytes` is the buffer one
                admin reply is built in; an admin reply is staged as a reply, so
                it may not exceed `limits.reply_payload_bytes` (the machine's,
                nor a session's own, lower one). `connect_endpoints` is the rows
                of the node's connect table, and a session whose
                `connect.endpoints` lists more than that is refused.
                `multicast_replies` is the room of a multicast pump's reply queue.

What the table adds to the checks above:

    count       the sessions the machine declares must fit `max_sessions`; a
                listening session claims `accept.max_sessions` slots and any
                other session one.
    budget      the pools one session takes (`session_rx_pool` and
                `reassembly_pool`, the session's own or else the machine's or
                else the profile's default) may not add up to more than
                `slot_bytes`: they are PART of the slot, so a slot smaller
                than they are cannot hold the session. The table's RAM is
                `max_sessions * slot_bytes`, one number. The typed part is
                `core::mem::size_of` of the slot, which only the compiler can
                say and the consuming crate asserts against the same
                `SLOT_SIZE`; when the pool names a `typed_slot_image` its
                MEASURED bytes are added to the pools, so the budget is
                pools + typed slot <= `slot_bytes`, and a session whose pools
                alone fit is still refused when the slot over them does not.
    placement   the table is `max_sessions * slot_bytes` bytes and its pool names
                a `section` (the document's `<sce:section>`, or an inline pool's
                `section`). When the machine STATES its `memory.sram_regions`, that
                section must be one of them and its `size` must hold the whole
                table. A machine that states no regions is not checked: a focused
                profile inherits its memory block from the profile it is built on
                and this reader sees only the machine's own keys.
    lwip_opts   optional; the path of the `lwipopts.h` the machine's image is built
                with, relative to the repository. It must define
                `MEMP_NUM_UDP_PCB` and the number must be at least `max_sessions +
                1`: each slot is one UDP socket and the listener is one more. The
                number is read from the header and stated nowhere else.
    typed_slot_image  optional; a key of `deploy/session_slot_bytes.json`, the image
                whose typed session slot the report states. The record holds the
                bytes ONE typed slot takes, MEASURED from the size of a probe symbol
                in the built image (`scripts/lib/session_slot_bytes.py`, which holds
                the file equal to a fresh build), so the number is the compiler's and
                never an estimate. The key is refused when the image is not in the
                record or when its measured slot exceeds the ceiling the pool states;
                the report carries the bytes and the headroom, or `null` when the
                machine names no image.
    limits      the machine's `limits` may name only the keys in
                `LIMIT_KEYS`, and a session's own `limits` may only LOWER the
                machine's value: the slot is sized by the machine's number, so
                a larger override would be a table the slot cannot hold.

`deploy_sessions.py --report <deploy.yaml> <machine>` prints the resolved
numbers and every refusal of one machine as JSON (see `session_pool_report`),
which is what an editor of the file shows beside its keys.

## The AP column (`platform.class: ap`)

Open-debt item 900 again: `wz-ap-demo --sessions <file>` starts every session
of such a list in one process, and its reader is judged against this module on
the shared cases in `deploy_sessions_ap_cases.json` (each side checks the same
documents against the same refused key paths). Where an AP runs a session
differently, the rule is stated here, once:

    link        optional. An AP session's link is the socket its own endpoint
                opens, so a machine needs no `links` table; a `link` that is
                given must still name a key of it.
    one link    a unicast session dials OR listens, not both, and listens on
                ONE endpoint; two sessions may not name the same listen or
                group endpoint (the `#` tail aside). Each of those would be a
                second link under one session.
    limits      refused. The AP runtime has no per-session table bound to
                apply one to, so an override would be read and do nothing.
    buffer_pools  refused. An AP session has no pools of its own: link buffers
                are the process's shared link-RX arena.
    session_pool  refused. An AP holds its sessions as tasks over a growable
                heap, so there is no table to size.
"""

from __future__ import annotations

import ipaddress
import json
import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

NAME_RE = re.compile(r"^[a-z][a-z0-9_]*$")
ZID_RE = re.compile(r"^[0-9a-f]+$")
MODES = ("client", "peer")
TRANSPORTS = ("unicast", "multicast")
SESSION_KEYS = frozenset(
    {
        "name",
        "mode",
        "transport",
        "link",
        "zid",
        "connect",
        "listen",
        "accept",
        "group",
        "limits",
        "buffer_pools",
        "heap_budget_bytes",
    }
)
UNICAST_ONLY = ("connect", "listen", "accept")
MULTICAST_ONLY = ("group",)
SESSION_POOLS = frozenset({"session_rx_pool", "session_tx_pool", "reassembly_pool"})
GROUP_KEYS = frozenset({"endpoint", "join_interval_ms", "lease_ms"})

# Round 3278 -- the session pool. Every name below is a key the editor of a
# deploy file offers, so each carries the constant it will set. EXISTING means
# the constant is in the tree today and the key only gives it a number a
# deploy can state; NEW means the limit has no constant yet (it is a growable
# table or an unbounded buffer on the MCU profile today).
POOL_KEYS = frozenset(
    {
        "ref",
        "max_sessions",
        "slot_bytes",
        "process",
        "section",
        "lwip_opts",
        "typed_slot_image",
    }
)
PROCESS_KEYS = frozenset(
    {
        "max_tasks",
        "max_timers",
        # The buffer one admin reply is built in. S9b: EXISTING
        # caps::MAX_ADMIN_REPLY_BYTES; a reply past it is refused, counted and
        # answered as a typed error. An admin reply is staged as a reply, so it may
        # not exceed `limits.reply_payload_bytes` (see session_pool_problems).
        "admin_reply_bytes",
        # S9b: the listening locators a node reports in its admin `local_data`
        # (EXISTING caps::MAX_ADMIN_LOCATORS) and the links one `sessions[]` row
        # lists (EXISTING caps::MAX_ADMIN_SESSION_LINKS).
        "admin_locators",
        "admin_session_links",
        # S9c: the rows of the node's connect table, which holds one row per endpoint
        # a host has written or a session lists in `connect.endpoints` (EXISTING
        # caps::MAX_STATIC_CONNECT). The list a host writes is itself that many rows,
        # so the table is as large as what feeds it.
        "connect_endpoints",
        # S9c: the replies a multicast pump queues for sending between the observer
        # that stages them and the loop that frames them (NEW
        # caps::MAX_MULTICAST_REPLIES); a reply past it is dropped and counted.
        "multicast_replies",
    }
)
LIMIT_KEYS = frozenset(
    {
        # The seven keys every deploy has declared since the first skeleton.
        "peer_table",
        "multicast_peer_table",
        "local_subscriptions",  # EXISTING caps::MAX_SUBSCRIPTIONS
        "local_queryables",  # EXISTING caps::MAX_QUERYABLES
        "pending_queries",  # EXISTING caps::MAX_PENDING_QUERIES
        "in_flight_reassembly",
        "tx_queue",
        # Existing caps that had no key.
        "inbound_sub_interests",  # EXISTING caps::MAX_INBOUND_SUB_INTERESTS
        "pending_declares",  # EXISTING caps::MAX_PENDING_DECLARES
        "keyexpr_bytes",  # EXISTING caps::MAX_KEYEXPR_BYTES
        # Per-session limits with no constant today.
        "tx_lend_slots",  # EXISTING wz-session-lwip driver.rs LENT_MAX (private)
        "peer_keyexpr_aliases",  # NEW: the peer alias table is an unbounded HashMap
        "remote_decls",  # NEW: the remote declaration tables are unbounded HashMaps
        "pending_replies",  # NEW
        "pending_finals",  # NEW
        "reply_payload_bytes",  # NEW
    }
)
# The two pools whose bytes are part of ONE session's slot, and the document
# each takes when neither the session nor the machine names one (the MCU
# profile's defaults, `deploy/mcu_target.yaml`).
SLOT_POOLS = ("session_rx_pool", "reassembly_pool")
DEFAULT_SLOT_POOL_REF = {
    "session_rx_pool": "session_rx_pool_mcu",
    "reassembly_pool": "reassembly_pool_mcu",
}
SCE_NS = "{http://sce.dev/ext}"


def zid_problem(value: object) -> str | None:
    """Why `value` is not a zenoh id upstream would parse, or None."""
    if not isinstance(value, str):
        return "must be a string of lowercase hex digits"
    if not value:
        return "must not be empty"
    if any(c.isupper() for c in value):
        return "uppercase hexadecimal is not accepted, use lowercase"
    if not ZID_RE.match(value):
        return "must be lowercase hex digits only"
    if value.startswith("0"):
        return "leading 0s are not valid"
    if len(value) > 32:
        return "is longer than 16 bytes (32 hex digits)"
    return None


def _positive_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value > 0


def _endpoints(errors: list[str], path: str, block: object) -> list[str]:
    if not isinstance(block, dict):
        errors.append(f"{path}: must be a mapping with an `endpoints` list")
        return []
    extra = sorted(set(block) - {"endpoints"})
    for key in extra:
        errors.append(f"{path}.{key}: unknown key")
    eps = block.get("endpoints")
    if not isinstance(eps, list) or not eps:
        errors.append(f"{path}.endpoints: must be a non-empty list of locators")
        return []
    out = []
    for i, ep in enumerate(eps):
        if not isinstance(ep, str) or "/" not in ep or ep.startswith("/"):
            errors.append(f"{path}.endpoints[{i}]: not a locator (`<proto>/<address>`)")
        else:
            out.append(ep)
    return out


def group_endpoint_problem(text: object, mcu_netif: str | None, is_mcu: bool) -> str | None:
    """Why `text` is not an admissible group endpoint, or None."""
    if not isinstance(text, str):
        return "must be a locator string"
    locator, sep, meta = text.partition("#")
    if not locator.startswith("udp/"):
        return "a group endpoint is `udp/<group>:<port>`"
    addr = locator[len("udp/") :]
    host, colon, port = addr.rpartition(":")
    if not colon or not port.isdigit() or not 0 < int(port) < 65536:
        return "needs a port between 1 and 65535"
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return f"`{host}` is not an IP address"
    if not ip.is_multicast:
        return f"`{host}` is not a multicast group address"
    if not sep:
        return None
    for pair in meta.split(";"):
        key, eq, value = pair.partition("=")
        if key != "iface":
            return f"`#{pair}`: only the `#iface=` tail is admitted on a group endpoint"
        if not eq or not value:
            return "`#iface=` needs a value; leave the tail out for the default interface"
        if value == "auto":
            return "`auto` is not a word on a locator; leave the tail out for the default interface"
        if is_mcu and value != mcu_netif:
            return (
                f"`#iface={value}` cannot be honoured on an MCU: lwIP joins on every "
                "IGMP interface unless the session's link declares the same `netif:`"
            )
    return None


def _pool_problem(repo_root: Path, value: object) -> str | None:
    if not isinstance(value, dict):
        return "must be `{ ref: <pool> }` or an inline `{ slot_count, slot_size, ... }`"
    if "ref" in value:
        ref = value["ref"]
        if set(value) != {"ref"}:
            return "a `ref` pool takes no other key"
        if not isinstance(ref, str) or not NAME_RE.match(ref):
            return "`ref` must name a buffer-pool document"
        if not any((repo_root / "sources").rglob(f"{ref}.scxml")):
            return f"`ref: {ref}` names no `sources/**/{ref}.scxml`"
        return None
    for key in ("slot_count", "slot_size"):
        if not _positive_int(value.get(key)):
            return f"an inline pool needs a positive `{key}`"
    return None


def _validate_zid_and_sessions(
    machine_name: str, machine: dict, repo_root: Path
) -> list[str]:
    """Every refusal for one machine's `zid` and `sessions`; [] when it passes."""
    errors: list[str] = []
    base = f"machines.{machine_name}"
    if "zid" in machine:
        why = zid_problem(machine["zid"])
        if why:
            errors.append(f"{base}.zid: {why}")
    if "sessions" not in machine:
        return errors
    sessions = machine["sessions"]
    if not isinstance(sessions, list) or not sessions:
        errors.append(f"{base}.sessions: must be a non-empty list")
        return errors

    platform = machine.get("platform") or {}
    is_mcu = platform.get("class") == "mcu"
    is_ap = platform.get("class") == "ap"
    single_accept = _single_accept(machine)
    links = machine.get("links") or {}
    machine_limits = machine.get("limits") or {}
    machine_zid = machine.get("zid") if zid_problem(machine.get("zid")) is None else None

    names: dict[str, int] = {}
    link_owner: dict[str, str] = {}
    zid_owner: dict[tuple[str, str], str] = {}
    # AP only: the session that already holds a listen or group endpoint,
    # keyed by the locator without its `#` tail.
    endpoint_owner: dict[str, str] = {}

    def claim_endpoint(at: str, endpoint: object, label: str) -> None:
        if not isinstance(endpoint, str):
            return
        locator = endpoint.partition("#")[0]
        if locator in endpoint_owner:
            errors.append(
                f"{at}: `{locator}` is already the link of {endpoint_owner[locator]}; "
                "one session per link"
            )
        else:
            endpoint_owner[locator] = label

    for i, s in enumerate(sessions):
        path = f"{base}.sessions[{i}]"
        if not isinstance(s, dict):
            errors.append(f"{path}: must be a mapping")
            continue
        for key in sorted(set(s) - SESSION_KEYS):
            errors.append(f"{path}.{key}: unknown key")
        if "heap_budget_bytes" in s:
            errors.append(
                f"{path}.heap_budget_bytes: reserved and not implemented -- the heap "
                "profiles share one image heap and a byte cap per session cannot be "
                "enforced on it. A session's memory is bounded by construction: its "
                "static `buffer_pools`, and on an image with a session table the "
                "`session_pool` (`max_sessions` x `slot_bytes`)"
            )

        name = s.get("name")
        label = path
        if not isinstance(name, str) or not NAME_RE.match(name):
            errors.append(f"{path}.name: required, `[a-z][a-z0-9_]*`")
        elif name in names:
            errors.append(
                f"{path}.name: `{name}` is already the name of sessions[{names[name]}]"
            )
        else:
            names[name] = i
            label = f"{path} (`{name}`)"

        mode = s.get("mode")
        if mode not in MODES:
            errors.append(f"{path}.mode: required, one of {', '.join(MODES)}")
        transport = s.get("transport")
        if transport not in TRANSPORTS:
            errors.append(f"{path}.transport: required, one of {', '.join(TRANSPORTS)}")

        link = s.get("link")
        if is_ap and "link" not in s:
            pass
        elif not isinstance(link, str) or link not in links:
            errors.append(f"{path}.link: required, a key of {base}.links")
        elif link in link_owner:
            errors.append(
                f"{path}.link: `{link}` already carries {link_owner[link]}; "
                "one session per link"
            )
        else:
            link_owner[link] = label

        own_zid = s.get("zid")
        if "zid" in s:
            why = zid_problem(own_zid)
            if why:
                errors.append(f"{path}.zid: {why}")
                own_zid = None
        zid = own_zid if own_zid is not None else machine_zid
        if zid is not None and transport in TRANSPORTS:
            key = (zid, transport)
            if key in zid_owner:
                errors.append(
                    f"{path}.zid: {label} and {zid_owner[key]} are both {transport} "
                    f"sessions with zid {zid}; sessions of one transport need distinct "
                    "ids (only a unicast and a multicast session may share one)"
                )
            else:
                zid_owner[key] = label

        if transport == "unicast":
            for key in MULTICAST_ONLY:
                if key in s:
                    errors.append(f"{path}.{key}: a unicast session has no `{key}`")
            for key in ("connect", "listen"):
                if key in s:
                    _endpoints(errors, f"{path}.{key}", s[key])
            if "connect" not in s and "listen" not in s:
                errors.append(
                    f"{path}.connect: a unicast session needs `connect.endpoints` "
                    "or `listen.endpoints`"
                )
            if is_ap and "connect" in s and "listen" in s:
                errors.append(
                    f"{path}.listen: an AP session holds one link, so it dials or "
                    "it listens; declare a second session for the other"
                )
            elif is_ap and isinstance(s.get("listen"), dict):
                eps = s["listen"].get("endpoints")
                if isinstance(eps, list) and len(eps) > 1:
                    errors.append(
                        f"{path}.listen.endpoints: an AP session listens on one "
                        "endpoint (one link per session)"
                    )
                elif isinstance(eps, list) and eps:
                    claim_endpoint(f"{path}.listen.endpoints[0]", eps[0], label)
            if "accept" in s:
                acc = s["accept"]
                if "listen" not in s:
                    errors.append(f"{path}.accept: only a session that listens accepts")
                if not isinstance(acc, dict):
                    errors.append(f"{path}.accept: must be a mapping")
                else:
                    for key in sorted(set(acc) - {"max_sessions"}):
                        errors.append(f"{path}.accept.{key}: unknown key")
                    n = acc.get("max_sessions")
                    if not _positive_int(n):
                        errors.append(f"{path}.accept.max_sessions: a positive integer")
                    elif single_accept and n != 1:
                        errors.append(
                            f"{path}.accept.max_sessions: {n} is refused on this "
                            "machine; an MCU or Zephyr acceptor holds ONE accepted "
                            "session at a time, so only 1 is accepted, unless the "
                            "machine declares a `session_pool`: the acceptor of "
                            "that profile claims a slot, a pump cell and a task "
                            "cell before it answers a peer, so it can hold several"
                        )
        elif transport == "multicast":
            for key in UNICAST_ONLY:
                if key in s:
                    errors.append(f"{path}.{key}: a multicast session has no `{key}`")
            if mode == "client":
                errors.append(f"{path}.mode: a multicast session is a `peer`")
            group = s.get("group")
            if not isinstance(group, dict):
                errors.append(f"{path}.group: required for a multicast session")
            else:
                for key in sorted(set(group) - GROUP_KEYS):
                    errors.append(f"{path}.group.{key}: unknown key")
                netif = None
                if isinstance(link, str) and isinstance(links.get(link), dict):
                    netif = links[link].get("netif")
                why = group_endpoint_problem(group.get("endpoint"), netif, is_mcu)
                if why:
                    errors.append(f"{path}.group.endpoint: {why}")
                elif is_ap:
                    claim_endpoint(f"{path}.group.endpoint", group.get("endpoint"), label)
                for key in ("join_interval_ms", "lease_ms"):
                    if key in group and not _positive_int(group[key]):
                        errors.append(f"{path}.group.{key}: a positive integer")

        if is_ap and "limits" in s:
            errors.append(
                f"{path}.limits: the AP runtime has no per-session table bound to "
                "apply a limit to"
            )
        elif "limits" in s:
            lim = s["limits"]
            if not isinstance(lim, dict):
                errors.append(f"{path}.limits: must be a mapping")
            else:
                for key, value in lim.items():
                    if key not in machine_limits:
                        errors.append(
                            f"{path}.limits.{key}: overrides {base}.limits.{key}, "
                            "which the machine does not declare"
                        )
                    elif not _positive_int(value):
                        errors.append(f"{path}.limits.{key}: a positive integer")

        if is_ap and "buffer_pools" in s:
            errors.append(
                f"{path}.buffer_pools: an AP session has no pools of its own; its "
                "link buffers are the process's shared link-RX arena"
            )
        elif "buffer_pools" in s:
            pools = s["buffer_pools"]
            if not isinstance(pools, dict):
                errors.append(f"{path}.buffer_pools: must be a mapping")
            else:
                for key, value in pools.items():
                    if key not in SESSION_POOLS:
                        errors.append(
                            f"{path}.buffer_pools.{key}: not a per-session pool "
                            f"(one of {', '.join(sorted(SESSION_POOLS))})"
                        )
                        continue
                    why = _pool_problem(repo_root, value)
                    if why:
                        errors.append(f"{path}.buffer_pools.{key}: {why}")
    return errors


def validate_machine(
    machine_name: str, machine: dict, repo_root: Path
) -> list[str]:
    """Every refusal for one machine's `zid`, `sessions` and `session_pool`."""
    return _validate_zid_and_sessions(
        machine_name, machine, repo_root
    ) + session_pool_problems(machine_name, machine, repo_root)


# ---------------------------------------------------------------------------
# Round 3278 -- the session pool
# ---------------------------------------------------------------------------


def pool_document_dims(repo_root: Path, ref: str) -> tuple[int, int] | str:
    """`(slot_count, slot_size)` of the buffer-pool document `ref`, or why not.

    The numbers are read from the document itself, which is their only home:
    this module never restates one.
    """
    paths = sorted((repo_root / "sources").rglob(f"{ref}.scxml"))
    if not paths:
        return f"`ref: {ref}` names no `sources/**/{ref}.scxml`"
    try:
        root = ET.parse(paths[0]).getroot()
    except ET.ParseError as e:
        return f"`{paths[0].name}` does not parse: {e}"
    if root.get(f"{SCE_NS}kind") != "buffer-pool":
        return f"`{ref}` is not an `sce:kind=\"buffer-pool\"` document"
    dims = []
    for tag in ("slot-count", "slot-size"):
        node = root.find(f"{SCE_NS}{tag}")
        text = node.text.strip() if node is not None and node.text else ""
        if not text.isdigit() or int(text) == 0:
            return f"`{ref}` has no positive `<sce:{tag}>`"
        dims.append(int(text))
    return dims[0], dims[1]


def pool_document_section(repo_root: Path, ref: str) -> str | None:
    """The `<sce:section>` the buffer-pool document `ref` names, or None.

    Read after `pool_document_dims` accepted the document, so a missing file or a
    parse error is that function's refusal and not this one's.
    """
    paths = sorted((repo_root / "sources").rglob(f"{ref}.scxml"))
    if not paths:
        return None
    try:
        root = ET.parse(paths[0]).getroot()
    except ET.ParseError:
        return None
    node = root.find(f"{SCE_NS}section")
    text = node.text.strip() if node is not None and node.text else ""
    return text or None


SIZE_RE = re.compile(r"^\s*(\d+)\s*([KkMm]?)\s*$")


def region_bytes(value: object) -> int | None:
    """The bytes of a `memory.sram_regions.<name>.size` (`128K`, `1M`, a bare
    number), or None when it is none of those."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value if value > 0 else None
    match = SIZE_RE.match(value) if isinstance(value, str) else None
    if match is None:
        return None
    scale = {"": 1, "k": 1024, "m": 1024 * 1024}[match.group(2).lower()]
    return int(match.group(1)) * scale or None


UDP_PCB_RE = re.compile(
    r"^\s*#\s*define\s+MEMP_NUM_UDP_PCB\s+\(?\s*(\d+)\s*\)?\s*(?:/[/*].*)?$"
)


def lwip_udp_pcbs(repo_root: Path, rel: object) -> int | str:
    """`MEMP_NUM_UDP_PCB` of the `lwipopts.h` at `rel`, or why it cannot be read.

    The LAST `#define` wins, as the preprocessor reads a file top to bottom. A
    header that includes another for it states no number of its own, and is
    refused as such: the machine names the header that DEFINES it.
    """
    if not isinstance(rel, str) or not rel:
        return "must be the path of an lwipopts.h, relative to the repository"
    path = (repo_root / rel).resolve()
    try:
        path.relative_to(repo_root.resolve())
    except ValueError:
        return f"`{rel}` is outside the repository"
    try:
        text = path.read_text(errors="replace")
    except OSError:
        return f"`{rel}` cannot be read"
    found = None
    for line in text.splitlines():
        match = UDP_PCB_RE.match(line)
        if match:
            found = int(match.group(1))
    if found is None:
        return f"`{rel}` states no `#define MEMP_NUM_UDP_PCB <number>`"
    return found


def _pool_numbers(
    repo_root: Path, pool: dict
) -> tuple[dict | None, list[tuple[str, str]]]:
    """The table's resolved numbers, and `(key, why)` for every refusal."""
    problems: list[tuple[str, str]] = []
    inline = sorted({"max_sessions", "slot_bytes", "section"} & set(pool))
    if "ref" in pool:
        if inline:
            problems.append(
                (
                    "ref",
                    f"a `ref` pool takes no {' or '.join(f'`{k}`' for k in inline)}; "
                    "the document holds them",
                )
            )
            return None, problems
        ref = pool["ref"]
        if not isinstance(ref, str) or not NAME_RE.match(ref):
            problems.append(("ref", "must name a buffer-pool document"))
            return None, problems
        dims = pool_document_dims(repo_root, ref)
        if isinstance(dims, str):
            problems.append(("ref", dims))
            return None, problems
        return (
            {
                "ref": ref,
                "generated": True,
                "max_sessions": dims[0],
                "slot_bytes": dims[1],
                "section": pool_document_section(repo_root, ref),
            },
            problems,
        )
    if not ({"max_sessions", "slot_bytes"} & set(pool)):
        problems.append(
            (
                "ref",
                "required: a buffer-pool document, or `max_sessions` with `slot_bytes`",
            )
        )
        return None, problems
    for key in ("max_sessions", "slot_bytes"):
        if key not in pool:
            problems.append((key, "required beside the other inline number"))
        elif not _positive_int(pool[key]):
            problems.append((key, "a positive integer"))
    section = pool.get("section")
    if "section" in pool and not (isinstance(section, str) and NAME_RE.match(section)):
        problems.append(("section", "must name a memory region"))
    if problems:
        return None, problems
    return (
        {
            "ref": None,
            "generated": False,
            "max_sessions": pool["max_sessions"],
            "slot_bytes": pool["slot_bytes"],
            "section": section,
        },
        problems,
    )


def _single_accept(machine: dict) -> bool:
    """Does an acceptor on this machine hold ONE accepted session at a time?

    An MCU or Zephyr acceptor does, unless the machine declares a `session_pool`.
    The heap profiles' acceptor binds one socket per accepted session, and lwIP
    refuses a second bind of the port, so it has one. The acceptor of the pool
    profile is a listener over ONE socket (`wz_session_lwip::listener`): it reads
    every peer's datagrams from it, and claims a session slot, a pump cell and a
    task cell for a peer before it answers it, answering nothing when one is
    missing, so it holds as many sessions as it has lanes and the pool has slots
    (S6, R1; the deploy lift is S9c).
    """
    platform = machine.get("platform") or {}
    return (
        platform.get("class") == "mcu" or platform.get("os") == "zephyr"
    ) and "session_pool" not in machine


def _slots_claimed(session: dict, single_accept: bool) -> int:
    """How many slots one declared session holds: a listening session claims
    every session it accepts, any other session one."""
    accept = session.get("accept")
    if (
        session.get("transport") == "unicast"
        and "listen" in session
        and isinstance(accept, dict)
        and _positive_int(accept.get("max_sessions"))
        and not single_accept
    ):
        return accept["max_sessions"]
    return 1


def _session_pool_parts(
    repo_root: Path, machine: dict, session: dict
) -> list[dict]:
    """The pools of ONE session that are part of its slot, with their bytes.

    A session's own `buffer_pools` entry wins, then the machine's, then the
    profile's default document. An entry that cannot be read is left out: the
    refusal for it is made where it is declared.
    """
    own = session.get("buffer_pools")
    own = own if isinstance(own, dict) else {}
    shared = machine.get("buffer_pools")
    shared = shared if isinstance(shared, dict) else {}
    parts = []
    for key in SLOT_POOLS:
        if key in own:
            spec, origin = own[key], "session"
        elif key in shared:
            spec, origin = shared[key], "machine"
        else:
            spec, origin = {"ref": DEFAULT_SLOT_POOL_REF[key]}, "default"
        if not isinstance(spec, dict):
            continue
        if "ref" in spec:
            ref = spec["ref"]
            if not isinstance(ref, str):
                continue
            dims = pool_document_dims(repo_root, ref)
            if isinstance(dims, str):
                continue
            count, size = dims
            source = ref
        else:
            count, size = spec.get("slot_count"), spec.get("slot_size")
            if not (_positive_int(count) and _positive_int(size)):
                continue
            source = "inline"
        parts.append(
            {
                "pool": key,
                "origin": origin,
                "source": source,
                "slots": count,
                "slot_size": size,
                "bytes": count * size,
            }
        )
    return parts


def session_pool_problems(
    machine_name: str, machine: dict, repo_root: Path
) -> list[str]:
    """Every refusal for one machine's `session_pool`; [] when it passes or is absent."""
    if "session_pool" not in machine:
        return []
    base = f"machines.{machine_name}"
    path = f"{base}.session_pool"
    platform = machine.get("platform") or {}
    if platform.get("class") == "ap":
        return [
            f"{path}: an AP holds its sessions as tasks over a growable heap; "
            "there is no session table to size"
        ]
    pool = machine["session_pool"]
    if not isinstance(pool, dict):
        return [f"{path}: must be a mapping"]
    errors: list[str] = []
    for key in sorted(set(pool) - POOL_KEYS):
        errors.append(f"{path}.{key}: unknown key")
    numbers, problems = _pool_numbers(repo_root, pool)
    errors.extend(f"{path}.{key}: {why}" for key, why in problems)

    process = pool.get("process", {})
    if not isinstance(process, dict):
        errors.append(f"{path}.process: must be a mapping")
    else:
        for key, value in process.items():
            if key not in PROCESS_KEYS:
                errors.append(f"{path}.process.{key}: unknown key")
            elif not _positive_int(value):
                errors.append(f"{path}.process.{key}: a positive integer")

    machine_limits = machine.get("limits")
    machine_limits = machine_limits if isinstance(machine_limits, dict) else {}
    for key, value in machine_limits.items():
        if key not in LIMIT_KEYS:
            errors.append(
                f"{base}.limits.{key}: unknown key (the keys are "
                f"{', '.join(sorted(LIMIT_KEYS))})"
            )
        elif not _positive_int(value):
            errors.append(f"{base}.limits.{key}: a positive integer")

    # S9b: an admin reply is STAGED as a reply, so a buffer for admin replies
    # larger than the reply payload bound would build replies the stage refuses.
    admin_bytes = process.get("admin_reply_bytes") if isinstance(process, dict) else None
    payload_bytes = machine_limits.get("reply_payload_bytes")
    if (
        _positive_int(admin_bytes)
        and _positive_int(payload_bytes)
        and admin_bytes > payload_bytes
    ):
        errors.append(
            f"{path}.process.admin_reply_bytes: {admin_bytes} exceeds "
            f"limits.reply_payload_bytes {payload_bytes}; an admin reply is staged "
            "as a reply, so a larger buffer builds replies the stage refuses"
        )

    sessions = machine.get("sessions")
    sessions = sessions if isinstance(sessions, list) else []
    single_accept = _single_accept(machine)
    connect_bound = process.get("connect_endpoints") if isinstance(process, dict) else None
    claimed = 0
    for i, s in enumerate(sessions):
        if not isinstance(s, dict):
            continue
        claimed += _slots_claimed(s, single_accept)
        # S9c: the endpoints a session dials are rows of the node's connect table,
        # which `process.connect_endpoints` bounds; a list longer than the table
        # would name endpoints the node has no row to hold.
        connect = s.get("connect")
        listed = connect.get("endpoints") if isinstance(connect, dict) else None
        if (
            _positive_int(connect_bound)
            and isinstance(listed, list)
            and len(listed) > connect_bound
        ):
            errors.append(
                f"{base}.sessions[{i}].connect.endpoints: {len(listed)} endpoints, "
                f"but process.connect_endpoints holds {connect_bound}; the node has "
                "no row for the rest"
            )
        lim = s.get("limits")
        if isinstance(lim, dict):
            own_payload = lim.get("reply_payload_bytes")
            if (
                _positive_int(admin_bytes)
                and _positive_int(own_payload)
                and own_payload < admin_bytes
            ):
                errors.append(
                    f"{base}.sessions[{i}].limits.reply_payload_bytes: {own_payload} "
                    f"is below process.admin_reply_bytes {admin_bytes}; an admin reply "
                    "built for this session would be refused by its stage"
                )
            for key, value in lim.items():
                declared = machine_limits.get(key)
                if (
                    _positive_int(value)
                    and _positive_int(declared)
                    and value > declared
                ):
                    errors.append(
                        f"{base}.sessions[{i}].limits.{key}: {value} raises the "
                        f"machine's {declared}; the slot is sized by the machine's "
                        "number, so a session may only lower it"
                    )
        if numbers is not None:
            parts = _session_pool_parts(repo_root, machine, s)
            total = sum(p["bytes"] for p in parts)
            typed = _typed_bytes(repo_root, pool)
            if typed is not None and typed > numbers["slot_bytes"]:
                # A typed slot over the ceiling by itself is refused ONCE, by
                # `_typed_slot_problems`; repeating it for every session would bury it.
                typed = None
            need = total + (typed or 0)
            if need > numbers["slot_bytes"]:
                detail = ", ".join(
                    f"{p['pool']} {p['slots']} x {p['slot_size']} = {p['bytes']}"
                    for p in parts
                )
                if typed is None:
                    what = f"add up to {total} bytes"
                else:
                    what = (
                        f"add up to {total} bytes and the measured typed slot takes "
                        f"{typed}, {need} together"
                    )
                errors.append(
                    f"{base}.sessions[{i}].buffer_pools: the pools this session "
                    f"takes ({detail}) {what}, more than the "
                    f"{numbers['slot_bytes']} a session slot holds "
                    "(session_pool slot size)"
                )
    if numbers is not None and claimed > numbers["max_sessions"]:
        errors.append(
            f"{path}.max_sessions: the machine's sessions claim {claimed} slots "
            f"and the table holds {numbers['max_sessions']}"
        )
    if numbers is not None:
        errors.extend(_placement_problems(path, machine, numbers))
        if "lwip_opts" in pool:
            errors.extend(_lwip_problems(path, repo_root, pool, numbers))
        if "typed_slot_image" in pool:
            errors.extend(_typed_slot_problems(path, repo_root, pool, numbers))
    return errors


SLOT_RECORD = "deploy/session_slot_bytes.json"


def typed_slot(repo_root: Path, image: object) -> dict | str:
    """The measured typed-slot entry for `image`, or why there is none.

    The record is `deploy/session_slot_bytes.json`, written by
    `scripts/lib/session_slot_bytes.py` from the size of a probe symbol in the built
    image: a number the compiler alone knows, held equal to a fresh measurement by
    that script's `--check`. This module reads it and states it nowhere.
    """
    if not isinstance(image, str) or not image:
        return "must name an image of the record `" + SLOT_RECORD + "`"
    try:
        record = json.loads((repo_root / SLOT_RECORD).read_text())
    except (OSError, ValueError) as err:
        return f"the record `{SLOT_RECORD}` cannot be read ({err})"
    images = record.get("images") if isinstance(record, dict) else None
    if not isinstance(images, dict):
        return f"the record `{SLOT_RECORD}` holds no `images` mapping"
    found = images.get(image)
    if not isinstance(found, dict) or not _positive_int(found.get("slot_bytes")):
        return f"`{image}` is not measured in `{SLOT_RECORD}` (it measures: {', '.join(sorted(images))})"
    return found


def _typed_bytes(repo_root: Path, pool: dict) -> int | None:
    """The MEASURED bytes of one typed slot when the pool names a measured image, else
    None: the budget then adds it to a session's pools, which is what a slot is (the
    pools it is built over and the typed part the compiler lays out)."""
    if "typed_slot_image" not in pool:
        return None
    found = typed_slot(repo_root, pool["typed_slot_image"])
    return found["slot_bytes"] if isinstance(found, dict) else None


def _typed_slot_problems(path: str, repo_root: Path, pool: dict, numbers: dict) -> list[str]:
    """Does the MEASURED typed slot of the machine's image fit the ceiling it names?

    The images assert the same at compile time against the generated `SLOT_SIZE`;
    this holds the deploy file's own ceiling (an inline pool states one, and a `ref`
    pool's is the document's) to the measurement, so a file that lowers the ceiling
    below what the image's slot takes is refused where it is written.
    """
    found = typed_slot(repo_root, pool["typed_slot_image"])
    if isinstance(found, str):
        return [f"{path}.typed_slot_image: {found}"]
    if found["slot_bytes"] > numbers["slot_bytes"]:
        return [
            f"{path}.typed_slot_image: `{pool['typed_slot_image']}` measures "
            f"{found['slot_bytes']} bytes per typed slot ({found.get('target')}), more "
            f"than the {numbers['slot_bytes']} a session slot holds"
        ]
    return []


def _declared_regions(machine: dict) -> dict | None:
    """`memory.sram_regions` as the machine WRITES it, or None when it writes none.

    A focused profile inherits its memory block from the profile it is built on
    (`mcu_client_and_group.yaml` says so in a comment) and this reader sees only
    the machine's own keys, so a machine that states no regions is not checked:
    the check is the machine's to arm by stating them.
    """
    memory = machine.get("memory")
    regions = memory.get("sram_regions") if isinstance(memory, dict) else None
    return regions if isinstance(regions, dict) and regions else None


def _placement_problems(path: str, machine: dict, numbers: dict) -> list[str]:
    """Does the whole table fit the memory region its pool document places it in?

    The table is `max_sessions * slot_bytes` bytes (one generated number) and its
    pool names a `section`. When the machine states its SRAM regions, that section
    must be one of them and the region must hold the table; one that does not is a
    layout the linker would fail on, or worse a table that spills into a neighbour.
    """
    regions = _declared_regions(machine)
    section = numbers.get("section")
    if regions is None or section is None:
        return []
    total = numbers["max_sessions"] * numbers["slot_bytes"]
    region = regions.get(section)
    if region is None:
        return [
            f"{path}.section: the pool is placed in `{section}`, which is not one of "
            f"the machine's memory.sram_regions ({', '.join(sorted(regions))})"
        ]
    size = region_bytes(region.get("size") if isinstance(region, dict) else None)
    if size is None:
        return [
            f"{path}.section: memory.sram_regions.{section}.size is not a size "
            "(a number of bytes, or a number with a K or M suffix)"
        ]
    if total > size:
        return [
            f"{path}: the table is {numbers['max_sessions']} x {numbers['slot_bytes']} "
            f"= {total} bytes and is placed in `{section}`, which holds {size} bytes"
        ]
    return []


def _lwip_problems(path: str, repo_root: Path, pool: dict, numbers: dict) -> list[str]:
    """Does the lwIP the machine is built with hold a socket for every slot?

    Each session slot is one UDP socket, and the listener is one more
    (`SessionRxPool<SESSIONS + 1>` in the images), so lwIP's `MEMP_NUM_UDP_PCB`
    must be at least `max_sessions + 1`: a smaller pool refuses the bind of the
    last session at run time, where this refuses the file. The number is read from
    the header the machine names and restated nowhere.
    """
    pcbs = lwip_udp_pcbs(repo_root, pool["lwip_opts"])
    if isinstance(pcbs, str):
        return [f"{path}.lwip_opts: {pcbs}"]
    needed = numbers["max_sessions"] + 1
    if pcbs < needed:
        return [
            f"{path}.lwip_opts: `{pool['lwip_opts']}` holds {pcbs} UDP sockets "
            f"(MEMP_NUM_UDP_PCB) and a table of {numbers['max_sessions']} sessions "
            f"with its listener needs {needed}"
        ]
    return []


def session_pool_report(machine_name: str, machine: dict, repo_root: Path) -> dict:
    """The resolved numbers of one machine and every refusal, as plain data.

    The shape an editor of the deploy file reads: nothing in it is derived by
    the reader. `pool` is None for a machine that declares no `session_pool`.
    """
    report: dict = {
        "machine": machine_name,
        "refusals": validate_machine(machine_name, machine, repo_root),
        "vocabulary": {
            "pool": sorted(POOL_KEYS),
            "process": sorted(PROCESS_KEYS),
            "limits": sorted(LIMIT_KEYS),
        },
        "pool": None,
        "lwip": None,
        "process": {},
        "limits": {},
        "sessions": [],
    }
    pool = machine.get("session_pool")
    if not isinstance(pool, dict):
        return report
    numbers, _ = _pool_numbers(repo_root, pool)
    process = pool.get("process")
    report["process"] = dict(process) if isinstance(process, dict) else {}
    machine_limits = machine.get("limits")
    machine_limits = dict(machine_limits) if isinstance(machine_limits, dict) else {}
    report["limits"] = machine_limits
    if numbers is None:
        return report
    report["pool"] = dict(
        numbers, total_bytes=numbers["max_sessions"] * numbers["slot_bytes"]
    )
    # The MEASURED typed slot (never an estimate): `null` for a machine that names no
    # measured image, so the editor can tell "not measured" from a number.
    report["pool"]["typed_slot"] = None
    if "typed_slot_image" in pool:
        found = typed_slot(repo_root, pool["typed_slot_image"])
        if isinstance(found, dict):
            report["pool"]["typed_slot"] = {
                "image": pool["typed_slot_image"],
                "target": found.get("target"),
                "bytes": found["slot_bytes"],
                "headroom_bytes": numbers["slot_bytes"] - found["slot_bytes"],
            }
    if "lwip_opts" in pool:
        pcbs = lwip_udp_pcbs(repo_root, pool["lwip_opts"])
        report["lwip"] = {
            "header": pool["lwip_opts"],
            "udp_pcbs": pcbs if isinstance(pcbs, int) else None,
            "needed": numbers["max_sessions"] + 1,
        }
    single_accept = _single_accept(machine)
    for s in machine.get("sessions") or []:
        if not isinstance(s, dict):
            continue
        parts = _session_pool_parts(repo_root, machine, s)
        total = sum(p["bytes"] for p in parts)
        typed = _typed_bytes(repo_root, pool)
        lim = s.get("limits")
        effective = dict(machine_limits)
        if isinstance(lim, dict):
            effective.update(lim)
        report["sessions"].append(
            {
                "name": s.get("name"),
                "slots": _slots_claimed(s, single_accept),
                "pools": parts,
                "pool_bytes": total,
                # The measured typed slot, or null when the machine names no measured
                # image; `session_bytes` is the pools plus it, and the headroom is the
                # ceiling less that, so the number the editor shows is what the
                # validator refuses on.
                "typed_slot_bytes": typed,
                "session_bytes": total + (typed or 0),
                "headroom_bytes": numbers["slot_bytes"] - total - (typed or 0),
                "limits": effective,
            }
        )
    return report


# ---------------------------------------------------------------------------
# selftest
# ---------------------------------------------------------------------------


def _fixture() -> dict:
    return {
        "platform": {"class": "mcu", "os": "freertos"},
        "zid": "a1b2c3",
        "links": {
            "udp_router": {"bind": "0.0.0.0:0"},
            "udp_group": {"bind": "224.0.0.224:7446"},
            "udp_listen": {"bind": "0.0.0.0:7447"},
        },
        "limits": {"local_subscriptions": 16, "pending_queries": 8},
        "sessions": [
            {
                "name": "to_router",
                "mode": "client",
                "transport": "unicast",
                "link": "udp_router",
                "connect": {"endpoints": ["udp/192.0.2.10:7447"]},
                "limits": {"pending_queries": 4},
                "buffer_pools": {"session_rx_pool": {"ref": "session_rx_pool_mcu"}},
            },
            {
                "name": "group",
                "mode": "peer",
                "transport": "multicast",
                "link": "udp_group",
                "group": {
                    "endpoint": "udp/224.0.0.224:7446",
                    "join_interval_ms": 2500,
                    "lease_ms": 10000,
                },
                "buffer_pools": {
                    "session_rx_pool": {"ref": "session_rx_pool_mcu_multicast"}
                },
            },
        ],
    }


def _selftest(repo_root: Path) -> int:
    import copy

    failures = 0

    def check(label: str, machine: dict, expect: str | None) -> None:
        nonlocal failures
        errs = validate_machine("m", machine, repo_root)
        if expect is None:
            ok = errs == []
        else:
            ok = len(errs) == 1 and expect in errs[0]
        print(f"  {'ok  ' if ok else 'FAIL'} {label}: {errs or 'accepted'}")
        failures += 0 if ok else 1

    def mutate(fn) -> dict:
        m = copy.deepcopy(_fixture())
        fn(m)
        return m

    check("the two-session fixture passes", _fixture(), None)
    check("a machine without sessions is not read", {"platform": {}}, None)

    def shared_own_zid(m):
        del m["zid"]
        m["sessions"][0]["zid"] = "c0ffee"
        m["sessions"][1]["zid"] = "c0ffee"

    # The fixture already shares the machine zid between its two sessions;
    # this is the same rule with the ids spelled on the sessions themselves.
    check(
        "a unicast and a multicast session may carry one zid",
        mutate(shared_own_zid),
        None,
    )

    def two_unicast_same_zid(m):
        m["sessions"][1] = {
            "name": "listener",
            "mode": "peer",
            "transport": "unicast",
            "link": "udp_listen",
            "listen": {"endpoints": ["udp/0.0.0.0:7447"]},
            "accept": {"max_sessions": 1},
        }

    check(
        "two unicast sessions inheriting one zid are refused, naming both",
        mutate(two_unicast_same_zid),
        "machines.m.sessions[1] (`listener`) and machines.m.sessions[0] (`to_router`)",
    )

    def distinct(m):
        two_unicast_same_zid(m)
        m["sessions"][1]["zid"] = "b1"

    check("an own zid makes them distinct", mutate(distinct), None)
    check(
        "an uppercase zid is refused naming the key",
        mutate(lambda m: m.update(zid="A1")),
        "machines.m.zid: uppercase",
    )
    check(
        "a leading zero is refused",
        mutate(lambda m: m["sessions"][0].update(zid="0a")),
        "sessions[0].zid: leading 0s",
    )
    check(
        "a 33-digit zid is refused",
        mutate(lambda m: m["sessions"][0].update(zid="1" * 33)),
        "longer than 16 bytes",
    )
    check(
        "heap_budget_bytes is reserved",
        mutate(lambda m: m["sessions"][0].update(heap_budget_bytes=4096)),
        "sessions[0].heap_budget_bytes: reserved",
    )
    check(
        "an unknown session key is refused by name",
        mutate(lambda m: m["sessions"][0].update(iface="eth0")),
        "sessions[0].iface: unknown key",
    )
    check(
        "a duplicate name is refused",
        mutate(lambda m: m["sessions"][1].update(name="to_router")),
        "sessions[1].name: `to_router` is already",
    )
    check(
        "two sessions on one link are refused",
        mutate(lambda m: m["sessions"][1].update(link="udp_router")),
        "sessions[1].link: `udp_router` already carries",
    )
    check(
        "a link the machine does not declare is refused",
        mutate(lambda m: m["sessions"][1].update(link="udp_nowhere")),
        "sessions[1].link: required",
    )
    check(
        "`auto` is not a word on a locator",
        mutate(lambda m: m["sessions"][1]["group"].update(endpoint="udp/224.0.0.224:7446#iface=auto")),
        "`auto` is not a word",
    )
    check(
        "an MCU refuses an iface its link's netif does not match",
        mutate(lambda m: m["sessions"][1]["group"].update(endpoint="udp/224.0.0.224:7446#iface=eth0")),
        "cannot be honoured on an MCU",
    )

    def netif(m):
        m["links"]["udp_group"]["netif"] = "eth0"
        m["sessions"][1]["group"]["endpoint"] = "udp/224.0.0.224:7446#iface=eth0"

    check("an MCU honours an iface its link's netif matches", mutate(netif), None)

    def on_ap(m):
        # The AP refuses per-session limits and pools (the module doc's AP
        # column), so an AP variant of the MCU fixture drops them.
        m["platform"] = {"class": "ap", "os": "linux"}
        for s in m["sessions"]:
            s.pop("limits", None)
            s.pop("buffer_pools", None)

    def ap_iface(m):
        on_ap(m)
        m["sessions"][1]["group"]["endpoint"] = "udp/224.0.0.224:7446#iface=192.0.2.4"

    check("an AP takes an iface by address", mutate(ap_iface), None)
    check(
        "an empty iface value is refused",
        mutate(lambda m: m["sessions"][1]["group"].update(endpoint="udp/224.0.0.224:7446#iface=")),
        "needs a value",
    )
    check(
        "a unicast group address is refused",
        mutate(lambda m: m["sessions"][1]["group"].update(endpoint="udp/192.0.2.1:7446")),
        "not a multicast group address",
    )
    check(
        "a multicast client is refused",
        mutate(lambda m: m["sessions"][1].update(mode="client")),
        "sessions[1].mode: a multicast session is a `peer`",
    )
    check(
        "connect on a multicast session is refused",
        mutate(lambda m: m["sessions"][1].update(connect={"endpoints": ["udp/192.0.2.1:1"]})),
        "sessions[1].connect: a multicast session has no",
    )

    def accept_two(m):
        two_unicast_same_zid(m)
        m["sessions"][1]["zid"] = "b1"
        m["sessions"][1]["accept"]["max_sessions"] = 2

    check(
        "an MCU acceptor holds one session",
        mutate(accept_two),
        "sessions[1].accept.max_sessions: 2 is refused",
    )

    def accept_two_ap(m):
        accept_two(m)
        on_ap(m)

    check("an AP acceptor may hold more", mutate(accept_two_ap), None)

    def accept_zephyr(m):
        accept_two(m)
        m["platform"] = {"class": "mcu_rtos", "os": "zephyr"}

    check(
        "a Zephyr acceptor holds one session",
        mutate(accept_zephyr),
        "accept.max_sessions: 2 is refused",
    )
    check(
        "accept without listen is refused",
        mutate(lambda m: m["sessions"][0].update(accept={"max_sessions": 1})),
        "sessions[0].accept: only a session that listens",
    )
    check(
        "a limit the machine does not declare is refused",
        mutate(lambda m: m["sessions"][0]["limits"].update(tx_queue=4)),
        "sessions[0].limits.tx_queue: overrides machines.m.limits.tx_queue",
    )
    check(
        "a pool ref that names no document is refused",
        mutate(lambda m: m["sessions"][0]["buffer_pools"].update(session_rx_pool={"ref": "no_such_pool"})),
        "names no `sources/**/no_such_pool.scxml`",
    )
    check(
        "a machine-wide pool is not a session's",
        mutate(lambda m: m["sessions"][0]["buffer_pools"].update(scout_rx_pool={"ref": "scout_rx_pool_mcu"})),
        "buffer_pools.scout_rx_pool: not a per-session pool",
    )
    check(
        "an inline pool needs its dimensions",
        mutate(lambda m: m["sessions"][0]["buffer_pools"].update(session_tx_pool={"slot_count": 8})),
        "needs a positive `slot_size`",
    )
    failures += _pool_selftest(repo_root)
    failures += _ap_cases(repo_root)
    print(f"deploy_sessions selftest: {'FAIL' if failures else 'OK'} ({failures} failing)")
    return 1 if failures else 0


POOL_DOCUMENT = "session_slot_pool_mcu"


def _pool_fixture() -> dict:
    """The two-session machine with a session pool, every pool spelled inline so
    the arithmetic of the budget is stated here and read from no document.

    Session 0 takes 4 x 1000 + 2 x 500 = 5000 bytes, session 1 takes
    8 x 1000 + 2 x 500 = 9000.
    """
    machine = _fixture()
    machine["limits"] = {"local_subscriptions": 16, "pending_queries": 8}
    machine["sessions"][0]["buffer_pools"] = {
        "session_rx_pool": {"slot_count": 4, "slot_size": 1000},
        "reassembly_pool": {"slot_count": 2, "slot_size": 500},
    }
    machine["sessions"][0]["limits"] = {"pending_queries": 4}
    machine["sessions"][1]["buffer_pools"] = {
        "session_rx_pool": {"slot_count": 8, "slot_size": 1000},
        "reassembly_pool": {"slot_count": 2, "slot_size": 500},
    }
    machine["sessions"][1]["limits"] = {"local_subscriptions": 8}
    machine["session_pool"] = {
        "max_sessions": 3,
        "slot_bytes": 9000,
        "process": {"max_tasks": 8, "max_timers": 16, "admin_reply_bytes": 1024},
    }
    return machine


def _pool_selftest(repo_root: Path) -> int:
    import copy

    failures = 0

    def check(label: str, machine: dict, expect: str | None) -> None:
        nonlocal failures
        errs = validate_machine("m", machine, repo_root)
        if expect is None:
            ok = errs == []
        else:
            ok = len(errs) == 1 and expect in errs[0]
        print(f"  {'ok  ' if ok else 'FAIL'} pool: {label}: {errs or 'accepted'}")
        failures += 0 if ok else 1

    def mutate(fn) -> dict:
        m = copy.deepcopy(_pool_fixture())
        fn(m)
        return m

    def expect_equal(label: str, got: object, want: object) -> None:
        nonlocal failures
        ok = got == want
        print(f"  {'ok  ' if ok else 'FAIL'} pool: {label}: {got}")
        if not ok:
            print(f"       want {want}")
        failures += 0 if ok else 1

    check("two sessions in a table of three, within the budget", _pool_fixture(), None)
    check(
        "a table of exactly the sessions it holds",
        mutate(lambda m: m["session_pool"].update(max_sessions=2)),
        None,
    )
    check(
        "a machine with no table is not read for limit keys",
        mutate(lambda m: (m.pop("session_pool"), m["limits"].update(zzz=1))),
        None,
    )
    check(
        "zero sessions is refused naming the key",
        mutate(lambda m: m["session_pool"].update(max_sessions=0)),
        "session_pool.max_sessions: a positive integer",
    )
    check(
        "a boolean is not a count",
        mutate(lambda m: m["session_pool"].update(max_sessions=True)),
        "session_pool.max_sessions: a positive integer",
    )
    check(
        "more sessions declared than the table holds",
        mutate(lambda m: m["session_pool"].update(max_sessions=1)),
        "claim 2 slots and the table holds 1",
    )
    check(
        "a session whose pools overflow the slot is refused naming it",
        mutate(lambda m: m["session_pool"].update(slot_bytes=8999)),
        "sessions[1].buffer_pools: the pools this session takes "
        "(session_rx_pool 8 x 1000 = 8000, reassembly_pool 2 x 500 = 1000) "
        "add up to 9000 bytes, more than the 8999",
    )

    def machine_pools(m):
        # The second session names no pools: the machine's stand for it.
        shared = m["sessions"][1].pop("buffer_pools")
        m["buffer_pools"] = shared

    check(
        "the machine's pools stand for a session that names none",
        mutate(machine_pools),
        None,
    )

    def machine_pools_overflow(m):
        machine_pools(m)
        m["session_pool"]["slot_bytes"] = 8999

    check(
        "and are budgeted the same",
        mutate(machine_pools_overflow),
        "sessions[1].buffer_pools: the pools this session takes",
    )
    check(
        "an unknown key of the table is refused by name",
        mutate(lambda m: m["session_pool"].update(heap_budget_bytes=4096)),
        "session_pool.heap_budget_bytes: unknown key",
    )
    check(
        "an unknown process key is refused by name",
        mutate(lambda m: m["session_pool"]["process"].update(max_threads=2)),
        "session_pool.process.max_threads: unknown key",
    )
    check(
        "a zero process number is refused",
        mutate(lambda m: m["session_pool"]["process"].update(max_tasks=0)),
        "session_pool.process.max_tasks: a positive integer",
    )
    # S9b: the admin node's tables and its reply buffer.
    check(
        "the admin node's two table sizes are process keys",
        mutate(
            lambda m: m["session_pool"]["process"].update(
                admin_locators=4, admin_session_links=2
            )
        ),
        None,
    )
    check(
        "a zero admin table size is refused",
        mutate(lambda m: m["session_pool"]["process"].update(admin_locators=0)),
        "session_pool.process.admin_locators: a positive integer",
    )
    # S9c: the connect table, the multicast reply queue, and the acceptor that holds
    # several sessions on a machine with a table.
    check(
        "the connect table and the multicast reply queue are process keys",
        mutate(
            lambda m: m["session_pool"]["process"].update(
                connect_endpoints=8, multicast_replies=8
            )
        ),
        None,
    )
    check(
        "a zero connect table is refused",
        mutate(lambda m: m["session_pool"]["process"].update(connect_endpoints=0)),
        "session_pool.process.connect_endpoints: a positive integer",
    )
    check(
        "a zero multicast reply queue is refused",
        mutate(lambda m: m["session_pool"]["process"].update(multicast_replies=0)),
        "session_pool.process.multicast_replies: a positive integer",
    )

    def endpoints_beyond_the_table(m):
        m["session_pool"]["process"]["connect_endpoints"] = 1
        m["sessions"][0]["connect"]["endpoints"] = ["udp/192.0.2.10:7447", "udp/192.0.2.11:7447"]

    check(
        "a session that lists more endpoints than the connect table holds is refused",
        mutate(endpoints_beyond_the_table),
        "sessions[0].connect.endpoints: 2 endpoints, but process.connect_endpoints holds 1",
    )

    def acceptor(m, n):
        m["links"]["udp_listen"] = {
            "bind": "0.0.0.0:7447",
            "driver": "lwip_udp",
            "mtu_bytes": 1472,
        }
        m["sessions"][1] = {
            "name": "listener",
            "mode": "peer",
            "transport": "unicast",
            "link": "udp_listen",
            "zid": "b1",
            "listen": {"endpoints": ["udp/0.0.0.0:7447"]},
            "accept": {"max_sessions": n},
            "buffer_pools": {
                "session_rx_pool": {"slot_count": 4, "slot_size": 1000},
                "reassembly_pool": {"slot_count": 2, "slot_size": 500},
            },
        }

    check(
        "an MCU acceptor of a machine with a session table holds two sessions",
        mutate(lambda m: acceptor(m, 2)),
        None,
    )
    check(
        "each accepted session claims a slot of the table",
        mutate(lambda m: acceptor(m, 3)),
        "session_pool.max_sessions: the machine's sessions claim 4 slots and the "
        "table holds 3",
    )

    def zephyr_acceptor(m):
        acceptor(m, 2)
        m["platform"] = {"class": "mcu_rtos", "os": "zephyr"}

    check(
        "a Zephyr acceptor of a machine with a session table holds two sessions",
        mutate(zephyr_acceptor),
        None,
    )

    def no_table_acceptor(m):
        acceptor(m, 2)
        m.pop("session_pool")

    check(
        "the same acceptor on a machine with no table still holds one",
        mutate(no_table_acceptor),
        "sessions[1].accept.max_sessions: 2 is refused",
    )
    # Placement: the table (3 x 9000 = 27000 bytes) in the region its pool names.
    def placed(size, section="sram1", regions=None):
        def apply(m):
            m["session_pool"]["section"] = section
            m["memory"] = {
                "sram_regions": regions
                if regions is not None
                else {"sram1": {"base": 0x30000000, "size": size}}
            }

        return apply

    check(
        "a table that fits the region it is placed in is accepted",
        mutate(placed("32K")),
        None,
    )
    check(
        "a table exactly the size of its region is accepted",
        mutate(placed(27000)),
        None,
    )
    check(
        "a table larger than its region is refused naming both",
        mutate(placed("16K")),
        "the table is 3 x 9000 = 27000 bytes and is placed in `sram1`, which holds "
        "16384 bytes",
    )
    check(
        "a section the machine's regions do not list is refused",
        mutate(placed("32K", section="sram9")),
        "the pool is placed in `sram9`, which is not one of the machine's "
        "memory.sram_regions (sram1)",
    )
    check(
        "a region size that is no size is refused",
        mutate(placed("big")),
        "memory.sram_regions.sram1.size is not a size",
    )
    check(
        "a machine that states no regions is not placed",
        mutate(lambda m: m["session_pool"].update(section="sram1")),
        None,
    )
    check(
        "a section that is no name is refused",
        mutate(lambda m: m["session_pool"].update(section="SRAM 1")),
        "session_pool.section: must name a memory region",
    )
    # lwIP: one socket per slot and one for the listener.
    check(
        "an lwIP that holds a socket for every slot and the listener is accepted",
        mutate(
            lambda m: m["session_pool"].update(
                lwip_opts="crates/lwip-sys/port/cross-test/lwipopts.h"
            )
        ),
        None,
    )
    check(
        "an lwIP with too few sockets is refused naming the number it has",
        mutate(
            lambda m: m["session_pool"].update(
                lwip_opts="crates/lwip-sys/port/microbit-minimal/lwipopts.h"
            )
        ),
        "holds 3 UDP sockets (MEMP_NUM_UDP_PCB) and a table of 3 sessions with its "
        "listener needs 4",
    )
    check(
        "a header that states no socket count is refused",
        mutate(
            lambda m: m["session_pool"].update(
                lwip_opts="crates/lwip-sys/port/cross-test-mcast/lwipopts.h"
            )
        ),
        "states no `#define MEMP_NUM_UDP_PCB <number>`",
    )
    check(
        "a header that is not there is refused",
        mutate(lambda m: m["session_pool"].update(lwip_opts="no/such/lwipopts.h")),
        "`no/such/lwipopts.h` cannot be read",
    )
    check(
        "a header outside the repository is refused",
        mutate(lambda m: m["session_pool"].update(lwip_opts="../outside.h")),
        "`../outside.h` is outside the repository",
    )
    check(
        "a header path that is no string is refused",
        mutate(lambda m: m["session_pool"].update(lwip_opts=4)),
        "must be the path of an lwipopts.h",
    )
    # The MEASURED typed slot (the record `deploy/session_slot_bytes.json`).
    def typed(image, slot_bytes=98304):
        def apply(m):
            m["session_pool"]["slot_bytes"] = slot_bytes
            m["session_pool"]["typed_slot_image"] = image

        return apply

    check(
        "a measured image whose slot fits the ceiling is accepted",
        mutate(typed("mcu-admin-node")),
        None,
    )
    check(
        "a ceiling below the measured slot is refused naming the image and both numbers",
        mutate(typed("mcu-admin-node", slot_bytes=9000)),
        "typed_slot_image: `mcu-admin-node` measures",
    )
    check(
        "an image the record does not measure is refused naming the ones it does",
        mutate(typed("no-such-image")),
        "`no-such-image` is not measured in `deploy/session_slot_bytes.json` (it measures: ",
    )
    check(
        "an image that is no string is refused",
        mutate(typed(4)),
        "must name an image of the record",
    )
    big = {
        "session_rx_pool": {"slot_count": 42, "slot_size": 1500},
        "reassembly_pool": {"slot_count": 2, "slot_size": 500},
    }

    def big_pools(image):
        def apply(m):
            m["session_pool"]["slot_bytes"] = 98304
            if image:
                m["session_pool"]["typed_slot_image"] = image
            m["sessions"][1]["buffer_pools"] = big

        return apply

    check(
        "pools that fit alone are refused when the measured slot over them does not",
        mutate(big_pools("mcu-admin-node")),
        "add up to 64000 bytes and the measured typed slot takes ",
    )
    check(
        "the same pools with no measured image are judged on the pools alone",
        mutate(big_pools(None)),
        None,
    )
    report = session_pool_report("m", mutate(big_pools(None)), repo_root)
    expect_equal(
        "without a measured image the session's bytes are its pools and the headroom is unchanged",
        [(s["pool_bytes"], s["session_bytes"], s["typed_slot_bytes"]) for s in report["sessions"]][1],
        (64000, 64000, None),
    )
    report = session_pool_report("m", mutate(typed("mcu-admin-node")), repo_root)
    expect_equal(
        "with a measured image the session's bytes are its pools plus the typed slot",
        all(
            s["session_bytes"] == s["pool_bytes"] + s["typed_slot_bytes"]
            and s["headroom_bytes"] == 98304 - s["session_bytes"]
            for s in report["sessions"]
        ),
        True,
    )
    report = session_pool_report("m", mutate(typed("mcu-admin-node")), repo_root)
    measured = (report["pool"] or {}).get("typed_slot") or {}
    expect_equal(
        "the report states the measured bytes and the headroom against the ceiling",
        (measured.get("bytes", 0) + measured.get("headroom_bytes", 0), measured.get("image")),
        (98304, "mcu-admin-node"),
    )
    report = session_pool_report("m", _pool_fixture(), repo_root)
    expect_equal(
        "a machine that names no image has no typed slot, null and not a guess",
        (report["pool"] or {}).get("typed_slot", "absent"),
        None,
    )
    check(
        "an admin reply buffer of exactly the reply payload bound is accepted",
        mutate(lambda m: m["limits"].update(reply_payload_bytes=1024)),
        None,
    )
    check(
        "an admin reply buffer larger than the reply payload bound is refused",
        mutate(lambda m: m["limits"].update(reply_payload_bytes=1023)),
        "session_pool.process.admin_reply_bytes: 1024 exceeds "
        "limits.reply_payload_bytes 1023",
    )
    check(
        "a session that lowers the payload bound below the admin buffer is refused",
        mutate(
            lambda m: (
                m["limits"].update(reply_payload_bytes=2048),
                m["sessions"][0]["limits"].update(reply_payload_bytes=512),
            )
        ),
        "sessions[0].limits.reply_payload_bytes: 512 is below "
        "process.admin_reply_bytes 1024",
    )
    check(
        "a table that is not a mapping is refused",
        mutate(lambda m: m.update(session_pool=4)),
        "session_pool: must be a mapping",
    )
    check(
        "a table with neither a document nor numbers is refused",
        mutate(lambda m: m.update(session_pool={})),
        "session_pool.ref: required",
    )
    check(
        "a table with one inline number is refused",
        mutate(lambda m: m["session_pool"].pop("slot_bytes")),
        "session_pool.slot_bytes: required beside",
    )
    check(
        "a document and inline numbers together are refused",
        mutate(lambda m: m["session_pool"].update(ref=POOL_DOCUMENT)),
        "a `ref` pool takes no `max_sessions` or `slot_bytes`",
    )
    check(
        "a document that does not exist is refused",
        mutate(lambda m: m.update(session_pool={"ref": "no_such_pool"})),
        "names no `sources/**/no_such_pool.scxml`",
    )
    check(
        "a document that is not a buffer-pool is refused",
        mutate(lambda m: m.update(session_pool={"ref": "reassembly_slot"})),
        "is not an `sce:kind=\"buffer-pool\"` document",
    )
    check(
        "a limit key the vocabulary does not have is refused by name",
        mutate(lambda m: m["limits"].update(sessions_max=4)),
        "machines.m.limits.sessions_max: unknown key",
    )
    check(
        "a session that raises a machine limit is refused",
        mutate(lambda m: m["sessions"][0]["limits"].update(pending_queries=9)),
        "sessions[0].limits.pending_queries: 9 raises the machine's 8",
    )
    check(
        "a session may lower it",
        mutate(lambda m: m["sessions"][0]["limits"].update(pending_queries=1)),
        None,
    )

    def on_ap(m):
        m["platform"] = {"class": "ap", "os": "linux"}
        for s in m["sessions"]:
            s.pop("limits", None)
            s.pop("buffer_pools", None)

    check(
        "an AP has no table to size",
        mutate(on_ap),
        "an AP holds its sessions as tasks over a growable heap",
    )

    # The report: the numbers an editor shows, and they are the arithmetic.
    report = session_pool_report("m", _pool_fixture(), repo_root)
    expect_equal("the report of the fixture has no refusal", report["refusals"], [])
    expect_equal(
        "the table is one number",
        (report["pool"] or {}).get("total_bytes"),
        27000,
    )
    expect_equal(
        "each session reports its pools and what is left of its slot",
        [(s["pool_bytes"], s["headroom_bytes"]) for s in report["sessions"]],
        [(5000, 4000), (9000, 0)],
    )
    expect_equal(
        "a session's limits are the machine's with its own laid over",
        report["sessions"][0]["limits"],
        {"local_subscriptions": 16, "pending_queries": 4},
    )
    refused = session_pool_report(
        "m", mutate(lambda m: m["session_pool"].update(max_sessions=0)), repo_root
    )
    expect_equal(
        "a refused table reports no number and says why",
        (refused["pool"], len(refused["refusals"])),
        (None, 1),
    )

    # The document is the only home of its numbers: the report reads them from
    # it, checked here against a read of the file's own text.
    document = repo_root / "sources" / "network" / f"{POOL_DOCUMENT}.scxml"
    try:
        text = document.read_text(encoding="utf-8")
    except OSError as e:
        print(f"  FAIL pool: the table's document cannot be read: {e}")
        return failures + 1
    want = []
    for tag in ("slot-count", "slot-size"):
        found = re.search(rf"<sce:{tag}>\s*(\d+)\s*</sce:{tag}>", text)
        want.append(int(found.group(1)) if found else None)
    from_document = session_pool_report(
        "m", mutate(lambda m: m.update(session_pool={"ref": POOL_DOCUMENT})), repo_root
    )
    expect_equal(
        f"`{POOL_DOCUMENT}`: the report holds the document's two numbers",
        (
            (from_document["pool"] or {}).get("max_sessions"),
            (from_document["pool"] or {}).get("slot_bytes"),
        ),
        tuple(want),
    )
    return failures


AP_CASES = Path(__file__).resolve().parent / "deploy_sessions_ap_cases.json"
AP_MACHINE = "m"


def refused_paths(refusals: list[str]) -> set[str]:
    """The key paths `validate_machine` refused, relative to the machine.

    A refusal is `machines.<m>.<path>: <why>`; the AP document a demo reads IS
    the machine, so the paths it reports carry no `machines.<m>.` prefix.
    """
    prefix = f"machines.{AP_MACHINE}."
    out = set()
    for refusal in refusals:
        path = refusal.split(": ", 1)[0]
        out.add(path[len(prefix) :] if path.startswith(prefix) else path)
    return out


def _ap_cases(repo_root: Path) -> int:
    """Run the AP cases `wz-ap-demo`'s `--sessions` reader is judged on too.

    Each document is read as a machine whose platform is an AP, and the SET of
    refused key paths must be the case's `refuses` exactly: a missing path is a
    rule this module lost, an extra one a rule the demo does not share.
    """
    import json

    cases = json.loads(AP_CASES.read_text(encoding="utf-8"))["cases"]
    failures = 0
    for case in cases:
        machine = dict(case["document"], platform={"class": "ap", "os": "linux"})
        got = refused_paths(validate_machine(AP_MACHINE, machine, repo_root))
        want = set(case["refuses"])
        ok = got == want
        print(f"  {'ok  ' if ok else 'FAIL'} ap: {case['label']}: {sorted(got) or 'accepted'}")
        if not ok:
            print(f"       want {sorted(want) or 'accepted'}")
        failures += 0 if ok else 1
    # Anti-vacuity: a file that lost its cases would agree with everything.
    if len(cases) < 20:
        print(f"  FAIL ap: only {len(cases)} case(s) in {AP_CASES.name}")
        failures += 1
    return failures


def main(argv: list[str]) -> int:
    repo_root = Path(__file__).resolve().parents[2]
    if argv[1:] == ["--selftest"]:
        return _selftest(repo_root)
    if len(argv) == 4 and argv[1] == "--report":
        return _report(repo_root, Path(argv[2]), argv[3])
    print(
        "usage: deploy_sessions.py --selftest\n"
        "       deploy_sessions.py --report <deploy.yaml> <machine>",
        file=sys.stderr,
    )
    return 2


def _report(repo_root: Path, deploy_file: Path, machine_name: str) -> int:
    """Print `session_pool_report` of one machine as JSON; 1 when it refuses."""
    try:
        import yaml
    except ImportError:
        print("deploy_sessions: python3 yaml module unavailable", file=sys.stderr)
        return 2
    try:
        document = yaml.safe_load(deploy_file.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as e:
        print(f"deploy_sessions: cannot read {deploy_file}: {e}", file=sys.stderr)
        return 2
    machines = document.get("machines") if isinstance(document, dict) else None
    machine = machines.get(machine_name) if isinstance(machines, dict) else None
    if not isinstance(machine, dict):
        print(
            f"deploy_sessions: {deploy_file} has no machine `{machine_name}`",
            file=sys.stderr,
        )
        return 2
    report = session_pool_report(machine_name, machine, repo_root)
    print(json.dumps(report, indent=2, sort_keys=True))
    return 1 if report["refusals"] else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
