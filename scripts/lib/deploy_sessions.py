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
                is accepted: the acceptor there holds one accepted session at
                a time and listens again when it ends.
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
                keep; the allocator is not split.

Any other key in a session is refused by name.

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
"""

from __future__ import annotations

import ipaddress
import re
import sys
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


def validate_machine(
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
    single_accept = is_mcu or platform.get("os") == "zephyr"
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
                "profiles have no per-session heap budget; a session's budget is its "
                "static `buffer_pools`"
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
                            "session at a time, so only 1 is accepted"
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
    failures += _ap_cases(repo_root)
    print(f"deploy_sessions selftest: {'FAIL' if failures else 'OK'} ({failures} failing)")
    return 1 if failures else 0


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
    print("usage: deploy_sessions.py --selftest", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
