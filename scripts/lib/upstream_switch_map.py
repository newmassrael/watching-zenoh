#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

"""R3406 (no register item) — the BUILD SWITCHES of zenoh-pico and zenoh-c as a
denominator, and wz's answer to each one as the numerator.

`docs/build-configuration.md` C7: an upstream original is reproduced by naming it,
which needs every switch that original has to be judged against wz, completely and
mechanically. `upstream_feature_census.py` already does this for the `zenoh` crate's
cargo features; this script is the same instrument for the other two originals wz
replaces, in the same shape, so that the three tables can move into the single
declaration of step 1 together.

## The population

* **zenoh-pico**: every `Z_FEATURE_*` name its `CMakeLists.txt` defines with `set(` or
  `option(`. The pinned source is the `vendor/zenoh-pico` submodule, present in every
  clone that initialised submodules, so this arm runs in the DEFAULT mode.
* **zenoh-c**: every cargo feature of its package, by cargo's own answer
  (`cargo metadata --no-deps`), less the two kinds that are derivable rather than
  judged: `default`, and the implicit feature of an optional dependency whose body is
  exactly that dependency (the rule `upstream_feature_census.py` documents). The pinned
  source is the checkout `scripts/install-zenoh-c.sh` provisions (`$WZ_ZENOH_C_REF`,
  default `~/zenoh-c-ref`), which only the lanes that install the oracle have, so this
  arm runs with `--zenoh-c` and the default run PRINTS that it was deferred.

Both pins are read from the shared deriver (`upstream_release_distance`); this file
spells no version.

## The four classes

Every switch gets exactly one row, and one of:

* `maps`    a wz cargo feature of the drop-in crate toggles the same capability. The
            anchor is `<crate>/<feature>`, and the crate must declare that feature.
* `always`  wz has the capability in that ABI build with no switch. The anchor is the
            tracked file that shows it, and the file must exist.
* `never`   wz does not have it in that ABI build. No anchor; the note must cite the
            open-debt item that owns the gap (`open-debt item <n>`), because a gap
            nobody carries is a gap nobody closes.
* `n/a`     the switch has no meaning for wz (a visibility toggle, a mutex strategy of
            the C implementation). No anchor; the note states why.

A `never` row is the table working, not a defect in it: it is how the capabilities
wz still owes for an upstream original are found at all.

## Agreement with the capability declaration

`deploy/capabilities.toml` names zenoh-pico's switch for a capability (`pico_flag`).
That is the same fact as a `maps` row here, written twice until step 1 merges the
two, so both directions are checked: a capability's `pico_flag` must have a `maps`
row to that capability, and a `maps` row to a capability must be that capability's
`pico_flag`.

## What this does NOT claim

That a `maps` or `always` capability is as DEEP as upstream's: that is the depth axis
(`depth_axis_census.py`). This is the breadth axis, per switch.

Usage:
    python3 scripts/lib/upstream_switch_map.py              # shape + pico arm
    python3 scripts/lib/upstream_switch_map.py --zenoh-c    # + zenoh-c arm
    python3 scripts/lib/upstream_switch_map.py --selftest
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts" / "lib"))

import capability_config  # noqa: E402
import upstream_release_distance as urd  # noqa: E402

WORKSPACE_MANIFEST = ROOT / "crates" / "Cargo.toml"
PICO_URL = "https://github.com/eclipse-zenoh/zenoh-pico"
ZENOH_C_URL = "https://github.com/eclipse-zenoh/zenoh-c"
PICO_SOURCE = ROOT / "vendor" / "zenoh-pico"
ZENOH_C_PACKAGE = "zenoh-c"

CLASSES = ("maps", "always", "never", "n/a")
DEBT_CITATION = "open-debt item "

# One row per zenoh-pico switch: (switch, class, anchor, note). Judged against
# `crates/wz-capi-pico`, the pico C ABI drop-in, at the pin. A `maps` anchor is a feature of
# that crate; an `always` anchor is the file that shows the capability is unconditional.
PICO_ROWS: tuple[tuple[str, str, str | None, str], ...] = (
    ("Z_FEATURE_UNSTABLE_API", "maps", "wz-capi-pico/unstable-api",
     "the entity ids, reliability, source info and the cancellation token, and the option "
     "fields that carry them; off, every option struct has upstream's default layout"),
    ("Z_FEATURE_CONNECTIVITY", "maps", "wz-capi-pico/connectivity",
     "the connectivity status and event doors; implies unstable-api, as upstream's CMake "
     "forces it off without the unstable API"),
    ("Z_FEATURE_PUBLICATION", "always", "crates/wz-capi-pico/src/pubsub.rs",
     "the publisher and z_put"),
    ("Z_FEATURE_ADVANCED_PUBLICATION", "maps", "wz-capi-pico/advanced",
     "the advanced publisher; one wz plane answers both advanced switches"),
    ("Z_FEATURE_SUBSCRIPTION", "always", "crates/wz-capi-pico/src/pubsub.rs",
     "the subscriber"),
    ("Z_FEATURE_ADVANCED_SUBSCRIPTION", "maps", "wz-capi-pico/advanced",
     "the advanced subscriber; the same wz plane as the publication switch"),
    ("Z_FEATURE_QUERY", "maps", "wz-capi-pico/query", "z_get and the querier"),
    ("Z_FEATURE_QUERYABLE", "maps", "wz-capi-pico/queryable",
     "z_declare_queryable and the replies"),
    ("Z_FEATURE_LIVELINESS", "maps", "wz-capi-pico/liveliness",
     "the token and the liveliness subscriber; pico's liveliness get needs QUERY as well, "
     "which wz spells as its own `liveliness-get` capability"),
    ("Z_FEATURE_INTEREST", "always", "crates/wz-capi-core/Cargo.toml",
     "declare-interest is part of every capi-core build"),
    ("Z_FEATURE_FRAGMENTATION", "always", "crates/wz-capi-pico/Cargo.toml",
     "transport-fragmentation is enabled unconditionally"),
    ("Z_FEATURE_ENCODING_VALUES", "always", "crates/wz-capi-pico/src/encoding.rs",
     "the predefined encoding table, held to the oracle"),
    ("Z_FEATURE_MULTI_THREAD", "maps", "wz-capi-pico/multi-thread",
     "which header arm the library is the drop-in for: on, the task doors, host sync and "
     "blocking channels; off, zp_read / zp_send_keep_alive / zp_send_join / zp_spin_once, "
     "a one-byte z_open_options_t and 48-byte channel collections. A session drives itself "
     "on its own runtime in both"),
    ("Z_FEATURE_LINK_TCP", "always", "crates/wz-capi-core/Cargo.toml",
     "the tcp/ link is part of every capi-core build"),
    ("Z_FEATURE_LINK_BLUETOOTH", "never", None,
     "no bt/ scheme in any wz build; open-debt item 912"),
    ("Z_FEATURE_LINK_WS", "maps", "wz-capi-pico/transport-link-ws",
     "the ws/ link, dial and accept; upstream allows it only on emscripten, wz on its host "
     "runtime"),
    ("Z_FEATURE_LINK_SERIAL", "maps", "wz-capi-pico/transport-link-serial",
     "the serial/ link, dial and accept, one peer at a time on a listener"),
    ("Z_FEATURE_LINK_SERIAL_USB", "never", None,
     "the USB CDC serial link of one board family; absent from wz; open-debt item 912"),
    ("Z_FEATURE_LINK_TLS", "maps", "wz-capi-pico/transport-link-tls",
     "the tls/ link, dial and accept"),
    ("Z_FEATURE_SCOUTING", "maps", "wz-capi-pico/scout", "z_scout and the hello family"),
    ("Z_FEATURE_LINK_UDP_MULTICAST", "never", None,
     "the C surface establishes unicast transports only; open-debt item 913"),
    ("Z_FEATURE_LINK_UDP_UNICAST", "maps", "wz-capi-pico/link-udp",
     "a udp/ endpoint to dial"),
    ("Z_FEATURE_MULTICAST_TRANSPORT", "never", None,
     "the C surface establishes unicast transports only, though the wz runtime has the "
     "multicast transport; open-debt item 913"),
    ("Z_FEATURE_UNICAST_TRANSPORT", "always", "crates/wz-capi-core/Cargo.toml",
     "the unicast transport"),
    ("Z_FEATURE_RAWETH_TRANSPORT", "never", None,
     "pico opens raw ethernet as a multicast-kind transport, which the C surface does not "
     "establish; the wz runtime has its framing and socket but no reth/ locator or "
     "session-open seam; open-debt item 911"),
    ("Z_FEATURE_TCP_NODELAY", "always", "crates/wz-runtime-tokio/src/lib.rs",
     "set on every TCP-backed link, as zenoh does; turning it off would be a policy"),
    ("Z_FEATURE_LOCAL_SUBSCRIBER", "maps", "wz-capi-pico/local-subscriber",
     "a session's own put reaches its own subscribers inside the call; allowed_origin and "
     "allowed_destination in the option structs; the write filter and matching count them"),
    ("Z_FEATURE_SESSION_CHECK", "always", "crates/wz-capi-pico/tests/session_check.rs",
     "a put, delete or get on an entity whose session was closed, and a reply on a query "
     "held past it, answer the session-closed error, as upstream's default does"),
    ("Z_FEATURE_BATCHING", "always", "crates/wz-capi-pico/src/session.rs",
     "zp_batch_start / flush / stop"),
    ("Z_FEATURE_BATCH_TX_MUTEX", "n/a", None,
     "which of pico's own mutexes a batch window holds; wz's batch window is per-face state"),
    ("Z_FEATURE_BATCH_PEER_MUTEX", "n/a", None,
     "the same locking choice of the C implementation, for the peer list"),
    ("Z_FEATURE_MATCHING", "always", "crates/wz-capi-pico/src/matching.rs",
     "the matching status and listeners"),
    ("Z_FEATURE_RX_CACHE", "always", "crates/wz-session-core/src/pubsub.rs",
     "a receive-path memo of which subscriptions a key matched (`MatchMemo`), always on in "
     "the host build where upstream's default is off; behaviour-neutral"),
    ("Z_FEATURE_UNICAST_PEER", "maps", "wz-capi-pico/peer",
     "the roles beyond the client; a stronger cut than pico's, which keeps a lone listener"),
    ("Z_FEATURE_AUTO_RECONNECT", "always", "crates/wz-capi-pico/src/session.rs",
     "the redial of a lost link"),
    ("Z_FEATURE_MULTICAST_DECLARATIONS", "never", None,
     "meaningful only over a multicast transport, which the C surface does not establish; "
     "open-debt item 913"),
    ("Z_FEATURE_LOCAL_QUERYABLE", "maps", "wz-capi-pico/local-queryable",
     "a session's own get reaches its own queryables, and their replies it, inside the "
     "calls; allowed_origin and allowed_destination in the option structs"),
    ("Z_FEATURE_ADMIN_SPACE", "maps", "wz-capi-pico/admin-space",
     "zp_start_admin_space / zp_stop_admin_space and the open flag, serving pico's "
     "@/<zid>/pico/** documents; the session-local connectivity half has no observer "
     "while the local switches are off"),
)

# One row per zenoh-c capability feature: (feature, class, anchor, note). Judged against
# `crates/wz-capi-c`, the zenoh-c drop-in, at the pin.
ZENOH_C_ROWS: tuple[tuple[str, str, str | None, str], ...] = (
    ("shared-memory", "maps", "wz-capi-c/zenoh-c-shared-memory",
     "the SHM provider and buffer doors"),
    ("unstable", "maps", "wz-capi-c/zenoh-c-no-unstable-api",
     "in the inverse sense: the unstable surface is built unless this feature removes it, "
     "where upstream's default is without it"),
    ("auth_usrpwd", "always", "crates/wz-capi-c/Cargo.toml",
     "the user/password handshake extension"),
    ("transport_compression", "always", "crates/wz-capi-c/Cargo.toml",
     "the batch compression codec, through session-extcompression"),
    ("transport_tcp", "always", "crates/wz-capi-core/Cargo.toml", "the tcp/ link"),
    ("transport_udp", "maps", "wz-capi-c/link-udp", "the udp/ link"),
    ("auth_pubkey", "maps", "wz-capi-c/auth_pubkey",
     "the public-key handshake, built from the four transport/auth/pubkey identity keys"),
    ("transport_multilink", "maps", "wz-capi-c/transport_multilink",
     "the multilink extension is built; a C session holds one link per peer, which is what "
     "upstream does at the default max_links of 1"),
    ("transport_quic", "maps", "wz-capi-c/transport_quic",
     "the quic/ link, dial and accept, with the transport/link/tls certificate material"),
    ("transport_quic_datagram", "maps", "wz-capi-c/transport_quic_datagram",
     "the quic-datagram/ link, over the quic link's certificate material"),
    ("transport_serial", "maps", "wz-capi-c/transport_serial", "the serial/ link"),
    ("transport_tls", "maps", "wz-capi-c/transport_tls",
     "the tls/ link, dial and accept, with the transport/link/tls certificate material"),
    ("transport_unixpipe", "maps", "wz-capi-c/transport_unixpipe",
     "the unixpipe/ link, on a Unix target"),
    ("transport_unixsock-stream", "maps", "wz-capi-c/transport_unixsock-stream",
     "the unixsock-stream/ link, on a Unix target"),
    ("transport_ws", "maps", "wz-capi-c/transport_ws", "the ws/ link, dial and accept"),
    ("transport_vsock", "maps", "wz-capi-c/transport_vsock",
     "the vsock/ link, on a Linux target"),
    ("stats", "maps", "wz-capi-c/stats",
     "the per-link transport counters; zenoh-c has no C door for them and neither has wz"),
)

TABLES = {"zenoh-pico": PICO_ROWS, "zenoh-c": ZENOH_C_ROWS}


class InputError(RuntimeError):
    """An input could not be read. Never a pass: always exit 2."""


def _cargo_metadata(manifest: Path) -> dict:
    cmd = ["cargo", "metadata", "--format-version=1", "--no-deps", "--manifest-path", str(manifest)]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
    except FileNotFoundError as e:
        raise InputError("cargo is not on PATH") from e
    if proc.returncode != 0:
        raise InputError(
            f"`cargo metadata --manifest-path {manifest}` failed (rc={proc.returncode}): "
            f"{proc.stderr.strip() or '<no stderr>'}"
        )
    try:
        md = json.loads(proc.stdout)
    except json.JSONDecodeError as e:
        raise InputError(f"`cargo metadata` on {manifest} printed no JSON ({e})") from e
    if not isinstance(md, dict) or not isinstance(md.get("packages"), list):
        raise InputError(f"`cargo metadata` on {manifest} carries no `packages` array")
    return md


def crate_features() -> dict[str, set[str]]:
    """Every workspace crate to the cargo features it declares."""
    md = _cargo_metadata(WORKSPACE_MANIFEST)
    out = {p["name"]: set(p.get("features", {})) for p in md["packages"]}
    if not any(out.values()):
        raise InputError("the workspace declares NO cargo features -- a population of zero")
    return out


def pins() -> dict[str, str | None]:
    """The pinned version of each original, from the shared deriver."""
    try:
        found = {**urd.submodule_pins(), **urd.script_pins(urd.tracked_paths())}
    except Exception as e:  # noqa: BLE001 - a deriver that cannot run is an INPUT fault
        raise InputError(f"the pin deriver could not run ({e})") from e
    return {"zenoh-pico": found.get(PICO_URL), "zenoh-c": found.get(ZENOH_C_URL)}


# ── the shape arm ───────────────────────────────────────────────────────────


def shape_arm(
    table: str,
    rows: tuple[tuple[str, str, str | None, str], ...],
    features: dict[str, set[str]],
) -> list[str]:
    """Is the table well formed, and does every anchor it names exist?"""
    failures: list[str] = []
    if not rows:
        return [f"{table}: the table is empty -- a census with no population reports green about nothing"]
    seen: dict[str, int] = {}
    for switch, cls, anchor, note in rows:
        seen[switch] = seen.get(switch, 0) + 1
        where = f"{table}: `{switch}`"
        if cls not in CLASSES:
            failures.append(f"{where} has class `{cls}`, not one of {', '.join(CLASSES)}")
            continue
        if not note.strip():
            failures.append(f"{where} carries no note -- a verdict with no reason is not one")
        if cls == "maps":
            crate, _, feature = (anchor or "").partition("/")
            if not crate or not feature:
                failures.append(f"{where} is `maps` but its anchor `{anchor}` is not `<crate>/<feature>`")
            elif crate not in features:
                failures.append(f"{where} maps to crate `{crate}`, which is not a workspace member")
            elif feature not in features[crate]:
                failures.append(
                    f"{where} maps to `{crate}/{feature}`, which that crate does not declare -- "
                    f"the anchor was renamed or removed and the row points at nothing"
                )
        elif cls == "always":
            path = (anchor or "").split("::", 1)[0]
            if not path:
                failures.append(f"{where} is `always` but names no file that shows it")
            elif not (ROOT / path).is_file():
                failures.append(f"{where} is `always` by `{anchor}`, and `{path}` is not a tracked file here")
        else:
            if anchor is not None:
                failures.append(f"{where} is `{cls}` and still names an anchor `{anchor}`")
            if cls == "never" and DEBT_CITATION not in note:
                failures.append(
                    f"{where} is `never` and its note cites no register item -- write "
                    f"`{DEBT_CITATION}<n>` into it"
                )
    for switch, n in sorted(seen.items()):
        if n > 1:
            failures.append(f"{table}: `{switch}` carries {n} rows -- two answers to one question")
    return failures


def declaration_arm(rows: tuple[tuple[str, str, str | None, str], ...], decl: dict) -> list[str]:
    """Do the pico rows and the capability declaration's `pico_flag` agree, both ways?"""
    failures: list[str] = []
    by_switch = {r[0]: r for r in rows}
    caps = {c["id"]: c for c in decl.get("capability", [])}
    for cap_id, cap in sorted(caps.items()):
        flag = cap.get("pico_flag")
        if not flag:
            continue
        row = by_switch.get(flag)
        want = f"wz-capi-pico/{cap_id}"
        if row is None or row[1] != "maps" or row[2] != want:
            got = "no row" if row is None else f"`{row[1]}` {row[2]}"
            failures.append(
                f"capability `{cap_id}` declares pico_flag `{flag}`, but its row here is {got}, "
                f"not `maps` {want}"
            )
    # The relation is many switches to one capability (pico splits the advanced publisher
    # and subscriber, wz builds them as one plane), so the second direction asks that a
    # capability's single pico_flag be ONE of the switches mapped to it, not the only one.
    mapped_to: dict[str, set[str]] = {}
    for switch, cls, anchor, _ in rows:
        if cls == "maps" and anchor and anchor.startswith("wz-capi-pico/"):
            mapped_to.setdefault(anchor.split("/", 1)[1], set()).add(switch)
    for cap_id, switches in sorted(mapped_to.items()):
        flag = caps.get(cap_id, {}).get("pico_flag")
        if cap_id in caps and flag not in switches:
            failures.append(
                f"zenoh-pico: {sorted(switches)} map to capability `{cap_id}`, whose pico_flag "
                f"is `{flag}` -- one fact written two ways"
            )
    return failures


# ── the upstream arms ───────────────────────────────────────────────────────

PICO_SWITCH = re.compile(r"\b(?:set|option)\(\s*(Z_FEATURE_[A-Z0-9_]+)\b")


def pico_switches(source: Path) -> tuple[str, set[str]]:
    """(version, switches) of a zenoh-pico source tree."""
    cmake = source / "CMakeLists.txt"
    version_file = source / "version.txt"
    if not cmake.is_file() or not version_file.is_file():
        raise InputError(
            f"no zenoh-pico source at {source} (CMakeLists.txt and version.txt). It is a "
            f"submodule: `git submodule update --init vendor/zenoh-pico`"
        )
    switches = set(PICO_SWITCH.findall(cmake.read_text(errors="replace")))
    if not switches:
        raise InputError(f"{cmake} defines no Z_FEATURE_* switch -- not a zenoh-pico CMakeLists")
    return version_file.read_text().strip(), switches


def zenoh_c_source() -> Path:
    return Path(os.environ.get("WZ_ZENOH_C_REF", Path.home() / "zenoh-c-ref"))


def zenoh_c_switches(source: Path) -> tuple[str, set[str], dict[str, str]]:
    """(version, capability features, {derived feature: why}) of a zenoh-c checkout."""
    injected = os.environ.get("WZ_ZENOH_C_METADATA")
    if injected:
        try:
            md = json.loads(Path(injected).read_text())
        except (OSError, json.JSONDecodeError) as e:
            raise InputError(f"the injected WZ_ZENOH_C_METADATA {injected} is not readable JSON ({e})") from e
        if not isinstance(md, dict) or not isinstance(md.get("packages"), list):
            raise InputError(f"the injected WZ_ZENOH_C_METADATA {injected} carries no `packages` array")
    else:
        manifest = source / "Cargo.toml"
        if not manifest.is_file():
            raise InputError(
                f"no zenoh-c checkout at {source}. Provision it with `bash scripts/install-zenoh-c.sh` "
                f"or point WZ_ZENOH_C_REF at a clone of the pinned tag"
            )
        md = _cargo_metadata(manifest)
    pkgs = [p for p in md["packages"] if isinstance(p, dict) and p.get("name") == ZENOH_C_PACKAGE]
    if len(pkgs) != 1:
        raise InputError(f"expected exactly one `{ZENOH_C_PACKAGE}` package, found {len(pkgs)}")
    pkg = pkgs[0]
    features: dict[str, list[str]] = pkg.get("features", {})
    optional = {d["name"] for d in pkg.get("dependencies", []) if d.get("optional")}
    derived: dict[str, str] = {}
    for name, body in features.items():
        if name == "default":
            derived[name] = "cargo's `default` aggregate"
        elif name in optional and body == [f"dep:{name}"]:
            derived[name] = f"cargo's implicit feature for the optional dependency `{name}`"
    return pkg.get("version", ""), set(features) - set(derived), derived


def upstream_arm(
    table: str,
    rows: tuple[tuple[str, str, str | None, str], ...],
    version: str,
    pinned: str | None,
    switches: set[str],
) -> list[str]:
    """Does the table still equal what the pinned original declares, both ways?"""
    if pinned is None:
        return [f"{table}: the pin deriver could not name this original -- graded against nothing"]
    if version != pinned:
        return [
            f"{table}: the source is version {version or '<unreadable>'}, not the pinned {pinned}. "
            f"Re-judge the rows in the round that moves the pin"
        ]
    judged = {r[0] for r in rows}
    failures = [
        f"{table}: upstream declares `{s}`, which no row judges -- a switch arrived UNJUDGED"
        for s in sorted(switches - judged)
    ]
    failures += [
        f"{table}: a row judges `{s}`, which upstream no longer declares -- the row outlived its subject"
        for s in sorted(judged - switches)
    ]
    return failures


# ── report ──────────────────────────────────────────────────────────────────


def report(table: str, rows: tuple[tuple[str, str, str | None, str], ...]) -> None:
    counts = {c: sum(1 for r in rows if r[1] == c) for c in CLASSES}
    print(
        f"  upstream-switch-map: {table}: {len(rows)} switch(es) -- "
        + ", ".join(f"{counts[c]} {c}" for c in CLASSES)
    )
    width = max((len(r[0]) for r in rows), default=4)
    for switch, cls, anchor, _ in rows:
        print(f"    {switch.ljust(width)}  {cls.ljust(6)}  {anchor or '-'}")
    never = [r[0] for r in rows if r[1] == "never"]
    if never:
        print(f"    -- NEVER by name: {', '.join(never)}")


# ── selftest ────────────────────────────────────────────────────────────────


def selftest() -> int:
    """Drive every failure branch from a faithful control, one mutation per case."""
    import tempfile

    features = {"wz-capi-pico": {"link-udp", "query"}, "wz-capi-c": {"query"}}
    control = (
        ("Z_FEATURE_LINK_UDP_UNICAST", "maps", "wz-capi-pico/link-udp", "the udp link"),
        ("Z_FEATURE_QUERY", "maps", "wz-capi-pico/query", "the query plane"),
        ("Z_FEATURE_PUBLICATION", "always", "crates/wz-capi-pico/Cargo.toml", "always built"),
        ("Z_FEATURE_LINK_BLUETOOTH", "never", None, "absent; open-debt item 1"),
        ("Z_FEATURE_BATCH_TX_MUTEX", "n/a", None, "a mutex strategy of the C implementation"),
    )
    decl = {"capability": [
        {"id": "link-udp", "pico_flag": "Z_FEATURE_LINK_UDP_UNICAST"},
        {"id": "query", "pico_flag": "Z_FEATURE_QUERY"},
    ]}
    switches = {r[0] for r in control}

    def swap(i: int, row: tuple) -> tuple:
        return control[:i] + (row,) + control[i + 1:]

    shape_cases: list[tuple[str, tuple, bool]] = [
        ("the faithful table passes", control, True),
        ("an empty table fails", (), False),
        ("an unknown class fails", swap(4, ("Z_FEATURE_BATCH_TX_MUTEX", "maybe", None, "x")), False),
        ("a maps row to an undeclared feature fails",
         swap(1, ("Z_FEATURE_QUERY", "maps", "wz-capi-pico/queries", "x")), False),
        ("a maps row to a non-member crate fails",
         swap(1, ("Z_FEATURE_QUERY", "maps", "wz-nope/query", "x")), False),
        ("an always row naming a missing file fails",
         swap(2, ("Z_FEATURE_PUBLICATION", "always", "crates/no/such.rs", "x")), False),
        ("a never row citing no register item fails",
         swap(3, ("Z_FEATURE_LINK_BLUETOOTH", "never", None, "absent")), False),
        ("an n/a row with an anchor fails",
         swap(4, ("Z_FEATURE_BATCH_TX_MUTEX", "n/a", "wz-capi-pico/query", "x")), False),
        ("a row with no note fails", swap(4, ("Z_FEATURE_BATCH_TX_MUTEX", "n/a", None, " ")), False),
        ("a duplicated switch fails", control + (control[0],), False),
    ]
    for label, rows, want_ok in shape_cases:
        got_ok = not shape_arm("t", rows, features)
        if got_ok != want_ok:
            print(f"  selftest FAIL [{label}]: expected {'pass' if want_ok else 'FAIL'}", file=sys.stderr)
            return 1

    decl_cases: list[tuple[str, tuple, dict, bool]] = [
        ("the declaration agrees", control, decl, True),
        ("a pico_flag with no maps row fails",
         swap(1, ("Z_FEATURE_QUERY", "never", None, "open-debt item 1")), decl, False),
        ("a maps row to a capability with another pico_flag fails", control,
         {"capability": [{"id": "link-udp", "pico_flag": "Z_FEATURE_LINK_UDP_UNICAST"},
                         {"id": "query", "pico_flag": "Z_FEATURE_QUERYABLE"}]}, False),
        ("two switches mapping to one capability agree when one is its pico_flag",
         control + (("Z_FEATURE_LOCAL_QUERY", "maps", "wz-capi-pico/query", "x"),), decl, True),
    ]
    for label, rows, d, want_ok in decl_cases:
        got_ok = not declaration_arm(rows, d)
        if got_ok != want_ok:
            print(f"  selftest FAIL [{label}]: expected {'pass' if want_ok else 'FAIL'}", file=sys.stderr)
            return 1

    up_cases: list[tuple[str, str, str | None, set[str], bool]] = [
        ("the faithful upstream passes", "1.0.0", "1.0.0", switches, True),
        ("a switch upstream GREW is unjudged", "1.0.0", "1.0.0", switches | {"Z_FEATURE_NEW"}, False),
        ("a switch upstream DROPPED is stale", "1.0.0", "1.0.0", switches - {"Z_FEATURE_QUERY"}, False),
        ("a source at another version is refused", "0.9.0", "1.0.0", switches, False),
        ("an unreadable pin is refused", "1.0.0", None, switches, False),
    ]
    for label, version, pinned, ups, want_ok in up_cases:
        got_ok = not upstream_arm("t", control, version, pinned, ups)
        if got_ok != want_ok:
            print(f"  selftest FAIL [{label}]: expected {'pass' if want_ok else 'FAIL'}", file=sys.stderr)
            return 1

    # The readers: a CMakeLists with both spellings, and every unusable zenoh-c answer.
    with tempfile.TemporaryDirectory() as td:
        src = Path(td)
        (src / "version.txt").write_text("1.0.0\n")
        (src / "CMakeLists.txt").write_text(
            'set(Z_FEATURE_QUERY 1 CACHE STRING "q")\noption(Z_FEATURE_LINK_TCP "t" ON)\n'
            "# Z_FEATURE_COMMENTED is not a definition\n"
        )
        version, found = pico_switches(src)
        if version != "1.0.0" or found != {"Z_FEATURE_QUERY", "Z_FEATURE_LINK_TCP"}:
            print(f"  selftest FAIL [the pico reader]: read {version} {sorted(found)}", file=sys.stderr)
            return 1
        (src / "CMakeLists.txt").write_text("project(x)\n")
        try:
            pico_switches(src)
        except InputError:
            pass
        else:
            print("  selftest FAIL [a CMakeLists with no switch]: ACCEPTED", file=sys.stderr)
            return 1

        meta = src / "meta.json"
        meta.write_text(json.dumps({"packages": [{
            "name": ZENOH_C_PACKAGE, "version": "1.0.0",
            "features": {"default": ["a"], "a": [], "zenoh-ext": ["dep:zenoh-ext"], "b": ["dep:zenoh-shm", "a"]},
            "dependencies": [{"name": "zenoh-ext", "optional": True}, {"name": "zenoh-shm", "optional": True}],
        }]}))
        os.environ["WZ_ZENOH_C_METADATA"] = str(meta)
        try:
            version, caps, derived = zenoh_c_switches(src)
        finally:
            os.environ.pop("WZ_ZENOH_C_METADATA", None)
        if caps != {"a", "b"} or set(derived) != {"default", "zenoh-ext"}:
            print(f"  selftest FAIL [the zenoh-c reader]: {sorted(caps)} {sorted(derived)}", file=sys.stderr)
            return 1
        for label, text in (("an empty file", ""), ("JSON with no packages", '{"x": 1}'),
                            ("packages that is not an array", '{"packages": {}}'),
                            ("no zenoh-c package", '{"packages": []}')):
            meta.write_text(text)
            os.environ["WZ_ZENOH_C_METADATA"] = str(meta)
            try:
                zenoh_c_switches(src)
            except InputError:
                continue
            except Exception as e:  # noqa: BLE001 - the defect IS "some other exception"
                print(f"  selftest FAIL [{label}]: raised {type(e).__name__}, not InputError", file=sys.stderr)
                return 1
            else:
                print(f"  selftest FAIL [{label}]: ACCEPTED", file=sys.stderr)
                return 1
            finally:
                os.environ.pop("WZ_ZENOH_C_METADATA", None)

    print(
        f"  upstream-switch-map: selftest {len(shape_cases)} shape + {len(decl_cases)} declaration "
        f"+ {len(up_cases)} upstream case(s) and the two readers pass"
    )
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description="zenoh-pico and zenoh-c build switches against wz")
    ap.add_argument("--zenoh-c", action="store_true", help="also grade the zenoh-c table against its checkout")
    ap.add_argument("--selftest", action="store_true", help="drive every failure branch on fixtures")
    args = ap.parse_args()
    if args.selftest:
        return selftest()

    try:
        features = crate_features()
        pinned = pins()
        decl = capability_config.load_decl()
    except InputError as e:
        print(f"  upstream-switch-map: INPUT -- {e}", file=sys.stderr)
        return 2

    failures: list[str] = []
    for table, rows in TABLES.items():
        report(table, rows)
        failures += shape_arm(table, rows, features)
    failures += declaration_arm(PICO_ROWS, decl)

    try:
        version, switches = pico_switches(PICO_SOURCE)
        failures += upstream_arm("zenoh-pico", PICO_ROWS, version, pinned["zenoh-pico"], switches)
        if args.zenoh_c:
            version, caps, derived = zenoh_c_switches(zenoh_c_source())
            for name, why in sorted(derived.items()):
                print(f"    zenoh-c not a switch: {name} -- {why}")
            failures += upstream_arm("zenoh-c", ZENOH_C_ROWS, version, pinned["zenoh-c"], caps)
        else:
            print(
                "    -- zenoh-c upstream arm DEFERRED: run with --zenoh-c where the pinned "
                "zenoh-c checkout is provisioned. Without it, a switch zenoh-c GREW cannot be seen."
            )
    except InputError as e:
        print(f"  upstream-switch-map: INPUT -- {e}", file=sys.stderr)
        return 2

    if failures:
        for f in failures:
            print(f"  upstream-switch-map: FAIL -- {f}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
