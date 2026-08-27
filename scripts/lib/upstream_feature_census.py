#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

"""R2162 (no register item) — the upstream `zenoh` crate's CAPABILITY FEATURES
as a denominator, and the wz cargo feature that answers each one as the
numerator.

It answers for open-debt item 199, which lives in the agent-memory register
OUTSIDE this tree and therefore has no `debt-` id to cite — the same position
`debt_plane_census.py` and `deepenable_audit.py` record for themselves.

## The gap this closes

Item 199 recorded a measurement: of the zenoh crate's 19 capability-shaped
cargo features, 18 have a wz counterpart and one (`tracing-instrument`) does
not. That number was arrived at by reading upstream's manifest once, by hand,
and NOTHING in this tree re-derived it afterwards. Two things follow, and both
are the failure mode this project keeps paying for:

  * upstream growing a capability feature is INVISIBLE here. `zenoh` 1.5.0
    declares `transport_quic_datagram`, which zenoh 1.0 did not; a wz that had
    never heard of QUIC datagrams would have graded 18/18 and reported full
    coverage of a surface that had moved.
  * the 18 is a remembered number. Item 47's whole family is "a register reason
    outlives the code", and a coverage fraction nobody re-runs is that.

Every other instrument over wz's capability surface — the A3 grade,
`audit-catalog-status.sh`, `apfull_membership.py` — starts from a WZ ATOM and
asks what became of it. Starting from upstream is the only direction that can
see a capability wz has never heard of, and before this script the config
census (`HONOURED_CONFIG_KEYS` and its unhonoured half) was the only instrument
in the tree that ran that direction over a zenoh surface. This is the second.

## The two arms, and why they are separate invocations

**The SHAPE arm** (default) needs no upstream checkout. It reads the wz side
with cargo's own parse and asks whether `ANSWERS` is well formed: every wz
feature it names is really declared by a workspace member, every upstream
feature is judged exactly once, and every UNANSWERED row cites the open-debt
item that owns it. That arm has its input on every machine, so it runs in the
fast static lane (Layer C0) with nothing built.

**The UPSTREAM arm** (`--upstream`) needs a zenoh source tree, and asks the
question the shape arm structurally cannot: does the pinned surface still equal
what upstream declares? Both directions FAIL —

  * upstream declares a feature no row and no exclusion names: a capability
    arrived UNJUDGED. This is the direction the item was blind in.
  * a row or an exclusion names a feature upstream no longer declares: the
    table has outlived its subject.

It runs in Layer Z, which is where the zenoh source tree already is (Layer Z
provisions zenohd, and `deepenable_audit.py` sits beside it for the same
reason). Without an anchor it exits 2 and names every path it tried — a gate
that cannot read its input must not report green, which is the rule the schema
pin and `deepenable_audit.py` already apply.

⚠ The default run PRINTS that the upstream arm was deferred, by name. A skip
that says nothing reads exactly like coverage.

## Why the exclusions are mostly DERIVED rather than listed

The manifest's `[features]` table is not the population. Two of its entries are
not capabilities at all and both are recognisable mechanically, so they are
recognised mechanically rather than typed into a list that would go stale:

  * `default` — an aggregate of other rows, by name.
  * the IMPLICIT feature cargo synthesises for an optional dependency
    (`zenoh-shm = ["dep:zenoh-shm"]`). It is the dependency-enabling half of
    `shared-memory`, which is the capability. Derived as "the feature's name is
    an optional dependency of the package AND its body is exactly that dep".
    ⚠ This one is INVISIBLE to a reader of `zenoh/Cargo.toml` — it appears in
    no `[features]` table there. Asking cargo rather than the file is what
    surfaces it, and it is why this script uses `cargo metadata` and not a TOML
    read.

Only `PINNED_NON_CAPABILITY` is typed by hand, because "this feature gates
visibility of internals rather than a capability" is a judgement no field
carries. Each entry states its reason, and the upstream arm holds it to the
same both-directions rule as the answered rows: an exclusion for a feature
upstream dropped is as much a stale fact as a missing row.

## What this does NOT claim

That wz's counterpart is as DEEP as upstream's. `transport-link-serial`
answering `transport_serial` says wz has a serial link feature, not that it
carries every parameter zenoh's does. That is open-debt item 200's question
(the depth axis), and item 220's for the config surface; this script is the
BREADTH axis and says so rather than letting a reader take a full table for a
full implementation.

Usage:
    python3 scripts/lib/upstream_feature_census.py            # shape arm
    python3 scripts/lib/upstream_feature_census.py --upstream # + upstream arm
    python3 scripts/lib/upstream_feature_census.py --selftest
"""

from __future__ import annotations

import argparse
import glob
import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
WORKSPACE_MANIFEST = ROOT / "crates" / "Cargo.toml"

UPSTREAM_PACKAGE = "zenoh"
# The pinned upstream. build-zenohd.sh asserts the same equality against the
# same checkout before it builds the oracle, for the same reason: a cache that
# later resolves a different zenoh must fail fast rather than silently regrade
# the surface. Bumping it is a round that RE-JUDGES the table below.
UPSTREAM_VERSION = "1.5.0"

# Features that are upstream capability toggles by shape but not by meaning.
# `default` and the implicit optional-dep feature are DERIVED (see the module
# doc); these three are not derivable and are named with their reason.
PINNED_NON_CAPABILITY: dict[str, str] = {
    "internal": (
        "widens the VISIBILITY of zenoh-internal items to other zenoh crates "
        "(`zenoh-keyexpr/internal` et al). It gates no capability an operator "
        "can deploy -- a node built with and without it speaks the same wire"
    ),
    "unstable": (
        "un-hides API surface upstream has not committed to. wz's drop-in claim "
        "is the two C ABIs and the wire, none of which this moves; the Rust "
        "usability layer it exposes is the axis item 199 itself ruled out"
    ),
    "internal_config": (
        "un-hides config-struct internals to zenoh's own crates. Same shape as "
        "`internal`, one crate narrower"
    ),
}

# The census proper: one row per upstream CAPABILITY feature.
#
# `wz` is the cargo feature in THIS workspace that answers it -- the anchor, and
# it is a cargo feature rather than a prose description on purpose (R2150: an
# anchor must be in the code, because a comment is not a mechanism). The shape
# arm holds every one against cargo's own view of the workspace, so a renamed or
# deleted wz feature reds here instead of leaving a row pointing at nothing.
#
# `wz = None` means UNANSWERED, and the note must cite the open-debt item that
# owns it. An unanswered row is not a defect in this table -- it is the table
# working.
ANSWERS: tuple[tuple[str, str | None, str], ...] = (
    (
        "auth_pubkey",
        "access-extauth-pubkey",
        "the RSA-keypair handshake extension; wz drives it against a real "
        "zenohd in pubkey_zenohd_interop",
    ),
    (
        "auth_usrpwd",
        "access-extauth-usrpwd",
        "the user/password handshake extension",
    ),
    (
        "plugins",
        "plugin-host-trait",
        "the compiled-in plugin HOST surface -- upstream's `zenoh::api::plugins` "
        "(PluginControl / PluginStatus) behind the same toggle",
    ),
    (
        "runtime_plugins",
        "adminspace-config-hotreload",
        "the config-diff-driven runtime plugin lifecycle -- upstream gates its "
        "`PluginDiff` adminspace legs on this, and wz's hot-reload feature is "
        "the same surface over its own registry",
    ),
    (
        "shared-memory",
        "transport-shm",
        "the SHM buffer plane; `session-extshm` composes it for the "
        "establishment extension",
    ),
    ("stats", "transport-stats", "per-transport counters"),
    ("transport_multilink", "transport-multilink", "several links per session"),
    ("transport_compression", "transport-compression", "the batch compression codec"),
    ("transport_quic", "transport-link-quic", "the QUIC stream link"),
    (
        "transport_quic_datagram",
        "transport-link-quic-datagram",
        "the QUIC DATAGRAM link -- upstream added it after 1.0, which is the "
        "kind of arrival only this direction can see",
    ),
    ("transport_serial", "transport-link-serial", "the serial link"),
    ("transport_unixpipe", "transport-link-unixpipe", "the named-pipe link"),
    ("transport_tcp", "transport-link-tcp", "the TCP link"),
    ("transport_tls", "transport-link-tls", "the TLS link"),
    ("transport_udp", "transport-link-udp", "the UDP link"),
    (
        "transport_unixsock-stream",
        "transport-link-unixsock",
        "the unix-domain stream link",
    ),
    ("transport_ws", "transport-link-ws", "the WebSocket link"),
    ("transport_vsock", "transport-link-vsock", "the AF_VSOCK link"),
    (
        "tracing-instrument",
        None,
        "UNANSWERED -- open-debt item 201. An instrumentation axis, not a "
        "protocol capability: it decorates zenoh-task / zenoh-runtime futures "
        "with tracing spans. Named rather than excused, because the one gap in "
        "an otherwise closed surface is the whole value of counting it",
    ),
)

# The shape a note must have to hand a row's residue to the register. Checked,
# not trusted: an UNANSWERED row whose note cites nothing is a gap with no owner.
DEBT_CITATION = "open-debt item "


class InputError(RuntimeError):
    """The census cannot read an input. Never a pass -- always exit 2."""


def _cargo_metadata(manifest: Path) -> dict:
    cmd = [
        "cargo",
        "metadata",
        "--format-version=1",
        "--no-deps",
        "--manifest-path",
        str(manifest),
    ]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
    except FileNotFoundError as e:
        raise InputError("cargo is not on PATH") from e
    if proc.returncode != 0:
        raise InputError(
            f"`cargo metadata --manifest-path {manifest}` failed "
            f"(rc={proc.returncode}): {proc.stderr.strip() or '<no stderr>'}"
        )
    return json.loads(proc.stdout)


def workspace_features() -> dict[str, list[str]]:
    """Every cargo feature any workspace member declares, to its owning crates.

    Raises rather than returning a partial answer: a census that cannot read its
    input must not report coverage.
    """
    md = _cargo_metadata(WORKSPACE_MANIFEST)
    owners: dict[str, list[str]] = {}
    for pkg in md["packages"]:
        for feature in pkg.get("features", {}):
            owners.setdefault(feature, []).append(pkg["name"])
    if not owners:
        raise InputError(
            "the workspace declares NO cargo features -- a population of zero "
            "would report green about nothing"
        )
    return owners


def upstream_anchors() -> list[Path]:
    """Every place a pinned zenoh source tree is looked for, in order.

    The chain deliberately mirrors `scripts/build-zenohd.sh`: the census and the
    reference oracle must not be able to disagree about WHICH upstream they mean.
    Absolute paths are resolved per machine and never written into a tracked
    file (the CLAUDE.md rule) -- hence an env override and $HOME-relative globs.
    """
    out: list[Path] = []
    explicit = os.environ.get("ZENOHD_SRC")
    if explicit:
        out.append(Path(explicit) / "zenoh" / "Cargo.toml")
    # Source A2: the shallow clone build-zenohd.sh makes on a runner with no
    # cargo-git checkout.
    out.append(ROOT / "target" / "zenohd-build" / "zenoh-src" / "zenoh" / "Cargo.toml")
    # Source A: the cargo git checkout, hash-named, hence the glob.
    home = Path(os.environ.get("HOME", "~")).expanduser()
    out.extend(
        Path(p)
        for p in sorted(
            glob.glob(str(home / ".cargo/git/checkouts/zenoh-*/*/zenoh/Cargo.toml"))
        )
    )
    # Source B: what `cargo install zenohd` leaves in the registry cache.
    cargo_home = Path(os.environ.get("CARGO_HOME", home / ".cargo"))
    out.extend(
        Path(p)
        for p in sorted(
            glob.glob(
                str(cargo_home / f"registry/src/*/zenoh-{UPSTREAM_VERSION}/Cargo.toml")
            )
        )
    )
    return out


def upstream_package() -> dict:
    """The upstream `zenoh` package as cargo itself resolves it.

    `WZ_UPSTREAM_FEATURE_METADATA` substitutes a `cargo metadata` JSON directly.
    That seam exists for `--selftest`, which must be able to drive both
    directions of the comparison on a machine with no zenoh checkout at all.
    """
    injected = os.environ.get("WZ_UPSTREAM_FEATURE_METADATA")
    if injected:
        md = json.loads(Path(injected).read_text())
    else:
        tried = upstream_anchors()
        found = next((p for p in tried if p.is_file()), None)
        if found is None:
            raise InputError(
                "no pinned zenoh source tree found. Tried, in order:\n    "
                + "\n    ".join(str(p) for p in tried)
                + "\n  Provision one with `bash scripts/build-zenohd.sh` "
                "(ZENOHD_ALLOW_CLONE=1 on a machine with no cargo checkout), "
                "or point ZENOHD_SRC at a clone of the pinned tag."
            )
        md = _cargo_metadata(found)
    pkgs = [p for p in md["packages"] if p["name"] == UPSTREAM_PACKAGE]
    if len(pkgs) != 1:
        raise InputError(
            f"expected exactly one `{UPSTREAM_PACKAGE}` package in the upstream "
            f"metadata, found {len(pkgs)}"
        )
    return pkgs[0]


def classify_upstream(pkg: dict) -> tuple[set[str], dict[str, str]]:
    """Split upstream's features into CAPABILITIES and derived non-capabilities.

    Returns (capabilities, {non-capability: why it is one}). The two derived
    kinds are named in the returned reasons so the printed breakdown can show
    what was removed from the denominator and on what ground.
    """
    features: dict[str, list[str]] = pkg.get("features", {})
    optional = {d["name"] for d in pkg.get("dependencies", []) if d.get("optional")}
    derived: dict[str, str] = {}
    for name, body in features.items():
        if name == "default":
            derived[name] = "derived: cargo's `default` aggregate"
        elif name in optional and body == [f"dep:{name}"]:
            derived[name] = (
                f"derived: cargo's implicit feature for the optional dependency "
                f"`{name}`"
            )
    for name, why in PINNED_NON_CAPABILITY.items():
        if name in features:
            derived[name] = f"pinned: {why}"
    return set(features) - set(derived), derived


def shape_arm(owners: dict[str, list[str]]) -> tuple[list[str], list[tuple]]:
    """Is the table well formed, and does every anchor it names exist in wz?"""
    failures: list[str] = []
    rows: list[tuple] = []

    if not ANSWERS:
        failures.append(
            "ANSWERS is empty -- a census with no population reports green about "
            "nothing"
        )

    seen: dict[str, int] = {}
    for upstream, wz, note in ANSWERS:
        seen[upstream] = seen.get(upstream, 0) + 1
        if wz is None:
            if DEBT_CITATION not in note:
                failures.append(
                    f"`{upstream}` is UNANSWERED and its note cites no register "
                    f"item -- a gap with no owner is a gap nobody is carrying. "
                    f"Write `{DEBT_CITATION}<n>` into the note"
                )
        elif wz not in owners:
            failures.append(
                f"`{upstream}` is answered by wz feature `{wz}`, which NO "
                f"workspace member declares -- the anchor was renamed or removed "
                f"and this row now points at nothing"
            )
        rows.append((upstream, wz, note))

    for upstream, n in sorted(seen.items()):
        if n > 1:
            failures.append(
                f"`{upstream}` carries {n} rows -- two answers to one question"
            )

    overlap = sorted(set(seen) & set(PINNED_NON_CAPABILITY))
    if overlap:
        failures.append(
            f"judged as BOTH a capability and a non-capability: {overlap} -- an "
            f"excluded feature that also carries a row is two verdicts"
        )

    answered = [r for r in rows if r[1] is not None]
    if not answered:
        failures.append("no row is ANSWERED -- the numerator emptied")
    unanswered = [r for r in rows if r[1] is None]

    print(
        f"  upstream-feature-census: {len(rows)} upstream capability feature(s) "
        f"judged -- {len(answered)} answered by a wz feature, "
        f"{len(unanswered)} UNANSWERED"
    )
    width = max((len(r[0]) for r in rows), default=4)
    for upstream, wz, note in rows:
        anchor = wz if wz else "-- none --"
        print(f"    {upstream.ljust(width)}  {anchor}")
        print(f"    {' ' * width}    {note}")
    if unanswered:
        # The breakdown, not the total. "18 of 19" reads the same whether the
        # one gap is instrumentation or the TCP link.
        print(f"    -- UNANSWERED by name: {', '.join(r[0] for r in unanswered)}")
    return failures, rows


def upstream_arm(rows: list[tuple]) -> list[str]:
    """Does the pinned surface still equal what upstream declares?"""
    failures: list[str] = []
    pkg = upstream_package()
    if pkg["version"] != UPSTREAM_VERSION:
        failures.append(
            f"the zenoh source tree is version {pkg['version']}, not the pinned "
            f"{UPSTREAM_VERSION} -- grading a surface against a different "
            f"upstream is not the measurement this table records. Move "
            f"UPSTREAM_VERSION in a round that RE-JUDGES the rows"
        )
        return failures

    capabilities, derived = classify_upstream(pkg)
    judged = {r[0] for r in rows}

    unjudged = sorted(capabilities - judged)
    for name in unjudged:
        failures.append(
            f"upstream declares capability feature `{name}`, which no row and no "
            f"exclusion names -- a capability arrived UNJUDGED. Answer it with a "
            f"wz feature, or record it UNANSWERED with the register item that "
            f"owns it"
        )
    stale = sorted(judged - capabilities)
    for name in stale:
        why = derived.get(name)
        failures.append(
            f"a row names `{name}`, which upstream "
            + (
                f"no longer treats as a capability ({why})"
                if why
                else "no longer declares"
            )
            + " -- the table has outlived its subject"
        )
    stale_excl = sorted(set(PINNED_NON_CAPABILITY) - set(pkg.get("features", {})))
    for name in stale_excl:
        failures.append(
            f"PINNED_NON_CAPABILITY names `{name}`, which upstream no longer "
            f"declares -- an exclusion for a feature that is gone is as stale as "
            f"a missing row"
        )

    print(
        f"  upstream-feature-census: upstream {UPSTREAM_PACKAGE} "
        f"{pkg['version']} declares {len(pkg.get('features', {}))} feature(s); "
        f"{len(capabilities)} are capabilities, {len(derived)} are not"
    )
    for name, why in sorted(derived.items()):
        print(f"    not a capability: {name} -- {why}")
    return failures


def selftest() -> int:
    """Drive BOTH directions of the upstream arm against injected metadata.

    The upstream arm is the half no machine without a zenoh checkout exercises,
    so it gets a population here instead of none. One case is the CONTROL -- the
    faithful surface, which must pass -- and every other case MUTATES that same
    fixture at the exact place the arm reads. A case that expects a FAIL without
    mutating anything is green from birth: it can only fail when the control
    already has, which makes it a second copy of the control rather than a test
    of the branch it names.
    """
    import tempfile

    base_rows = list(ANSWERS)
    judged = [r[0] for r in base_rows]

    def metadata(
        features: dict[str, list[str]], version: str = UPSTREAM_VERSION
    ) -> dict:
        return {
            "packages": [
                {
                    "name": UPSTREAM_PACKAGE,
                    "version": version,
                    "features": features,
                    "dependencies": [{"name": "zenoh-shm", "optional": True}],
                }
            ]
        }

    faithful: dict[str, list[str]] = {name: [] for name in judged}
    faithful["default"] = list(judged[:2])
    faithful["zenoh-shm"] = ["dep:zenoh-shm"]
    for name in PINNED_NON_CAPABILITY:
        faithful[name] = []

    cases: list[tuple[str, dict, bool]] = [
        ("a faithful surface passes", metadata(faithful), True),
        (
            "a capability upstream GREW is unjudged",
            metadata({**faithful, "transport_zzz_new": []}),
            False,
        ),
        (
            "a row whose feature upstream DROPPED is stale",
            metadata({k: v for k, v in faithful.items() if k != judged[0]}),
            False,
        ),
        (
            "an exclusion upstream DROPPED is stale",
            metadata(
                {
                    k: v
                    for k, v in faithful.items()
                    if k != next(iter(PINNED_NON_CAPABILITY))
                }
            ),
            False,
        ),
        (
            "a different upstream VERSION is refused",
            metadata(faithful, version="9.9.9"),
            False,
        ),
        (
            # The derivation is a CONJUNCTION -- the name is an optional dep AND
            # the body is exactly that dep -- and only the first half had a case.
            # Measured by mutating the implementation: dropping the body conjunct
            # left the selftest at 6/6 and the live upstream arm at rc=0, so the
            # narrowness was asserted nowhere. Here the optional dep's feature
            # does MORE than enable it, which makes it a real capability upstream
            # is declaring, so it must be JUDGED rather than derived away.
            #
            # ⚠ The case this replaced re-used the faithful fixture unchanged and
            # expected a pass, so it could only fail when case 1 already had --
            # green from birth, which is the one thing every case here must not
            # be (R2137's lesson, in the file that lesson is about).
            "an optional-dep feature that does MORE than enable the dep is a "
            "capability",
            metadata({**faithful, "zenoh-shm": ["dep:zenoh-shm", judged[0]]}),
            False,
        ),
    ]

    passed = 0
    with tempfile.TemporaryDirectory() as td:
        path = Path(td) / "meta.json"
        for label, md, want_ok in cases:
            path.write_text(json.dumps(md))
            os.environ["WZ_UPSTREAM_FEATURE_METADATA"] = str(path)
            try:
                failures = upstream_arm(base_rows)
            except InputError as e:  # a broken fixture is not a negative result
                print(f"  selftest FAIL [{label}]: input error {e}", file=sys.stderr)
                return 1
            got_ok = not failures
            if got_ok != want_ok:
                print(
                    f"  selftest FAIL [{label}]: expected "
                    f"{'pass' if want_ok else 'FAIL'}, got "
                    f"{'pass' if got_ok else 'FAIL'} {failures}",
                    file=sys.stderr,
                )
                return 1
            passed += 1
    os.environ.pop("WZ_UPSTREAM_FEATURE_METADATA", None)
    print(f"  upstream-feature-census: selftest {passed}/{len(cases)} case(s) pass")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description="upstream zenoh capability census")
    ap.add_argument(
        "--upstream",
        action="store_true",
        help="also compare the table against a pinned zenoh source tree",
    )
    ap.add_argument(
        "--selftest",
        action="store_true",
        help="drive both directions of the upstream arm against fixtures",
    )
    args = ap.parse_args()

    if args.selftest:
        return selftest()

    try:
        owners = workspace_features()
    except InputError as e:
        print(f"  upstream-feature-census: INPUT -- {e}", file=sys.stderr)
        return 2

    failures, rows = shape_arm(owners)

    if args.upstream:
        try:
            failures += upstream_arm(rows)
        except InputError as e:
            print(f"  upstream-feature-census: INPUT -- {e}", file=sys.stderr)
            return 2
    else:
        # A deferral states itself. A skip that says nothing reads as coverage.
        print(
            "    -- upstream arm DEFERRED: run with --upstream where a pinned "
            "zenoh source tree is (Layer Z). Without it, a capability upstream "
            "GREW cannot be seen from here."
        )

    if failures:
        for f in failures:
            print(f"  upstream-feature-census: FAIL -- {f}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
