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

  * PROBED           -- derived by importing `feature_gate_diagnostic`, so
                        widening that axis moves this fraction automatically
                        rather than needing a second edit;
  * NO_PUBLIC_PATH   -- derived from the same module's declaration;
  * UNPROBED         -- named here, per package, WITH the reason that package
                        is still waiting.

A pair in none of the three is a FINDING, so the population cannot grow in
silence: a feature added tomorrow that gates a public item reds this until
somebody decides which it is. A name in UNPROBED that no longer gates a public
item is a FINDING too.

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
import json
import pathlib
import re
import subprocess
import sys
import tempfile

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

# path -> why this gate cannot classify the site there. BOTH DIRECTIONS: an
# undeclared unclassified site FAILS, and a declaration with no site FAILS.
UNCLASSIFIED_DECLARED: dict[str, str] = {
    "crates/wz-runtime-tokio/tests/multicast_pubsub_loopback.rs": (
        "the attribute is followed by the continuation of a multi-line string "
        "literal belonging to an earlier attribute, so the next source line is "
        "not the item this one is attached to"
    ),
}

# package -> (why this package is still waiting, the features waiting).
#
# A SET, not a count. Adding a feature that gates a public item without listing
# it FAILS; listing one that no longer does FAILS. Both directions are what
# keeps this from being the permission slip a bare number would be.
UNPROBED: dict[str, tuple[str, frozenset[str]]] = {
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
        "one feature, and it selects between two ABI spellings rather than "
        "adding or removing a Rust path a consumer names",
        frozenset({"zenoh-c-no-unstable-api"}),
    ),
    "wz-codecs-test-support": (
        "a test-support crate: its consumers are this workspace's own test "
        "targets, which the lanes already compile under every combination",
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
    "wz-runtime-tokio": (
        "the largest surface in the workspace and the one a real consumer "
        "actually imports; this is where widening the axis buys the most, and "
        "it is deliberately the next round's work rather than this one's",
        frozenset(
            {
                "access-acl",
                "access-downsampling",
                "access-extauth-pubkey",
                "access-quota",
                "adminspace-config-hotreload",
                "adminspace-core",
                "adminspace-introspection-handlers",
                "adminspace-plugins-handlers",
                "ext-pubsub-advanced-cache",
                "ext-pubsub-advanced-history",
                "ext-pubsub-advanced-publisher",
                "ext-pubsub-advanced-recovery",
                "ext-pubsub-advanced-subscriber",
                "ext-pubsub-group-membership",
                "ext-pubsub-serde-codec",
                "live-capture",
                "liveliness-get",
                "locator-iface",
                "plugin-dynamic-loading",
                "reassembly",
                "router-multicast-faces",
                "routing-accept",
                "routing-interceptor-hotreload",
                "routing-interest-pending-gc",
                "routing-namespace",
                "routing-peer",
                "routing-router-hat",
                "routing-routes",
                "routing-token-tables",
                "runtime-tokio-uring",
                "runtime-zero-copy",
                "scouting-active",
                "scouting-responder",
                "scouting-static",
                "session-extauth",
                "session-extcompression",
                "session-extqos",
                "session-extshm",
                "storage-aligner",
                "storage-backend",
                "storage-backend-filesystem",
                "storage-mgr-dynamic-volume-loading",
                "storage-mgr-garbage-collection",
                "storage-mgr-multi-storage-host",
                "storage-replication",
                "time-hlc",
                "transport-link-quic",
                "transport-link-quic-datagram",
                "transport-link-raweth",
                "transport-link-serial",
                "transport-link-tls",
                "transport-link-unixpipe",
                "transport-link-unixsock",
                "transport-link-vsock",
                "transport-link-ws",
                "transport-lowlatency",
                "transport-multicast",
                "transport-multilink",
                "transport-qos",
                "transport-shm",
                "transport-stats",
                "zenoh-config",
            }
        ),
    ),
    "wz-runtime-tokio-test-support": (
        "a test-support crate; same reason as the other one",
        frozenset({"tls-fixtures"}),
    ),
    "wz-session-core": (
        "the protocol core, second-largest surface. Most of these gate a codec "
        "or a declaration arm that the runtime crates re-export, so probing "
        "here and at the runtime would ask the same question twice; which of "
        "the two layers owns the probe is the decision this round did not make",
        frozenset(
            {
                "access-extauth-usrpwd",
                "adminspace-config-hotreload",
                "adminspace-core",
                "adminspace-metrics",
                "attachment-bytes",
                "codec-close",
                "codec-declare",
                "codec-frame",
                "codec-hello",
                "codec-init-body",
                "codec-join",
                "codec-linkstate",
                "codec-open-body",
                "codec-push",
                "codec-request",
                "codec-response",
                "codec-response-final",
                "codec-scout",
                "declare-interest",
                "declare-queryable",
                "declare-subscriber",
                "declare-token",
                "declare-undeclare",
                "deferred-fire",
                "dissect",
                "ext-pubsub-group-membership",
                "ext-pubsub-serde-codec",
                "keyexpr-prefix",
                "liveliness-get",
                "liveliness-token",
                "multicast-declarations",
                "query-attachment",
                "query-reply-err",
                "query-source-info",
                "query-value",
                "reassembly",
                "routing-namespace",
                "routing-routes",
                "scouting-active",
                "scouting-static",
                "session-extauth",
                "session-extcompression",
                "session-extqos",
                "session-extshm",
                "session-matching",
                "session-multicast",
                "session-unicast",
                "storage-aligner",
                "storage-backend",
                "storage-history",
                "storage-mgr-garbage-collection",
                "storage-mgr-multi-storage-host",
                "storage-mgr-strip-prefix",
                "storage-replication",
                "switchboard",
                "transport-compression",
                "transport-fragmentation",
                "transport-keepalive",
                "transport-link-raweth",
                "transport-link-serial",
                "transport-lowlatency",
                "transport-multilink",
                "transport-qos",
                "transport-shm",
                "transport-stats",
            }
        ),
    ),
    "wz-session-lwip": (
        "one feature, on the lwip session glue; consumers are deploy probes",
        frozenset({"transport-multicast"}),
    ),
    "wz-tls-record": (
        "one feature, and it gates test fixtures",
        frozenset({"fixtures"}),
    ),
}


def workspace() -> tuple[dict[str, str], dict[str, set[str]]]:
    """(manifest dir -> package, package -> its NON-DEFAULT features)."""
    out = subprocess.run(
        ["cargo", "metadata", "--no-deps", "--format-version", "1"],
        cwd=CRATES,
        capture_output=True,
        text=True,
    )
    if out.returncode != 0:
        raise RuntimeError(f"cargo metadata failed: {out.stderr[:400]}")
    meta = json.loads(out.stdout)
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
) -> tuple[collections.Counter, set[tuple[str, str]], list[tuple[str, int, str]]]:
    """(class counts, denominator pairs, unclassified sites)."""
    counts: collections.Counter = collections.Counter()
    denom: set[tuple[str, str]] = set()
    unclassified: list[tuple[str, int, str]] = []
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
                for f in feats:
                    if f in nondefault.get(pkg, ()):
                        denom.add((pkg, f))
    return counts, denom, unclassified


def probed_pairs() -> set[tuple[str, str]]:
    """DERIVED from the diagnostic axis, so widening it moves this fraction.

    MEASURED, because the first version of this was a dead probe: it read a
    single-package constant, so adding a probe for any OTHER package moved
    nothing here and the "widening moves the fraction" claim was prose. R2193
    made that axis a per-package table for this reason.
    """
    return {(pkg, f) for pkg, feats in fgd.PROBES.items() for f in feats}


def declared_pairs() -> set[tuple[str, str]]:
    return {(pkg, f) for pkg, feats in fgd.NO_PUBLIC_PATH.items() for f in feats}


def unprobed_pairs() -> set[tuple[str, str]]:
    return {(pkg, f) for pkg, (_why, fs) in UNPROBED.items() for f in fs}


def check() -> int:
    dirs, nondefault = workspace()
    files = subprocess.run(
        ["git", "ls-files", "crates"], cwd=ROOT, capture_output=True, text=True
    ).stdout.split()
    counts, denom, unclassified = scan(ROOT, files, dirs, nondefault)

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
    for pkg, feat in sorted(denom - accounted):
        findings.append(
            f"`{pkg}` / `{feat}` is a non-default feature gating a public item "
            f"and nothing here says what is being done about it. Give it a "
            f"probe in `feature_gate_diagnostic.PROBES`, an entry in that "
            f"module's `NO_PUBLIC_PATH`, or a row under `UNPROBED` with the "
            f"reason its package is waiting -- the population must not be able "
            f"to grow in silence, which is the whole of item 532."
        )
    for pkg, feat in sorted(unprobed - denom):
        findings.append(
            f"`{pkg}` / `{feat}` is listed as an unprobed public-surface "
            f"feature and no `#[cfg]` in that package attaches it to a public "
            f"item any more. Delete the name: a waiting list that keeps names "
            f"nothing is waiting for reports work that does not exist."
        )
    overlap = (probed | declared) & unprobed
    for pkg, feat in sorted(overlap):
        findings.append(
            f"`{pkg}` / `{feat}` is both handled by the diagnostic axis and "
            f"listed as unprobed, and those cannot both be true"
        )

    if findings:
        print(f"feature-public-surface: FAIL -- {len(findings)} finding(s)")
        for f in findings:
            print(f"  {f}")
        return 1

    nd_total = sum(len(v) for v in nondefault.values())
    print(
        f"  feature-public-surface: {total_sites} `#[cfg(feature)]` site(s) all "
        f"classified; of {nd_total} non-default feature(s) in this workspace, "
        f"{len(denom)} gate a public item -- "
        f"{len(denom & probed)} probed, {len(denom & declared)} declared to "
        f"gate no public path, {len(denom & unprobed)} unprobed across "
        f"{len(UNPROBED)} package(s)"
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
        counts, denom, unclassified = scan(
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
    print(
        "feature-public-surface: selftest OK -- separates a public item, a "
        "macro call, a restricted item, a private item, a field, a statement "
        "and an assertion; finds an item behind a stacked attribute; and "
        "refuses to guess at a shape it does not know"
    )
    return 0


def main(argv: list[str]) -> int:
    if len(argv) != 1 or argv[0] not in {"--check", "--selftest"}:
        print("usage: feature_public_surface_census.py --check | --selftest")
        return 2
    return selftest() if argv[0] == "--selftest" else check()


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
