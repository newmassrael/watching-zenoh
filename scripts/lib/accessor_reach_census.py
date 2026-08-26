#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

"""R2128 (no register item) — which dissection ACCESSORS no shipped surface asks.

The citation is `no register item` for the reason `debt_plane_census.py` gives
for its own: the item this closes -- unregistered open-debt item 479 -- lives in
the agent-memory register, which has no store id for `gate_provenance_lint.py`
to resolve. The item is named here in prose instead.

## The failure this ends

wz-capture answers questions about a capture through public `&self` accessors on
the types a dissection hands back. An accessor whose only callers are tests
SHIPS -- it compiles into the cdylib a product links -- while no surface asks
it, and `dead_code` is structurally blind to it because a `pub` method on a
`pub` type is externally reachable by definition. `#[cfg(test)]` methods are a
different thing entirely; the compiler knows about those.

Nothing counted this class. R2041 and R2042 each stumbled on one member of it
while doing something else, one round after the other, and item 479 was filed on
the observation that accident had become the instrument.

## Why NOT the sweep the item prescribed

Item 479 proposed a name sweep -- for each accessor, grep for `.name(` outside
`mod tests` -- and offered its own probe as the draft. MEASURED here before
building it: that sweep UNDER-REPORTS, which is the one direction a gate must
never be wrong in.

Three of the accessors share a name with an unrelated method elsewhere in the
tree, and `Dissection::flow` is the witness. Its only `.flow(` call site in 836
tracked files is `wz-analyze/src/lib.rs:2798`, which calls `FieldNote::flow` --
a PRIVATE method, on a different type, in a different crate. A name sweep
credits that call to `Dissection::flow` and reports it reached. It is not
reached; it has no caller of any kind anywhere in the tree. The sweep found 3
members and this gate finds 21, and the one it silently swallowed is the one its
own draft could not have seen.

## What answers instead: the linker

Reach is read from SYMBOLS in the built shipped artifacts. Rust's mangling --
legacy `_ZN` and v0 `_R` alike -- writes a path as a run of `<len><ident>`
pairs, so `10Dissection5flows` names the method AND the impl type it hangs off.
No name collision is possible: `FieldNote::flow` mangles under `9FieldNote`.
This is the same shape as `capi_abi_pin.py` making `gcc -aux-info` the
authenticator rather than a reader of C prototypes.

The length prefix pins the identifier's extent, so the needle needs a guard on
its LEFT only -- the digits must not be preceded by another digit, or the length
being read is not the length that was written. A right-hand boundary check is
WRONG here and was removed after being written: v0 appends a disambiguator digit
directly after the identifier (`22evict_flows_beyond_cap0NC`), so requiring a
non-alphanumeric on the right rejects real matches.

An accessor absent from every shipped artifact is unreached. The direction of
any residual error is safe: a call the linker dropped reports the accessor as
unreached (over-report), never the reverse, because `#[cfg(test)]` code is not
compiled into these artifacts at all.

## The axis this deliberately does NOT gate

"Test-only" and "called by nothing at all" are different states -- `flow` and
`serial_messages` have no caller in the tree, while `chain_bytes_lost` has two
tests -- and this gate does not split them. Deriving that split soundly needs
the test binary of every workspace member that could hold a caller, and reading
only the ones that happen to be built is the defect the cdylib SONAME probe was
caught by on 2026-08-25: a population taken from what was lying in the target
directory. A half-derived second axis is under-reporting wearing a hat. One
axis, soundly derived, is what this reports -- the same call open-debt item 531
made about the second delivery degree.

## Population, and why it is a closure rather than a list

The population is the `&self` accessors on every type a dissection hands a
consumer, TRANSITIVELY: start at `Dissection`, follow the struct types named in
each inherent method's return position, repeat. Item 479 named two types; the
closure finds 33, and 17 of the 21 members it reports sit on types the item
never mentioned. A hand-listed population would have been a second thing to keep
up to date and would have reproduced exactly the blindness the item is about.

The closure is read from rustdoc's own HTML, which is the compiler's answer to
"what is public here" and works on the stable toolchain this workspace is pinned
to (rustdoc's JSON output is nightly-only). Trait implementations and
`Methods from Deref<...>` blocks are cut away: `MessageList` derefs to a slice,
and counting slice's 132 methods as its own put the first measurement 132 rows
over the truth.

A population of zero is a FAIL, and so is a reached count of zero: a parse that
finds nothing and a tree with nothing in it exit the same way otherwise, and
this workspace has paid for that confusion more than once.
"""

from __future__ import annotations

import argparse
import html
import pathlib
import re
import subprocess
import sys

REPO = pathlib.Path(__file__).resolve().parents[2]
CRATES = REPO / "crates"
DOCS = CRATES / "target/doc/wz_capture"

# The root of the closure. Everything else is derived from it.
ROOT = "Dissection"

# The two consumption surfaces, which are the two `analysis_surface_parity.py`
# names as the surfaces a product can reach: the command line and the C ABI a
# framework links. A missing artifact is a FAIL, never a skip.
SHIPPED = (
    ("wz-analyze", CRATES / "target/debug/wz-analyze"),
    ("wz-capi-dissect", CRATES / "target/debug/libwz_capi_dissect.so"),
)

# MEASURED at R2128, against freshly built artifacts. This is a RATCHET, not an
# exemption list: an accessor leaves it by being asked -- wired to a surface --
# or by ceasing to exist. The gate fails when the set grows AND when a row here
# turns out to be reached, so neither direction can drift quietly. Do not add a
# row to make a red go away; a new row is a new debt and belongs in the round
# that filed it.
ROSTER: frozenset[tuple[str, str]] = frozenset(
    {
        ("DatagramDissection", "chain_loss"),
        ("Dissection", "chain_bytes_lost"),
        ("Dissection", "flow"),
        ("Dissection", "serial_messages"),
        ("DissectionHealth", "any_checksum_invalid"),
        ("DissectionLimits", "max_flows_held"),
        ("DroppedFrameCensus", "oam"),
        ("EncryptedFlow", "totals"),
        ("FlowDissection", "chain_loss"),
        ("FlowDissection", "context"),
        ("FlowDissection", "packet_for"),
        ("FlowDissection", "ws_resyncs"),
        ("FragmentStats", "any"),
        ("StreamAssembler", "fin_seen"),
        ("StreamAssembler", "held_segments"),
        ("StreamAssembler", "is_empty"),
        ("StreamAssembler", "packet_for_offset"),
        ("StreamAssembler", "rst_seen"),
        ("StreamAssembler", "runs"),
        ("StreamAssembler", "synced_from_syn"),
        ("Tunnel", "depth"),
    }
)


class Fail(SystemExit):
    def __init__(self, msg: str, code: int = 1) -> None:
        super().__init__(code)
        self.msg = msg


def build() -> None:
    """Produce the two artifacts and the rustdoc the population is read from.

    Content-addressed by cargo, so a warm tree pays almost nothing and a stale
    one cannot be read by accident -- which an mtime guard would allow.
    """
    for cmd in (
        ["cargo", "build", "-p", "wz-analyze", "-p", "wz-capi-dissect", "--quiet"],
        ["cargo", "doc", "-p", "wz-capture", "--no-deps", "--quiet"],
    ):
        r = subprocess.run(cmd, cwd=CRATES)
        if r.returncode != 0:
            raise Fail(f"`{' '.join(cmd)}` failed; the census has nothing to read", 2)


def page(ty: str) -> pathlib.Path | None:
    for p in DOCS.rglob(f"struct.{ty}.html"):
        return p
    return None


def own_impls(doc: str) -> str:
    """The part of a rustdoc page that is this type's OWN inherent methods.

    Trait impls and `Methods from Deref<Target=...>` are somebody else's items
    rendered on this page, and counting them put the first measurement of
    `MessageList` 132 rows over the truth.
    """
    for marker in ('id="trait-implementations"', 'id="deref-methods'):
        cut = doc.find(marker)
        if cut > 0:
            doc = doc[:cut]
    return doc


def methods(p: pathlib.Path) -> dict[str, str]:
    """Every public inherent method of the type, name -> rendered signature."""
    doc = own_impls(p.read_text())
    out: dict[str, str] = {}
    for m in re.finditer(r'id="method\.([A-Za-z0-9_]+)"', doc):
        end = doc.find("</h4>", m.end())
        out[m.group(1)] = doc[m.end() : end if end > 0 else m.end() + 800]
    return out


def takes_ref_self(sig: str) -> bool:
    text = html.unescape(re.sub(r"<[^>]+>", "", sig))
    open_paren = text.find("(")
    if open_paren < 0:
        return False
    return bool(re.match(r"\(\s*&(?:'[a-z_]+\s+)?self\b", text[open_paren:]))


def returned_structs(sig: str) -> list[str]:
    """The struct types in a signature's RETURN position.

    rustdoc links every named type it renders, so the closure is read from the
    hrefs rather than from the prose of the signature.
    """
    arrow = sig.find("-&gt;")
    if arrow < 0:
        return []
    return re.findall(
        r'href="(?:\.\./)*[a-z_/]*struct\.([A-Za-z0-9_]+)\.html', sig[arrow:]
    )


def closure() -> list[str]:
    """Types a dissection hands a consumer, transitively from ROOT."""
    seen: set[str] = set()
    frontier = [ROOT]
    order: list[str] = []
    while frontier:
        ty = frontier.pop()
        if ty in seen:
            continue
        p = page(ty)
        if p is None:
            continue
        seen.add(ty)
        order.append(ty)
        for sig in methods(p).values():
            frontier.extend(r for r in returned_structs(sig) if r not in seen)
    return sorted(order)


def population() -> dict[tuple[str, str], None]:
    pop: dict[tuple[str, str], None] = {}
    for ty in closure():
        p = page(ty)
        if p is None:
            continue
        for name, sig in methods(p).items():
            if takes_ref_self(sig):
                pop[(ty, name)] = None
    return pop


def symbols() -> str:
    blob = ""
    for label, path in SHIPPED:
        if not path.exists():
            raise Fail(
                f"the {label} artifact is absent ({path}); a gate that cannot "
                f"read its input must not report green",
                2,
            )
        r = subprocess.run(["nm", str(path)], capture_output=True, text=True)
        if r.returncode != 0:
            raise Fail(f"nm(1) could not read {path}", 2)
        blob += r.stdout
    return blob


def reached(blob: str, ty: str, name: str) -> bool:
    """Does any shipped artifact name this method of this type?

    `<len><ident>` pairs, so the extent of the identifier is already pinned on
    the right by the length that introduces it. Guard the LEFT only -- a digit
    in front means the length being read is not the length that was written.
    """
    needle = f"{len(ty)}{ty}{len(name)}{name}"
    i = blob.find(needle)
    while i != -1:
        if i == 0 or not blob[i - 1].isdigit():
            return True
        i = blob.find(needle, i + 1)
    return False


def census(pop: dict[tuple[str, str], None], blob: str) -> tuple[set, set]:
    hit = {k for k in pop if reached(blob, *k)}
    return hit, set(pop) - hit


def judge(pop, hit, miss) -> list[str]:
    """Every way this can be wrong, as a list of sentences."""
    problems: list[str] = []
    if not pop:
        problems.append(
            "population is EMPTY -- the rustdoc parse found no accessor at all. "
            "A dead probe and a clean tree exit the same way; this is the dead "
            "probe."
        )
        return problems
    if not hit:
        problems.append(
            f"NOTHING in a population of {len(pop)} is reached by any shipped "
            f"artifact. That is a broken symbol read, not a finding."
        )
        return problems
    for ty, name in sorted(miss - ROSTER):
        problems.append(
            f"NEW: {ty}::{name} is asked by no shipped surface and is not on "
            f"the roster. Wire it to a surface, or file it and add the row in "
            f"the round that files it."
        )
    for ty, name in sorted(ROSTER & hit):
        problems.append(
            f"ROTTED: {ty}::{name} is on the roster but a shipped surface now "
            f"asks it. Remove the row -- the debt is paid."
        )
    for ty, name in sorted(ROSTER - set(pop)):
        problems.append(
            f"ABSENT: {ty}::{name} is on the roster but is no longer a public "
            f"&self accessor in the closure. Remove the row."
        )
    return problems


def selftest() -> int:
    """Both directions, plus the two ways of reporting nothing.

    Driven against injected populations and symbol blobs rather than the real
    tree: a selftest that needs a build cannot fail the build's absence.
    """
    fake_pop = {("Foo", "a"): None, ("Foo", "b"): None}
    blob_hit = "_ZN3Foo1a17hdeadbeefE"
    cases = []

    # 1. a clean tree, with the roster naming the one that misses
    global ROSTER
    saved = ROSTER
    try:
        ROSTER = frozenset({("Foo", "b")})
        hit, miss = census(fake_pop, blob_hit)
        cases.append(("clean", judge(fake_pop, hit, miss) == [], hit == {("Foo", "a")}))

        # 2. a new unreached accessor, unrostered -> red
        ROSTER = frozenset()
        hit, miss = census(fake_pop, blob_hit)
        problems = judge(fake_pop, hit, miss)
        cases.append(("new", any(p.startswith("NEW: Foo::b") for p in problems), True))

        # 3. a rostered accessor that is now reached -> red
        ROSTER = frozenset({("Foo", "a"), ("Foo", "b")})
        hit, miss = census(fake_pop, blob_hit)
        problems = judge(fake_pop, hit, miss)
        cases.append(
            ("rotted", any(p.startswith("ROTTED: Foo::a") for p in problems), True)
        )

        # 4. a rostered accessor that no longer exists -> red
        ROSTER = frozenset({("Foo", "b"), ("Gone", "x")})
        hit, miss = census(fake_pop, blob_hit)
        problems = judge(fake_pop, hit, miss)
        cases.append(
            ("absent", any(p.startswith("ABSENT: Gone::x") for p in problems), True)
        )

        # 5. an empty population is a FAIL, not a green
        ROSTER = frozenset()
        hit, miss = census({}, blob_hit)
        cases.append(("empty-population", judge({}, hit, miss) != [], True))

        # 6. a symbol read that hits nothing is a FAIL, not 100% debt
        hit, miss = census(fake_pop, "")
        problems = judge(fake_pop, hit, miss)
        cases.append(
            ("no-symbol-read", any("NOTHING in a population" in p for p in problems), True)
        )

        # 7. the left guard: a longer length prefix must not match
        cases.append(
            ("left-guard", not reached("_ZN13Foo1a", "Foo", "a"), True)
        )
        # 8. ...and a disambiguator digit on the right must still match
        cases.append(("right-open", reached("_R3Foo1a0NC", "Foo", "a"), True))
    finally:
        ROSTER = saved

    bad = [n for n, ok, ok2 in cases if not (ok and ok2)]
    for n, ok, ok2 in cases:
        print(f"  selftest {n}: {'ok' if ok and ok2 else 'FAIL'}")
    if bad:
        print(f"accessor-reach-census: SELFTEST FAIL -- {', '.join(bad)}")
        return 1
    print(f"accessor-reach-census: selftest ok ({len(cases)} cases)")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument(
        "--no-build",
        action="store_true",
        help="read artifacts a layer already built instead of building them",
    )
    ap.add_argument("--list", action="store_true", help="print every unreached accessor")
    args = ap.parse_args()

    if args.selftest:
        return selftest()

    if not args.no_build:
        build()

    pop = population()
    blob = symbols()
    hit, miss = census(pop, blob)
    problems = judge(pop, hit, miss)

    if args.list:
        for ty, name in sorted(miss):
            print(f"    {ty}::{name}")

    if problems:
        print("accessor-reach-census: FAIL")
        for p in problems:
            print(f"  {p}")
        return 1

    print(
        f"accessor-reach-census: ok -- {len(pop)} public &self accessor(s) across "
        f"{len(closure())} dissection result type(s); {len(hit)} reached by a "
        f"shipped surface, {len(miss)} on the roster."
    )
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Fail as f:
        print(f"accessor-reach-census: FAIL -- {f.msg}")
        sys.exit(f.code)
