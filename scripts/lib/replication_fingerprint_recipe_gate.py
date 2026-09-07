#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
r"""R2420 (no register item) — the storage-replication CONFIG FINGERPRINT
recipe, derived from the pinned zenoh source on BOTH sides rather than trusted
to a literal somebody captured once.

The citation is `no register item` in the sense `grading_pin_ratchet.py` uses:
the item this answers for -- unregistered open-debt 675, "move every grading
onto the pin" -- lives in the agent-memory register, which has no store `debt-`
id for `gate_provenance_lint.py` to resolve. It is named in prose here instead.

## The defect, measured

`storage-replication` is graded COMPLETE, and its cross-implementation
FOUNDATION is one literal:

    crates/wz-integration-tests/tests/wz_zenohd_storage_replication.rs
        const ZENOHD_CONFIG_FINGERPRINT: u64 = 3912446778783065544;

Digest and aligner keyexprs embed that hash (`@-digest/<zid>/<fp>`,
`@zid/<zid>/<fp>/aligner`), so wz and a real zenohd MEET only when their
recipes agree; `Digest::diff` returns `None` the instant two configuration
fingerprints differ. The literal's provenance, as that file declared it until
this round, was "captured from a real zenohd 1.5.0" -- and this tree pins
1.10.0 (`scripts/build-zenohd.sh`, enforced by `oracle_pin_gate.py`).

What graded that literal against the pin: NOTHING. Its only reader is an
`#[ignore]`d Layer Z test that needs `target/zenohd`, and the assertion it
makes is

    wz's own recipe  ==  the captured literal

which is green for as long as wz is unchanged, WHATEVER upstream did. Upstream
adding a field to `ReplicaConfig`, reordering two, or widening one moves the
fingerprint a real zenohd publishes and leaves that assertion passing; the two
replicas then never meet, and the leg reports it -- if it runs at all -- as a
convergence timeout, which reads like a flake rather than like a stale claim.
A green check that read nothing is indistinguishable from one that read and
agreed, and this one read only wz.

## HALF OF THIS WAS ALREADY LOCKED, and the round measured which half

`storage_replication.rs` @ `fn config_fingerprint_recipe_matches_zenoh_field_
order` is a running unit test -- not `#[ignore]`d, no zenohd needed -- that
rebuilds the recipe by hand and compares. It works: swapping wz's `hot` and
`warm` updates, an edit that COMPILES and changes only a hash value, reds it
(`running 444 tests`, 1 failed, measured this round on the build machine).

So the first draft of this header was WRONG, and the probe is what said so.
`cargo test` is NOT structurally unable to fail on a recipe drift; the wz half
has had an instrument all along.

What that test cannot do is stated in its own doc comment -- "a recipe lock,
not an independent oracle". BOTH sides of its assertion are wz-authored
literals: a hand-written `h.update(&5u64.to_le_bytes())` sequence checked
against wz's own constructor. An upstream field added, reordered or widened
leaves it GREEN, exactly as it leaves the Layer Z assertion green, because
neither one reads upstream. The lock locks the lock.

⇒ THIS GATE'S SUBJECT IS THE PIN SIDE, and that is the whole of its
non-redundancy. Which also fixes where a control probe belongs: damaging wz
reds this gate AND the test above, so it discriminates nothing; the damage that
only this gate can see is an UPSTREAM-side one, and `--selftest` is the only
place that can be driven, because the pinned checkout is read-only and editing
it to prove a point would be editing the oracle.

## What this gate does instead

It DERIVES the recipe from source, on both sides, and compares the sequences:

  * upstream: the ordered `hasher.update(..)` calls in `Configuration::new`
    (`plugins/zenoh-plugin-storage-manager/src/replication/configuration.rs`
    @ `hasher.update(storage_key_expr.as_bytes())`), with each argument's field
    resolved against `plugins/zenoh-backend-traits/src/config.rs`
    @ `pub struct ReplicaConfig` for its Rust type;
  * wz: the same, in `ReplicationConfig::new`
    (`crates/wz-session-core/src/storage_replication.rs`), resolved against
    that function's own signature and its struct.

Three things must hold, element by element and IN ORDER: the same number of
hashed inputs, the same field at each position, and the same hashed BYTE WIDTH
at each position. Order matters because a hash is not commutative; width
matters because `to_le_bytes()` on a `u64` and on a `u128` feed a different
number of bytes for the same value.

⚠ THE RENAME MAP CANNOT CHANGE THE POPULATION. wz spells two fields
`interval_ms` / `propagation_delay_ms` where upstream carries `Duration`s, so
a name correspondence has to be declared somewhere. `RENAME` is therefore
required to be TOTAL over the upstream sequence and INJECTIVE: it may rename a
member, never add or drop one. An upstream field renamed, added or removed
leaves the map non-total and FAILS. That is the opposite of the declared-table
escape hatch this tree keeps finding (R2194), and it is why the map is CHECKED
rather than merely applied.

## The `usize` asymmetry, stated rather than hidden

Upstream hashes `replica_config.sub_intervals`, and at the pin that field is
`usize` (`plugins/zenoh-backend-traits/src/config.rs` @ `pub sub_intervals`).
wz hashes a `u64`. Those agree on an LP64 host and NOWHERE else: against a
32-bit zenohd the two fingerprints differ and the replicas never meet. wz's
choice is the portable one -- its own width does not move with the target --
and `ReplicationConfig::new` already says so in prose. `USIZE_BYTES` below is
that assumption made load-bearing and NAMED, not an exemption: it is the width
of the host every interop leg in this tree runs on, and a type this gate does
not know FAILS the run rather than being guessed at.

## A gate that cannot measure must not report green

Four ways this refuses instead of passing, which is the rule its
checkout-reading siblings follow (`serde_format_surface_gate.py`,
`upstream_citation_anchor_gate.py`):

  * no pinned checkout is reachable                        -> rc 2;
  * a file the derivation needs is missing there           -> rc 2;
  * either derived sequence is EMPTY                       -> rc 1;
  * an argument expression cannot be PLACED                -> rc 1.

The last one is the load-bearing one. A parser that silently skips the
expression it does not understand reports a SHORTER sequence, and a short
sequence can agree with a short one on the other side -- so an unrecognised
form is a failure OF THE GATE and is reported as such, never dropped.
"""

from __future__ import annotations

import argparse
import pathlib
import re
import sys

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]

#: Where each side's recipe lives, relative to its own root.
#:
#: SEGMENTS rather than one literal, the idiom `serde_format_surface_gate` and
#: `upstream_link_axis_gate` already use. A literal upstream path in a tracked
#: file IS a citation to `upstream_citation_anchor_gate`, and a path a program
#: needs to OPEN cannot be written in that gate's anchored form, so the two
#: rules only both hold when the path is composed. This gate's first draft wrote
#: both as literals and pushed that bare-form ratchet from 60 to 64 without
#: moving the budget -- the same slip R2362 made and R2363 repaired.
UPSTREAM_CONFIG_PARTS = (
    "plugins",
    "zenoh-plugin-storage-manager",
    "src",
    "replication",
    "configuration.rs",
)
UPSTREAM_TRAITS_PARTS = ("plugins", "zenoh-backend-traits", "src", "config.rs")
UPSTREAM_CONFIG_REL = "/".join(UPSTREAM_CONFIG_PARTS)
UPSTREAM_TRAITS_REL = "/".join(UPSTREAM_TRAITS_PARTS)
WZ_REL = "crates/wz-session-core/src/storage_replication.rs"

#: The `impl` block whose `new` IS the recipe, one per side. Anchored on the
#: impl and not on `pub fn new(` alone: `storage_replication.rs` carries
#: several constructors and the first one in the file is not this one.
UPSTREAM_IMPL = "impl Configuration"
WZ_IMPL = "impl ReplicationConfig"
RECIPE_FN = "pub fn new("

#: The structs each side's hashed fields are typed by.
UPSTREAM_STRUCT = "ReplicaConfig"
WZ_STRUCT = "ReplicationConfig"

#: upstream field -> wz field. Required TOTAL over the upstream sequence and
#: INJECTIVE; see the header. It may rename, never add or drop.
RENAME = {
    "storage_key_expr": "storage_key_expr",
    "prefix": "prefix",
    "interval": "interval_ms",
    "sub_intervals": "sub_intervals",
    "hot": "hot",
    "warm": "warm",
    "propagation_delay": "propagation_delay_ms",
}

#: The width of `usize` on the host every interop leg in this tree runs on.
#: Named rather than assumed -- see "The `usize` asymmetry" above.
USIZE_BYTES = 8

#: `to_le_bytes()` widths. An unknown type FAILS the run; it is never guessed.
WIDTHS = {
    "u8": 1,
    "u16": 2,
    "u32": 4,
    "u64": 8,
    "u128": 16,
    "usize": USIZE_BYTES,
    "i8": 1,
    "i16": 2,
    "i32": 4,
    "i64": 8,
    "i128": 16,
    "isize": USIZE_BYTES,
}

#: `Duration::as_millis()` returns `u128`, so the accessor fixes the width
#: without consulting the field's own type. A mapping so that a second such
#: accessor is one row rather than a branch.
ACCESSOR_WIDTHS = {"as_millis": 16, "as_micros": 16, "as_nanos": 16, "as_secs": 8}

#: The one argument shape whose width is the VALUE's length, not a type's.
BYTES_WIDTH = "bytes"

_IDENT = r"[A-Za-z_][A-Za-z0-9_]*"


def _balanced_body(src: str, marker: str) -> str | None:
    """The `{ .. }` body of the first `marker` in `src`.

    Brace-counted rather than regexed: these bodies hold string literals with
    braces in them (`{interval_ms}` inside wz's assert message) and nested
    blocks, both of which defeat a non-counting match.
    """
    at = src.find(marker)
    if at < 0:
        return None
    open_at = src.find("{", at)
    if open_at < 0:
        return None
    depth = 0
    for i in range(open_at, len(src)):
        if src[i] == "{":
            depth += 1
        elif src[i] == "}":
            depth -= 1
            if depth == 0:
                return src[open_at : i + 1]
    return None


def recipe_body(src: str, impl_marker: str) -> str | None:
    """The body of `new` inside `impl_marker`'s block."""
    block = _balanced_body(src, impl_marker)
    if block is None:
        return None
    return _balanced_body(block, RECIPE_FN)


def field_types(src: str, struct: str, fn_body_src: str | None) -> dict[str, str]:
    """`{field: rust type}` from a struct's fields AND a constructor's params.

    Both, because upstream's expressions reach fields through a parameter
    (`replica_config.sub_intervals`) while wz's reach the parameters directly
    (`sub_intervals`), and the placer should not have to know which side it is
    reading. A name carrying two DIFFERENT types across the two sources is
    recorded as a conflict, which lands it in the unplaced set rather than
    letting one silently win.
    """
    out: dict[str, str] = {}
    body = _balanced_body(src, f"struct {struct}")
    if body:
        for name, ty in re.findall(
            rf"^\s*(?:pub(?:\([^)]*\))?\s+)?({_IDENT})\s*:\s*([^,\n]+),",
            body,
            re.M,
        ):
            out[name] = ty.strip()
    if fn_body_src:
        for name, ty in re.findall(rf"({_IDENT})\s*:\s*([^,\n]+)", fn_body_src):
            ty = ty.strip()
            prior = out.get(name)
            if prior is not None and prior != ty:
                out[name] = f"<conflict {prior} / {ty}>"
            else:
                out[name] = ty
    return out


def _params(src: str, impl_marker: str) -> str:
    """The parameter list text of `new` inside `impl_marker`'s block."""
    block = _balanced_body(src, impl_marker)
    if block is None:
        return ""
    at = block.find(RECIPE_FN)
    if at < 0:
        return ""
    end = block.find(")", at)
    return block[at + len(RECIPE_FN) : end] if end > 0 else ""


def update_args(body: str) -> list[str]:
    """Every `hasher.update(<arg>)` argument, in source order, paren-balanced."""
    out: list[str] = []
    for m in re.finditer(r"\bhasher\s*\.\s*update\s*\(", body):
        i = m.end() - 1
        depth = 0
        for j in range(i, len(body)):
            if body[j] == "(":
                depth += 1
            elif body[j] == ")":
                depth -= 1
                if depth == 0:
                    out.append(body[i + 1 : j])
                    break
    return out


def hashed_inputs(
    body: str, types: dict[str, str]
) -> tuple[list[tuple[str, object]], list[str]]:
    """The ordered `(field, width)` sequence a recipe body hashes.

    Returns `(sequence, unplaced)`. `unplaced` holds the argument expressions
    this placer could not resolve; a caller MUST fail on a non-empty one rather
    than grade the shortened sequence -- see the header's last paragraph.
    """
    seq: list[tuple[str, object]] = []
    unplaced: list[str] = []
    for arg in update_args(body):
        expr = " ".join(arg.split()).strip().lstrip("&").strip()
        # `X.as_bytes()` -- a variable-length byte run.
        m = re.fullmatch(rf"(?:[\w.]*\.)?({_IDENT})\s*\.\s*as_bytes\s*\(\s*\)", expr)
        if m:
            seq.append((m.group(1), BYTES_WIDTH))
            continue
        # `(<ident> as <ty>).to_le_bytes()` -- the cast fixes the width.
        m = re.fullmatch(
            rf"\(\s*({_IDENT})\s+as\s+({_IDENT})\s*\)\s*\.\s*to_le_bytes\s*\(\s*\)",
            expr,
        )
        if m:
            if m.group(2) in WIDTHS:
                seq.append((m.group(1), WIDTHS[m.group(2)]))
                continue
            unplaced.append(f"{expr}  (cast to unknown type `{m.group(2)}`)")
            continue
        # `<path>.<accessor>().to_le_bytes()` -- the accessor fixes the width.
        m = re.fullmatch(
            rf"(?:[\w.]*\.)?({_IDENT})\s*\.\s*({_IDENT})\s*\(\s*\)"
            r"\s*\.\s*to_le_bytes\s*\(\s*\)",
            expr,
        )
        if m:
            if m.group(2) in ACCESSOR_WIDTHS:
                seq.append((m.group(1), ACCESSOR_WIDTHS[m.group(2)]))
                continue
            unplaced.append(f"{expr}  (unknown accessor `{m.group(2)}`)")
            continue
        # `<path>.to_le_bytes()` -- the field's own declared type fixes it.
        m = re.fullmatch(rf"(?:[\w.]*\.)?({_IDENT})\s*\.\s*to_le_bytes\s*\(\s*\)", expr)
        if m:
            ty = types.get(m.group(1))
            if ty in WIDTHS:
                seq.append((m.group(1), WIDTHS[ty]))
                continue
            unplaced.append(f"{expr}  (field `{m.group(1)}` has type `{ty}`)")
            continue
        unplaced.append(expr)
    return seq, unplaced


def _render(seq: list[tuple[str, object]]) -> str:
    return ", ".join(
        f"{f}:{w if w == BYTES_WIDTH else str(w) + 'B'}" for f, w in seq
    )


LABEL = "  replication-fingerprint-recipe:"


def grade(up_config: str, up_traits: str, wz_src: str) -> tuple[int, list[str]]:
    """`(exit code, report lines)` for one pair of sources."""
    out: list[str] = []

    up_body = recipe_body(up_config, UPSTREAM_IMPL)
    wz_body = recipe_body(wz_src, WZ_IMPL)
    if not up_body:
        out.append(
            f"{LABEL} FAIL -- no `{UPSTREAM_IMPL}` / `{RECIPE_FN}` body in the "
            f"pinned {UPSTREAM_CONFIG_REL}; nothing was derived upstream."
        )
        return 1, out
    if not wz_body:
        out.append(
            f"{LABEL} FAIL -- no `{WZ_IMPL}` / `{RECIPE_FN}` body in {WZ_REL}; "
            "nothing was derived on the wz side."
        )
        return 1, out

    up_types = field_types(up_traits, UPSTREAM_STRUCT, _params(up_config, UPSTREAM_IMPL))
    wz_types = field_types(wz_src, WZ_STRUCT, _params(wz_src, WZ_IMPL))
    up_seq, up_bad = hashed_inputs(up_body, up_types)
    wz_seq, wz_bad = hashed_inputs(wz_body, wz_types)

    for side, bad in (("upstream", up_bad), ("wz", wz_bad)):
        if bad:
            out.append(
                f"{LABEL} FAIL -- {len(bad)} {side} `hasher.update` argument(s) "
                "could not be PLACED, so the derived sequence is short and "
                "would agree with a short one: " + " | ".join(bad)
            )
            return 1, out

    if not up_seq or not wz_seq:
        out.append(
            f"{LABEL} FAIL -- a derived sequence is EMPTY (upstream "
            f"{len(up_seq)}, wz {len(wz_seq)}). A recipe of nothing agrees "
            "with everything; this is a reader that has stopped reading."
        )
        return 1, out

    if len(set(RENAME.values())) != len(RENAME):
        out.append(
            f"{LABEL} FAIL -- the rename map is not INJECTIVE, so it can fold "
            "two upstream inputs onto one wz input."
        )
        return 1, out

    up_fields = [f for f, _ in up_seq]
    missing = sorted({f for f in up_fields if f not in RENAME})
    if missing:
        out.append(
            f"{LABEL} FAIL -- the rename map is not TOTAL over the pin's "
            f"recipe: {', '.join(missing)} is hashed upstream with no wz "
            "counterpart declared. Upstream moved, so the captured "
            "`ZENOHD_CONFIG_FINGERPRINT` no longer describes what a real "
            "zenohd publishes."
        )
        return 1, out

    mapped = [(RENAME[f], w) for f, w in up_seq]
    if mapped != wz_seq:
        out.append(
            f"{LABEL} FAIL -- the recipes DIVERGE at the pin. wz and a real "
            "zenohd meet only on an EQUAL configuration fingerprint, so this "
            "is the digest exchange itself and not a cosmetic difference."
        )
        out.append(f"{LABEL}   pin (renamed to wz spelling): {_render(mapped)}")
        out.append(f"{LABEL}   wz                          : {_render(wz_seq)}")
        for i in range(max(len(mapped), len(wz_seq))):
            want = mapped[i] if i < len(mapped) else None
            got = wz_seq[i] if i < len(wz_seq) else None
            if want != got:
                out.append(
                    f"{LABEL}   first divergence at position {i}: "
                    f"pin {want} vs wz {got}"
                )
                break
        return 1, out

    unused = sorted(set(RENAME) - set(up_fields))
    out.append(
        f"{LABEL} OK -- {len(up_seq)} hashed input(s), same field and same byte "
        f"width in the same order on both sides: {_render(wz_seq)}"
    )
    if unused:
        out.append(
            f"{LABEL} note -- {len(unused)} rename row(s) the pin's recipe does "
            f"not use ({', '.join(unused)}); harmless, but they grade nothing."
        )
    return 0, out


# ── selftest ────────────────────────────────────────────────────────────
#
# The fixtures carry the shapes that defeated this gate's own first draft: a
# constructor that is NOT the first `pub fn new(` in its file, and an argument
# whose width comes from a cast rather than from a field type. Both made a
# first draft read a recipe that was not the recipe.

FIXTURE_TRAITS = """
pub struct ReplicaConfig {
    pub interval: Duration,
    pub sub_intervals: usize,
    pub hot: u64,
    pub warm: u64,
    pub propagation_delay: Duration,
}
"""

FIXTURE_UPSTREAM = """
impl Deref for Configuration {
    pub fn new(decoy: u8) -> Self { let mut hasher = X::default(); hasher.update(&decoy.to_le_bytes()); }
}
impl Configuration {
    pub fn new(
        storage_key_expr: OwnedKeyExpr,
        prefix: Option<OwnedKeyExpr>,
        replica_config: ReplicaConfig,
    ) -> Self {
        let mut hasher = xxhash_rust::xxh3::Xxh3::default();
        hasher.update(storage_key_expr.as_bytes());
        if let Some(prefix) = &prefix {
            hasher.update(prefix.as_bytes());
        }
        hasher.update(&replica_config.interval.as_millis().to_le_bytes());
        hasher.update(&replica_config.sub_intervals.to_le_bytes());
        hasher.update(&replica_config.hot.to_le_bytes());
        hasher.update(&replica_config.warm.to_le_bytes());
        hasher.update(&replica_config.propagation_delay.as_millis().to_le_bytes());
    }
}
"""


def selftest() -> int:
    wz_path = REPO_ROOT / WZ_REL
    if not wz_path.is_file():
        print(f"{LABEL} SELFTEST FAIL -- wz source missing at {WZ_REL}")
        return 1
    wz_src = wz_path.read_text(encoding="utf-8")
    rows: list[tuple[str, int, int]] = []

    rc, _ = grade(FIXTURE_UPSTREAM, FIXTURE_TRAITS, wz_src)
    rows.append(("the synthetic pin agrees with the live wz recipe", rc, 0))

    # An upstream field ADDED: the rename map stops being total.
    grown = FIXTURE_UPSTREAM.replace(
        "        hasher.update(&replica_config.hot.to_le_bytes());",
        "        hasher.update(&replica_config.hot.to_le_bytes());\n"
        "        hasher.update(&replica_config.novel.to_le_bytes());",
    ).replace("    pub hot: u64,", "    pub hot: u64,\n    pub novel: u64,")
    grown_traits = FIXTURE_TRAITS.replace(
        "    pub hot: u64,", "    pub hot: u64,\n    pub novel: u64,"
    )
    rc, _ = grade(grown, grown_traits, wz_src)
    rows.append(("an upstream field ADDED must FAIL", rc, 1))

    # An upstream field REORDERED: same set, different sequence.
    swapped = FIXTURE_UPSTREAM.replace(
        "        hasher.update(&replica_config.hot.to_le_bytes());\n"
        "        hasher.update(&replica_config.warm.to_le_bytes());",
        "        hasher.update(&replica_config.warm.to_le_bytes());\n"
        "        hasher.update(&replica_config.hot.to_le_bytes());",
    )
    rc, _ = grade(swapped, FIXTURE_TRAITS, wz_src)
    rows.append(("an upstream field REORDERED must FAIL", rc, 1))

    # An upstream field WIDENED: same set, same order, different byte count.
    widened_traits = FIXTURE_TRAITS.replace(
        "    pub hot: u64,", "    pub hot: u128,"
    )
    rc, _ = grade(FIXTURE_UPSTREAM, widened_traits, wz_src)
    rows.append(("an upstream field WIDENED must FAIL", rc, 1))

    # An upstream field DROPPED: the sequences differ in length.
    shrunk = FIXTURE_UPSTREAM.replace(
        "        hasher.update(&replica_config.warm.to_le_bytes());\n", ""
    )
    rc, _ = grade(shrunk, FIXTURE_TRAITS, wz_src)
    rows.append(("an upstream field DROPPED must FAIL", rc, 1))

    # An upstream type this placer does not know: refused, never guessed.
    unknown_traits = FIXTURE_TRAITS.replace(
        "    pub hot: u64,", "    pub hot: Newtype,"
    )
    rc, _ = grade(FIXTURE_UPSTREAM, unknown_traits, wz_src)
    rows.append(("an UNPLACEABLE upstream argument must FAIL", rc, 1))

    # The two empty floors: a population of zero must not report green.
    rc, _ = grade(FIXTURE_UPSTREAM.replace("hasher.update", "other.update"),
                  FIXTURE_TRAITS, wz_src)
    rows.append(("an EMPTY upstream recipe must FAIL", rc, 1))
    rc, _ = grade(FIXTURE_UPSTREAM, FIXTURE_TRAITS,
                  wz_src.replace("hasher.update", "other.update"))
    rows.append(("an EMPTY wz recipe must FAIL", rc, 1))

    # The decoy constructor: reading the FIRST `pub fn new(` in the file rather
    # than the one inside `impl Configuration` yields a one-input recipe.
    rc, _ = grade(FIXTURE_UPSTREAM.replace("impl Configuration {", "impl Other {"),
                  FIXTURE_TRAITS, wz_src)
    rows.append(("the decoy constructor must not be read as the recipe", rc, 1))

    # The wz side moved instead: the same divergence, from the other direction.
    wz_widened = wz_src.replace(
        "hasher.update(&sub_intervals.to_le_bytes());",
        "hasher.update(&(sub_intervals as u128).to_le_bytes());",
    )
    rc, _ = grade(FIXTURE_UPSTREAM, FIXTURE_TRAITS, wz_widened)
    rows.append(("a wz WIDENING must FAIL", rc, 1))

    bad = 0
    for name, got, want in rows:
        ok = got == want
        bad += 0 if ok else 1
        print(
            f"{LABEL} selftest: {'ok  ' if ok else 'FAIL'} {name} "
            f"(rc={got}, want {want})"
        )
    if bad:
        print(f"{LABEL} SELFTEST FAILED -- {bad} row(s)")
        return 1
    print(f"{LABEL} selftest ok -- {len(rows)} row(s)")
    return 0


def upstream_root() -> pathlib.Path | None:
    """The pinned zenoh checkout, through this tree's own discovery.

    Delegated to `upstream_citation_anchor_gate.upstream_root()` so the gates
    that read the pin can never disagree about WHICH checkout it is.
    """
    sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
    try:
        import upstream_citation_anchor_gate as anchor

        root = anchor.upstream_root()
    except Exception:
        return None
    return pathlib.Path(root) if root else None


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "--selftest",
        action="store_true",
        help="drive the gate over a synthetic pin; needs no checkout",
    )
    args = ap.parse_args()

    if args.selftest:
        return selftest()

    wz_path = REPO_ROOT / WZ_REL
    if not wz_path.is_file():
        print(f"{LABEL} FAIL -- wz source missing at {WZ_REL}, so NOTHING was graded.")
        return 2
    root = upstream_root()
    if root is None:
        print(
            f"{LABEL} FAIL -- no pinned zenoh checkout is reachable, so NOTHING "
            "was graded. Provision one (scripts/build-zenohd.sh) or point "
            "ZENOHD_SRC at a checkout of the pinned tag."
        )
        return 2
    up_config = root / UPSTREAM_CONFIG_REL
    up_traits = root / UPSTREAM_TRAITS_REL
    for path in (up_config, up_traits):
        if not path.is_file():
            print(
                f"{LABEL} FAIL -- the pinned checkout at {root} has no "
                f"{path.relative_to(root)}, so the upstream recipe could not "
                "be read. The storage plugin needs a DELIBERATE checkout; no "
                "build provisions it (CLAUDE.md, External references)."
            )
            return 2

    rc, lines = grade(
        up_config.read_text(encoding="utf-8"),
        up_traits.read_text(encoding="utf-8"),
        wz_path.read_text(encoding="utf-8"),
    )
    for line in lines:
        print(line)
    print(f"{LABEL} pin = {root}")
    return rc


if __name__ == "__main__":
    sys.exit(main())
