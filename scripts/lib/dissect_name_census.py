#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
"""R311y595 (no register item) — the dissect field-name census: the walker's vocabulary vs the codecs'.

## Why this exists

`Field::name`'s own doc declares the rule: a field is named "matching the generated
codec's struct field where one exists so a reader can move between the two without a
translation table". The prose was the specification and the walkers were the
implementation, and NOTHING COMPARED THEM. That is the same shape R311y585 recorded one
level up — a feature whose doc claimed it selected the whole codec-* MID space while the
scouting half was missing — and it is why this file is a census rather than a golden
output test.

## Why NOT a golden test

The obvious alternative is to pin the emitted JSON for a fixed input. It decays: every
legitimate walker addition reds it, the expected string gets updated mechanically, and by
the time an UNINTENDED rename arrives the reflex is to update it too. R311y585 already
renamed one field for a real reason (`locator` -> `locator_entry`, because `Field::find`
is first-match-by-name and a group sharing its leaf's name shadows it), so renames are
not hypothetical.

A census inverts that. A new walker does not red it — the census DEMANDS the name. An
accidental rename reds it, because the name stops matching the codec. And a gap
(`linkstate`) is carried by name with a reason rather than being invisible.

## The three invariants

    1. every WALKER name is a codec field, or declared protocol vocabulary,
       or declared OWN vocabulary                      -- a new invention must be decided
    2. every CODEC field is emitted by a walker, or declared as awaiting one
    3. no declared entry is STALE                      -- a gap that closed must be removed

Rule 3 is what keeps the allowlists from becoming the thing they were meant to prevent.

## What it does NOT check

That a name is emitted for the RIGHT message. A walker emitting `zid` inside a Put would
satisfy this census. The claim here is about vocabulary, not placement; placement is what
the walkers' own tests assert.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DISSECT = ROOT / "crates" / "wz-session-core" / "src" / "dissect.rs"
CODECS = ROOT / "out" / "wz-codecs"

# ── Declared vocabulary ──────────────────────────────────────────────────────
#
# PROTOCOL: names that come from the zenoh wire spec rather than from a wz codec
# struct. Flag letters are the spec's own single-character flag names, and the
# discriminators are its message / body variant names. Neither is a field of any
# generated struct, and neither is ours to choose.
PROTOCOL_FLAGS = {"a", "c", "e", "i", "l", "m", "n", "p", "r", "s", "t", "z", "mid"}
PROTOCOL_VARIANTS = {
    "decl_final",
    "decl_kexpr",
    "decl_queryable",
    "decl_subscriber",
    "decl_token",
    "undecl_kexpr",
    "undecl_queryable",
    "undecl_subscriber",
    "undecl_token",
    "put",
    "del",
    "query",
    "reply",
    "err",
}

# OWN: the names the DISSECTOR invents, each with the reason it is not a codec
# field. This is the whole of wz's own vocabulary on this surface, and a consumer
# keying on any of them is keying on a wz decision rather than on the protocol.
# Adding one is a deliberate act, which is the point of listing them. The COUNT is
# deliberately not written here: it moved twice in one round and a hand-kept tally
# is exactly what this file exists to replace.
OWN_VOCABULARY = {
    "hdr": "the header byte of a nested record, where the codec's own field is `header`",
    "ext": "one entry of an extension chain; the codec models the chain, not the entry",
    "ext_id": "the extension's id bits, split out of the entry header -- the FOUR "
    "bits zenoh's `iext::ID_MASK` gives it, not the five a `& 0x1F` reads",
    "ext_name": "what the entry's eid MEANS in the carrier it was read from "
    "(`ext_name::ext_name`). NOT a codec field and not read off the wire: it is a "
    "table lookup, which is why it renders as `label` rather than `text`. Absent "
    "rather than guessed when the carrier declares no such extension -- a chain is "
    "where a later-vintage peer puts what this build has never heard of",
    "mapping": "zenoh-protocol's `WireExpr::mapping`; wz's codec encodes it as the "
    "local/nonlocal variant TAG rather than as a field",
    "has_schema": "the packed encoding's bit 0, surfaced as a flag",
    "zid_len_m1": "the zid length is stored minus one; the raw field is named for what "
    "it holds rather than for what it means",
    "locator_entry": "one locator record. NOT `locator`: `Field::find` is "
    "first-match-by-name and a group sharing its leaf's name shadows it (R311y585)",
    "keyexprs": "the Declare body's keyexpr group",
    "subscribers": "the Declare body's subscriber group",
    "queryables": "the Declare body's queryable group",
    "tokens": "the Declare body's token group",
    "current": "Interest mode bit",
    "future": "Interest mode bit",
    "restricted": "Interest options bit",
    "what": "Scout's what-am-I-looking-for bits",
    "rest": "trailing bytes of a record the walker read but does not name further",
    "unparsed": "bytes after a halt -- the best-effort marker, not a wire field",
    "shm_descriptor": "the Put/Err payload slot when the body ext chain carries the "
    "SHM marker. NOT `payload`: the codec's field is the payload and these bytes are "
    "an ADDRESS, so sharing the name is what let a reader take one for the other "
    "(R311y597). Opaque on purpose -- wz and stock zenoh put DIFFERENT descriptor "
    "layouts here and nothing on the wire tells them apart",
    "linkstate": "the OAM ZBuf body walked as a LinkstateList. The codec models the "
    "body as `value`; this name says WHICH body it is, since only the OAM id "
    "distinguishes a topology advertisement from an opaque blob (R311y597)",
    "linkstate_entry": "one Linkstate record. NOT `link_states`, which is the "
    "aggregate the group itself is named for; same first-match-by-name shadowing "
    "rule as `locator_entry`",
    # R311y890 — the five ZBuf extension BODIES the walker reads. Four are named
    # for what the body IS, on the same rule as `linkstate`: the codec models an
    # `ExtZbuf` as `value`, and only the carrier plus the eid says which
    # structure those bytes hold. `eid` is the odd one -- a field of a body no
    # generated codec in this tree declares.
    "source_info": "the `(zid, eid, sn)` ext body, walked. The codec models it as "
    "`value`; this name says WHICH body it is, since only the carrier and the eid "
    "distinguish an origin triple from an opaque blob (R311y890)",
    "responder_id": "the `(zid, eid)` ext body on a Response. Held apart from "
    "`source_info` because it has no `sn` and a shared walker would read the next "
    "extension's header as one",
    "query_body": "the Query VALUE ext body (`encoding || payload`) -- the ext a "
    "reader that looks only at the message body never finds",
    "wire_expr": "the Declare common keyexpr ext body. NOT walked by "
    "`walk_wireexpr`: that one length-prefixes its suffix and this body's suffix "
    "is the remainder",
    "eid": "the entity id inside `source_info` / `responder_id`. No generated "
    "codec in this tree declares it -- both bodies are hand-encoded",
    # R311y894 — the SIXTH and SEVENTH walked ZBuf bodies: `Join`'s mandatory
    # `qos` table and the `Init` establishment `shm` handshake. Both were listed
    # as opaque for want of a producer in this tree, and both had one.
    "qos": "the JOIN per-priority next-SN table, walked. Same rule as "
    "`linkstate`: the codec models the ext body as `value`, and only the "
    "carrier plus the eid says a table of sixteen VLEs is what these bytes "
    "hold. The name is `ext_name`'s own row for the eid",
    "priority_sn": "one row of that table -- upstream's own type name "
    "(`zenoh-protocol::transport::PrioritySn`). NOT `qos`, by the same "
    "first-match-by-name shadowing rule as `locator_entry`",
    "shm": "the ESTABLISHMENT shm handshake body on an `Init`, walked. Same "
    "rule as `linkstate` and `qos`. Held to the Init carrier by the arm's "
    "guard: `Join` declares an unrelated `shm` at the same id and encoding",
    "alice_segment": "the segment an InitSyn offers -- upstream's own field "
    "name (`zenoh-transport` `unicast/establishment/ext/shm.rs`)",
    "alice_challenge": "the InitAck's proof it could map that segment. The "
    "SAME wire position as `alice_segment` in the other half of the handshake, "
    "renamed because a reader told `alice_segment` on an ACK would have the "
    "direction backwards",
    "bob_segment": "the acceptor's own segment, the InitAck's second VLE",
    "priority": "which priority a `priority_sn` row belongs to. POSITIONAL on "
    "the wire -- the body carries no such field -- so it is emitted from the "
    "index and aliases the row's own span, carrying the zenoh `Priority` "
    "discriminant rather than a name (a name would be a table with no "
    "adjudicator behind it)",
}

# AWAITING: codec fields no walker emits yet, each with WHY. Rule 3 makes closing
# one mandatory rather than optional: land the walker and this entry must go.
AWAITING_WALKER = {
    "crc32": "serial_envelope is LINK framing, not a zenoh message -- outside the "
    "dissector's MID space by design",
    "header_flags": "ext_envelope's codec-internal split of the header byte; the "
    "walker surfaces those bits individually instead",
}


def walker_names(src: str) -> set[str]:
    """Every field name the walkers emit.

    Three producing forms, and MISSING ONE IS HOW THIS GOES WRONG: the first
    version of this census matched only a fixed list of cursor methods, missed
    `c.text(` and `c.vle_u32(`, and reported `suffix` / `schema` / `packed_id` as
    absent when all three are emitted. So the cursor arm matches ANY method.
    """
    names: set[str] = set()
    names |= set(re.findall(r'\bc\.[a-z_0-9]+\(\s*"([a-z0-9_]+)"', src))
    names |= set(re.findall(r'\b(?:bits|flag|group|leaf|text|label)\(\s*"([a-z0-9_]+)"', src))
    names |= set(re.findall(r'name:\s*"([a-z0-9_]+)"', src))
    return names


EXT_ZBUF_MATCH = re.compile(
    r"fn walk_ext_zbuf_body\b.*?\blet walked = match name \{(?P<arms>.*?)\n    \}",
    re.S,
)
"""The `match name` inside `walk_ext_zbuf_body`, arms only.

Anchored on the function name AND on the binding, so a second `match name`
elsewhere in the file cannot be mistaken for this one, and a rename of either
end makes the block unfindable -- which this gate reports as a failure rather
than as an empty population.
"""

ARM_HEAD = re.compile(r"^        (?P<pat>\S.*?)\s*(?:\bif\b.*?)?=>", re.M)
"""One arm head of that match, at the block's own indentation."""


def ext_zbuf_arms_from_the_table(src: str) -> list[str]:
    """R311y894, open-debt item 387 -- the walker's arms must name the TABLE.

    R311y893 gave `crate::ext_name` a constant per walked row so that renaming
    a row carries the arm with it: spelled twice, the contract between the two
    modules is invisible to the compiler, and a row renamed on one side leaves
    the body silently back to opaque `value`. But that repair reached only the
    rows that already had constants. A NEW arm written as `"new_ext" =>` still
    compiles, and the class regrows one arm at a time -- the "scope of a
    closure" shape open-debt item 47 is a register of.

    So the shape of the fix is a rule about the arms rather than about the
    names: every pattern here must be a path through `ext_name`, never a
    literal. `_` is the decline arm and is exempt by construction.

    The gate FAILS on an empty population. A regex that finds no arms would
    otherwise report a walker with no contract at all as clean, which is the
    most expensive way this check could be wrong.
    """
    block = EXT_ZBUF_MATCH.search(src)
    if block is None:
        return [
            "cannot find `walk_ext_zbuf_body`'s `let walked = match name {` -- the "
            "arm-provenance rule (item 387) measured NOTHING. Re-anchor this regex "
            "on whatever the walker's dispatch is called now"
        ]
    arms = [m.group("pat").strip() for m in ARM_HEAD.finditer(block.group("arms"))]
    named = [a for a in arms if a != "_"]
    if not named:
        return [
            "`walk_ext_zbuf_body` dispatches on no named extension -- either the "
            "match lost its arms or this gate stopped seeing them"
        ]
    out = []
    for arm in named:
        if not re.fullmatch(r"(?:crate::)?ext_name::[A-Z][A-Z0-9_]*", arm):
            out.append(
                f"`walk_ext_zbuf_body` matches {arm!r}, which is not an "
                "`ext_name::` constant -- spell the arm as the table's own "
                "constant so a renamed row carries the walker with it (R311y893, "
                "open-debt item 387)"
            )
    return out


def codec_fields() -> dict[str, list[str]]:
    """Every `pub <field>:` of every generated codec, and which codec declares it."""
    out: dict[str, list[str]] = {}
    for path in sorted(CODECS.glob("*.rs")):
        for field in sorted(
            set(re.findall(r"^\s*pub ([a-z_][a-z0-9_]*)\s*:", path.read_text(encoding="utf-8"), re.M))
        ):
            out.setdefault(field, []).append(path.stem)
    return out


def main() -> int:
    if not DISSECT.is_file():
        print(f"dissect-name-census: cannot read {DISSECT}", file=sys.stderr)
        return 1
    if not CODECS.is_dir():
        print(f"dissect-name-census: cannot read {CODECS}", file=sys.stderr)
        return 1

    src = DISSECT.read_text(encoding="utf-8")
    walkers = walker_names(src)
    codecs = codec_fields()
    declared = PROTOCOL_FLAGS | PROTOCOL_VARIANTS | set(OWN_VOCABULARY)

    failures: list[str] = ext_zbuf_arms_from_the_table(src)

    # Invariant 4 (structural): the declared sets must be disjoint from each other
    # and from the codec's, or a name would be excused twice and neither excuse
    # would be load-bearing.
    for name in sorted(declared & set(codecs)):
        failures.append(
            f"declared vocabulary {name!r} IS a codec field ({', '.join(codecs[name])}) -- "
            "remove it from the declaration and let the codec own the name"
        )
    for name in sorted(set(OWN_VOCABULARY) & (PROTOCOL_FLAGS | PROTOCOL_VARIANTS)):
        failures.append(f"{name!r} is declared as both protocol and own vocabulary")
    for name in sorted(set(AWAITING_WALKER) & declared):
        failures.append(f"{name!r} is declared as awaiting a walker AND as vocabulary")

    # Invariant 1: no undeclared invention.
    for name in sorted(walkers - set(codecs) - declared):
        failures.append(
            f"walker emits {name!r}, which is neither a codec field nor declared "
            "vocabulary -- name it after the codec's field, or add it to "
            "OWN_VOCABULARY with the reason it differs"
        )

    # Invariant 2: no silently unwalked codec field.
    for name in sorted(set(codecs) - walkers - set(AWAITING_WALKER)):
        failures.append(
            f"codec field {name!r} ({', '.join(codecs[name])}) is emitted by no walker "
            "and is not declared as awaiting one"
        )

    # Invariant 3: no stale excuse.
    for name in sorted(set(AWAITING_WALKER) & walkers):
        failures.append(
            f"{name!r} is declared as awaiting a walker, but a walker now emits it -- "
            "delete the AWAITING_WALKER entry"
        )
    for name in sorted(set(OWN_VOCABULARY) - walkers):
        failures.append(
            f"{name!r} is declared as own vocabulary but no walker emits it -- "
            "delete the OWN_VOCABULARY entry"
        )

    matched = len(walkers & set(codecs))
    print(
        f"dissect-name-census: {len(walkers)} walker name(s), {len(codecs)} codec "
        f"field(s), {matched} shared; {len(OWN_VOCABULARY)} own vocabulary, "
        f"{len(AWAITING_WALKER)} awaiting a walker"
    )
    if failures:
        for line in failures:
            print(f"  FAIL {line}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
