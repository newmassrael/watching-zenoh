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
    "auth": "the `0x3` establishment auth ext body, walked -- and unlike every "
    "sibling here it is not a field layout but an ext CHAIN: zenoh multiplexes "
    "each configured method into one extension keyed by `auth::id`, so the "
    "group's children are `ext` entries whose `ext_name` is the METHOD "
    "(`pubkey` / `usrpwd`). Held to Init and Open by the arm's guard, because "
    "`0x3` is a `Put`'s user `attachment` and those bytes can parse as a chain",
    "alice_segment": "the segment an InitSyn offers -- upstream's own field "
    "name (`zenoh-transport` `unicast/establishment/ext/shm.rs`)",
    "alice_challenge": "the InitAck's proof it could map that segment. The "
    "SAME wire position as `alice_segment` in the other half of the handshake, "
    "renamed because a reader told `alice_segment` on an ACK would have the "
    "direction backwards",
    "bob_segment": "the acceptor's own segment, the InitAck's second VLE",
    # R311y897 — the four METHOD bodies one level inside the `auth` chain, plus
    # the two `multi_link` halves that carry the same bytes under zenoh's
    # `.transmute()`d id. Group names on the `linkstate` rule; leaf names are
    # the layout's own, and none of them is a generated codec field because
    # every one of these bodies is hand-encoded.
    "usrpwd": "the usrpwd method's OpenSyn body inside the auth chain, walked. "
    "Same rule as `auth` one level up: the codec models the sub-ext body as "
    "`value`, and only the chain's carrier plus the method id says a "
    "credential is what these bytes hold",
    "pubkey": "the pubkey method's sub-ext body -- one, two or three ZBufs, "
    "the count being which stage of the mutual challenge-response this is",
    "multi_link": "`Init`'s `0x4`, which is pubkey's payload `.transmute()`d "
    "onto its own ext id with no re-framing, so it shares that walker. NOT "
    "`pubkey`: the name says which EXTENSION was read, and a reader told "
    "`pubkey` on a multilink Init would look for an auth chain that is not "
    "there",
    "multi_link_syn": "the `Open` half of that transmute. Held apart from "
    "`multi_link` because `Open` declares BOTH halves at `0x4` and only the "
    "ZBuf one has a body",
    "user": "the username in a usrpwd OpenSyn. Upstream's own field name "
    "(zenoh `establishment/ext/auth/usrpwd.rs` `OpenSyn { user, hmac }`)",
    "user_len": "that record's ZBuf length prefix, emitted so the walk TILES "
    "the body rather than leaving the two length bytes unaccounted for",
    "hmac": "the HMAC-SHA3-256 tag over the InitAck nonce -- upstream's own "
    "field name. Carried as bytes and NOT interpreted: what is inside it is "
    "the method's secret, which is the part that really is opaque",
    "hmac_len": "as `user_len`, for the second record",
    "pubkey_n": "the RSA modulus of a serialised public key, `n.to_bytes_le()` "
    "(zenoh's `ZPublicKey` `WCodec`). NOT `n`: that is already a protocol FLAG "
    "letter in this vocabulary, and a reader could not tell a modulus from a "
    "header bit",
    "pubkey_n_len": "as `user_len`, for the modulus record",
    "pubkey_e": "the RSA public exponent, `e.to_bytes_le()`. NOT `e`, for the "
    "same reason as `pubkey_n`",
    "pubkey_e_len": "as `user_len`, for the exponent record",
    "challenge": "the encrypted nonce of the mutual challenge-response, "
    "ciphertext and therefore terminal. Named for what the field IS rather "
    "than for its wz-side variable (`challenge_ct`), since the same record is "
    "the acceptor's challenge on an InitAck and the initiator's answer on an "
    "OpenSyn",
    "challenge_len": "as `user_len`, for the ciphertext record",
    "priority": "which priority band a message or a `priority_sn` row belongs "
    "to. TWO emitters, and both carry the BAND'S NAME as a label: the JOIN "
    "table's rows, where it is POSITIONAL (the body carries no such field, so "
    "it is emitted from the index and aliases the row's span), and the Z64 "
    "`qos` reading, where it is the low three bits. The adjudicator behind the "
    "name is `crate::qos::Priority::name` plus that module's own test pinning "
    "the eight discriminants to the zenoh-pico constants. R311y898 unified the "
    "two: this entry used to say a name 'would be a table with no adjudicator "
    "behind it' and the JOIN row emitted the raw discriminant, which left one "
    "field name carrying two value KINDS the moment the second emitter landed",
    # R311y898 -- the Z64 extension BODIES the walker reads. The whole `ExtZint`
    # encoding had no walker until this round, and three of the rows behind it
    # are bitfields: the QoS byte, a Request's target, a queryable's info. The
    # group name in each case is `ext_name`'s own row for the eid (`qos`,
    # `target`, `queryable_info`); the leaf names below are the sub-fields.
    "congestion": "the QoS byte's congestion-control field, read from bits 3 "
    "AND 5 (`QoSType::{D_FLAG, F_FLAG}`). A label rather than a delegation to "
    "`crate::qos::CongestionControl`, which has two variants where the wire "
    "has three: bit 5 alone is upstream's `BlockFirst`, and a reading through "
    "the narrower enum would call it `Drop`",
    "express": "the QoS byte's express flag, bit 4 -- upstream's own name "
    "(`QoSType::is_express`)",
    "undefined_bits": "whatever the reading did NOT account for, emitted only "
    "when non-zero. Upstream drops these silently (`From<ZExtZ64> for QoSType` "
    "is `ext.value as u8`), so a walk that showed clean sub-fields for a value "
    "with a high bit set would be every field correct and the message "
    "misreported",
    "read_as": "the value a conforming RECEIVER acts on, when that is not the "
    "value on the wire. Three Z64 rows are narrowed rather than rejected -- "
    "`NodeIdType::from` is `ext.value as u16`, `PatchType::from` is "
    "`as u8`, and zenoh-codec's Request reader is "
    "`BudgetType::new(l.value as u32)` -- so a capture carrying `node_id: "
    "70000` was reported as 70000 while every participant routed on 4464. "
    "Emitted only when the two differ, so its presence is a finding",
    "absent_to_receiver": "the third outcome of a narrowing, and only "
    "`budget` has it: `BudgetType` is a `NonZeroU32`, so a low word of zero "
    "collapses the extension to `None` and the query runs with NO reply "
    "budget. Not derivable from `undefined_bits` -- a literal `0` on the wire "
    "discards nothing and still means it",
    "target": "which matching queryables a Request is FOR -- upstream's own "
    "name (`network/request.rs` `ext_target`), as a label because the wire "
    "carries the enum's discriminant and the reader wants the value. Absent "
    "rather than guessed for a discriminant upstream rejects",
    "complete": "whether a declared queryable can serve the whole query by "
    "itself -- upstream's own field name (`QueryableInfoType { complete, "
    "distance }`), bit 0 of the z64",
    "distance": "the hop distance to that queryable, bits 8..24 of the same "
    "z64 -- upstream's own field name, and the ordering key a BestMatching "
    "route is chosen by",
}

# AWAITING: codec fields no walker emits yet, each with WHY. Rule 3 makes closing
# one mandatory rather than optional: land the walker and this entry must go.
AWAITING_WALKER = {
    "crc32": "serial_envelope is LINK framing, not a zenoh message -- outside the "
    "dissector's MID space by design",
    "header_flags": "ext_envelope's codec-internal split of the header byte; the "
    "walker surfaces those bits individually instead",
}


def walker_sites(src: str) -> dict[str, list[int]]:
    """Every field name the walkers emit, and the LINES it was read from.

    Three producing forms, and MISSING ONE IS HOW THIS GOES WRONG: the first
    version of this census matched only a fixed list of cursor methods, missed
    `c.text(` and `c.vle_u32(`, and reported `suffix` / `schema` / `packed_id` as
    absent when all three are emitted. So the cursor arm matches ANY method.

    R311y924 (item 321) — the lines ride along because the over-inclusion above
    is right and the REPORT of it was not. These patterns run over the raw file,
    so a `name: "x"` inside a doc comment, or inside a test that builds a field
    by hand, is claimed exactly as a walker's own literal is. That is deliberate:
    a name that is not a field must be DECLARED rather than silently skipped.
    But the failure then said "walker emits 'x'" and named no location, so a
    reader went looking for a walker that does not exist. R311y920 lost a round
    to it: a test wrote `name: "f"` and the census reported a walker.

    Nothing here classifies the site -- no attempt to tell a comment from a test
    from a walker, which is the kind of heuristic that earns false positives and
    stops being read. It reports WHERE, and the reader decides what they are
    looking at in one keystroke.
    """
    names: dict[str, list[int]] = {}

    def claim(pattern: str, text: str, base: int = 0) -> None:
        for m in re.finditer(pattern, text):
            line = text.count("\n", 0, m.start()) + 1 + base
            names.setdefault(m.group(1), []).append(line)

    claim(r'\bc\.[a-z_0-9]+\(\s*"([a-z0-9_]+)"', src)
    # R311y897 — the FOURTH producing form, and it was a live blind spot before
    # it was written: a helper that takes the cursor as its first argument and
    # the field names as literals after it. `read_zbuf_field(c, "user_len",
    # "user", &mut out)` emits two names that no arm above can see, so `user`,
    # `hmac`, `pubkey_n`, `pubkey_e` and `challenge` all reached the wire while
    # this census reported "34 own vocabulary" and exit 0. Same shape as the
    # `walked` tuple R311y896 found — a name that moves out of a call site
    # leaves the gate that exists to decide it — except that repair changed the
    # CODE and this one changes the gate, because a helper whose whole job is
    # to be the tiling SSOT should not have to be inlined to stay visible.
    # Deliberately OVER-inclusive: any literal in such a call is claimed, so a
    # name that is not a field must still be declared rather than silently
    # skipped.
    for call in re.finditer(r"\b[a-z_0-9]+\(\s*c,(.*?)\)\s*\?", src, re.S):
        base = src.count("\n", 0, call.start(1))
        claim(r'"([a-z0-9_]+)"', call.group(1), base)
    # `walked` joined this list at R311y896: the ZBuf-body dispatch was split
    # out of the walk so a test could ask WHICH rows have a walker without
    # having to hand each one a body its layout would accept. Its arms name
    # their group through `walked("literal", ..)`, which is why the helper is a
    # function and not a tuple -- as a tuple the eight names below it left this
    # census entirely, and the gate said so.
    claim(r'\b(?:bits|flag|group|leaf|text|label|walked)\(\s*"([a-z0-9_]+)"', src)
    claim(r'name:\s*"([a-z0-9_]+)"', src)
    return names


def walker_names(src: str) -> set[str]:
    """The names alone, for the arms that ask only whether one is present."""
    return set(walker_sites(src))


EXT_ZBUF_MATCH = re.compile(
    r"fn zbuf_body_walker\b.*?\blet hit: \(&'static str, ZbufBodyWalker\) = match name \{"
    r"(?P<arms>.*?)\n    \}",
    re.S,
)
"""The `match name` inside `zbuf_body_walker`, arms only.

Anchored on the function name AND on the binding, so a second `match name`
elsewhere in the file cannot be mistaken for this one, and a rename of either
end makes the block unfindable -- which this gate reports as a failure rather
than as an empty population.

R311y896 re-anchored it: the dispatch moved out of `walk_ext_zbuf_body` into
its own function so a test could interrogate it. The move was made visible by
this very message, which is the whole reason the "unfindable" branch below
exists.
"""

ARM_HEAD = re.compile(r"^        (?P<pat>\S.*?)\s*(?:\bif\b.*?)?=>", re.M)
"""One arm head of that match, at the block's own indentation.

R311y896 MEASURED, because the opposite was assumed first and a check was
written on the assumption: this DOES read an arm whose guard rustfmt wrapped
onto its own line, because `\\s*` matches the newline. Probed by wrapping the
`auth` arm's head and spelling its pattern as the literal `"auth"` -- the gate
reported it, so a wrapped head is checked rather than skipped. The check
written for the imagined hole was deleted: it could not be made to fail, and a
check that cannot fail is furniture.
"""


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
            "cannot find `zbuf_body_walker`'s `let hit: (&'static str, "
            "ZbufBodyWalker) = match name {` -- the arm-provenance rule (item 387) "
            "measured NOTHING. Re-anchor this regex on whatever the walker's "
            "dispatch is called now"
        ]
    arms = [m.group("pat").strip() for m in ARM_HEAD.finditer(block.group("arms"))]
    named = [a for a in arms if a != "_"]
    if not named:
        return [
            "`zbuf_body_walker` dispatches on no named extension -- either the "
            "match lost its arms or this gate stopped seeing them"
        ]
    out = []
    for arm in named:
        if not re.fullmatch(r"(?:crate::)?ext_name::[A-Z][A-Z0-9_]*", arm):
            out.append(
                f"`zbuf_body_walker` matches {arm!r}, which is not an "
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
    # An optional path, so a fixture can drive the arms below. R311y924 wanted
    # to SHOW that a name read out of a doc comment reports the comment's line
    # rather than an imaginary walker, and a gate whose message cannot be
    # exercised is a message nobody has read.
    dissect = Path(sys.argv[1]) if len(sys.argv) > 1 else DISSECT
    if not dissect.is_file():
        print(f"dissect-name-census: cannot read {dissect}", file=sys.stderr)
        return 1
    if not CODECS.is_dir():
        print(f"dissect-name-census: cannot read {CODECS}", file=sys.stderr)
        return 1

    src = dissect.read_text(encoding="utf-8")
    where = dissect.name
    sites = walker_sites(src)
    walkers = set(sites)

    def at(name: str) -> str:
        """Where this name was read, so the reader looks at the site and not
        for a walker that may not be one.

        Every caller passes a name drawn FROM `walkers`, so the lookup cannot
        come back empty and there is no fallback string to write -- a branch
        that cannot be reached is one nobody has ever seen be right.
        """
        lines = sorted(set(sites[name]))
        shown = ", ".join(f"{where}:{n}" for n in lines[:3])
        return shown if len(lines) <= 3 else f"{shown} (+{len(lines) - 3} more)"
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
            f"{name!r} is read at {at(name)} and is neither a codec field nor "
            "declared vocabulary -- name it after the codec's field, or add it "
            "to OWN_VOCABULARY with the reason it differs. This census claims "
            "any such literal, a doc comment's and a test's included, so read "
            "the site before assuming a walker emits it"
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
            f"{name!r} is declared as awaiting a walker, but it is now read at "
            f"{at(name)} -- delete the AWAITING_WALKER entry"
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
