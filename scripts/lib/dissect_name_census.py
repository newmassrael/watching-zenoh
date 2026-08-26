#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
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

## The four invariants

    1. every WALKER name is a codec field, or declared protocol vocabulary,
       or declared OWN vocabulary                      -- a new invention must be decided
    2. every CODEC field is emitted by a walker, or declared as awaiting one
    3. no declared entry is STALE                      -- a gap that closed must be removed
    4. every identifier a REASON cites is a live name  -- an excuse is adjudicated too

Rule 3 is what keeps the allowlists from becoming the thing they were meant to prevent.
Rule 4 keeps the REASONS from becoming it, and it arrived last: for most of this file's
life exit 0 said the name had been DECLARED and said nothing about whether the sentence
declaring it was still true of this tree. See [`reason_citations`].

## What it does NOT check

That a name is emitted for the RIGHT message. A walker emitting `zid` inside a Put would
satisfy this census. The claim here is about vocabulary, not placement; placement is what
the walkers' own tests assert.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import rust_comments  # noqa: E402  -- after the path insert that finds it

ROOT = Path(__file__).resolve().parents[2]
DISSECT = ROOT / "crates" / "wz-session-core" / "src" / "dissect.rs"
EXT_NAME = ROOT / "crates" / "wz-session-core" / "src" / "ext_name.rs"
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

# NON-NAMES: identifiers a reason backticks that are deliberately NOT names on
# this surface, each with what it is instead. Invariant 4 resolves every other
# backticked identifier against the two LIVE namespaces; this table is what is
# left over, and writing it down is what makes that sweep total rather than
# best-effort. It is checked in BOTH staleness directions on rule 3's own logic:
# an entry that BECOMES a name fails, and an entry no reason cites any more
# fails. The first of those is the shape that actually fired -- see
# [`reason_citations`].
REASON_NON_NAMES = {
    "challenge_ct": "the wz-side VARIABLE the record is built from. The reason "
    "names it so a reader can find the producer; the FIELD is `challenge`",
    "ext_target": "upstream's own field name, which the `target` row takes its "
    "name from. Not adjudicable here: it belongs to a checkout this repository "
    "deliberately records no path for, and a gate reading it would SKIP on "
    "every clone that has none -- green on an input it never opened",
    "label": "a `FieldValue` RENDER KIND. That reason says how the value is "
    "SHOWN, not what the field is called",
    "text": "the sibling render kind, cited in the same contrast as `label`",
    "walk_wireexpr": "a walker FUNCTION. The reason cites it to say which "
    "walker does NOT read this body",
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
    # Round 2036, open-debt item 327 — DERIVED, because this arm used to be a
    # hand-written alternation and a hand-written alternation is a list that
    # shuts its eyes on the next constructor.
    #
    # The docstring above already records this lesson for the FIRST arm ("the
    # first draft matched a fixed method list and missed `c.text(`, so it
    # matches any method"), and the lesson was applied to one arm only. Two
    # things the enumeration had quietly accumulated by the time it was
    # measured: `leaf` NAMED NOTHING -- it occurs in this file's prose and in
    # no call -- and `text` is a CURSOR METHOD that the `c.<method>(` arm above
    # already claims, so listing it here hid which arm owned it. A list that
    # can hold a dead entry for rounds is the shape `debt-47` is about,
    # arriving inside a gate.
    #
    # The class that is really closed: a free function whose FIRST parameter is
    # the field name. That is what makes a call site name-producing, and it is
    # readable straight off the source rather than remembered.
    claim(constructor_pattern(src), src)
    claim(r'name:\s*"([a-z0-9_]+)"', src)
    return names


FIELD_CONSTRUCTOR = re.compile(r"\bfn\s+([a-z_0-9]+)\(\s*name:\s*&'static str")
"""A free function that takes the field NAME as its first argument.

Anchored on the parameter rather than on the return type on purpose: `walked`
returns a `(&'static str, ZbufBodyWalker)` pair rather than a `Field`, and it is
every bit as much a name-producing site -- R311y896 measured what happened when
those eight names left the census by becoming a tuple.
"""


def field_constructors(src: str) -> list[str]:
    """The name-producing constructors this source defines, read from it.

    ⚠ ANTI-VACUITY IS THE CALLER'S JOB AND `constructor_pattern` DOES IT. A
    regex that stops matching returns an empty list, and an empty alternation
    would make this whole arm silently dead -- a population of zero passing as
    a clean sweep, which is the failure this gate exists to prevent in the code
    it reads.
    """
    return sorted(set(FIELD_CONSTRUCTOR.findall(src)))


def constructor_pattern(src: str) -> str:
    """The claim pattern for [`field_constructors`], or a hard failure.

    Raising rather than returning something harmless: the alternative to a
    constructor set is not a smaller sweep, it is a sweep that reports success
    over nothing. The known residue, stated rather than hidden: a constructor
    that does NOT take the name first is invisible to this derivation, exactly
    as it was to the list it replaces. What changed is that the ordinary case
    -- one more constructor in the existing shape -- no longer needs an edit
    here to be seen.
    """
    found = field_constructors(src)
    if not found:
        raise SystemExit(
            "dissect-name-census: no field constructor matches "
            f"{FIELD_CONSTRUCTOR.pattern!r} -- the derivation is dead and this "
            "arm would sweep nothing while reporting a clean census"
        )
    return r"\b(?:" + "|".join(found) + r')\(\s*"([a-z0-9_]+)"'


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


ROW_NAME_CONST = re.compile(r'\bconst\s+([A-Z][A-Z0-9_]*)\s*:\s*&str\s*=\s*"([a-z0-9_]+)"')
ROW_TUPLE = re.compile(r"\(\s*0x[0-9A-Fa-f]+\s*,\s*\w+\s*,\s*\w+\s*,\s*([^)]+?)\s*\)")


def ext_name_rows(src: str) -> set[str]:
    """Every row name of `ext_name`'s per-carrier tables -- the SECOND live
    namespace on this surface.

    Invariant 4 needs it because a reason citing `budget` or `attachment` is
    citing a real name that `walker_sites` structurally cannot see. Those are
    the names `z64_body_walker` dispatches on, and its group name is DISCARDED
    at the walk site (`let (_, walker) = z64_body_walker(..)?`), so no field is
    ever constructed from one. Without this set, five true citations would read
    as inventions and the repair would be to write down a lie.

    ⚠ COMMENTS ARE STRIPPED, and that is the OPPOSITE of what `walker_sites`
    does one screen up -- same class, different answer, which R2131 measured
    across three sweeps in a single round. There, over-collection is safe
    because a claimed literal must then be DECLARED, so claiming a comment costs
    a line of prose. Here the set EXCUSES citations, so a name picked up out of
    a commented-out row would silently license a reason that argues about
    nothing. Measured when this was written: stripping changes the answer by
    zero rows today. It is the ratchet that matters, not the delta.

    Half the tuples spell the name as a CONSTANT rather than a literal, so a
    sweep of literals alone under-reports -- the one direction a gate must not
    have. An unresolved fourth element is therefore a hard failure and not a
    skipped row: a namespace that quietly shrinks makes invariant 4 demand a
    declaration for a name that is perfectly live.
    """
    stripped = rust_comments.strip_comments(src)
    consts = dict(ROW_NAME_CONST.findall(stripped))
    names: set[str] = set()
    unresolved: set[str] = set()
    for raw in ROW_TUPLE.findall(stripped):
        item = raw.strip()
        if item.startswith('"') and item.endswith('"'):
            names.add(item[1:-1])
        elif item in consts:
            names.add(consts[item])
        else:
            unresolved.add(item)
    if unresolved:
        raise SystemExit(
            "dissect-name-census: ext_name row name(s) "
            + ", ".join(sorted(unresolved))
            + " resolve to neither a literal nor a `const _: &str` in "
            "ext_name.rs -- the second namespace would be short by that many "
            "and invariant 4 would demand a declaration for a live name"
        )
    if not names:
        raise SystemExit(
            "dissect-name-census: ext_name declares no rows -- the second "
            "namespace is dead, and every citation of one would read as an "
            "invention"
        )
    return names


REASON_BACKTICK = re.compile(r"`([^`]+)`")
REASON_IDENT = re.compile(r"[a-z][a-z0-9_]*")


def reason_citations(*tables: dict[str, str]) -> dict[str, list[str]]:
    """Every backticked PLAIN IDENTIFIER in a reason, and which rows cite it.

    ## The class this exists for

    R311y898 found the `priority` row asserting that a name there "would be a
    table with no adjudicator behind it" while the SAME round put
    `crate::qos::Priority::name` behind it. The census said nothing: its exit 0
    only ever meant the name had been declared. A human opened that table
    because six unrelated new names were REJECTED -- the discovery path was an
    accident, which is another way of saying there was none.

    ## Why the backtick is the population

    A reason is an argument, and an argument is not checkable. What IS checkable
    is where the argument stops and NAMES something, and in these reasons that
    place is marked: it is inside backticks. R2130 found the same thing one gate
    over, which is why this is the second instrument of the shape rather than
    the first.

    ## Why the token SHAPE is the discriminator

    A reason's backticks hold three kinds of thing and only one is adjudicable
    HERE. Names on this surface (`locator`, `budget`) are; upstream types and
    expressions (`QoSType::is_express`, `ext.value as u8`) and file paths
    (`network/request.rs`) are not -- they live in a checkout this repository
    records no path for. A bare lowercase identifier is exactly the first kind's
    shape, so anything carrying `::`, an uppercase letter, whitespace, a dot or
    a slash is left alone. That boundary is stated here rather than discovered
    later, and R2131 is why it is stated at all: one round found one sweep right
    to over-collect and two wrong to, so "over-inclusion is safe" is false for
    any sweep whose output EXCUSES something.

    Backticks are PAIRED first and the shape test applied second, rather than
    folded into one pattern. A lone `(?:[a-z][a-z0-9_]*)` between backticks
    would also match across a CLOSING backtick and the next OPENING one, so an
    identifier sitting between two quoted things would be claimed as if it had
    been quoted itself. Both readings agree on this tree's 47 citations; they
    would not agree on the first reason that puts two quotations side by side.
    """
    out: dict[str, list[str]] = {}
    for table in tables:
        for row, reason in table.items():
            for quoted in REASON_BACKTICK.findall(reason):
                if REASON_IDENT.fullmatch(quoted):
                    out.setdefault(quoted, []).append(row)
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


def selftest() -> int:
    """R2131 (unregistered open-debt item 402) — the OVER-INCLUSION is a
    decision, so it is asserted rather than only described.

    Item 402's first complaint is that the fourth producing form's boundary --
    `(c,` to the next `)?`, which takes any literal in between -- is stated in
    one comment and nowhere else, so nothing would notice if it silently
    changed. Two other sweeps of this shape were measured this round and BOTH
    were wrong to count a comment (`count_guard_lint.py` published a false test
    count, `analysis_surface_parity.py` resolved a claim against prose), which
    makes it worth pinning that this one is right to.

    It is right to because of what happens next: a literal claimed here must be
    DECLARED, and declaring one costs a line. Over-collecting cannot hide a name
    that reached the wire, which is the failure this census exists for.
    """
    # A constructor is part of the fixture because the constructor arm DERIVES
    # its own alternation and refuses a source with none -- its population-zero
    # guard, which fired the first time this selftest was run against a fixture
    # that had only calls in it.
    fixture = (
        "fn flag(name: &'static str, at: usize) -> Field {\n"
        "    Field::new(name, at)\n"
        "}\n"
        "fn probe(c: &mut SpanCursor<'_>) -> Result<Vec<Field>, CodecError> {\n"
        '    // read_zbuf_field(c, "wz_probe_len", "wz_probe", &mut out)?;\n'
        '    read_zbuf_field(c, "real_len", "real", &mut out)?;\n'
        "    Ok(out)\n"
        "}\n"
    )
    sites = walker_sites(fixture)
    bad: list[str] = []
    for name in ("wz_probe", "wz_probe_len"):
        if name not in sites:
            bad.append(
                f"the fourth form stopped claiming {name!r} from a comment -- "
                f"if that is now deliberate, this selftest is the place to say so"
            )
    if sites.get("wz_probe") != [5]:
        bad.append(
            f"a comment's literal must report the COMMENT's line, not a "
            f"walker's: got {sites.get('wz_probe')}"
        )
    # THE CONTROL: the same fixture's real call is claimed too, so the
    # assertions above are not satisfied by a sweep that claims everything, and
    # a name that is in no call at all is not claimed.
    if "real" not in sites:
        bad.append("the fourth form stopped claiming a REAL call's literal")
    if "wz_absent" in sites:
        bad.append("a name in no call at all was claimed")

    # ── invariant 4's two derivations (R2132, open-debt item 405) ────────
    #
    # Fixture-driven because NEITHER can be exercised against this tree.
    # `ext_name_rows` strips comments and the real table holds no
    # commented-out row -- measured, the delta is zero today -- and both of
    # its refusals are unreachable while that table is well-formed. A branch
    # nothing has ever been seen to take is a branch nobody has checked is
    # right, and the stripping arm in particular is the OPPOSITE decision to
    # the one asserted above, so leaving it unprobed would leave the file
    # asserting one answer and silently relying on the other.
    rows = ext_name_rows(
        'pub const AUTH: &str = "auth";\n'
        "const T: &[Row] = &[\n"
        '    (0x1, OPT, EXT_ENC_UNIT, "qos"),\n'
        "    (0x3, OPT, EXT_ENC_ZBUF, AUTH),\n"
        '    // (0x9, OPT, EXT_ENC_UNIT, "wz_commented_row"),\n'
        "];\n"
    )
    if rows != {"qos", "auth"}:
        bad.append(
            f"ext_name_rows read {sorted(rows)} from a fixture holding a "
            "literal row, a CONST row and a commented-out one -- expected the "
            "first two and only those"
        )

    def refuses(src: str, needle: str, why: str) -> None:
        try:
            ext_name_rows(src)
        except SystemExit as exc:
            if needle not in str(exc):
                bad.append(f"ext_name_rows refused {why}, but said: {exc}")
            return
        bad.append(f"ext_name_rows ACCEPTED {why} instead of refusing")

    refuses(
        'pub const AUTH: &str = "auth";\n'
        "const T: &[Row] = &[(0x1, OPT, EXT_ENC_UNIT, WZ_UNRESOLVED)];\n",
        "resolve to neither",
        "a row whose name resolves to nothing",
    )
    refuses("// every row commented out\n", "declares no rows", "an empty table")

    # The token SHAPE, both directions in one fixture: a bare identifier is a
    # claim about a name HERE, and a path, a type, an expression or a file is
    # a claim about a checkout this repository records no path for.
    cites = reason_citations(
        {
            "row": "cites `locator` and `budget`; `QoSType::is_express`, "
            "`ext.value as u8`, `network/request.rs` and `OpenSyn { user }` "
            "belong to upstream and are not adjudicable here"
        }
    )
    if sorted(cites) != ["budget", "locator"]:
        bad.append(
            f"the citation sweep claimed {sorted(cites)} -- expected the two "
            "bare identifiers and none of the four upstream tokens"
        )

    for line in bad:
        print(f"  dissect-name-census FAIL -- {line}")
    if bad:
        return 1
    print(
        f"  dissect-name-census: selftest ok -- the fourth form claims a "
        f"comment's literals on purpose ({len(sites)} name(s) in the fixture); "
        f"the ext_name sweep does NOT, and refuses both an unresolved row and "
        f"an empty table"
    )
    return 0


def main() -> int:
    # An optional path, so a fixture can drive the arms below. R311y924 wanted
    # to SHOW that a name read out of a doc comment reports the comment's line
    # rather than an imaginary walker, and a gate whose message cannot be
    # exercised is a message nobody has read.
    if len(sys.argv) > 1 and sys.argv[1] == "--selftest":
        return selftest()
    dissect = Path(sys.argv[1]) if len(sys.argv) > 1 else DISSECT
    if not dissect.is_file():
        print(f"dissect-name-census: cannot read {dissect}", file=sys.stderr)
        return 1
    if not CODECS.is_dir():
        print(f"dissect-name-census: cannot read {CODECS}", file=sys.stderr)
        return 1
    if not EXT_NAME.is_file():
        print(f"dissect-name-census: cannot read {EXT_NAME}", file=sys.stderr)
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

    # Invariant 4 (R2132, unregistered open-debt item 405): the REASONS are
    # adjudicated too, and not only the names they excuse.
    ext_rows = ext_name_rows(EXT_NAME.read_text(encoding="utf-8"))
    live = walkers | set(codecs) | declared | set(AWAITING_WALKER) | ext_rows
    cited = reason_citations(OWN_VOCABULARY, AWAITING_WALKER)
    if not cited:
        failures.append(
            "no reason cites a single backticked identifier -- either the "
            "vocabulary lost every cross-reference it had or this sweep stopped "
            "seeing them, and reporting success over an empty population is the "
            "way this invariant would be worst wrong"
        )
    for token in sorted(cited):
        if token in live or token in REASON_NON_NAMES:
            continue
        rows = ", ".join(sorted(set(cited[token])))
        failures.append(
            f"the reason for {rows} cites `{token}`, which is neither a name on "
            "this surface nor an `ext_name` row -- if that name went away the "
            "reason now argues about nothing, and if it never was one, declare "
            "it in REASON_NON_NAMES with what it is instead"
        )
    for token in sorted(REASON_NON_NAMES):
        if token in live:
            failures.append(
                f"`{token}` is declared in REASON_NON_NAMES as not a name on "
                "this surface, and it IS one now -- every reason citing it is "
                "arguing against a state of the tree that has moved. This is "
                "the exact shape R311y898 found in the `priority` row"
            )
        if token not in cited:
            failures.append(
                f"`{token}` is declared in REASON_NON_NAMES but no reason cites "
                "it any more -- delete the entry (rule 3)"
            )

    matched = len(walkers & set(codecs))
    print(
        f"dissect-name-census: {len(walkers)} walker name(s), {len(codecs)} codec "
        f"field(s), {matched} shared; {len(OWN_VOCABULARY)} own vocabulary, "
        f"{len(AWAITING_WALKER)} awaiting a walker"
    )
    # And what invariant 4 actually weighed. A sweep that prints only its verdict
    # cannot be told from one whose population collapsed, and this one's
    # population is PROSE -- the single easiest thing in the file to empty out
    # without anyone noticing.
    print(
        f"  reasons adjudicated: {sum(len(v) for v in cited.values())} citation(s) "
        f"of {len(cited)} identifier(s), against {len(live)} live name(s) "
        f"({len(ext_rows)} of them ext_name rows); "
        f"{len(REASON_NON_NAMES)} declared non-name(s)"
    )
    # Round 2036 (item 327) — AND WHICH CONSTRUCTORS THIS SWEEP WAS BUILT FROM.
    # R2012's lesson on item 253, one gate over: a sweep that narrows must
    # PRINT what it narrowed to, or a reader has no way to tell a complete
    # census from one whose derivation quietly stopped seeing a shape. The list
    # is short and the failure it makes visible is silent by nature.
    print(
        "  constructors swept (derived from the source, not listed here): "
        + ", ".join(field_constructors(src))
    )
    if failures:
        for line in failures:
            print(f"  FAIL {line}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
