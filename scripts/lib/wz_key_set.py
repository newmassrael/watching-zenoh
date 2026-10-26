#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

"""R3685 (no register item) -- the closed key set of `docs/closed-key-set.md`, phase 1: the declaration, what it refuses, and
the table `wz_session_core::key_catalogue::KeyCatalogue` is built over.

    wz_key_set.py --check               the fixture declaration validates, and the two files derived
                                        from it (the table and the matcher corpus) are current
    wz_key_set.py --write               write those files
    wz_key_set.py --emit FILE           print the table of the declaration FILE
    wz_key_set.py --selftest

## What a declaration says

The shape of a node declaration's entities (`scripts/lib/wz_node.py`, `docs/target-build-contract.md`
5b): a list of `[[entity]]` tables, each a `kind` (`publisher`, `subscriber`, `queryable`,
`querier` or `liveliness-token`) and a `key`. The key set is the distinct keys of those entities,
wildcard ones included, and an entity's number is its place in the order of kind and then key, so
adding an entity renumbers none that sort before it.

## What it refuses, and why a refusal is an exit

* a key that is not a key expression (the node declaration's own rule, `wz_node.key_problem`) or
  not a CANONICAL one (`a/**/*` is spelled `a/*/**`, a chunk of only `$*` is spelled `*`), since
  the subscriber table registers a pattern in canonical form and a key spelled otherwise would
  never be the text it holds; one deeper than the matcher holds; or the same entity twice;
* a publisher or a token on a wildcard: both name one concrete key (a wildcard publisher is the
  open question of the design note);
* a wildcard entity that no concrete key of the set meets: it could never select anything, and a
  closed image refuses what is outside the set, so declaring it is a mistake the build reports;
* a set past what `u16` numbers, in keys, entities or bytes of text.

## The selection is what the glob matcher says

An entity of kind `c` is in the selection of key `k` and kind `c` when its pattern intersects `k`.
`intersects` here is a port of the matcher the receive path runs
(`wz-session-core/src/keyexpr_match.rs`, `keyexpr_intersects_text`, every wildcard on). A port can
drift, so it is not trusted: `--write` also writes the matcher corpus (every pair of keys over a
small vocabulary, up to three chunks deep, with this module's answer), and
`crates/wz-session-core/tests/key_catalogue_model.rs` compares each answer with the real matcher and
every selection of the fixture's table with it. A change to the matcher that this module does not
follow fails that test, and the fixture's `--check` here fails when this module changes an answer.

The canonical-form verdict (`is_key_expression`, a port of `keyexpr_canon::validate_keyexpr`) is held
the same way: the corpus also carries its verdict on every text of up to six characters over
`a / * $ ?`, and the model test compares each with the validator and checks that what the validator
accepts is its own canonical form.
"""

from __future__ import annotations

import itertools
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import wz_config  # noqa: E402

ROOT = pathlib.Path(__file__).resolve().parents[2]
DATA = ROOT / "crates" / "wz-session-core" / "tests" / "key_set_data"
FIXTURE = DATA / "fixture.toml"
FIXTURE_RS = DATA / "fixture.rs"
CORPUS_RS = DATA / "corpus.rs"

# The kinds, in the order of `EntityKind::ALL`: the column of a key's row of the selection table.
KINDS = ("publisher", "subscriber", "queryable", "querier", "liveliness-token")
RUST_KIND = {
    "publisher": "Publisher",
    "subscriber": "Subscriber",
    "queryable": "Queryable",
    "querier": "Querier",
    "liveliness-token": "LivelinessToken",
}
# A kind that names one concrete key and not a pattern.
CONCRETE_ONLY = {
    "publisher": "puts on one concrete key",
    "liveliness-token": "is one literal key",
}
# `keyexpr_match::MAX_KEYEXPR_CHUNKS`: a key deeper than this is no-match on the fixed backing.
MAX_CHUNKS = 32
# What a `u16` numbers: keys, entities and bytes of text.
U16 = 0xFFFF

# The corpus: every key of one to DEPTH chunks over these chunks. A literal, a verbatim chunk, the
# three wildcards (`*`, `**`, a trailing and a leading `$*`) and a second literal to tell a literal
# from itself.
CORPUS_CHUNKS = ("a", "b", "@v", "*", "**", "a$*", "$*b")
CORPUS_DEPTH = 3

# The verdict corpus: every text of one to VERDICT_MAX_LEN characters over this alphabet, in product
# order, with whether `is_key_expression` accepts it. A literal, the separator, and the four
# characters the validator's arms turn on.
VERDICT_ALPHABET = ("a", "/", "*", "$", "?")
VERDICT_MAX_LEN = 6

ENTITY_KEYS = {"kind", "key"}
GENERATED_NOTE = "scripts/lib/wz_key_set.py --write"


# ---------------------------------------------------------------------------------------------
# the matcher, ported
# ---------------------------------------------------------------------------------------------


# The ports of the matcher and of the canonical-form verdict live in `wz_keyexpr.py`, which
# `wz_node.py` also uses; they are imported here under their own names.
from wz_keyexpr import (  # noqa: E402,F401
    ZID_RE,
    intersects,
    is_key_expression,
    is_wild,
    key_problem,
    rust_string,
    zid_bytes,
)


# ---------------------------------------------------------------------------------------------
# the declaration
# ---------------------------------------------------------------------------------------------


def key_limit(decl: dict) -> int:
    return next(lim["default"] for lim in decl["limits"] if lim["id"] == "MAX_KEYEXPR_BYTES")


def validate(entities: object, limit: int) -> list[str]:
    """Why the declared entities are not a key set the table can carry, or nothing."""
    if not isinstance(entities, list):
        return ["entity: not a list of tables"]
    problems: list[str] = []
    seen: set[tuple[str, str]] = set()
    keys: list[str] = []
    for number, entity in enumerate(entities, 1):
        who = f"entity {number}"
        if not isinstance(entity, dict):
            problems.append(f"{who}: not a table")
            continue
        for stray in sorted(set(entity) - ENTITY_KEYS):
            problems.append(f"{who}: `{stray}` is not a word of a key set's entity")
        kind, key = entity.get("kind"), entity.get("key")
        if kind not in KINDS:
            problems.append(f"{who}: kind {kind!r} is not one of {', '.join(KINDS)}")
            continue
        if not isinstance(key, str):
            problems.append(f"{who}: key is missing or not a string")
            continue
        who = f"{who} ({kind} `{key}`)"
        why = key_problem(key, limit)
        if why:
            problems.append(f"{who}: key {why}")
            continue
        if not is_key_expression(key):
            problems.append(
                f"{who}: key is not a canonical key expression (the table holds a pattern in "
                "canonical form, so a key spelled otherwise would never be the text it holds)"
            )
            continue
        if key.count("/") + 1 > MAX_CHUNKS:
            problems.append(f"{who}: key is deeper than {MAX_CHUNKS} chunks, which the matcher holds")
            continue
        if kind in CONCRETE_ONLY and is_wild(key):
            problems.append(f"{who}: a {kind} {CONCRETE_ONLY[kind]}, and this key has a wildcard")
        if (kind, key) in seen:
            problems.append(f"{who}: declared twice")
        seen.add((kind, key))
        keys.append(key)
    concrete = sorted({key for key in keys if not is_wild(key)})
    for kind, key in sorted(seen):
        if is_wild(key) and not any(intersects(key, other) for other in concrete):
            problems.append(
                f"{kind} `{key}`: no concrete key of the set meets this pattern, so it could never "
                "select anything and a closed image refuses every key outside the set"
            )
    distinct = {key for _, key in seen}
    if len(distinct) > U16:
        problems.append(f"{len(distinct)} keys: a table numbers at most {U16}")
    if len(seen) > U16:
        problems.append(f"{len(seen)} entities: a table numbers at most {U16}")
    text_bytes = sum(len(key.encode("utf-8")) for key in distinct)
    if text_bytes > U16:
        problems.append(f"{text_bytes} bytes of key text: a table addresses at most {U16}")
    return problems


# ---------------------------------------------------------------------------------------------
# the table
# ---------------------------------------------------------------------------------------------


def build(entities: list[dict]) -> dict:
    """The table of a declaration `validate` accepted: keys sorted by their bytes, entities by kind
    and then key, and for each key and kind the entities that intersect it, in entity order."""
    distinct = {entity["key"] for entity in entities}
    keys = sorted(distinct, key=lambda key: key.encode("utf-8"))
    key_id = {key: index for index, key in enumerate(keys)}
    rows = sorted(
        ((KINDS.index(entity["kind"]), entity["key"]) for entity in entities),
        key=lambda row: (row[0], row[1].encode("utf-8")),
    )
    offsets = [0]
    members: list[int] = []
    for key in keys:
        for kind in range(len(KINDS)):
            members.extend(
                number
                for number, (row_kind, pattern) in enumerate(rows)
                if row_kind == kind and intersects(pattern, key)
            )
            offsets.append(len(members))
    ends: list[int] = []
    total = 0
    for key in keys:
        total += len(key.encode("utf-8"))
        ends.append(total)
    return {
        "keys": keys,
        "ends": ends,
        "offsets": offsets,
        "members": members,
        "entities": [(KINDS[kind], key_id[key], key) for kind, key in rows],
    }


# ---------------------------------------------------------------------------------------------
# what each declared peer may use
# ---------------------------------------------------------------------------------------------

# The operations an allowance decides, in the order of `PeerOp::ALL`: the row beside a peer's.
PEER_OPS = ("publish",)
ALLOW_WORDS = {"peer", "ops", "keys"}


def validate_allows(allows: object, entities: list[dict], limit: int, peers: set[str] | None = None) -> list[str]:
    """Why the `[[allow]]` tables are not an allowance the table can carry, or nothing. `entities` are
    the entities of the key set, already valid; `peers` are the zids the node declares as peers, when
    there is a node to say (a peer that is allowed something must be one it declares)."""
    if not isinstance(allows, list):
        return ["allow: not a list of tables"]
    concrete = sorted({e["key"] for e in entities if not is_wild(e["key"])})
    problems: list[str] = []
    for number, allow in enumerate(allows, 1):
        who = f"allow {number}"
        if not isinstance(allow, dict):
            problems.append(f"{who}: not a table")
            continue
        for stray in sorted(set(allow) - ALLOW_WORDS):
            problems.append(f"{who}: `{stray}` is not a word of an allowance")
        peer = allow.get("peer")
        if not isinstance(peer, str) or ZID_RE.fullmatch(peer) is None:
            problems.append(f"{who}: peer is {peer!r}, not the lowercase hex of a zid (no leading 0, at most 32 digits)")
        elif peers is not None and peer not in peers:
            problems.append(f"{who}: peer {peer} is not a peer endpoint the node declares")
        else:
            who = f"{who} (peer {peer})"
        ops = allow.get("ops")
        if not isinstance(ops, list) or not ops or any(op not in PEER_OPS for op in ops):
            problems.append(f"{who}: ops is {ops!r}, a non-empty list of {', '.join(PEER_OPS)}")
        patterns = allow.get("keys")
        if not isinstance(patterns, list) or not patterns:
            problems.append(f"{who}: keys is missing or not a non-empty list of key expressions")
            continue
        for pattern in patterns:
            if not isinstance(pattern, str):
                problems.append(f"{who}: key {pattern!r} is not a string")
            elif key_problem(pattern, limit) or not is_key_expression(pattern):
                problems.append(f"{who}: key `{pattern}` is not a canonical key expression")
            elif not any(intersects(pattern, key) for key in concrete):
                problems.append(f"{who}: key `{pattern}` allows no concrete key of the set, so it allows nothing")
    return problems


def build_allowance(entities: list[dict], allows: list[dict]) -> dict:
    """The allowance of valid `[[allow]]` tables over the table of `entities`: the declared peers in
    ascending order of their zid bytes (the form `PEER_NODES` holds), and a row of one bit for each key
    of the set for each peer and operation. A key is allowed to a peer for an operation when it is
    concrete and some pattern listed for that peer and operation intersects it."""
    keys = build(entities)["keys"]
    by_peer: dict[str, dict[str, set[str]]] = {}
    for allow in allows:
        for op in allow["ops"]:
            by_peer.setdefault(allow["peer"], {}).setdefault(op, set()).update(allow["keys"])
    peers = sorted(by_peer, key=lambda peer: bytes(zid_bytes(peer)))
    row = (len(keys) + 7) // 8
    bits: list[int] = []
    for peer in peers:
        for op in PEER_OPS:
            patterns = by_peer[peer].get(op, set())
            cells = [0] * row
            for index, key in enumerate(keys):
                if not is_wild(key) and any(intersects(pattern, key) for pattern in patterns):
                    cells[index // 8] |= 1 << (index % 8)
            bits.extend(cells)
    return {
        "zids": [zid_bytes(peer) for peer in peers],
        "keys": len(keys),
        "bits": bits,
        "declared": [
            (zid_bytes(peer), PEER_OPS.index(op), sorted(by_peer[peer][op]))
            for peer in peers
            for op in PEER_OPS
            if op in by_peer[peer]
        ],
    }


def packed(items: list[str], indent: str, width: int = wz_config.RUST_MAX_WIDTH) -> list[str]:
    """`items` as lines no wider than `width`, each a run of `item,` separated by spaces."""
    lines: list[str] = []
    line = indent
    for item in items:
        piece = f"{item},"
        if line.strip() and len(line) + 1 + len(piece) > width:
            lines.append(line)
            line = indent
        line = f"{line} {piece}" if line.strip() else f"{line}{piece}"
    if line.strip():
        lines.append(line)
    return lines


def header(source: str) -> list[str]:
    return [
        f"// {wz_config.SPDX}",
        f"// {wz_config.COPYRIGHT}",
        "//",
        f"// GENERATED from {source} by {GENERATED_NOTE}.",
        "// Do not edit: `wz_key_set.py --check` fails when this file is stale.",
        "",
    ]


def open_lines() -> list[str]:
    """What a node that states no closed key set has where a closed one has its table: the module, and
    in it `CLOSED`, which is `None`. A node's code reads `key_set::CLOSED` whichever it is, and a node
    that declares its keys is the one that has `Some`."""
    return [
        "/// The key set the node declares: none, since it does not state a closed one.",
        "pub mod key_set {",
        "    #![allow(dead_code)]",
        "    pub const CLOSED: Option<&'static wz_session_core::key_catalogue::KeyCatalogue<'static>> = None;",
        "    pub const ALLOWED_PEERS: Option<&'static wz_session_core::key_allowance::PeerAllowance<'static>> = None;",
        "}",
    ]


def table_lines(
    table: dict, declared: bool = False, closed: bool = False, allowance: dict | None = None
) -> list[str]:
    """The Rust of a table, as one module `key_set` that a file includes where it is wanted: the arrays,
    private, and the `CATALOGUE` built over them, public. It is a module so that it names nothing of
    its includer's (a node's `declared.rs` has its own `MEMBERS`), carries its own `use` and inner
    attribute, and refers to the crate by its name, so it is the same text in an image and in a test.
    `declared` adds the declaration as the entities were numbered, which the model test reads and an
    image has no use for. `closed` adds `CLOSED`, the table as an `Option`, which is `Some` here and
    `None` in [`open_lines`], so that code reads one name for both; with it, `ALLOWED_PEERS` is the
    peer allowance as an `Option` in the same way, `Some` when `allowance` is given."""
    skip = "    #[rustfmt::skip]"
    out = [
        "/// The key catalogue of the declaration, as `KeyCatalogue` reads it. A bad table is a build",
        "/// error: `KeyCatalogue::new` checks every property in a `const`.",
        "pub mod key_set {",
        "    #![allow(dead_code)]",
        "    use wz_session_core::key_catalogue::{EntityId, EntityKind, EntityRow, KeyCatalogue, KeyId};",
        "",
        skip,
    ]
    if table["keys"]:
        out.append("    const KEY_TEXT: &str = concat!(")
        out += [f"        {rust_string(key)}," for key in table["keys"]]
        out.append("    );")
    else:
        out.append('    const KEY_TEXT: &str = "";')
    out += ["", skip, f"    const KEY_ENDS: [u16; {len(table['ends'])}] = ["]
    out += packed([str(n) for n in table["ends"]], "        ")
    out += ["    ];", "", skip, f"    const OFFSETS: [u16; {len(table['offsets'])}] = ["]
    out += packed([str(n) for n in table["offsets"]], "        ")
    out += ["    ];", "", skip, f"    const MEMBERS: [EntityId; {len(table['members'])}] = ["]
    out += packed([f"EntityId::new({n})" for n in table["members"]], "        ")
    out += ["    ];", "", skip, f"    const ENTITIES: [EntityRow; {len(table['entities'])}] = ["]
    out += [
        f"        EntityRow::new(EntityKind::{RUST_KIND[kind]}, KeyId::new({key})),"
        for kind, key, _ in table["entities"]
    ]
    out += [
        "    ];",
        "",
        skip,
        "    pub const CATALOGUE: KeyCatalogue<'static> =",
        "        KeyCatalogue::new(KEY_TEXT, &KEY_ENDS, &OFFSETS, &MEMBERS, &ENTITIES);",
    ]
    if closed:
        out += [
            "",
            "    /// The table of a node that states a closed key set; `None` for one that does not.",
            "    pub const CLOSED: Option<&'static KeyCatalogue<'static>> = Some(&CATALOGUE);",
        ]
        if allowance is None:
            out += [
                "",
                "    /// What each declared peer may use: none declared, so the peer is not asked.",
                "    pub const ALLOWED_PEERS: Option<&'static wz_session_core::key_allowance::PeerAllowance<'static>> =",
                "        None;",
            ]
        else:
            zids = [f"[{', '.join(str(b) for b in zid)}]" for zid in allowance["zids"]]
            out += [
                "",
                "    /// What each declared peer may use: a row of one bit for each key of the set, for each",
                "    /// peer (by the sixteen bytes of its zid, as `PEER_NODES` holds it) and each operation.",
                skip,
                f"    const PEER_ZIDS: [[u8; 16]; {len(zids)}] = [",
            ]
            out += packed(zids, "        ", 100)
            out += ["    ];", "", skip, f"    const PEER_BITS: [u8; {len(allowance['bits'])}] = ["]
            out += packed([str(n) for n in allowance["bits"]], "        ")
            out += [
                "    ];",
                "",
                skip,
                "    pub const PEER_ALLOWANCE: wz_session_core::key_allowance::PeerAllowance<'static> =",
                f"        wz_session_core::key_allowance::PeerAllowance::new(&PEER_ZIDS, {allowance['keys']}, &PEER_BITS);",
                "",
                skip,
                "    pub const ALLOWED_PEERS: Option<&'static wz_session_core::key_allowance::PeerAllowance<'static>> =",
                "        Some(&PEER_ALLOWANCE);",
            ]
    if declared and allowance is not None:
        out += [
            "",
            "    /// The allowance as declared: for each peer and operation (an index of `PeerOp::ALL`) the",
            "    /// patterns the declaration lists, which the model test compares every bit with.",
            skip,
            f"    pub const ALLOW_DECLARED: [([u8; 16], usize, &[&str]); {len(allowance['declared'])}] = [",
        ]
        for zid, op, patterns in allowance["declared"]:
            listed = ", ".join(rust_string(pattern) for pattern in patterns)
            out.append(f"        ([{', '.join(str(b) for b in zid)}], {op}, &[{listed}]),")
        out.append("    ];")
    if declared:
        out += [
            "",
            "    /// The declaration as the entities were numbered: row `n` is entity `n`.",
            skip,
            f"    pub const DECLARED: [(EntityKind, &str); {len(table['entities'])}] = [",
        ]
        out += [
            f"        (EntityKind::{RUST_KIND[kind]}, {rust_string(key)}),"
            for kind, _, key in table["entities"]
        ]
        out.append("    ];")
    out.append("}")
    return out


def emit_table(
    table: dict, source: str, declared: bool = False, closed: bool = False, allowance: dict | None = None
) -> str:
    """The file a test includes: a header and the module of [`table_lines`]."""
    return "\n".join(header(source) + table_lines(table, declared, closed, allowance)) + "\n"


def corpus_keys() -> list[str]:
    return [
        "/".join(chunks)
        for depth in range(1, CORPUS_DEPTH + 1)
        for chunks in itertools.product(CORPUS_CHUNKS, repeat=depth)
    ]


def emit_corpus() -> str:
    """Every pair of the corpus's keys, answered by `intersects`. The matcher is symmetric, so row `i`
    holds the bits of the pairs `(i, j)` with `j >= i`, four to a hex digit (the pair `(i, i + 4n + r)`
    is bit `r` of digit `n`); the model test asks both orders of every pair, which checks the symmetry
    too."""
    keys = corpus_keys()
    rows = []
    for i, left in enumerate(keys):
        bits = [intersects(left, right) for right in keys[i:]]
        bits += [False] * (-len(bits) % 4)
        rows.append("".join(f"{sum(1 << r for r in range(4) if bits[n + r]):x}" for n in range(0, len(bits), 4)))
    out = header("the matcher port of scripts/lib/wz_key_set.py")
    out += [
        "//! The answers of the matcher port, for every pair of keys over a small vocabulary: what",
        "//! `tests/key_catalogue_model.rs` compares with the real matcher.",
        "",
        "#![allow(dead_code)]",
        "",
        "/// Every key of one to three chunks over the vocabulary, in product order.",
        "#[rustfmt::skip]",
        f"pub const KEYS: [&str; {len(keys)}] = [",
    ]
    out += packed([rust_string(key) for key in keys], "    ")
    out += [
        "];",
        "",
        "/// Row `i`: the pairs `(i, j)` for `j >= i`, four to a hex digit, bit `r` of digit `n` being",
        "/// the pair `(i, i + 4n + r)`.",
        "#[rustfmt::skip]",
        f"pub const ROWS: [&str; {len(rows)}] = [",
    ]
    out += [f'    "{row}",' for row in rows]
    out.append("];")
    verdicts = [
        is_key_expression("".join(letters))
        for length in range(1, VERDICT_MAX_LEN + 1)
        for letters in itertools.product(VERDICT_ALPHABET, repeat=length)
    ]
    verdicts += [False] * (-len(verdicts) % 4)
    digits = "".join(
        f"{sum(1 << r for r in range(4) if verdicts[n + r]):x}" for n in range(0, len(verdicts), 4)
    )
    lines = [digits[at : at + 100] for at in range(0, len(digits), 100)]
    out += [
        "",
        "/// The alphabet of the verdict corpus.",
        "pub const VERDICT_ALPHABET: [char; "
        + f"{len(VERDICT_ALPHABET)}] = ["
        + ", ".join(f"'{letter}'" for letter in VERDICT_ALPHABET)
        + "];",
        "",
        "/// The longest text of the verdict corpus.",
        f"pub const VERDICT_MAX_LEN: usize = {VERDICT_MAX_LEN};",
        "",
        "/// Whether `is_key_expression` accepts each text of one to `VERDICT_MAX_LEN` characters over the",
        "/// alphabet, in product order (the first letter varies slowest), four to a hex digit, bit `r` of",
        "/// digit `n` being text `4n + r`, the digits split into lines.",
        "#[rustfmt::skip]",
        f"pub const VERDICT: [&str; {len(lines)}] = [",
    ]
    out += [f'    "{line}",' for line in lines]
    out.append("];")
    return "\n".join(out) + "\n"


# ---------------------------------------------------------------------------------------------
# the fixture, check and write
# ---------------------------------------------------------------------------------------------


def load_declaration(path: pathlib.Path, limit: int) -> tuple[list[dict], list[dict]]:
    """A declaration file's entities and its `[[allow]]` tables, validated."""
    data = wz_config.read_decl_toml(path.read_text(encoding="utf-8"))
    stray = sorted(set(data) - {"entity", "allow"})
    if stray:
        raise ValueError(f"{path.name}: `{', '.join(stray)}` is not a table of a key set declaration")
    entities = data.get("entity", [])
    allows = data.get("allow", [])
    problems = validate(entities, limit)
    if not problems:
        problems = validate_allows(allows, entities, limit)
    if problems:
        raise ValueError(f"{path.name}: " + "; ".join(problems))
    return entities, allows


def load_entities(path: pathlib.Path, limit: int) -> list[dict]:
    return load_declaration(path, limit)[0]


def derived(decl: dict) -> dict[pathlib.Path, str]:
    entities, allows = load_declaration(FIXTURE, key_limit(decl))
    table = build(entities)
    allowance = build_allowance(entities, allows) if allows else None
    return {
        FIXTURE_RS: emit_table(
            table,
            "crates/wz-session-core/tests/key_set_data/fixture.toml",
            declared=True,
            closed=True,
            allowance=allowance,
        ),
        CORPUS_RS: emit_corpus(),
    }


def check(decl: dict) -> int:
    try:
        files = derived(decl)
    except (ValueError, OSError) as err:
        print(f"  wz-key-set FAIL: {err}", file=sys.stderr)
        return 1
    bad = 0
    for path, text in files.items():
        if not path.is_file() or path.read_text(encoding="utf-8") != text:
            print(f"  wz-key-set FAIL: {path.name} is missing or stale: regenerate it with --write", file=sys.stderr)
            bad += 1
    print(f"wz-key-set: the fixture and its {len(files)} derived file(s), {len(files) - bad} current")
    return 1 if bad else 0


def write(decl: dict) -> int:
    try:
        files = derived(decl)
    except (ValueError, OSError) as err:
        print(f"  wz-key-set FAIL: {err}", file=sys.stderr)
        return 1
    for path, text in files.items():
        path.write_text(text, encoding="utf-8")
    print(f"wz-key-set: wrote {len(files)} file(s)")
    return 0


# ---------------------------------------------------------------------------------------------
# selftest
# ---------------------------------------------------------------------------------------------


def _selftest() -> int:
    decl = wz_config.load_decl()
    limit = key_limit(decl)

    def expect(what: str, ok: bool) -> None:
        if not ok:
            raise AssertionError(what)

    def refuses(what: str, entities: list[dict], needle: str) -> None:
        found = validate(entities, limit)
        expect(f"{what}: expected a finding naming {needle!r}, got {found}", any(needle in p for p in found))

    def entity(kind: str, key: str) -> dict:
        return {"kind": kind, "key": key}

    # The matcher port, on cases the matcher's own comments and zenoh's rules settle.
    for left, right, answer in [
        ("a/**", "a", True),
        ("a/*", "a", False),
        ("a/*", "a/b", True),
        ("**", "a/b/c", True),
        ("**", "@v", False),
        ("**/a", "@v/a", False),
        ("@v", "@v", True),
        ("@v/**", "@v/a/b", True),
        ("a/**/c", "a/c", True),
        ("a/**/c", "a/b/d/c", True),
        ("a/**/c", "a/b/d", False),
        ("a$*", "ab", True),
        ("a$*", "a", True),
        ("a$*", "b", False),
        ("$*b", "ab", True),
        ("$*b", "a", False),
        ("$*b", "a$*", True),
        ("a$*", "b$*", False),
        ("*/a", "b/*", True),
        ("a/b", "a/b", True),
        ("a/b", "a/c", False),
    ]:
        expect(f"intersects({left!r}, {right!r}) is {answer}", intersects(left, right) is answer)
        expect(f"intersects is symmetric on ({left!r}, {right!r})", intersects(right, left) is answer)

    # A valid declaration, and the table it builds.
    entities = [
        entity("publisher", "a/b"),
        entity("subscriber", "a/*"),
        entity("queryable", "a"),
    ]
    expect("the sample declaration is valid", validate(entities, limit) == [])
    table = build(entities)
    expect("keys are sorted by their bytes", table["keys"] == ["a", "a/*", "a/b"])
    expect("entities are numbered by kind and then key",
           table["entities"] == [("publisher", 2, "a/b"), ("subscriber", 1, "a/*"), ("queryable", 0, "a")])
    expect("the selections are the intersections",
           table["offsets"] == [0, 0, 0, 1, 1, 1, 2, 3, 3, 3, 3, 4, 5, 5, 5, 5] and table["members"] == [2, 0, 1, 0, 1])
    expect("key ends are cumulative", table["ends"] == [1, 4, 7])
    ordered = [(KINDS.index(kind), key) for kind, key, _ in table["entities"]]
    expect("entities ascend strictly by kind and then key id, which find_entity searches on",
           all(a < b for a, b in zip(ordered, ordered[1:])))
    expect("renumbering: another entity sorting after changes no earlier number",
           build(entities + [entity("querier", "a/b")])["entities"][:3] == table["entities"])
    expect("the order of declaration does not change the table", build(list(reversed(entities))) == table)
    rs = emit_table(table, "x.toml", declared=True)
    expect("the table names its source", "GENERATED from x.toml by scripts/lib/wz_key_set.py --write." in rs)
    expect("the keys are one concat", 'concat!(\n        "a",\n        "a/*",\n        "a/b",\n    );' in rs)
    expect("the table is one module that names nothing of its includer's",
           "pub mod key_set {" in rs and "pub const CATALOGUE: KeyCatalogue<'static>" in rs
           and "#![allow(dead_code)]" in rs and "\n//!" not in rs)
    expect("the declaration is a constant of the file when asked for", "pub const DECLARED: [(EntityKind, &str); 3]" in rs)
    expect("and left out when not", "DECLARED" not in emit_table(table, "x.toml"))
    expect("`CLOSED` is `Some` of the table for a closed node and is not there otherwise",
           "pub const CLOSED: Option<&'static KeyCatalogue<'static>> = Some(&CATALOGUE);"
           in emit_table(table, "x.toml", closed=True) and "CLOSED" not in emit_table(table, "x.toml"))
    expect("a node that states no closed key set has `CLOSED = None`",
           "pub const CLOSED: Option<&'static wz_session_core::key_catalogue::KeyCatalogue<'static>> = None;"
           in "\n".join(open_lines()))
    expect("an empty declaration is a table", "const KEY_TEXT: &str = \"\";" in emit_table(build([]), "x.toml"))

    # What it refuses.
    refuses("a kind outside the vocabulary", [entity("sink", "a")], "is not one of")
    refuses("a key that is not a key", [entity("queryable", "a//b")], "empty chunk")
    refuses("a key with a space", [entity("queryable", "a b")], "a character a key expression does not")
    refuses("a key past the key limit", [entity("queryable", "a" * (limit + 1))], "MAX_KEYEXPR_BYTES")
    refuses("a key too deep", [entity("queryable", "/".join("a" * 33))], "deeper than")
    for text in ["a/b", "a/*/**", "lab/sensor/t$*", "**", "*", "@/lab/*", "a$*b/c", "a/$*b", "*/**/a"]:
        expect(f"{text!r} is a key expression", is_key_expression(text))
    for text in ["", "/", "a//b", "/a", "a/", "a/**/*", "a/**/**", "a/$*", "$*", "a*", "*a", "**a",
                 "a$", "$a", "a$*$b", "a$*$*b", "a#", "a?", "a/*b", "a/**/*/b"]:
        expect(f"{text!r} is not a key expression", not is_key_expression(text))
    for text, why in [("a/$*", "a lone `$*` chunk"), ("a/**/*", "a `*` after a `**`"),
                      ("a*b", "a star inside a chunk"), ("a$*$*b", "a run of `$*`"),
                      ("a/**/**", "a `**` after a `**`")]:
        refuses(why, [entity("queryable", text), entity("publisher", "a/b")], "canonical")
    refuses("an entity word outside the vocabulary", [{"kind": "queryable", "key": "a", "bytes": 1}], "is not a word")
    refuses("the same entity twice", [entity("queryable", "a"), entity("queryable", "a")], "declared twice")
    refuses("a wildcard publisher", [entity("subscriber", "a"), entity("publisher", "a/*")], "puts on one concrete key")
    refuses("a wildcard token", [entity("subscriber", "a"), entity("liveliness-token", "a/**")], "one literal key")
    refuses("a wildcard that nothing concrete meets", [entity("subscriber", "a/**")], "no concrete key")
    refuses("a wildcard that only another wildcard meets",
            [entity("subscriber", "a/**"), entity("queryable", "a/*")], "no concrete key")
    expect("a wildcard that a concrete key meets is valid",
           validate([entity("subscriber", "a/**"), entity("publisher", "a/b")], limit) == [])
    expect("one key under two kinds is one key",
           build([entity("subscriber", "a"), entity("queryable", "a")])["keys"] == ["a"])

    # Allowances: what each declared peer may publish.
    small = [entity("publisher", "a/b"), entity("subscriber", "a/*"), entity("queryable", "a")]

    def allow(peer: str, keys: list, ops: tuple = ("publish",)) -> dict:
        return {"peer": peer, "ops": list(ops), "keys": list(keys)}

    def refuses_allow(what: str, allows: list, needle: str, peers: set | None = None) -> None:
        found = validate_allows(allows, small, limit, peers)
        expect(f"{what}: expected a finding naming {needle!r}, got {found}", any(needle in p for p in found))

    expect("an allowance over the key set is valid",
           validate_allows([allow("a1", ["a/**"]), allow("b2", ["a/b", "a"])], small, limit, {"a1", "b2"}) == [])
    allowed = build_allowance(small, [allow("b2", ["a/**"]), allow("a1", ["a/b"])])
    expect("peers are in ascending order of their zid bytes", allowed["zids"][0][0] == 0xA1 and allowed["zids"][1][0] == 0xB2)
    expect("a key is allowed when a listed pattern intersects it, and a pattern key never is",
           allowed["bits"] == [0b100, 0b101] and allowed["keys"] == 3)
    expect("the declaration is kept as it was listed", allowed["declared"][0][2] == ["a/b"])
    refuses_allow("a peer that is not a zid", [allow("0a", ["a/b"])], "lowercase hex")
    refuses_allow("an operation outside the vocabulary", [allow("a1", ["a/b"], ("subscribe",))], "ops is")
    refuses_allow("an allowance with no keys", [allow("a1", [])], "keys is missing")
    refuses_allow("a pattern that is not canonical", [allow("a1", ["a/**/*"])], "canonical key expression")
    refuses_allow("a pattern that allows nothing", [allow("a1", ["zzz/**"])], "allows nothing")
    refuses_allow("a word outside the vocabulary", [{**allow("a1", ["a/b"]), "deny": []}], "is not a word")
    refuses_allow("a peer the node does not declare", [allow("a1", ["a/b"])], "not a peer endpoint", {"b2"})
    one = emit_table(build(small), "x.toml", closed=True, allowance=allowed)
    expect("the allowance is a table checked in a const, and `ALLOWED_PEERS` is `Some` of it",
           "PeerAllowance::new(&PEER_ZIDS, 3, &PEER_BITS)" in one and "Some(&PEER_ALLOWANCE)" in one)
    expect("a closed key set that declares no peers has `ALLOWED_PEERS = None`",
           "ALLOWED_PEERS" in emit_table(build(small), "x.toml", closed=True)
           and "PEER_BITS" not in emit_table(build(small), "x.toml", closed=True))

    # The fixture and the derived files are current, and the fixture uses every kind.
    kinds = {e["kind"] for e in load_entities(FIXTURE, limit)}
    expect("the fixture declares every kind", kinds == set(KINDS))
    expect("the corpus has the rows it says", emit_corpus().count('    "') >= len(corpus_keys()))
    return check(decl)


def main(argv: list[str]) -> int:
    if argv == ["--selftest"]:
        try:
            return _selftest()
        except AssertionError as err:
            print(f"wz-key-set: FAIL -- {err}", file=sys.stderr)
            return 1
    decl = wz_config.load_decl()
    if argv == ["--check"]:
        return check(decl)
    if argv == ["--write"]:
        return write(decl)
    if len(argv) == 2 and argv[0] == "--emit":
        try:
            entities = load_entities(pathlib.Path(argv[1]), key_limit(decl))
        except (ValueError, OSError) as err:
            print(f"wz-key-set: REFUSED -- {err}", file=sys.stderr)
            return 1
        print(emit_table(build(entities), argv[1]), end="")
        return 0
    print(__doc__, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
