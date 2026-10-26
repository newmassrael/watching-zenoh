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

* a key that is not a key expression (the node declaration's own rule, `wz_node.key_problem`), one
  deeper than the matcher holds, or the same entity twice;
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
"""

from __future__ import annotations

import functools
import itertools
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import wz_config  # noqa: E402
import wz_node  # noqa: E402

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

ENTITY_KEYS = {"kind", "key"}
GENERATED_NOTE = "scripts/lib/wz_key_set.py --write"


# ---------------------------------------------------------------------------------------------
# the matcher, ported
# ---------------------------------------------------------------------------------------------


def is_wild(key: str) -> bool:
    """`keyexpr_match::is_wild`: a wildcard chunk is one with a `*`, the sole wildcard lead byte."""
    return "*" in key


def is_verbatim(chunk: str) -> bool:
    return chunk.startswith("@")


def dsl_matches(pattern: str, target: str) -> bool:
    """`chunk_matches_with_dsl`: `pattern` has a `$*`, `target` is one literal chunk."""
    parts = pattern.split("$*")
    remaining = target
    if parts[0]:
        if not remaining.startswith(parts[0]):
            return False
        remaining = remaining[len(parts[0]) :]
    for index in range(1, len(parts)):
        part = parts[index]
        if index == len(parts) - 1:
            return True if not part else remaining.endswith(part)
        if not part:
            continue
        found = remaining.find(part)
        if found < 0:
            return False
        remaining = remaining[found + len(part) :]
    return False  # unreachable: a pattern with a `$*` has two parts or more


def chunk_intersects(a: str, b: str) -> bool:
    """`chunk_intersects`, in the matcher's own order: equality, then the verbatim refusal, then the
    wildcard rules."""
    if a == b:
        return True
    if is_verbatim(a) or is_verbatim(b):
        return False
    if a == "*" or b == "*":
        return True
    a_dsl, b_dsl = "$*" in a, "$*" in b
    if a_dsl and not b_dsl:
        return dsl_matches(a, b)
    if b_dsl and not a_dsl:
        return dsl_matches(b, a)
    if a_dsl and b_dsl:
        a_lead, a_trail = a.split("$*")[0], a.rsplit("$*", 1)[1]
        b_lead, b_trail = b.split("$*")[0], b.rsplit("$*", 1)[1]
        return (a_lead.startswith(b_lead) or b_lead.startswith(a_lead)) and (
            a_trail.endswith(b_trail) or b_trail.endswith(a_trail)
        )
    return False


@functools.lru_cache(maxsize=None)
def intersect_chunks(a: tuple, b: tuple) -> bool:
    """`intersect_chunks`: the arms of the matcher, in its order. `**` consumes zero or more chunks
    of the other side and does not cross a verbatim one."""
    if not a and not b:
        return True
    if a and a[0] == "**":
        if intersect_chunks(a[1:], b):
            return True
        if not b or is_verbatim(b[0]):
            return False
        return intersect_chunks(a, b[1:])
    if b and b[0] == "**":
        return intersect_chunks(b, a)
    if not a or not b:
        return False
    return chunk_intersects(a[0], b[0]) and intersect_chunks(a[1:], b[1:])


def intersects(candidate: str, target: str) -> bool:
    """`keyexpr_intersects_text` for two keys the declaration check accepts (no empty chunk)."""
    return intersect_chunks(tuple(candidate.split("/")), tuple(target.split("/")))


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
        why = wz_node.key_problem(key, limit)
        if why:
            problems.append(f"{who}: key {why}")
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


def rust_string(text: str) -> str:
    return wz_node.rust_string(text)


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


def emit_table(table: dict, source: str, path: str = "wz_session_core", declared: bool = False) -> str:
    """The Rust module of a table: the arrays and the `CATALOGUE` built over them. `declared` adds the
    declaration as the entities were numbered, which the model test reads and an image has no use for."""
    out = header(source)
    out += [
        "//! The key catalogue of the declaration, as `KeyCatalogue` reads it. A bad table is a build",
        "//! error: `KeyCatalogue::new` checks every property in a `const`.",
        "",
        "#![allow(dead_code)]",
        "",
        f"use {path}::key_catalogue::{{EntityId, EntityKind, EntityRow, KeyCatalogue, KeyId}};",
        "",
    ]
    out.append("#[rustfmt::skip]")
    if table["keys"]:
        out.append("const KEY_TEXT: &str = concat!(")
        out += [f"    {rust_string(key)}," for key in table["keys"]]
        out.append(");")
    else:
        out.append('const KEY_TEXT: &str = "";')
    out += ["", "#[rustfmt::skip]", f"const KEY_ENDS: [u16; {len(table['ends'])}] = ["]
    out += packed([str(n) for n in table["ends"]], "    ")
    out += ["];", "", "#[rustfmt::skip]", f"const OFFSETS: [u16; {len(table['offsets'])}] = ["]
    out += packed([str(n) for n in table["offsets"]], "    ")
    out += ["];", "", "#[rustfmt::skip]", f"const MEMBERS: [EntityId; {len(table['members'])}] = ["]
    out += packed([f"EntityId::new({n})" for n in table["members"]], "    ")
    out += ["];", "", "#[rustfmt::skip]", f"const ENTITIES: [EntityRow; {len(table['entities'])}] = ["]
    out += [
        f"    EntityRow::new(EntityKind::{RUST_KIND[kind]}, KeyId::new({key})),"
        for kind, key, _ in table["entities"]
    ]
    out += [
        "];",
        "",
        "pub const CATALOGUE: KeyCatalogue<'static> =",
        "    KeyCatalogue::new(KEY_TEXT, &KEY_ENDS, &OFFSETS, &MEMBERS, &ENTITIES);",
    ]
    if declared:
        out += [
            "",
            "/// The declaration as the entities were numbered: row `n` is entity `n`.",
            "#[rustfmt::skip]",
            f"pub const DECLARED: [(EntityKind, &str); {len(table['entities'])}] = [",
        ]
        out += [f"    (EntityKind::{RUST_KIND[kind]}, {rust_string(key)})," for kind, _, key in table["entities"]]
        out.append("];")
    return "\n".join(out) + "\n"


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
    return "\n".join(out) + "\n"


# ---------------------------------------------------------------------------------------------
# the fixture, check and write
# ---------------------------------------------------------------------------------------------


def load_entities(path: pathlib.Path, limit: int) -> list[dict]:
    data = wz_config.read_decl_toml(path.read_text(encoding="utf-8"))
    stray = sorted(set(data) - {"entity"})
    if stray:
        raise ValueError(f"{path.name}: `{', '.join(stray)}` is not a table of a key set declaration")
    entities = data.get("entity", [])
    problems = validate(entities, limit)
    if problems:
        raise ValueError(f"{path.name}: " + "; ".join(problems))
    return entities


def derived(decl: dict) -> dict[pathlib.Path, str]:
    table = build(load_entities(FIXTURE, key_limit(decl)))
    return {
        FIXTURE_RS: emit_table(table, "crates/wz-session-core/tests/key_set_data/fixture.toml", declared=True),
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
    expect("the keys are one concat", 'concat!(\n    "a",\n    "a/*",\n    "a/b",\n);' in rs)
    expect("the declaration is a constant of the file when asked for", "pub const DECLARED: [(EntityKind, &str); 3]" in rs)
    expect("and left out when not", "DECLARED" not in emit_table(table, "x.toml"))
    expect("an empty declaration is a table", "const KEY_TEXT: &str = \"\";" in emit_table(build([]), "x.toml"))

    # What it refuses.
    refuses("a kind outside the vocabulary", [entity("sink", "a")], "is not one of")
    refuses("a key that is not a key", [entity("queryable", "a//b")], "empty chunk")
    refuses("a key with a space", [entity("queryable", "a b")], "a character a key expression does not")
    refuses("a key past the key limit", [entity("queryable", "a" * (limit + 1))], "MAX_KEYEXPR_BYTES")
    refuses("a key too deep", [entity("queryable", "/".join("a" * 33))], "deeper than")
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
