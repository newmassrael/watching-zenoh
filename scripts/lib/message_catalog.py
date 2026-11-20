#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

"""R4541 (no register item) -- the message catalog's generator: one JSON5 declaration of a
deployment's messages turned into the static tables a fixed-memory image links, judged by the
rules the host reader judges it by.

    message_catalog.py --check                 the fixture catalog validates, and the tables derived
                                               from it are current
    message_catalog.py --write                 write those tables
    message_catalog.py --catalog FILE          print the tables of the catalog FILE
    message_catalog.py --catalog FILE --write --out RS
                                               write them to RS
    message_catalog.py --selftest              every rule on the shared corpus, then --check

`--limit NAME=VALUE` (MESSAGE_CATALOG_ENTRIES, REPLAY_DEPTH_MAX, E2E_SENDER_SLOTS,
INSTANCE_KEY_FIELDS, INSTANCES_PER_MESSAGE) states an
image's own bound in place of the declaration's default; a catalog over a bound is refused, so no
table longer than its limit is written.

## One set of rules, two judges

A host reads the catalog at run time with `wz_app_frame::message_catalog::Catalog::parse`; an image
links the tables this script writes. The two must hold the same messages by the same rules, and
they are kept one this way:

* the SHAPE (which members each object has, which are required, the type and range of each value,
  which limit bounds which list, and the refusal each rule is named by) is stated once, in
  `deploy/message-catalog.schema.json`. This script interprets it; the reader's unit test
  (`the_schema_states_the_readers_members_and_refusals`) holds the reader's members, required
  members and refusal words equal to it;
* the rules that relate one entry to the rest (a name that resolves, an id or key stated twice, a
  supervised message with no period, senders that are not publishers, ...) are written in both,
  and both run the one corpus `crates/wz-app-frame/catalog/refusals.json5`: each case is refused by
  both by its name at its place, and each accepted catalog is accepted by both;
* the rules that depend on what a PROFILE says (the e2e and segment profile documents themselves,
  whether the header values build a frame for each node, whether the profile's message cell can
  carry the senders) are the reader's alone: the schema lists their words in `x-wz-reader-only`,
  and the selftest holds that this script does not refuse those corpus cases. Every table this
  script writes carries a test that reads it back through `Catalog::from_table`, which runs every
  rule of the reader on it, so an image's own tests judge its tables by the reader.

## The fixture

`crates/wz-app-frame/catalog/synthetic.json5` is a synthetic catalog; `--write` writes its tables
to `catalog/synthetic_tables.rs`, which the reader's tests include and compare with the reader's
resolved form of the same text (`the_generated_tables_are_the_readers_resolved_form`).
"""

from __future__ import annotations

import argparse
import json
import pathlib
import re
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import wz_config  # noqa: E402

ROOT = pathlib.Path(__file__).resolve().parents[2]
SCHEMA = ROOT / "deploy" / "message-catalog.schema.json"
DATA = ROOT / "crates" / "wz-app-frame" / "catalog"
FIXTURE = DATA / "synthetic.json5"
FIXTURE_RS = DATA / "synthetic_tables.rs"
CORPUS = DATA / "refusals.json5"
GENERATED_NOTE = "scripts/lib/message_catalog.py --write"
TYPES = "wz_app_frame::message_catalog_table"

# `message_catalog::MAX_CATALOG_JSON_DEPTH`: a profile document's depth (`e2e_profile::MAX_JSON_DEPTH`,
# 8) under the catalog and its `e2e_profiles` object.
MAX_DEPTH = 10
# `message_catalog::MAX_DEADLINE_MS`: the longest deadline a reception supervisor holds.
MAX_DEADLINE_MS = 2_147_483_646
U64 = (1 << 64) - 1

# The limits a catalog is read against, by the name the declaration gives each, and the member of
# `message_catalog_table::Limits` it is.
LIMITS = (
    ("MESSAGE_CATALOG_ENTRIES", "messages"),
    ("REPLAY_DEPTH_MAX", "replay_depth_max"),
    ("E2E_SENDER_SLOTS", "sender_slots"),
    ("INSTANCE_KEY_FIELDS", "key_fields"),
    ("INSTANCES_PER_MESSAGE", "instances"),
)

# Every refusal word this script raises. The selftest holds it equal to the schema's words less the
# reader's own.
RAISED = (
    "syntax",
    "unknown_field",
    "duplicate_field",
    "missing_field",
    "wrong_type",
    "value_out_of_range",
    "invalid_name",
    "empty",
    "duplicate_node",
    "unknown_node",
    "key_expr",
    "duplicate_key_expr",
    "duplicate_id",
    "period_zero",
    "deadline_out_of_range",
    "supervision_without_period",
    "replay_depth_out_of_range",
    "too_many_messages",
    "unknown_e2e_profile",
    "unknown_segment_profile",
    "senders_without_protection",
    "sender_not_publisher",
    "duplicate_sender",
    "too_many_senders",
    "instance_key_with_senders",
    "duplicate_instance_key",
    "too_many_key_fields",
    "too_many_instances",
)


class Refused(Exception):
    """A catalog refused: the rule's word, the JSON pointer to the place, and why."""

    def __init__(self, word: str, path: str, reason: str) -> None:
        super().__init__(f"{word} at {path}: {reason}" if path else f"{word}: {reason}")
        self.word = word
        self.path = path
        self.reason = reason


# ---------------------------------------------------------------------------------------------
# the JSON5 reader, the workspace's (`wz_session_core::json5_lex`) restated
# ---------------------------------------------------------------------------------------------


class Num(str):
    """A number, held as its source text, as `Json5Value::Number` holds it."""


class Obj:
    """An object: its members in document order, a repeated one kept so it can be refused."""

    __slots__ = ("pairs",)

    def __init__(self, pairs: list) -> None:
        self.pairs = pairs

    def keys(self) -> list:
        return [k for k, _ in self.pairs]

    def has(self, key: str) -> bool:
        return any(k == key for k, _ in self.pairs)

    def get(self, key: str, default=None):
        for k, v in self.pairs:
            if k == key:
                return v
        return default

    def __eq__(self, other: object) -> bool:
        return isinstance(other, Obj) and self.pairs == other.pairs

    def __repr__(self) -> str:
        return f"Obj({self.pairs!r})"


DIGITS = "0123456789"
HEX_DIGITS = "0123456789abcdefABCDEF"
SIMPLE_ESCAPES = {
    '"': '"',
    "'": "'",
    "\\": "\\",
    "/": "/",
    "b": "\b",
    "f": "\f",
    "n": "\n",
    "r": "\r",
    "t": "\t",
    "0": "\0",
    "\n": "",
}


class Reader:
    """One document: comments, unquoted keys, single-quoted strings, trailing commas, numbers as
    their text, nesting bounded. What the reader refuses, this refuses."""

    def __init__(self, text: str) -> None:
        self.s = text
        self.i = 0

    def fail(self, expected: str):
        raise Refused("syntax", "", f"not JSON5 at character {self.i}: expected {expected}")

    def peek(self):
        return self.s[self.i] if self.i < len(self.s) else None

    def at(self, chars: str) -> bool:
        c = self.peek()
        return c is not None and c in chars

    def trivia(self) -> None:
        while True:
            c = self.peek()
            if c is not None and c in " \t\r\n":
                self.i += 1
            elif c == "/" and self.s.startswith("//", self.i):
                end = self.s.find("\n", self.i)
                self.i = len(self.s) if end < 0 else end
            elif c == "/" and self.s.startswith("/*", self.i):
                end = self.s.find("*/", self.i + 2)
                if end < 0:
                    self.fail("*/ closing a block comment")
                self.i = end + 2
            else:
                return

    def value(self, depth: int):
        c = self.peek()
        if c == "{":
            return self.obj(depth)
        if c == "[":
            return self.arr(depth)
        if c is not None and c in "\"'":
            return self.string()
        if c is not None and c in "+-." + DIGITS:
            return self.number()
        for word, val in (("true", True), ("false", False), ("null", None)):
            if self.s.startswith(word, self.i):
                self.i += len(word)
                return val
        self.fail("a value")

    def obj(self, depth: int) -> Obj:
        if depth == 0:
            self.fail("a shallower value")
        self.i += 1
        pairs = []
        while True:
            self.trivia()
            c = self.peek()
            if c == "}":
                self.i += 1
                return Obj(pairs)
            if c is None:
                self.fail("} closing an object")
            key = self.member_name()
            self.trivia()
            if self.peek() != ":":
                self.fail(": after a member name")
            self.i += 1
            self.trivia()
            pairs.append((key, self.value(depth - 1)))
            self.trivia()
            c = self.peek()
            if c == ",":
                self.i += 1
            elif c != "}":
                self.fail(", or } after a member")

    def arr(self, depth: int) -> list:
        if depth == 0:
            self.fail("a shallower value")
        self.i += 1
        items = []
        while True:
            self.trivia()
            c = self.peek()
            if c == "]":
                self.i += 1
                return items
            if c is None:
                self.fail("] closing an array")
            items.append(self.value(depth - 1))
            self.trivia()
            c = self.peek()
            if c == ",":
                self.i += 1
            elif c != "]":
                self.fail(", or ] after an element")

    def member_name(self) -> str:
        if self.at("\"'"):
            return self.string()
        start = self.i
        while self.peek() is not None and (
            (self.peek().isascii() and self.peek().isalnum()) or self.peek() in "_$"
        ):
            self.i += 1
        if self.i == start or self.s[start] in DIGITS:
            self.i = start
            self.fail("a member name")
        return self.s[start:self.i]

    def string(self) -> str:
        quote = self.s[self.i]
        self.i += 1
        out = []
        while True:
            c = self.peek()
            if c is None:
                self.fail("a closing quote")
            self.i += 1
            if c == quote:
                return "".join(out)
            if c != "\\":
                out.append(c)
                continue
            e = self.peek()
            if e is None:
                self.fail("an escape after backslash")
            self.i += 1
            if e in SIMPLE_ESCAPES:
                out.append(SIMPLE_ESCAPES[e])
            elif e == "\r":
                if self.peek() == "\n":
                    self.i += 1
            elif e == "u":
                out.append(self.unicode_escape())
            else:
                self.i -= 1
                self.fail("a known escape")

    def hex4(self) -> int:
        text = self.s[self.i:self.i + 4]
        if len(text) != 4 or any(c not in HEX_DIGITS for c in text):
            self.fail("four hex digits")
        self.i += 4
        return int(text, 16)

    def unicode_escape(self) -> str:
        hi = self.hex4()
        if 0xD800 <= hi < 0xDC00:
            if not self.s.startswith("\\u", self.i):
                self.fail("a low surrogate escape")
            self.i += 2
            lo = self.hex4()
            if not 0xDC00 <= lo < 0xE000:
                self.fail("a low surrogate escape")
            return chr(0x10000 + ((hi - 0xD800) << 10) + (lo - 0xDC00))
        if 0xDC00 <= hi < 0xE000:
            self.fail("a Unicode scalar")
        return chr(hi)

    def number(self) -> Num:
        start = self.i
        if self.at("+-"):
            self.i += 1
        digits = self.i
        if self.peek() == "0" and self.s[self.i + 1:self.i + 2] in ("x", "X"):
            self.i += 2
            hd = self.i
            while self.at(HEX_DIGITS):
                self.i += 1
            if self.i == hd:
                self.i = start
                self.fail("hex digits after 0x")
        else:
            while self.at(DIGITS):
                self.i += 1
            if self.peek() == ".":
                self.i += 1
                while self.at(DIGITS):
                    self.i += 1
            if self.i == digits:
                self.i = start
                self.fail("a number")
            if self.at("eE"):
                self.i += 1
                if self.at("+-"):
                    self.i += 1
                ed = self.i
                while self.at(DIGITS):
                    self.i += 1
                if self.i == ed:
                    self.i = start
                    self.fail("exponent digits")
        return Num(self.s[start:self.i])


def read_json5(text: str, depth: int = MAX_DEPTH):
    reader = Reader(text)
    reader.trivia()
    value = reader.value(depth)
    reader.trivia()
    if reader.i != len(text):
        reader.fail("end of document")
    return value


def to_text(value) -> str:
    """A value as compact JSON, its numbers spelled as written: what the reader's
    `Json5Value::to_json5_text` writes, up to the escaping of strings."""
    if isinstance(value, Obj):
        return "{" + ",".join(
            json.dumps(k, ensure_ascii=False) + ":" + to_text(v) for k, v in value.pairs
        ) + "}"
    if isinstance(value, list):
        return "[" + ",".join(to_text(v) for v in value) + "]"
    if isinstance(value, Num):
        return str(value)
    if value is True:
        return "true"
    if value is False:
        return "false"
    if value is None:
        return "null"
    if isinstance(value, str):
        return json.dumps(value, ensure_ascii=False)
    raise TypeError(f"not a JSON5 value: {value!r}")


# ---------------------------------------------------------------------------------------------
# the rules
# ---------------------------------------------------------------------------------------------


def child(path: str, key: str) -> str:
    """`e2e_profile::child`: an RFC 6901 pointer one member deeper."""
    return path + "/" + key.replace("~", "~0").replace("/", "~1")


def at(path: str, index: int) -> str:
    return f"{path}/{index}"


def describe(value) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "a boolean"
    if isinstance(value, Num):
        return "a number"
    if isinstance(value, str):
        return "a string"
    if isinstance(value, list):
        return "an array"
    return "an object"


PLAIN_DECIMAL = re.compile(r"0|[1-9][0-9]*")
HEX_TEXT = re.compile(r"0[xX][0-9a-fA-F]+")


def uint(value, path: str) -> int:
    """`message_catalog::uint`: a plain decimal number, or a string of decimal or 0x hex digits."""
    if isinstance(value, Num):
        if not PLAIN_DECIMAL.fullmatch(value):
            raise Refused("wrong_type", path, f"`{value}` is not a plain unsigned decimal number")
        n = int(value)
    elif isinstance(value, str):
        if HEX_TEXT.fullmatch(value):
            n = int(value[2:], 16)
        elif PLAIN_DECIMAL.fullmatch(value):
            n = int(value)
        else:
            raise Refused("wrong_type", path, f"`{value}` is not decimal digits, nor 0x and hex digits")
    else:
        raise Refused("wrong_type", path, f"expected an unsigned integer, found {describe(value)}")
    if n > U64:
        raise Refused("value_out_of_range", path, f"`{value}` does not fit in 64 bits")
    return n


def literal_key_problem(text: str) -> str | None:
    """Why `text` is not a literal key: `keyexpr_canon::validate_keyexpr` on a text with no
    wildcard faults only on an empty chunk and on `#` or `?`, and a wildcard is a pattern."""
    if not text or text.startswith("/") or text.endswith("/") or "//" in text:
        return "has an empty chunk"
    if "#" in text or "?" in text:
        return "has `#` or `?`"
    if "*" in text or "$" in text:
        return "is a pattern: a message is put on a literal key"
    return None


class Judge:
    """The schema's rules and the rules between entries, over one catalog, against `limits` (a
    dict from the `Limits` member names)."""

    def __init__(self, schema: dict, limits: dict) -> None:
        self.schema = schema
        self.defs = schema["$defs"]
        self.limits = limits

    def limit(self, name: str) -> int:
        member = dict(LIMITS)[name]
        return self.limits[member]

    def bound(self, value) -> int:
        return self.limit(value) if isinstance(value, str) else value

    # -- the shape, as the schema states it ---------------------------------------------------

    def shape(self, value, node: dict, path: str) -> None:
        ref = node.get("$ref")
        if ref == "#/$defs/uint":
            n = uint(value, path)
            span = node.get("x-wz-range")
            if span is not None:
                lo, hi = self.bound(span[0]), self.bound(span[1])
                if n < lo:
                    raise Refused(node.get("x-wz-refusal-below", "value_out_of_range"), path,
                                  f"{n} is below {lo}")
                if n > hi:
                    raise Refused(node.get("x-wz-refusal-above", "value_out_of_range"), path,
                                  f"{n} is above {hi}")
            return
        if ref is not None:
            self.shape(value, self.defs[ref.rsplit("/", 1)[1]], path)
            return
        kind = node.get("type")
        if kind == "object":
            self.shape_object(value, node, path)
        elif kind == "array":
            self.shape_array(value, node, path)
        elif kind == "string":
            self.shape_string(value, node, path)
        elif kind == "boolean" and not isinstance(value, bool):
            raise Refused("wrong_type", path, f"expected true or false, found {describe(value)}")

    def shape_object(self, value, node: dict, path: str) -> None:
        if not isinstance(value, Obj):
            raise Refused("wrong_type", path, f"expected an object, found {describe(value)}")
        if "x-wz-document" in node:
            # Another reader's document: judged by the reader, under its word.
            return
        members = node.get("properties", {})
        others = node.get("additionalProperties", True)
        if others is False:
            for key in value.keys():
                if key not in members:
                    raise Refused("unknown_field", child(path, key), f"unknown member `{key}`")
        seen: set = set()
        for key in value.keys():
            if key in seen:
                raise Refused("duplicate_field", child(path, key),
                              f"the member `{key}` is stated twice")
            seen.add(key)
        for key in node.get("required", []):
            if key not in seen:
                raise Refused("missing_field", path, f"the member `{key}` is required")
        most = node.get("maxProperties")
        if most is not None and len(value.pairs) > most:
            raise Refused("value_out_of_range", path, f"at most {most} members")
        for key, member in value.pairs:
            here = child(path, key)
            if key in members:
                self.shape(member, members[key], here)
            elif isinstance(others, dict):
                names = node.get("propertyNames")
                if names is not None:
                    self.shape(key, names, here)
                self.shape(member, others, here)

    def shape_array(self, value, node: dict, path: str) -> None:
        if not isinstance(value, list):
            raise Refused("wrong_type", path, f"expected an array, found {describe(value)}")
        least = node.get("minItems")
        if least is not None and len(value) < least:
            raise Refused("empty", path, "the list is empty")
        most = node.get("maxItems")
        if most is not None and len(value) > most:
            raise Refused("value_out_of_range", path, f"at most {most} items")
        limit = node.get("x-wz-limit-items")
        if limit is not None and len(value) > self.limit(limit):
            raise Refused(node["x-wz-refusal-items"], path,
                          f"{len(value)} items, and the build's {limit} is {self.limit(limit)}")
        if node.get("x-wz-key-values"):
            for j, item in enumerate(value):
                if isinstance(item, Num) or not isinstance(item, str):
                    uint(item, at(path, j))
            return
        items = node.get("items")
        if items is not None:
            for j, item in enumerate(value):
                self.shape(item, items, at(path, j))

    def shape_string(self, value, node: dict, path: str) -> None:
        if isinstance(value, Num) or not isinstance(value, str):
            raise Refused("wrong_type", path, f"expected a string, found {describe(value)}")
        least = node.get("minLength")
        if least is not None and len(value) < least:
            raise Refused("empty", path, "the text is empty")
        pattern = node.get("pattern")
        if pattern is not None and not re.fullmatch(pattern, value):
            raise Refused(node.get("x-wz-refusal", "wrong_type"), path,
                          f"`{value}` does not match {pattern}")
        if node.get("x-wz-key-expr"):
            problem = literal_key_problem(value)
            if problem is not None:
                raise Refused("key_expr", path, f"`{value}` {problem}")

    # -- the rules between entries ------------------------------------------------------------

    def node_list(self, items: list, path: str, names: list) -> list:
        out: list = []
        for j, wanted in enumerate(items):
            if wanted not in names:
                raise Refused("unknown_node", at(path, j), f"no node is named `{wanted}`")
            index = names.index(wanted)
            if index in out:
                raise Refused("duplicate_node", at(path, j), f"`{wanted}` is named twice")
            out.append(index)
        return out

    def resolve(self, doc: Obj) -> dict:
        """The catalog with every reference an index and every number its value: the rows the
        tables are written from, and `message_catalog::Catalog`'s resolved form."""
        names: list = []
        nodes: list = []
        for i, node in enumerate(doc.get("nodes")):
            name = node.get("name")
            if name in names:
                raise Refused("duplicate_node", f"/nodes/{i}/name",
                              f"a node is already named `{name}`")
            names.append(name)
            address = node.get("address") if node.has("address") else None
            nodes.append((name, None if address is None else uint(address, "")))
        e2e = doc.get("e2e_profiles", Obj([]))
        segments = doc.get("segment_profiles", Obj([]))
        e2e_names = e2e.keys()
        segment_names = segments.keys()
        supervision = doc.get("supervision")
        start_delay = uint(supervision.get("start_delay_ms"), "") if supervision is not None else 0

        messages: list = []
        keys: list = []
        ids: list = []
        for i, m in enumerate(doc.get("messages")):
            p = f"/messages/{i}"
            publishers = self.node_list(m.get("publishers"), child(p, "publishers"), names)
            subscribers = self.node_list(m.get("subscribers"), child(p, "subscribers"), names)
            period = uint(m.get("period_ms"), "") if m.has("period_ms") else None

            protection = None
            if m.has("protection"):
                body = m.get("protection")
                wanted = body.get("profile")
                if wanted not in e2e_names:
                    raise Refused("unknown_e2e_profile", child(child(p, "protection"), "profile"),
                                  f"no e2e profile is named `{wanted}`")
                protection = (e2e_names.index(wanted), to_text(body.get("values")))

            senders: list = []
            if m.has("senders"):
                for j, sender in enumerate(m.get("senders")):
                    here = at(child(p, "senders"), j)
                    wanted = sender.get("node")
                    if wanted not in names:
                        raise Refused("unknown_node", child(here, "node"),
                                      f"no node is named `{wanted}`")
                    index = names.index(wanted)
                    identity = uint(sender.get("id"), "")
                    if any(s[0] == index or s[1] == identity for s in senders):
                        raise Refused("duplicate_sender", here,
                                      f"`{wanted}` or the identity {identity} is stated twice")
                    senders.append((index, identity))

            instance_key: list = []
            if m.has("instance_key"):
                for j, field in enumerate(m.get("instance_key")):
                    here = at(child(p, "instance_key"), j)
                    values: list = []
                    for k, item in enumerate(field.get("values")):
                        value = ("t", item) if isinstance(item, str) and not isinstance(item, Num) \
                            else ("n", uint(item, ""))
                        if value in values:
                            raise Refused("duplicate_instance_key", at(child(here, "values"), k),
                                          "the value is listed twice")
                        values.append(value)
                    name = field.get("field")
                    if any(f[0] == name for f in instance_key):
                        raise Refused("duplicate_instance_key", child(here, "field"),
                                      f"the field `{name}` is named twice")
                    instance_key.append((name, values))
                instances = 1
                for _, listed in instance_key:
                    instances *= len(listed)
                if instances > self.limit("INSTANCES_PER_MESSAGE"):
                    raise Refused("too_many_instances", child(p, "instance_key"),
                                  "the lists of values make more instances than the build's "
                                  f"INSTANCES_PER_MESSAGE, {self.limit('INSTANCES_PER_MESSAGE')}")

            depth = uint(m.get("replay_depth"), "") if m.has("replay_depth") else None
            watch = None
            if m.has("supervision"):
                body = m.get("supervision")
                awaited = body.get("awaited") if body.has("awaited") else True
                watch = (uint(body.get("factor"), ""), awaited)

            segment = None
            if m.has("segment_profile"):
                wanted = m.get("segment_profile")
                if wanted not in segment_names:
                    raise Refused("unknown_segment_profile", child(p, "segment_profile"),
                                  f"no segment profile is named `{wanted}`")
                segment = segment_names.index(wanted)

            key = m.get("key_expr")
            if key in keys:
                raise Refused("duplicate_key_expr", child(p, "key_expr"),
                              f"another message is put on `{key}`")
            ident = uint(m.get("id"), "")
            if ident in ids:
                raise Refused("duplicate_id", child(p, "id"), f"another message has the id {ident}")
            if watch is not None:
                if period is None:
                    raise Refused("supervision_without_period", child(p, "supervision"),
                                  "only a periodic message has a reception deadline")
                if period * watch[0] > MAX_DEADLINE_MS:
                    raise Refused("deadline_out_of_range", child(child(p, "supervision"), "factor"),
                                  f"the deadline {period * watch[0]} ms is above {MAX_DEADLINE_MS} ms")
            if senders:
                if protection is None:
                    raise Refused("senders_without_protection", child(p, "senders"),
                                  "a receiver tells senders apart by the protection header")
                for j, (index, _) in enumerate(senders):
                    if index not in publishers:
                        raise Refused("sender_not_publisher",
                                      child(at(child(p, "senders"), j), "node"),
                                      f"`{names[index]}` does not publish the message")
                if instance_key:
                    raise Refused("instance_key_with_senders", child(p, "instance_key"),
                                  "a message keeps its streams by sender or by instance, not both")
            keys.append(key)
            ids.append(ident)
            messages.append({
                "key_expr": key,
                "id": ident,
                "publishers": publishers,
                "subscribers": subscribers,
                "period_ms": period,
                "protection": protection,
                "senders": senders,
                "instance_key": instance_key,
                "replay_depth": depth,
                "supervision": watch,
                "segment_profile": segment,
            })
        return {
            "nodes": nodes,
            "e2e_profiles": [(k, to_text(v)) for k, v in e2e.pairs],
            "segment_profiles": [(k, to_text(v)) for k, v in segments.pairs],
            "start_delay_ms": start_delay,
            "messages": messages,
        }

    def judge(self, text: str) -> dict:
        """Read, shape and resolve one catalog; a `Refused` names the first rule it breaks."""
        doc = read_json5(text)
        self.shape(doc, self.schema, "")
        return self.resolve(doc)


# ---------------------------------------------------------------------------------------------
# the tables
# ---------------------------------------------------------------------------------------------


def rust_str(text: str) -> str:
    out = []
    for c in text:
        if c in "\\\"":
            out.append("\\" + c)
        elif ord(c) < 0x20 or ord(c) == 0x7F:
            out.append("\\u{%x}" % ord(c))
        else:
            out.append(c)
    return '"' + "".join(out) + '"'


def rust_raw(text: str) -> str:
    """`text` as a raw string literal, with as many `#` as it needs; a JSON text has no control
    character a raw literal cannot carry."""
    hashes = "#"
    while '"' + hashes in text:
        hashes += "#"
    return f'r{hashes}"{text}"{hashes}'


def option(value, form=str) -> str:
    return "None" if value is None else f"Some({form(value)})"


def numbers(values: list) -> str:
    return "&[" + ", ".join(str(v) for v in values) + "]"


def header(source: str) -> list:
    return [
        f"// {wz_config.SPDX}",
        f"// {wz_config.COPYRIGHT}",
        "//",
        f"// GENERATED from {source} by {GENERATED_NOTE}.",
        "// Do not edit: `message_catalog.py --check` fails when this file is stale.",
        "",
    ]


def documents_lines(member: str, rows: list) -> list:
    if not rows:
        return [f"        {member}: &[],"]
    out = [f"        {member}: &["]
    for name, text in rows:
        out += [
            "            DocumentRow {",
            f"                name: {rust_str(name)},",
            f"                text: {rust_raw(text)},",
            "            },",
        ]
    out.append("        ],")
    return out


def key_value(value: tuple) -> str:
    kind, v = value
    return f"KeyValue::Text({rust_str(v)})" if kind == "t" else f"KeyValue::Number({v})"


def message_lines(m: dict) -> list:
    out = [
        "            MessageRow {",
        f"                key_expr: {rust_str(m['key_expr'])},",
        f"                id: {m['id']},",
        f"                publishers: {numbers(m['publishers'])},",
        f"                subscribers: {numbers(m['subscribers'])},",
        f"                period_ms: {option(m['period_ms'])},",
    ]
    if m["protection"] is None:
        out.append("                protection: None,")
    else:
        profile, values = m["protection"]
        out += [
            "                protection: Some(ProtectionRow {",
            f"                    profile: {profile},",
            f"                    values: {rust_raw(values)},",
            "                }),",
        ]
    if not m["senders"]:
        out.append("                senders: &[],")
    else:
        out.append("                senders: &[")
        for node, identity in m["senders"]:
            out.append(f"                    SenderRow {{ node: {node}, id: {identity} }},")
        out.append("                ],")
    if not m["instance_key"]:
        out.append("                instance_key: &[],")
    else:
        out.append("                instance_key: &[")
        for field, values in m["instance_key"]:
            out += [
                "                    KeyFieldRow {",
                f"                        field: {rust_str(field)},",
                "                        values: &[" + ", ".join(key_value(v) for v in values) + "],",
                "                    },",
            ]
        out.append("                ],")
    out.append(f"                replay_depth: {option(m['replay_depth'])},")
    if m["supervision"] is None:
        out.append("                supervision: None,")
    else:
        factor, awaited = m["supervision"]
        out += [
            "                supervision: Some(SupervisionRow {",
            f"                    factor: {factor},",
            f"                    awaited: {'true' if awaited else 'false'},",
            "                }),",
        ]
    out += [
        f"                segment_profile: {option(m['segment_profile'])},",
        "            },",
    ]
    return out


def emit_tables(model: dict, source: str, limits: dict) -> str:
    """The Rust of a catalog's tables, as one module `catalog_tables` a file includes where it is
    wanted: the limits they were judged against, the `Table`, and the test that reads the table
    back through the reader. It names the crate of its types by its name, so it is the same text
    in an image and in the reader's own tests."""
    out = header(source) + [
        f"/// The message catalog of `{source}`, as the static tables of",
        f"/// `{TYPES}`.",
        # The layout is this function's, one row a line as the table reads: rustfmt would fold a
        # one-row list into its brackets, and the text must be the same before and after it.
        "#[rustfmt::skip]",
        "pub mod catalog_tables {",
        "    #![allow(dead_code)]",
        f"    use {TYPES}::*;",
        "",
        "    /// The limits the tables were generated against.",
        "    pub const LIMITS: Limits = Limits {",
    ]
    out += [f"        {member}: {limits[member]}," for _, member in LIMITS]
    out += [
        "    };",
        "",
        "    /// The catalog.",
        "    pub const CATALOG: Table = Table {",
        "        nodes: &[",
    ]
    for name, address in model["nodes"]:
        out += [
            "            NodeRow {",
            f"                name: {rust_str(name)},",
            f"                address: {option(address)},",
            "            },",
        ]
    out.append("        ],")
    out += documents_lines("e2e_profiles", model["e2e_profiles"])
    out += documents_lines("segment_profiles", model["segment_profiles"])
    out.append(f"        supervision_start_delay_ms: {model['start_delay_ms']},")
    if not model["messages"]:
        out.append("        messages: &[],")
    else:
        out.append("        messages: &[")
        for m in model["messages"]:
            out += message_lines(m)
        out.append("        ],")
    out += [
        "    };",
        "",
        "    #[test]",
        "    fn the_tables_pass_the_catalog_reader() {",
        "        if let Err(refusal) = wz_app_frame::message_catalog::Catalog::from_table(&CATALOG, LIMITS) {",
        '            panic!("the catalog reader refuses the generated tables: {refusal}");',
        "        }",
        "    }",
        "}",
    ]
    return "\n".join(out) + "\n"


# ---------------------------------------------------------------------------------------------
# the declaration's limits, the fixture, check and write
# ---------------------------------------------------------------------------------------------


def declared_limits(decl: dict, stated: list) -> dict:
    """The declaration's default of each limit, with `NAME=VALUE` statements over them."""
    defaults = {lim["id"]: lim["default"] for lim in decl["limits"]}
    out = {}
    for name, member in LIMITS:
        if name not in defaults:
            raise ValueError(f"deploy/wz-config.toml declares no limit {name}")
        out[member] = defaults[name]
    for statement in stated:
        name, _, value = statement.partition("=")
        member = dict(LIMITS).get(name)
        if member is None or not value.isdigit() or int(value) < 1:
            raise ValueError(f"`--limit {statement}`: name one of "
                             f"{', '.join(n for n, _ in LIMITS)} and a count of at least 1")
        out[member] = int(value)
    return out


def load_schema() -> dict:
    return json.loads(SCHEMA.read_text(encoding="utf-8"))


def fixture_tables(decl: dict) -> str:
    limits = declared_limits(decl, [])
    model = Judge(load_schema(), limits).judge(FIXTURE.read_text(encoding="utf-8"))
    return emit_tables(model, FIXTURE.relative_to(ROOT).as_posix(), limits)


def check(decl: dict) -> int:
    try:
        text = fixture_tables(decl)
    except (Refused, ValueError, OSError) as err:
        print(f"  message-catalog FAIL: {err}", file=sys.stderr)
        return 1
    if not FIXTURE_RS.is_file() or FIXTURE_RS.read_text(encoding="utf-8") != text:
        print(f"  message-catalog FAIL: {FIXTURE_RS.name} is missing or stale: regenerate it "
              "with --write", file=sys.stderr)
        return 1
    print(f"message-catalog: the fixture catalog validates and {FIXTURE_RS.name} is current")
    return 0


def write(decl: dict) -> int:
    try:
        text = fixture_tables(decl)
    except (Refused, ValueError, OSError) as err:
        print(f"  message-catalog FAIL: {err}", file=sys.stderr)
        return 1
    FIXTURE_RS.write_text(text, encoding="utf-8")
    print(f"message-catalog: wrote {FIXTURE_RS.relative_to(ROOT).as_posix()}")
    return 0


def generate(decl: dict, catalog: pathlib.Path, stated: list, out: pathlib.Path | None) -> int:
    """An image's tables: printed, or written to `out` under `--write`."""
    try:
        limits = declared_limits(decl, stated)
        model = Judge(load_schema(), limits).judge(catalog.read_text(encoding="utf-8"))
    except (Refused, ValueError, OSError) as err:
        print(f"message-catalog: REFUSED -- {err}", file=sys.stderr)
        return 1
    text = emit_tables(model, catalog.as_posix(), limits)
    if out is None:
        print(text, end="")
    else:
        out.write_text(text, encoding="utf-8")
        print(f"message-catalog: wrote {out}")
    return 0


# ---------------------------------------------------------------------------------------------
# selftest
# ---------------------------------------------------------------------------------------------


def _selftest() -> int:
    failures: list = []

    def expect(what: str, ok: bool) -> None:
        print(f"  {'ok  ' if ok else 'FAIL'} {what}")
        if not ok:
            failures.append(what)

    def refusal(text: str, judge: Judge):
        try:
            judge.judge(text)
        except Refused as err:
            return err
        return None

    # The reader, on what the workspace's reader reads and refuses.
    doc = read_json5("{a: 1, 'b': [0x1F, -2.5e3,], \"c\": {d: null, e: true,}, // note\n"
                     " /* block */ f: 'x\\u00e9\\n'}")
    expect("unquoted, single-quoted and double-quoted keys, in document order",
           doc.keys() == ["a", "b", "c", "f"])
    expect("a number keeps its spelling", doc.get("b") == [Num("0x1F"), Num("-2.5e3")])
    expect("null and booleans", doc.get("c") == Obj([("d", None), ("e", True)]))
    expect("escapes are resolved", doc.get("f") == "xé\n")
    expect("a repeated member is kept, for the shape to refuse",
           read_json5("{a: 1, a: 2}").keys() == ["a", "a"])
    for bad, why in (("{a: 1", "an unclosed object"), ("{a: 1} 2", "a second value"),
                     ("{1a: 2}", "a member name that starts with a digit"),
                     ("[NaN]", "NaN"), ("['\\q']", "an unknown escape"),
                     ("[0x]", "0x with no digits"), ("[/* open", "an open comment"),
                     ("[" * 11 + "]" * 11, "nesting past the reader's depth")):
        try:
            read_json5(bad)
            expect(f"{why} is refused as syntax", False)
        except Refused as err:
            expect(f"{why} is refused as syntax", err.word == "syntax")
    expect("ten levels are read", read_json5("[" * 10 + "]" * 10) is not None)
    sample = read_json5("{k: ['a\"b', 0x10, {z: false}], n: 007}")
    expect("the emitted text reads back as the same value", read_json5(to_text(sample)) == sample)
    expect("the emitted text is compact JSON with numbers as written",
           to_text(sample) == '{"k":["a\\"b",0x10,{"z":false}],"n":007}')

    expect("a raw literal takes a hash more than the text needs",
           rust_raw('a"#b') == 'r##"a"#b"##' and rust_raw("{}") == 'r#"{}"#')
    expect("a string literal escapes quotes, backslashes and controls",
           rust_str('a"\\\n') == '"a\\"\\\\\\u{a}"')

    # The schema's words are this script's and the reader's own, each once.
    schema = load_schema()
    words = list(schema["x-wz-refusals"])
    reader_only = schema["x-wz-reader-only"]
    expect("the schema names each refusal once", len(words) == len(set(words)))
    expect("every word this script raises is the schema's, and the rest are the reader's",
           sorted(RAISED) == sorted(w for w in words if w not in reader_only))
    expect("the reader's own words are refusals of the schema", set(reader_only) <= set(words))

    # The shared corpus.
    corpus = read_json5(CORPUS.read_text(encoding="utf-8"), MAX_DEPTH + 4)
    base = {member: int(corpus.get("limits").get(member)) for _, member in LIMITS}
    for i, catalog in enumerate(corpus.get("accepted")):
        found = refusal(to_text(catalog), Judge(schema, base))
        expect(f"accepted catalog {i} is accepted", found is None)
    covered: set = set()
    for i, case in enumerate(corpus.get("cases")):
        want, place = case.get("refusal"), case.get("at")
        limits = dict(base)
        if case.has("limits"):
            for key, value in case.get("limits").pairs:
                limits[key] = int(value)
        text = case.get("text") if case.has("text") else to_text(case.get("catalog"))
        found = refusal(text, Judge(schema, limits))
        if want in reader_only:
            expect(f"case {i}: {want} is the reader's, and this script leaves it", found is None)
            continue
        ok = found is not None and found.word == want and found.path == place
        expect(f"case {i}: {want} at `{place}`" + ("" if ok else f", got {found}"), ok)
        covered.add(want)
    expect("the corpus refuses a catalog by every word this script raises",
           covered == set(RAISED))

    # The tables, on the accepted catalog that has senders and an instance key.
    model = Judge(schema, base).judge(to_text(corpus.get("accepted")[1]))
    text = emit_tables(model, "corpus", base)
    expect("a table names each sender's node and identity",
           "SenderRow { node: 0, id: 261 }," in text and "SenderRow { node: 1, id: 517 }," in text)
    expect("an instance key keeps its numbers and its texts",
           "values: &[KeyValue::Number(1), KeyValue::Number(2), KeyValue::Text(\"far\")]," in text)
    expect("an unsupervised message and an awaited flag are written as stated",
           "awaited: false," in text and "supervision: None," in text)
    tight = dict(base, messages=1)
    found = refusal(to_text(corpus.get("accepted")[1]), Judge(schema, tight))
    expect("a catalog longer than its table's limit writes no table",
           found is not None and found.word == "too_many_messages")

    decl = wz_config.load_decl()
    try:
        declared_limits(decl, ["REPLAY_DEPTH_MAX=0"])
        expect("a limit stated as 0 is refused", False)
    except ValueError:
        expect("a limit stated as 0 is refused", True)
    expect("a limit stated over the declaration's is the one judged by",
           declared_limits(decl, ["E2E_SENDER_SLOTS=3"])["sender_slots"] == 3)

    print(f"message-catalog selftest: {'FAIL' if failures else 'OK'} ({len(failures)} failing)")
    if failures:
        return 1
    return check(decl)


def main(argv: list) -> int:
    parser = argparse.ArgumentParser(description="the message catalog's tables, and its rules")
    parser.add_argument("--check", action="store_true",
                        help="the fixture catalog validates and its tables are current")
    parser.add_argument("--write", action="store_true",
                        help="write the fixture's tables, or with --catalog the tables to --out")
    parser.add_argument("--catalog", type=pathlib.Path, help="a catalog to generate the tables of")
    parser.add_argument("--out", type=pathlib.Path, help="with --catalog --write: where to write")
    parser.add_argument("--limit", action="append", default=[], metavar="NAME=VALUE",
                        help="an image's own bound in place of the declaration's default")
    parser.add_argument("--selftest", action="store_true")
    args = parser.parse_args(argv)
    if args.selftest:
        return _selftest()
    decl = wz_config.load_decl()
    if args.catalog is not None:
        if args.write and args.out is None:
            parser.error("--catalog --write needs --out")
        if args.out is not None and not args.write:
            parser.error("--out writes a file, and only --write writes")
        return generate(decl, args.catalog, args.limit, args.out)
    if args.check:
        return check(decl)
    if args.write:
        return write(decl)
    parser.print_usage(sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
