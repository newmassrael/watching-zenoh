#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

"""R4557 (no register item) -- a deployment's own description of its messages, in whatever JSON
its tools write, turned into a wz message catalog by a declarative mapping; and the tool that
writes that JSON, run as the user configured it.

    message_catalog_map.py --mapping MAP --source JSON [--out CATALOG] [--limit NAME=VALUE]...
    message_catalog_map.py --mapping MAP --generator 'TOOL ARG {out}' [--out CATALOG] ...
    message_catalog_map.py --mapping MAP --generator-config CONFIG [--out CATALOG] ...
    message_catalog_map.py --selftest

## Two devices, and no translator

A deployment describes its messages in its own format, read by its own tools. This script reads no
such format and knows none of its words. It holds two general devices:

* it RUNS the deployment's generator, a command the user configures, which writes JSON to the path
  the command names as `{out}`; what that JSON means is the generator's business;
* it MAPS any JSON document into the catalog by a mapping document that says, with RFC 6901 JSON
  pointers, where the message list is and where each member of a message is. Values are COPIED as
  the source spells them, never computed: a number keeps its digits, a string its text.

The deployment's part is data: the generator's command line and the mapping document. Both are
the deployment's and stay outside this repository, and so do the JSON it maps and the catalog it
writes; a path inside the repository is refused for each.

## The mapping document

JSON5, read by the workspace's reader (`message_catalog.read_json5`):

    {
      mapping: 1,                          // the revision of this format
      messages: '/doc/list',               // the message list: an array, or an object whose
                                           // members are the messages, in document order
      message: {                           // target in a catalog message -> its source
        '/key_expr': '/path/in/element',   // a pointer relative to the message
        '/id': '0#',                       // the name of the message's member in an object list
        '/subscribers': {value: ['b']},    // a value copied as the mapping writes it
      },
      nodes: {list: '/doc/hosts', node: {'/name': '/label'}},   // or {collect: true}
      catalog: {'/supervision/start_delay_ms': '/doc/delay'},   // pointers from the source's root
    }

A TARGET is a pointer into the catalog's shape (`deploy/message-catalog.schema.json`): the members
a catalog message, node or catalog has, and inside an object member its members. Which targets
exist, which are required and what type each holds are read from that shape, so a member the
catalog gains is mappable without a change here. A target names a member, never an element of a
list: a list is copied whole.

`nodes: {collect: true}` lists the node names the catalog's messages name as publishers and
subscribers, each once, in the order they first appear.

## What is refused

Every problem is named, all of them at once, before anything is written:

* the mapping: not JSON5, a revision or member it does not have, a member stated twice, a pointer
  that is not RFC 6901, a target the catalog has not or one that names a list element, two targets
  one inside the other, no source for a member every message (node, catalog) requires;
* a mapping that POINTS NOWHERE: a message list that is not in the source, a source that no
  message of a non-empty list has;
* a TYPE MISMATCH, and every other rule of the shape a single value breaks (a number where a list
  is, `40.0` where an unsigned integer is, a JSON null anywhere): the shape's own word
  (`wrong_type`, `empty`, `value_out_of_range`, ...), at the catalog member, with the source it was
  copied from;
* a message MISSING A REQUIRED FIELD: the message, the member and the source that was not there;
* a source member stated twice where a pointer goes through it, which leaves the pointer two
  values to copy.

The catalog the mapping makes is then judged whole by the catalog's own rules
(`message_catalog.Judge`: unknown nodes, a key or an id stated twice, the build's limits); the
first refusal is printed with its word, its place in the catalog and the source it came from.

## The generator

`--generator` takes a command line, split as a POSIX shell splits it (no shell runs it);
`--generator-config` takes a JSON5 file of the user's: `{generator: ['tool', '--to', '{out}'],
timeout_s: 300, cwd: 'dir'}`, the command a list of arguments or one line, `cwd` relative to the
file. Every `{out}` in an argument is replaced by the path the JSON is to be written to, and a
command that names none is refused. A generator that exits non-zero, is killed, outlives its
timeout, cannot be started, or writes no JSON at `{out}` is a failure, reported with the last
lines of its standard error as it printed them, or of its standard output when its standard error
is empty.

## Exit status

0 the catalog was written; 1 refused (the mapping, the source or the catalog); 2 usage; 3 the
generator failed.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import re
import shlex
import subprocess
import sys
import tempfile

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import message_catalog as mc  # noqa: E402
import wz_config  # noqa: E402

ROOT = pathlib.Path(__file__).resolve().parents[2]
REVISION = 1
# How deep a source document may nest: a generator's JSON is not the catalog, and its own
# structure may be deeper than a catalog's.
SOURCE_DEPTH = 64
# How many lines of a failed generator's output are reported.
TAIL_LINES = 20
OUT = "{out}"
NAME_OF_MEMBER = "0#"
MAPPING_MEMBERS = ("mapping", "messages", "message", "nodes", "catalog")
CONFIG_MEMBERS = ("generator", "timeout_s", "cwd")
ARRAY_INDEX = re.compile(r"0|[1-9][0-9]*")

EXIT_REFUSED = 1
EXIT_GENERATOR = 3


class MapRefused(Exception):
    """A mapping, a source or a catalog refused: every problem, one sentence each."""

    def __init__(self, problems: list) -> None:
        super().__init__("; ".join(problems))
        self.problems = problems


class GeneratorFailed(Exception):
    """The generator did not leave JSON at `{out}`: what happened, and its last lines."""


# ---------------------------------------------------------------------------------------------
# RFC 6901 pointers
# ---------------------------------------------------------------------------------------------


def parse_pointer(text: str) -> tuple:
    """The reference tokens of a JSON pointer; ValueError for text that is not one."""
    if text == "":
        return ()
    if not text.startswith("/"):
        raise ValueError(f"`{text}` is not a JSON pointer: it starts with `/`, or is empty")
    tokens = []
    for raw in text[1:].split("/"):
        if re.search(r"~(?![01])", raw):
            raise ValueError(f"`{text}` is not a JSON pointer: `~` is followed by 0 or 1")
        tokens.append(raw.replace("~1", "/").replace("~0", "~"))
    return tuple(tokens)


def pointer_text(tokens: tuple) -> str:
    return "".join("/" + t.replace("~", "~0").replace("/", "~1") for t in tokens)


ABSENT = object()


def resolve(value, tokens: tuple, where: str):
    """The value `tokens` names inside `value`, or ABSENT. A member stated twice on the way is
    refused: the pointer would name two values."""
    for depth, token in enumerate(tokens):
        if isinstance(value, mc.Obj):
            found = [v for k, v in value.pairs if k == token]
            if not found:
                return ABSENT
            if len(found) > 1:
                raise MapRefused([f"{where}: the member `{pointer_text(tokens[:depth + 1])}` is "
                                  "stated twice in the source, so the pointer names two values"])
            value = found[0]
        elif isinstance(value, list):
            if not ARRAY_INDEX.fullmatch(token) or int(token) >= len(value):
                return ABSENT
            value = value[int(token)]
        else:
            return ABSENT
    return value


# ---------------------------------------------------------------------------------------------
# the catalog's shape, as targets
# ---------------------------------------------------------------------------------------------


class Shape:
    """The catalog's shape: the member a target names, and what the catalog requires."""

    UNIT = {"message": "message", "node": "node", "catalog": "catalog"}

    def __init__(self, schema: dict) -> None:
        self.schema = schema
        self.defs = schema["$defs"]

    def deref(self, node: dict) -> dict:
        # An unsigned integer stays a reference: the shape's judge reads its range off the node
        # that refers to it.
        while "$ref" in node and node["$ref"] != "#/$defs/uint":
            node = self.defs[node["$ref"].rsplit("/", 1)[1]]
        return node

    def unit(self, name: str) -> dict:
        return self.defs[self.UNIT[name]]

    def target(self, unit: str, tokens: tuple):
        """The shape node `tokens` names in a `unit`, or a sentence saying why there is none."""
        node = self.unit(unit)
        for depth, token in enumerate(tokens):
            here = self.deref(node)
            so_far = pointer_text(tokens[:depth + 1])
            if here.get("type") == "array":
                return f"`{so_far}` names an element of a list: a list is copied whole"
            if here.get("type") != "object":
                return f"`{pointer_text(tokens[:depth])}` holds no members"
            members = here.get("properties", {})
            if token in members:
                node = members[token]
                continue
            others = here.get("additionalProperties")
            if isinstance(others, dict):
                node = others
                continue
            return f"a catalog {unit} has no member `{so_far}`"
        return node

    def unmapped_required(self, unit: str, targets: list) -> list:
        """The required members a set of targets leaves without a source: in the unit, and inside
        each object member some target reaches into without copying it whole."""
        out: list = []

        def walk(node: dict, prefix: tuple) -> None:
            here = self.deref(node)
            if here.get("type") != "object" or "x-wz-document" in here:
                return
            for name in here.get("required", []):
                path = prefix + (name,)
                if not any(t[:len(path)] == path for t in targets):
                    out.append(path)
            for name, member in here.get("properties", {}).items():
                path = prefix + (name,)
                if path in targets:
                    continue
                if any(t[:len(path)] == path and len(t) > len(path) for t in targets):
                    walk(member, path)

        walk(self.unit(unit), ())
        return out

    def missing(self, node: dict, built: dict, prefix: tuple) -> list:
        """The required members absent from what was built for `node`, through the objects the
        mapping built member by member (a value copied whole is the judge's to read)."""
        here = self.deref(node)
        out = [prefix + (name,) for name in here.get("required", []) if name not in built]
        for name, value in built.items():
            if isinstance(value, dict):
                member = here.get("properties", {}).get(name, here.get("additionalProperties"))
                if isinstance(member, dict):
                    out.extend(self.missing(member, value, prefix + (name,)))
        return out

    def ordered(self, node: dict, built: dict) -> mc.Obj:
        """What was built, as an object whose members are in the shape's order, then the rest in
        the mapping's."""
        here = self.deref(node)
        members = here.get("properties", {})
        names = [n for n in members if n in built] + [n for n in built if n not in members]
        pairs = []
        for name in names:
            value = built[name]
            if isinstance(value, dict):
                value = self.ordered(members.get(name, here.get("additionalProperties", {})), value)
            pairs.append((name, value))
        return mc.Obj(pairs)


# ---------------------------------------------------------------------------------------------
# the mapping document
# ---------------------------------------------------------------------------------------------


class Source:
    """Where one target's value comes from: a pointer, the member's name, or a value."""

    def __init__(self, kind: str, tokens: tuple = (), value=None, text: str = "") -> None:
        self.kind = kind
        self.tokens = tokens
        self.value = value
        self.text = text


class Unit:
    """The targets of one unit (a message, a node, the catalog) and each one's source."""

    def __init__(self, name: str, rows: list) -> None:
        self.name = name
        self.rows = rows

    def targets(self) -> list:
        return [t for t, _ in self.rows]


def distinct_members(obj: mc.Obj, where: str, problems: list) -> None:
    seen: set = set()
    for key in obj.keys():
        if key in seen:
            problems.append(f"{where}: the member `{key}` is stated twice")
        seen.add(key)


def read_unit(shape: Shape, unit: str, body, where: str, problems: list,
              named: bool, require: bool = True) -> Unit:
    """The rows of one unit's mapping: target pointer -> source. `require` holds the rows to the
    members the unit requires; the catalog's own are judged with its lists by the caller."""
    rows: list = []
    if not isinstance(body, mc.Obj):
        problems.append(f"{where}: expected an object of target pointers, found "
                        f"{mc.describe(body)}")
        return Unit(unit, rows)
    distinct_members(body, where, problems)
    for key, raw in body.pairs:
        here = f"{where}[`{key}`]"
        try:
            target = parse_pointer(key)
        except ValueError as err:
            problems.append(f"{here}: {err}")
            continue
        if not target:
            problems.append(f"{here}: a target names a member, and the empty pointer names the "
                            f"whole {unit}")
            continue
        found = shape.target(unit, target)
        if isinstance(found, str):
            problems.append(f"{here}: {found}")
            continue
        source = read_source(raw, here, problems, named)
        if source is not None:
            rows.append((target, source))
    targets = [t for t, _ in rows]
    for a in targets:
        for b in targets:
            if a != b and b[:len(a)] == a:
                problems.append(f"{where}: `{pointer_text(a)}` is copied whole and "
                                f"`{pointer_text(b)}` inside it as well")
    if require:
        for path in shape.unmapped_required(unit, targets):
            problems.append(f"{where}: the mapping gives no source for `{pointer_text(path)}`, "
                            f"which every catalog {unit} has")
    return Unit(unit, rows)


def read_source(raw, where: str, problems: list, named: bool):
    if isinstance(raw, mc.Obj):
        if raw.keys() != ["value"]:
            problems.append(f"{where}: a source is a pointer, `{NAME_OF_MEMBER}`, or "
                            "{value: ...}")
            return None
        return Source("value", value=raw.get("value"), text="the mapping's value")
    if isinstance(raw, mc.Num) or not isinstance(raw, str):
        problems.append(f"{where}: a source is a pointer, `{NAME_OF_MEMBER}`, or {{value: ...}}, "
                        f"found {mc.describe(raw)}")
        return None
    if raw == NAME_OF_MEMBER:
        if not named:
            problems.append(f"{where}: `{NAME_OF_MEMBER}` is the name of a member of the list, "
                            "which only a message or a node has")
            return None
        return Source("name", text=NAME_OF_MEMBER)
    try:
        return Source("pointer", tokens=parse_pointer(raw), text=raw)
    except ValueError as err:
        problems.append(f"{where}: {err}")
        return None


def list_pointer(raw, where: str, problems: list):
    if isinstance(raw, mc.Num) or not isinstance(raw, str):
        problems.append(f"{where}: expected a JSON pointer, found {mc.describe(raw)}")
        return None
    try:
        return parse_pointer(raw)
    except ValueError as err:
        problems.append(f"{where}: {err}")
        return None


class Mapping:
    """A mapping document, read and judged against the catalog's shape."""

    def __init__(self, shape: Shape, text: str) -> None:
        problems: list = []
        try:
            doc = mc.read_json5(text, SOURCE_DEPTH)
        except mc.Refused as err:
            raise MapRefused([f"the mapping is not JSON5: {err.reason}"]) from None
        if not isinstance(doc, mc.Obj):
            raise MapRefused([f"the mapping is {mc.describe(doc)}, not an object"])
        distinct_members(doc, "the mapping", problems)
        for key in doc.keys():
            if key not in MAPPING_MEMBERS:
                problems.append(f"the mapping has no member `{key}` (it has "
                                f"{', '.join(MAPPING_MEMBERS)})")
        revision = doc.get("mapping")
        if not (isinstance(revision, mc.Num) and revision == str(REVISION)):
            stated = mc.to_text(revision) if doc.has("mapping") else "none"
            problems.append(f"the mapping states `mapping: {REVISION}`, the revision of this "
                            f"format, and states {stated}")
        self.messages = None
        self.message = Unit("message", [])
        if not doc.has("messages") or not doc.has("message"):
            problems.append("the mapping states `messages`, where the message list is, and "
                            "`message`, where each member of a message is")
        else:
            self.messages = list_pointer(doc.get("messages"), "`messages`", problems)
            self.message = read_unit(shape, "message", doc.get("message"), "`message`",
                                     problems, named=True)
        self.nodes_list = None
        self.node = None
        self.collect = False
        catalog_targets = [("messages",)]
        if doc.has("nodes"):
            catalog_targets.append(("nodes",))
            nodes = doc.get("nodes")
            if isinstance(nodes, mc.Obj) and nodes.keys() == ["collect"]:
                if nodes.get("collect") is not True:
                    problems.append("`nodes`: `collect` is true, or the member is left out")
                self.collect = True
            elif isinstance(nodes, mc.Obj) and sorted(nodes.keys()) == ["list", "node"]:
                self.nodes_list = list_pointer(nodes.get("list"), "`nodes.list`", problems)
                self.node = read_unit(shape, "node", nodes.get("node"), "`nodes.node`",
                                      problems, named=True)
            else:
                problems.append("`nodes` is {list: <pointer>, node: {...}} or {collect: true}")
        self.catalog = Unit("catalog", [])
        if doc.has("catalog"):
            self.catalog = read_unit(shape, "catalog", doc.get("catalog"), "`catalog`",
                                     problems, named=False, require=False)
        for target in self.catalog.targets():
            if target[:1] in catalog_targets:
                problems.append(f"`catalog`: `{pointer_text(target)}` is made by the mapping's "
                                f"`{target[0]}`, and only there")
        for path in shape.unmapped_required("catalog", self.catalog.targets() + catalog_targets):
            problems.append(f"the mapping gives no source for `{pointer_text(path)}`, which a "
                            "catalog has: state `nodes`, or map it under `catalog`")
        if problems:
            raise MapRefused(problems)


# ---------------------------------------------------------------------------------------------
# the mapping applied
# ---------------------------------------------------------------------------------------------


def put(built: dict, tokens: tuple, value) -> None:
    for token in tokens[:-1]:
        built = built.setdefault(token, {})
    built[tokens[-1]] = value


def elements(source, tokens: tuple, what: str) -> list:
    """The (name, value) of each element of the list `tokens` names; the name is None in an
    array."""
    found = resolve(source, tokens, f"the {what} list")
    if found is ABSENT:
        raise MapRefused([f"the {what} list `{pointer_text(tokens)}` points nowhere: the source "
                          "has no such member"])
    if isinstance(found, list):
        return [(None, v) for v in found]
    if isinstance(found, mc.Obj):
        seen: set = set()
        for key in found.keys():
            if key in seen:
                raise MapRefused([f"the {what} list `{pointer_text(tokens)}` states the member "
                                  f"`{key}` twice"])
            seen.add(key)
        return list(found.pairs)
    raise MapRefused([f"the {what} list `{pointer_text(tokens)}` is {mc.describe(found)}, not an "
                      "array or an object"])


class Applied:
    """One unit made from its elements: the objects, each value's source, and the problems."""

    def __init__(self) -> None:
        self.objects: list = []
        self.provenance: dict = {}
        self.problems: list = []


def apply_unit(shape: Shape, judge: mc.Judge, unit: Unit, base: tuple, items: list,
               place: str) -> Applied:
    """The catalog objects of `items` (each `(name, element)`) at `/<place>/<i>`, the list being
    at `base` in the source."""
    out = Applied()
    hits = {t: 0 for t, s in unit.rows if s.kind == "pointer"}
    absent: list = []
    for i, (name, element) in enumerate(items):
        step = (name,) if name is not None else (str(i),)
        at = f"/{place}/{i}"
        built: dict = {}
        refused: list = []
        for target, source in unit.rows:
            origin = pointer_text(base + step + source.tokens)
            if source.kind == "value":
                value, origin = source.value, source.text
            elif source.kind == "name":
                if name is None:
                    out.problems.append(f"{at}: `{NAME_OF_MEMBER}` for `{pointer_text(target)}` "
                                        f"names a member, and `{pointer_text(base)}` is an "
                                        "array, whose elements have none")
                    refused.append(target)
                    continue
                value, origin = name, pointer_text(base + step) + f" ({NAME_OF_MEMBER})"
            else:
                value = resolve(element, source.tokens, f"{at}{pointer_text(target)}")
                if value is ABSENT:
                    continue
                hits[target] += 1
            put(built, target, value)
            catalog_at = at + pointer_text(target)
            out.provenance[catalog_at] = origin
            node = shape.target(unit.name, target)
            try:
                judge.shape(value, node, catalog_at)
            except mc.Refused as err:
                out.problems.append(f"{catalog_at} (copied from `{origin}`): {err.word}: "
                                    f"{err.reason}")
        for path in shape.missing(shape.unit(unit.name), built, ()):
            if path not in refused:
                absent.append((i, at, path))
        out.objects.append(shape.ordered(shape.unit(unit.name), built))
    nowhere = {t for t, n in hits.items() if n == 0 and items}
    for target, source in unit.rows:
        if target in nowhere:
            out.problems.append(f"the {unit.name} source `{source.text}` for "
                                f"`{pointer_text(target)}` points nowhere: no {unit.name} of "
                                f"`{pointer_text(base)}` has it")
    for i, at, path in absent:
        if any(path[:len(t)] == t for t in nowhere):
            continue
        given = [s.text for t, s in unit.rows if t[:len(path)] == path]
        why = f" (`{'`, `'.join(given)}` is not there)" if given else ""
        out.problems.append(f"{at}: the {unit.name} is missing the required field "
                            f"`{pointer_text(path)}`{why}")
    return out


def collect_nodes(messages: list) -> list:
    names: list = []
    for message in messages:
        for member in ("publishers", "subscribers"):
            listed = message.get(member, [])
            if isinstance(listed, list):
                for name in listed:
                    if isinstance(name, str) and not isinstance(name, mc.Num) \
                            and name not in names:
                        names.append(name)
    return [mc.Obj([("name", name)]) for name in names]


def map_catalog(mapping: Mapping, shape: Shape, judge: mc.Judge, text: str) -> tuple:
    """The catalog the mapping makes of the source `text`, and where each value came from."""
    try:
        source = mc.read_json5(text, SOURCE_DEPTH)
    except mc.Refused as err:
        raise MapRefused([f"the source is not JSON: {err.reason}"]) from None
    problems: list = []
    provenance: dict = {}
    built: dict = {}

    messages = apply_unit(shape, judge, mapping.message, mapping.messages,
                          elements(source, mapping.messages, "message"), "messages")
    problems += messages.problems
    provenance.update(messages.provenance)
    built["messages"] = messages.objects

    if mapping.collect:
        built["nodes"] = collect_nodes(messages.objects)
    elif mapping.node is not None:
        nodes = apply_unit(shape, judge, mapping.node, mapping.nodes_list,
                           elements(source, mapping.nodes_list, "node"), "nodes")
        problems += nodes.problems
        provenance.update(nodes.provenance)
        built["nodes"] = nodes.objects

    for target, src in mapping.catalog.rows:
        catalog_at = pointer_text(target)
        if src.kind == "value":
            value, origin = src.value, src.text
        else:
            value = resolve(source, src.tokens, catalog_at)
            origin = src.text
            if value is ABSENT:
                problems.append(f"the catalog source `{src.text}` for `{catalog_at}` points "
                                "nowhere: the source has no such member")
                continue
        put(built, target, value)
        provenance[catalog_at] = origin
        try:
            judge.shape(value, shape.target("catalog", target), catalog_at)
        except mc.Refused as err:
            problems.append(f"{catalog_at} (copied from `{origin}`): {err.word}: {err.reason}")
    if problems:
        raise MapRefused(problems)
    return shape.ordered(shape.unit("catalog"), built), provenance


def judged(catalog: mc.Obj, provenance: dict, judge: mc.Judge) -> None:
    """The catalog's own rules over the whole, the first refusal named with its source."""
    try:
        judge.judge(mc.to_text(catalog))
    except mc.Refused as err:
        origin = ""
        for place in sorted(provenance, key=len, reverse=True):
            if err.path == place or err.path.startswith(place + "/"):
                origin = f" (copied from `{provenance[place]}`)"
                break
        where = f" at {err.path}" if err.path else ""
        raise MapRefused([f"the catalog is refused: {err.word}{where}{origin}: "
                          f"{err.reason}"]) from None


def pretty(value, depth: int = 0) -> str:
    pad, end = "  " * (depth + 1), "  " * depth
    if isinstance(value, mc.Obj):
        if not value.pairs:
            return "{}"
        inner = ",\n".join(f"{pad}{json.dumps(k, ensure_ascii=False)}: {pretty(v, depth + 1)}"
                           for k, v in value.pairs)
        return "{\n" + inner + "\n" + end + "}"
    if isinstance(value, list):
        if not value:
            return "[]"
        inner = ",\n".join(pad + pretty(v, depth + 1) for v in value)
        return "[\n" + inner + "\n" + end + "]"
    return mc.to_text(value)


# ---------------------------------------------------------------------------------------------
# the generator
# ---------------------------------------------------------------------------------------------


def tail(data: bytes) -> str:
    lines = data.decode("utf-8", errors="replace").rstrip("\r\n").splitlines()
    return "\n".join(lines[-TAIL_LINES:])


def last_words(stderr: bytes, stdout: bytes) -> str:
    if stderr.strip():
        return f"; the last lines of its standard error:\n{tail(stderr)}"
    if stdout.strip():
        return f"; its standard error is empty, and the last lines of its standard output:\n" \
               f"{tail(stdout)}"
    return "; it printed nothing"


def run_generator(argv: list, timeout: float | None = None,
                  cwd: pathlib.Path | None = None) -> str:
    """Run the generator and return the JSON text it wrote at `{out}`."""
    if not argv:
        raise GeneratorFailed("the generator command is empty")
    if not any(OUT in arg for arg in argv):
        raise GeneratorFailed(f"the generator command names no `{OUT}`: the tool is told where "
                              "to write its JSON through it")
    with tempfile.TemporaryDirectory(prefix="wz-catalog-map-") as scratch:
        out = pathlib.Path(scratch) / "source.json"
        args = [arg.replace(OUT, str(out)) for arg in argv]
        try:
            done = subprocess.run(args, cwd=cwd, stdin=subprocess.DEVNULL, capture_output=True,
                                  timeout=timeout, check=False)
        except FileNotFoundError:
            raise GeneratorFailed(f"the generator `{argv[0]}` could not be started: no such "
                                  "program") from None
        except PermissionError:
            raise GeneratorFailed(f"the generator `{argv[0]}` could not be started: it is not "
                                  "executable") from None
        except subprocess.TimeoutExpired as err:
            raise GeneratorFailed(f"the generator `{argv[0]}` did not finish in {timeout} s"
                                  + last_words(err.stderr or b"", err.output or b"")) from None
        if done.returncode < 0:
            raise GeneratorFailed(f"the generator `{argv[0]}` was killed by signal "
                                  f"{-done.returncode}" + last_words(done.stderr, done.stdout))
        if done.returncode != 0:
            raise GeneratorFailed(f"the generator `{argv[0]}` exited with status "
                                  f"{done.returncode}" + last_words(done.stderr, done.stdout))
        if not out.is_file():
            raise GeneratorFailed(f"the generator `{argv[0]}` exited 0 and wrote nothing at "
                                  f"`{OUT}`" + last_words(done.stderr, done.stdout))
        try:
            return out.read_text(encoding="utf-8")
        except UnicodeDecodeError as err:
            raise GeneratorFailed(f"the generator `{argv[0]}` wrote text at `{OUT}` that is not "
                                  f"UTF-8 (byte {err.start})") from None


def read_config(path: pathlib.Path) -> tuple:
    """The generator a config file states: its arguments, its timeout and its directory."""
    try:
        doc = mc.read_json5(path.read_text(encoding="utf-8"), SOURCE_DEPTH)
    except mc.Refused as err:
        raise MapRefused([f"the generator config is not JSON5: {err.reason}"]) from None
    if not isinstance(doc, mc.Obj):
        raise MapRefused([f"the generator config is {mc.describe(doc)}, not an object"])
    problems: list = []
    distinct_members(doc, "the generator config", problems)
    for key in doc.keys():
        if key not in CONFIG_MEMBERS:
            problems.append(f"the generator config has no member `{key}` (it has "
                            f"{', '.join(CONFIG_MEMBERS)})")
    command = doc.get("generator")
    argv: list = []
    if isinstance(command, str) and not isinstance(command, mc.Num):
        try:
            argv = shlex.split(command)
        except ValueError as err:
            problems.append(f"the generator config's `generator` does not split: {err}")
    elif isinstance(command, list) and command and all(
            isinstance(a, str) and not isinstance(a, mc.Num) for a in command):
        argv = list(command)
    else:
        problems.append("the generator config's `generator` is a command line or a list of "
                        "arguments, and is required")
    timeout = None
    if doc.has("timeout_s"):
        raw = doc.get("timeout_s")
        try:
            timeout = float(raw) if isinstance(raw, mc.Num) else None
        except ValueError:
            timeout = None
        if timeout is None or not timeout > 0:
            problems.append("the generator config's `timeout_s` is a number of seconds above 0")
    cwd = None
    if doc.has("cwd"):
        raw = doc.get("cwd")
        if isinstance(raw, str) and not isinstance(raw, mc.Num):
            cwd = (path.parent / raw).resolve()
        else:
            problems.append("the generator config's `cwd` is a directory, as a string")
    if problems:
        raise MapRefused(problems)
    return argv, timeout, cwd


# ---------------------------------------------------------------------------------------------
# the command
# ---------------------------------------------------------------------------------------------


def outside_repository(path: pathlib.Path, what: str) -> None:
    """A deployment's own file is refused inside this repository, which is public."""
    try:
        inside = path.resolve().is_relative_to(ROOT)
    except OSError:
        inside = False
    if inside:
        raise MapRefused([f"the {what} `{path}` is inside the wz repository: a deployment's "
                          f"{what} is its own data and is kept outside the public tree"])


def produce(mapping_text: str, source_text: str, limits: dict) -> str:
    """The catalog text a mapping makes of a source, judged."""
    schema = mc.load_schema()
    shape = Shape(schema)
    judge = mc.Judge(schema, limits)
    mapping = Mapping(shape, mapping_text)
    catalog, provenance = map_catalog(mapping, shape, judge, source_text)
    judged(catalog, provenance, judge)
    return pretty(catalog) + "\n"


def main(argv: list) -> int:
    parser = argparse.ArgumentParser(
        description="a deployment's JSON mapped into a wz message catalog")
    parser.add_argument("--mapping", type=pathlib.Path, help="the mapping document (JSON5)")
    given = parser.add_mutually_exclusive_group()
    given.add_argument("--source", type=pathlib.Path, help="the JSON to map")
    given.add_argument("--generator", help="the command that writes the JSON to {out}")
    given.add_argument("--generator-config", type=pathlib.Path,
                       help="a JSON5 file stating the generator")
    parser.add_argument("--out", type=pathlib.Path, help="where to write the catalog (stdout)")
    parser.add_argument("--limit", action="append", default=[], metavar="NAME=VALUE",
                        help="an image's own bound in place of the declaration's default")
    parser.add_argument("--selftest", action="store_true")
    args = parser.parse_args(argv)
    if args.selftest:
        return _selftest()
    if args.mapping is None or (args.source is None and args.generator is None
                                and args.generator_config is None):
        parser.error("name --mapping, and one of --source, --generator, --generator-config")
    try:
        limits = mc.declared_limits(wz_config.load_decl(), args.limit)
    except ValueError as err:
        parser.error(str(err))
    try:
        for path, what in ((args.mapping, "mapping"), (args.source, "source"),
                           (args.generator_config, "generator config"), (args.out, "catalog")):
            if path is not None:
                outside_repository(path, what)
        if args.source is not None:
            source_text = args.source.read_text(encoding="utf-8")
        else:
            if args.generator is not None:
                try:
                    command, timeout, cwd = shlex.split(args.generator), None, None
                except ValueError as err:
                    parser.error(f"--generator does not split: {err}")
            else:
                command, timeout, cwd = read_config(args.generator_config)
            source_text = run_generator(command, timeout, cwd)
        text = produce(args.mapping.read_text(encoding="utf-8"), source_text, limits)
    except GeneratorFailed as err:
        print(f"message-catalog-map: GENERATOR FAILED -- {err}", file=sys.stderr)
        return EXIT_GENERATOR
    except MapRefused as err:
        print("message-catalog-map: REFUSED", file=sys.stderr)
        for problem in err.problems:
            print(f"  {problem}", file=sys.stderr)
        return EXIT_REFUSED
    except (OSError, UnicodeDecodeError) as err:
        print(f"message-catalog-map: REFUSED -- {err}", file=sys.stderr)
        return EXIT_REFUSED
    if args.out is None:
        sys.stdout.write(text)
    else:
        args.out.write_text(text, encoding="utf-8")
        print(f"message-catalog-map: wrote {args.out}", file=sys.stderr)
    return 0


# ---------------------------------------------------------------------------------------------
# selftest: synthetic documents only, made up for it and unlike any deployment's
# ---------------------------------------------------------------------------------------------

SOURCE = """{
  "spec": {
    "hosts": [{"label": "alpha"}, {"label": "beta", "where": "0x00F1"}],
    "start": 250,
    "rows": [
      {"path": "sample/one", "number": 11, "every": 20, "writers": ["alpha"],
       "readers": ["beta"], "depth": 2,
       "guard": {"name": "cat-demo", "words": {"ident": {"group": 21, "msg": 300},
                                               "cell": {"kind": 6}}},
       "misses": 3},
      {"path": "sample/two", "number": "0x0C", "writers": ["beta"], "readers": ["alpha"]}
    ]
  }
}"""

MAPPING = """{
  mapping: 1,
  messages: '/spec/rows',
  message: {
    '/key_expr': '/path',
    '/id': '/number',
    '/publishers': '/writers',
    '/subscribers': '/readers',
    '/period_ms': '/every',
    '/protection/profile': '/guard/name',
    '/protection/values': '/guard/words',
    '/replay_depth': '/depth',
    '/supervision/factor': '/misses',
  },
  nodes: {list: '/spec/hosts', node: {'/name': '/label', '/address': '/where'}},
  catalog: {'/supervision/start_delay_ms': '/spec/start', '/e2e_profiles': %s},
}"""


def _selftest() -> int:
    failures: list = []

    def expect(what: str, ok: bool) -> None:
        print(f"  {'ok  ' if ok else 'FAIL'} {what}")
        if not ok:
            failures.append(what)

    def problems_of(call) -> list:
        try:
            call()
        except MapRefused as err:
            return err.problems
        return []

    def has(problems: list, *needles: str) -> bool:
        return any(all(n in p for n in needles) for p in problems)

    limits = mc.declared_limits(wz_config.load_decl(), [])
    schema = mc.load_schema()
    shape = Shape(schema)
    judge = mc.Judge(schema, limits)
    profiles = mc.read_json5(mc.FIXTURE.read_text(encoding="utf-8")).get("e2e_profiles")
    mapping = MAPPING % ("{value: " + mc.to_text(profiles) + "}")

    # RFC 6901.
    doc = mc.read_json5('{"a/b": {"m~n": [10, 20]}, "c": {"d": 1, "d": 2}}')
    expect("`~1` and `~0` unescape, and an index reads an element",
           resolve(doc, parse_pointer("/a~1b/m~0n/1"), "x") == mc.Num("20"))
    expect("the empty pointer is the whole document", resolve(doc, parse_pointer(""), "x") is doc)
    for bad in ("a/b", "/a~2b", "/a~"):
        try:
            parse_pointer(bad)
            expect(f"`{bad}` is refused as a pointer", False)
        except ValueError:
            expect(f"`{bad}` is refused as a pointer", True)
    expect("a leading zero, `-` and an index past the end point nowhere",
           all(resolve(doc, parse_pointer(p), "x") is ABSENT
               for p in ("/a~1b/m~0n/01", "/a~1b/m~0n/-", "/a~1b/m~0n/2", "/z")))
    expect("a pointer through a member stated twice is refused",
           has(problems_of(lambda: resolve(doc, parse_pointer("/c/d"), "x")), "stated twice"))
    expect("a pointer is written back with its escapes",
           pointer_text(("a/b", "m~n")) == "/a~1b/m~0n")

    # A mapping that is sound.
    text = produce(mapping, SOURCE, limits)
    catalog = mc.read_json5(text)
    first, second = catalog.get("messages")
    expect("the catalog's members are in the shape's order",
           catalog.keys() == ["nodes", "e2e_profiles", "supervision", "messages"])
    expect("a message's members are in the shape's order",
           first.keys() == ["key_expr", "id", "publishers", "subscribers", "period_ms",
                            "protection", "replay_depth", "supervision"])
    expect("values are copied as the source spells them",
           first.get("id") == mc.Num("11") and second.get("id") == "0x0C"
           and first.get("protection").get("values") == mc.Obj(
               [("ident", mc.Obj([("group", mc.Num("21")), ("msg", mc.Num("300"))])),
                ("cell", mc.Obj([("kind", mc.Num("6"))]))]))
    expect("an optional member a message does not have is left out",
           second.keys() == ["key_expr", "id", "publishers", "subscribers"])
    expect("nodes come from their list, an absent address left out",
           catalog.get("nodes") == [mc.Obj([("name", "alpha")]),
                                    mc.Obj([("name", "beta"), ("address", "0x00F1")])])
    expect("a catalog member comes from the source's root, and a value from the mapping",
           catalog.get("supervision") == mc.Obj([("start_delay_ms", mc.Num("250"))])
           and catalog.get("e2e_profiles") == profiles)
    expect("the catalog is the catalog's: its own judge reads it",
           len(judge.judge(mc.to_text(catalog))["messages"]) == 2)

    # The message list as an object, its members' names copied, the nodes collected.
    keyed = ('{"set": {"left/a": {"n": 3, "w": ["p"], "r": ["q", "p"]},'
             ' "left/b": {"n": 4, "w": ["q"], "r": []}}}')
    keyed_map = ("{mapping: 1, messages: '/set', message: {'/key_expr': '0#', '/id': '/n', "
                 "'/publishers': '/w', '/subscribers': '/r'}, nodes: {collect: true}}")
    out = mc.read_json5(produce(keyed_map, keyed, limits))
    expect("`0#` copies the name a message has in an object list",
           [m.get("key_expr") for m in out.get("messages")] == ["left/a", "left/b"])
    expect("collected nodes are each name once, in the order they first appear",
           [n.get("name") for n in out.get("nodes")] == ["p", "q"])
    expect("`0#` in an array list is refused, naming the message",
           has(problems_of(lambda: produce(keyed_map.replace("'/set'", "'/arr'"),
                                           '{"arr": [{"n": 1, "w": ["p"], "r": []}]}',
                                           limits)),
               "/messages/0", "0#", "an array"))
    expect("a value of the mapping is copied as written",
           mc.read_json5(produce(keyed_map.replace("'/r'", "{value: ['p']}"), keyed, limits))
           .get("messages")[1].get("subscribers") == ["p"])

    # The mapping refused, every problem named.
    def mapping_problems(text: str) -> list:
        return problems_of(lambda: Mapping(shape, text))

    base = ("{mapping: 1, messages: '/spec/rows', message: {'/key_expr': '/path', "
            "'/id': '/number', '/publishers': '/writers', '/subscribers': '/readers'%s}, "
            "nodes: {collect: true}%s}")
    sound = base % ("", "")
    expect("the base mapping is sound", mapping_problems(sound) == [])
    for extra, needles, why in (
            (", '/timeout_ms': '/t'", ("no member `/timeout_ms`",),
             "a target the catalog has not"),
            (", '/publishers/0': '/w'", ("element of a list",), "a target inside a list"),
            (", '/protection': '/g', '/protection/profile': '/g/n'",
             ("copied whole", "/protection/profile"), "a target inside a target"),
            (", '/protection/profile': '/g/n'", ("no source for `/protection/values`",),
             "a nested member left without a source"),
            (", '/period_ms': 'every'", ("not a JSON pointer",), "a source that is no pointer"),
            (", '/period_ms': 40", ("found a number",), "a source that is a number"),
            (", '/key_expr': '/again'", ("`/key_expr` is stated twice",), "a target twice")):
        found = mapping_problems(base % (extra, ""))
        expect(f"{why} is refused by name", has(found, *needles))
    found = mapping_problems(base.replace("'/id': '/number', ", "") % ("", ", extra: 1"))
    expect("two problems are both named: an unmapped required member and an unknown member",
           has(found, "no source for `/id`") and has(found, "no member `extra`"))
    expect("a mapping of another revision is refused",
           has(mapping_problems(sound.replace("mapping: 1", "mapping: 2")), "revision"))
    expect("a mapping that is not JSON5 is refused",
           has(mapping_problems("{mapping: 1,"), "not JSON5"))
    expect("a catalog with no nodes is refused at the mapping",
           has(mapping_problems(sound.replace(", nodes: {collect: true}", "")),
               "no source for `/nodes`"))

    # The source refused, every problem named.
    def source_problems(source: str, text: str = sound) -> list:
        return problems_of(lambda: produce(text, source, limits))

    expect("a message list that is not in the source points nowhere",
           has(source_problems('{"spec": {}}'), "message list `/spec/rows` points nowhere"))
    expect("a source no message has points nowhere",
           has(source_problems(SOURCE, base % (", '/period_ms': '/evry'", "")),
               "`/evry`", "points nowhere"))
    rows = ('{"spec": {"rows": [{"path": "s/a", "number": 1, "writers": ["a"], "readers": []},'
            ' {"path": "s/b", "writers": "a", "readers": [], "every": 20.0}]}}')
    found = source_problems(rows, base % (", '/period_ms': '/every'", ""))
    expect("a type mismatch is named with its catalog member and its source",
           has(found, "/messages/1/publishers", "/spec/rows/1/writers", "wrong_type"))
    expect("a number that is not an unsigned integer is a type mismatch",
           has(found, "/messages/1/period_ms", "wrong_type", "20.0"))
    expect("a message missing a required field is named, with the source that is not there",
           has(found, "/messages/1", "required field `/id`", "`/number`"))
    expect("null is a value, and a mismatch",
           has(source_problems('{"spec": {"rows": [{"path": "s/a", "number": null, '
                               '"writers": ["a"], "readers": []}]}}'),
               "/messages/0/id", "wrong_type", "null"))
    expect("the catalog's own rules name the source of a refused value",
           has(source_problems('{"spec": {"rows": [{"path": "s/a", "number": 7, "writers": '
                               '["a"], "readers": []}, {"path": "s/b", "number": 7, '
                               '"writers": ["a"], "readers": []}]}}'),
               "duplicate_id at /messages/1/id", "copied from `/spec/rows/1/number`"))
    expect("a source that is not JSON is refused", has(source_problems("{"), "not JSON"))

    # A deployment's files stay outside the repository.
    expect("a mapping inside the repository is refused",
           has(problems_of(lambda: outside_repository(ROOT / "m.json5", "mapping")),
               "inside the wz repository"))

    # The generator.
    write_rows = ("import sys, pathlib; pathlib.Path(sys.argv[1]).write_text("
                  + repr(SOURCE) + ")")
    py = sys.executable
    expect("a generator's JSON is mapped",
           mc.read_json5(produce(mapping, run_generator([py, "-c", write_rows, OUT]), limits))
           .get("messages")[0].get("key_expr") == "sample/one")

    def failure(argv: list, timeout: float | None = None) -> str:
        try:
            run_generator(argv, timeout)
        except GeneratorFailed as err:
            return str(err)
        return ""

    noisy = ("import sys\nfor i in range(30): print(f'line {i}', file=sys.stderr)\n"
             "sys.exit(4)")
    said = failure([py, "-c", noisy, OUT])
    expect("a failure names the exit status and the last lines of standard error, verbatim",
           "exited with status 4" in said and said.endswith("\n".join(
               f"line {i}" for i in range(10, 30))) and "line 9\n" not in said)
    said = failure([py, "-c", "print('only out'); raise SystemExit(2)", OUT])
    expect("with standard error empty, standard output's last lines are named",
           "standard error is empty" in said and said.endswith("only out"))
    expect("a command with no {out} is refused", "names no `{out}`" in failure([py, "-c", ""]))
    expect("a program that does not exist is named",
           "no such program" in failure(["wz-no-such-generator-on-this-path", OUT]))
    expect("a generator that exits 0 and writes nothing is a failure",
           "wrote nothing" in failure([py, "-c", "print('done')", OUT]))
    expect("a generator outliving its timeout is a failure",
           "did not finish" in failure([py, "-c", "import time; time.sleep(5)", OUT], 0.5))
    expect("what a generator wrote that is not JSON is refused",
           has(source_problems(run_generator(
               [py, "-c", "import sys, pathlib; pathlib.Path(sys.argv[1]).write_text('[1,')",
                OUT])), "not JSON"))

    # The generator's config, and the command end to end.
    with tempfile.TemporaryDirectory(prefix="wz-catalog-map-selftest-") as scratch:
        where = pathlib.Path(scratch)
        (where / "rows.py").write_text(write_rows, encoding="utf-8")
        config = where / "generator.json5"
        config.write_text(json.dumps({"generator": [py, "rows.py", OUT], "cwd": "."}),
                          encoding="utf-8")
        argv_read, timeout_read, cwd_read = read_config(config)
        expect("a config states the arguments and a directory relative to itself",
               argv_read == [py, "rows.py", OUT] and timeout_read is None
               and cwd_read == where.resolve())
        line = where / "line.json5"
        line.write_text("{generator: 'tool --to {out} \"two words\"', timeout_s: 30}",
                        encoding="utf-8")
        expect("a config's command line is split as a shell splits it",
               read_config(line)[:2] == (["tool", "--to", OUT, "two words"], 30.0))
        bad = where / "bad.json5"
        bad.write_text("{generator: [], timeout_s: 0, shell: true}", encoding="utf-8")
        found = problems_of(lambda: read_config(bad))
        expect("a config's empty command, timeout of 0 and unknown member are each named",
               has(found, "`generator`") and has(found, "`timeout_s`")
               and has(found, "no member `shell`"))
        (where / "map.json5").write_text(mapping, encoding="utf-8")
        rc = main(["--mapping", str(where / "map.json5"), "--generator-config", str(config),
                   "--out", str(where / "catalog.json5")])
        expect("the command writes the catalog the generator's JSON maps to",
               rc == 0 and mc.read_json5((where / "catalog.json5").read_text(encoding="utf-8"))
               == catalog)
        (where / "fail.py").write_text("import sys; sys.exit('nothing to write')",
                                       encoding="utf-8")
        rc = main(["--mapping", str(where / "map.json5"), "--generator",
                   f"{shlex.quote(py)} {shlex.quote(str(where / 'fail.py'))} {OUT}"])
        expect("a generator that fails ends the command with its own status", rc == EXIT_GENERATOR)
        (where / "src.json").write_text('{"spec": {}}', encoding="utf-8")
        rc = main(["--mapping", str(where / "map.json5"), "--source", str(where / "src.json")])
        expect("a refused mapping ends the command with the refusal's status", rc == EXIT_REFUSED)

    print(f"message-catalog-map selftest: {'FAIL' if failures else 'OK'} "
          f"({len(failures)} failing)")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
