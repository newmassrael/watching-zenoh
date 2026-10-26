#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

"""R3685 (no register item) -- what the generators know of a key expression, split out of
`wz_key_set.py` so that `wz_node.py` can use it without importing the generator that imports it.

Three questions, each a port of what the receive path runs, none to be trusted alone:

* `key_problem(key, limit)`: why a text is not a key a node can declare (the node declaration's own
  rule: empty, too long, an empty chunk, a character a key expression does not have);
* `is_key_expression(text)`: whether it is a CANONICAL key expression, a port of
  `keyexpr_canon::validate_keyexpr`;
* `intersects(candidate, target)`: whether two key expressions share a key, a port of
  `keyexpr_match::keyexpr_intersects_text` with every wildcard on.

The last two are held to the real ones by the corpus `wz_key_set.py --write` generates and
`crates/wz-session-core/tests/key_catalogue_model.rs` compares (see `wz_key_set.py`).
"""

from __future__ import annotations

import functools
import re

# The text of a zid as zenoh prints it and as `credential_identity::zid_from_key_text` reads it (the
# one place its refusals are written): lowercase hex, no leading zero, at most 32 digits, the value
# of a `u128` whose little-endian bytes are the zid's sixteen.
ZID_RE = re.compile(r"[1-9a-f][0-9a-f]{0,31}")


def zid_bytes(text: str) -> list[int]:
    """The sixteen bytes of a zid's text, the little-endian bytes of its `u128`: the form a node's
    `PEER_NODES` holds and a peer's zid is looked up by."""
    return list(int(text, 16).to_bytes(16, "little"))


def rust_string(text: str) -> str:
    return '"' + text.replace("\\", "\\\\").replace('"', '\\"') + '"'


def key_problem(key: str, limit: int) -> str | None:
    """Why `key` is not a key expression a node can declare, or None."""
    if not key:
        return "is empty"
    if len(key.encode("utf-8")) > limit:
        return f"is longer than MAX_KEYEXPR_BYTES ({limit})"
    if key.startswith("/") or key.endswith("/") or "//" in key:
        return "has an empty chunk"
    if any(c in key for c in "?#") or any(ord(c) < 0x21 or ord(c) == 0x7F for c in key):
        return "has a character a key expression does not (`?`, `#`, a space or a control)"
    return None


def is_key_expression(text: str) -> bool:
    """`keyexpr_canon::validate_keyexpr`, as a verdict: whether `text` is a key expression, which means
    a CANONICAL one (`a/**/*` is not: it is spelled `a/*/**`). The arms are the validator's, in its
    order, over the bytes. A key the table stores is a pattern the subscriber table registers, and the
    table registers it in canonical form, so a declared key that is not canonical would never be the
    text the table holds."""
    data = text.encode("utf-8")
    size = len(data)

    def at(position: int) -> int | None:
        return data[position] if position < size else None

    slash, star, dollar = 0x2F, 0x2A, 0x24
    chunk_start = 0
    i = 0
    while i < size:
        byte = data[i]
        if byte == slash:
            if i == chunk_start:
                return False
            i += 1
            chunk_start = i
        elif byte == star:
            if i != chunk_start:
                return False
            following = at(i + 1)
            if following is None:
                break
            if following == slash:
                i += 2
                chunk_start = i
            elif following == star:
                after = at(i + 2)
                if after is None:
                    break
                if after == slash and at(i + 3) == star:
                    return False
                if after != slash:
                    return False
                i += 3
                chunk_start = i
            else:
                return False
        elif byte == dollar:
            if at(i + 1) != star:
                return False
            after = at(i + 2)
            if after == dollar:
                return False
            if (after == slash or after is None) and i == chunk_start:
                return False
            if after is None:
                break
            i += 2
        elif byte in (0x23, 0x3F):  # `#` and `?`
            return False
        else:
            i += 1
    return chunk_start != size


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
