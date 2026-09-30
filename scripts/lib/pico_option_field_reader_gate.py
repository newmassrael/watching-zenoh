#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
"""R2990 (no register item) -- a field of a pico options struct must be READ by
something, or be listed here with the reason nothing reads it.

## The defect this closes, and why it is a class

`wz-capi-pico` mirrors zenoh-pico's `*_options_t` structs field for field so a
C program can stack-allocate one, fill it and pass it. Mirroring the LAYOUT is
a different act from reading the FIELDS, and nothing ties them: a struct can be
declared, sized, offset-pinned, defaulted and exported while the function that
takes it never looks at a field. The program links, runs and delivers, and what
it asked for is not what happens. This crate has paid for that at least five
times, each time found by reading one struct:

  * `z_put_options_t` took a `void *` and ignored every field (R311y559);
  * `z_get_options_t`'s QoS trio was carried and dropped (R311y551);
  * the reply options' encoding, timestamp and source info (R311y562);
  * `z_declare_publisher`'s options, five fields, with the advanced publisher's
    embedded copy of them (R2990);
  * and, found in R2990 by the audit this gate makes permanent, a querier's
    encoding, a detection key's metadata and a reply's express flag.

Each of those was a SENTENCE in a reason ("options are ignored", "a named gap")
that was true when written and was not struck when the round that fixed it
landed, and each was found by a person reading a struct. A class that leaks
more than twice gets a gate.

## What it measures

POPULATION, derived from the source and never listed: every `pub struct
<name>_options_t` under `crates/wz-capi-pico/src`, and each named field of it.
A field is READ when some function that takes that struct -- or a struct that
EMBEDS it, which is how `ze_advanced_publisher_options_t` carries a
`z_publisher_options_t` -- reads it as `.field` in its body, a function named
`*_default` (which only writes) not counting, and an assignment not counting.

An UNREAD field must be in `UNREAD_WITH_REASON`, each with the reason nothing
reads it. The table is checked in BOTH directions: an unread field that is not
listed fails, and a listed field that has become read fails too, so the reason
cannot outlive the gap it explained.

## What it does NOT measure, stated rather than implied

It finds fields NO function reads. It cannot say a read is the RIGHT read: a
function that reads `.encoding` of a different struct than the one it takes
would satisfy it, and a field read and then dropped would too. That half is the
wire legs' and the round trips'. It is also text-based: a read through a
destructuring pattern (`Struct { field, .. } = *options`) is invisible to it.
A real read it misses shows up as a FALSE unread, which fails loudly, and the
fix is to write the read as a field access. The blind spot that matters runs
the other way (a wrong read passes), and it is the first one.

## Population zero is a FAIL

Below `MIN_STRUCTS` structs or `MIN_FUNCTIONS` parsed functions the gate fails
rather than report green over a source it could not read; the number it prints
is the signal, not the exit status. `--selftest` drives the analysis over
fixtures, each axis on its own.

## Exit codes

  0  every options field is read or listed
  1  a field is unread and unlisted, or a listed field is read or absent
  2  the source could not be read, or the population is below its floor
"""
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
SRC_DIR = os.path.join(ROOT, "crates", "wz-capi-pico", "src")

# The floors. A parse that finds fewer has stopped reading the crate.
MIN_STRUCTS = 25
MIN_FUNCTIONS = 400

# Every unread field and WHY nothing reads it. Checked both ways.
UNREAD_WITH_REASON = {
    "z_open_options_t.auto_start_read_task": (
        "THE LIVE RESIDUAL of api-compat-pico: pico starts its executor in z_open only "
        "if this is set, and wz ignores it. Remove this line when the read task is built."
    ),
    "z_open_options_t.auto_start_lease_task": (
        "pico's z_open never reads it either (api.c z_open reads only auto_start_read_task "
        "and auto_start_admin_space); its DEFAULT is compared by the options-default leg"
    ),
    "z_open_options_t.executor_task_attributes": (
        "thread attributes of pico's executor thread; wz's drive thread takes none"
    ),
    "zp_task_read_options_t.task_attributes": (
        "thread attributes of pico's read task; wz has no such thread to apply them to"
    ),
    "zp_task_lease_options_t.task_attributes": (
        "thread attributes of pico's lease task, itself a no-op in pico 1.10.1"
    ),
    "z_query_reply_options_t.congestion_control": (
        "documented ignored by pico itself: a reply's congestion control is the query's"
    ),
    "z_query_reply_options_t.priority": (
        "documented ignored by pico itself: a reply's priority is the query's"
    ),
    "z_query_reply_del_options_t.congestion_control": (
        "documented ignored by pico itself: a reply's congestion control is the query's"
    ),
    "z_query_reply_del_options_t.priority": (
        "documented ignored by pico itself: a reply's priority is the query's"
    ),
    "ze_advanced_publisher_delete_options_t.timestamp": (
        "pico overwrites it with the publisher's own sequencing before it sends "
        "(ze_advanced_publisher_delete sets opt.delete_options.timestamp)"
    ),
    "ze_advanced_publisher_delete_options_t.source_info": (
        "pico overwrites it with the publisher's own sequencing before it sends "
        "(ze_advanced_publisher_delete sets opt.delete_options.source_info)"
    ),
    "ze_advanced_subscriber_options_t.subscriber_options": (
        "z_subscriber_options_t is a one-byte dummy in this configuration "
        "(Z_FEATURE_LOCAL_SUBSCRIBER is 0), so there is nothing in it to read"
    ),
}


def strip_code(text):
    """`text` with comments removed and string and char literals blanked, so a
    field name in a comment or a message is not read as code."""
    out = []
    i, n = 0, len(text)
    while i < n:
        c = text[i]
        two = text[i:i + 2]
        if two == "//":
            while i < n and text[i] != "\n":
                i += 1
        elif two == "/*":
            depth = 1
            i += 2
            while i < n and depth:
                if text[i:i + 2] == "/*":
                    depth += 1
                    i += 2
                elif text[i:i + 2] == "*/":
                    depth -= 1
                    i += 2
                else:
                    i += 1
        elif (
            c == "r"
            and re.match(r'r#*"', text[i:i + 8])
            and (i == 0 or not (text[i - 1].isalnum() or text[i - 1] == "_"))
        ):
            m = re.match(r'r(#*)"', text[i:])
            closer = '"' + m.group(1)
            j = text.find(closer, i + len(m.group(0)))
            i = n if j < 0 else j + len(closer)
            out.append('""')
        elif c == '"':
            i += 1
            while i < n and text[i] != '"':
                i += 2 if text[i] == "\\" else 1
            i += 1
            out.append('""')
        elif c == "'":
            m = re.match(r"'(?:\\.[^']*|[^'\\])'", text[i:])
            if m:
                out.append("' '")
                i += len(m.group(0))
            else:
                out.append(c)
                i += 1
        else:
            out.append(c)
            i += 1
    return "".join(out)


def balanced(text, start, open_ch, close_ch):
    """Index just past the `close_ch` matching the `open_ch` at `start`."""
    depth = 0
    i = start
    while i < len(text):
        if text[i] == open_ch:
            depth += 1
        elif text[i] == close_ch:
            depth -= 1
            if depth == 0:
                return i + 1
        i += 1
    return len(text)


STRUCT_RE = re.compile(r"\bpub\s+struct\s+(\w+_options_t)\s*\{")
FN_RE = re.compile(r"\bfn\s+(\w+)\s*")


def parse_structs(code):
    """`{struct: [(field, type text)]}` for every `pub struct *_options_t`."""
    structs = {}
    for m in STRUCT_RE.finditer(code):
        body_end = balanced(code, m.end() - 1, "{", "}")
        body = code[m.end():body_end - 1]
        depth = 0
        start = 0
        pieces = []
        for i, ch in enumerate(body):
            if ch in "<([{":
                depth += 1
            elif ch == ">" and i > 0 and body[i - 1] == "-":
                continue  # the arrow of a fn-pointer type closes nothing
            elif ch in ">)]}":
                depth -= 1
            elif ch == "," and depth == 0:
                pieces.append(body[start:i])
                start = i + 1
        pieces.append(body[start:])
        fields = []
        for piece in pieces:
            fm = re.match(r"\s*(?:pub(?:\([^)]*\))?\s+)?(\w+)\s*:\s*(.+)", piece, re.S)
            if fm:
                fields.append((fm.group(1), fm.group(2)))
        structs[m.group(1)] = fields
    return structs


def parse_functions(code):
    """`[(name, params text, body text)]` for every `fn` with a body."""
    fns = []
    for m in FN_RE.finditer(code):
        i = m.end()
        if i < len(code) and code[i] == "<":
            i = balanced(code, i, "<", ">")
            while i < len(code) and code[i].isspace():
                i += 1
        if i >= len(code) or code[i] != "(":
            continue
        params_end = balanced(code, i, "(", ")")
        params = code[i + 1:params_end - 1]
        j = params_end
        while j < len(code) and code[j] not in "{;":
            j += 1
        if j >= len(code) or code[j] != "{":
            continue
        body_end = balanced(code, j, "{", "}")
        fns.append((m.group(1), params, code[j + 1:body_end - 1]))
    return fns


def analyse(sources):
    """(structs, functions, unread) over `{path: source text}`.

    `unread` is the set of `struct.field` that no function taking the struct, or
    one embedding it, reads.
    """
    code = "\n".join(strip_code(t) for t in sources.values())
    structs = parse_structs(code)
    fns = parse_functions(code)
    embeds = {}
    for name, fields in structs.items():
        inner = set()
        for _, ty in fields:
            for ident in re.findall(r"\w+", ty):
                if ident in structs and ident != name:
                    inner.add(ident)
        embeds[name] = inner

    def holders(name):
        out = {name}
        changed = True
        while changed:
            changed = False
            for outer, inner in embeds.items():
                if outer not in out and inner & out:
                    out.add(outer)
                    changed = True
        return out

    read = set()
    for name, fields in structs.items():
        held = holders(name)
        pat = re.compile(r"\b(?:" + "|".join(map(re.escape, sorted(held))) + r")\b")
        for fname, params, body in fns:
            if fname.endswith("_default") or not pat.search(params):
                continue
            for fld, _ in fields:
                if re.search(r"\." + re.escape(fld) + r"\b(?!\s*=[^=])", body):
                    read.add(f"{name}.{fld}")
    unread = set()
    for name, fields in structs.items():
        for fld, _ in fields:
            if fld.startswith("_"):
                continue
            if f"{name}.{fld}" not in read:
                unread.add(f"{name}.{fld}")
    return structs, fns, unread


def judge(structs, unread, exceptions):
    """Findings as a list of strings; empty means the tree is answered."""
    findings = []
    all_fields = {f"{n}.{f}" for n, fs in structs.items() for f, _ in fs}
    for field in sorted(unread - set(exceptions)):
        findings.append(f"unread and unlisted: {field}")
    for field in sorted(set(exceptions) - unread):
        if field in all_fields:
            findings.append(f"listed but now READ (strike the reason): {field}")
        else:
            findings.append(f"listed but no such field: {field}")
    return findings


def read_sources():
    if not os.path.isdir(SRC_DIR):
        print(f"pico-option-field-readers: INPUT ERROR: {SRC_DIR} is not a directory", file=sys.stderr)
        sys.exit(2)
    sources = {}
    for name in sorted(os.listdir(SRC_DIR)):
        if name.endswith(".rs"):
            with open(os.path.join(SRC_DIR, name), encoding="utf-8") as fh:
                sources[name] = fh.read()
    return sources


def check():
    structs, fns, unread = analyse(read_sources())
    total = sum(len(fs) for fs in structs.values())
    print(
        f"pico-option-field-readers: {len(structs)} options struct(s), {total} field(s), "
        f"{len(fns)} function(s) parsed, {len(unread)} unread, {len(UNREAD_WITH_REASON)} listed"
    )
    if len(structs) < MIN_STRUCTS or len(fns) < MIN_FUNCTIONS:
        print(
            f"pico-option-field-readers: INPUT ERROR: {len(structs)} struct(s) (floor {MIN_STRUCTS}) "
            f"and {len(fns)} function(s) (floor {MIN_FUNCTIONS}); the parse has stopped reading the "
            "crate, so this gate measured nothing",
            file=sys.stderr,
        )
        return 2
    findings = judge(structs, unread, UNREAD_WITH_REASON)
    for f in findings:
        print(f"  FAIL {f}")
    if findings:
        print(
            "pico-option-field-readers: FAIL -- a field of a pico options struct that no function "
            "reads is a program's request that does nothing. Read it, or list it in "
            "UNREAD_WITH_REASON with the reason (pico ignores it too, pico overwrites it, ...)."
        )
        return 1
    print("pico-option-field-readers: OK -- every options field is read or carries its reason")
    return 0


def selftest():
    base = """
        pub struct a_options_t { pub x: i32, pub y: i32, pub _pad: u8 }
        pub unsafe extern "C" fn take_a(o: *const a_options_t) -> i32 { (*o).x }
        pub unsafe extern "C" fn a_options_default(o: *mut a_options_t) { (*o).y = 0; (*o).x = 0; }
    """
    _, _, unread = analyse({"a.rs": base})
    assert unread == {"a_options_t.y"}, f"a write in a default and in an assignment is not a read: {unread}"

    commented = base.replace("(*o).x }", "(*o).x /* .y */ } // .y")
    _, _, unread = analyse({"a.rs": commented})
    assert unread == {"a_options_t.y"}, f"a field in a comment is not a read: {unread}"

    in_string = base.replace("(*o).x }", '(*o).x + "a.y".len() as i32 }')
    _, _, unread = analyse({"a.rs": in_string})
    assert unread == {"a_options_t.y"}, f"a field in a string is not a read: {unread}"

    read_y = base.replace("(*o).x }", "(*o).x + (*o).y }")
    _, _, unread = analyse({"a.rs": read_y})
    assert unread == set(), f"a read of y must clear it: {unread}"

    embedded = base + """
        pub struct b_options_t { pub inner: a_options_t, pub z: bool }
        pub unsafe extern "C" fn take_b(o: *const b_options_t) -> i32 { let i = &(*o).inner; i.y + (*o).z as i32 }
    """
    _, _, unread = analyse({"a.rs": embedded})
    assert unread == set(), f"a read through the struct that EMBEDS it counts: {unread}"

    only_b = """
        pub struct a_options_t { pub x: i32 }
        pub struct b_options_t { pub inner: a_options_t, pub z: bool }
        pub unsafe extern "C" fn take_b(o: *const b_options_t) -> bool { (*o).z }
    """
    _, _, unread = analyse({"a.rs": only_b})
    assert unread == {"a_options_t.x", "b_options_t.inner"}, f"embedding is not reading: {unread}"

    other_fn = base + "pub fn unrelated(v: i32) -> i32 { v.y }"
    _, _, unread = analyse({"a.rs": other_fn})
    assert unread == {"a_options_t.y"}, f"a function that does not take the struct reads nothing of it: {unread}"

    fn_pointer_param = """
        pub struct c_options_t { pub cb: Option<unsafe extern "C" fn(i32) -> i32>, pub n: u8 }
        pub unsafe extern "C" fn take_c(o: *const c_options_t) -> u8 { (*o).n }
    """
    structs, _, unread = analyse({"c.rs": fn_pointer_param})
    assert [f for f, _ in structs["c_options_t"]] == ["cb", "n"], "a fn-pointer type holds commas and parens"
    assert unread == {"c_options_t.cb"}, unread

    # The judge, in both directions and on an unlisted field.
    structs, _, unread = analyse({"a.rs": base})
    assert judge(structs, unread, {}) == ["unread and unlisted: a_options_t.y"]
    assert judge(structs, unread, {"a_options_t.y": "r"}) == []
    assert judge(structs, unread, {"a_options_t.y": "r", "a_options_t.x": "r"}) == [
        "listed but now READ (strike the reason): a_options_t.x"
    ]
    assert judge(structs, unread, {"a_options_t.y": "r", "a_options_t.q": "r"}) == [
        "listed but no such field: a_options_t.q"
    ]

    # Zero population is not green: the floor is what the real check tests.
    structs, fns, _ = analyse({"empty.rs": "pub fn f() {}"})
    assert structs == {} and len(structs) < MIN_STRUCTS and len(fns) < MIN_FUNCTIONS

    # The real tree clears its floors.
    real_structs, real_fns, _ = analyse(read_sources())
    assert len(real_structs) >= MIN_STRUCTS, len(real_structs)
    assert len(real_fns) >= MIN_FUNCTIONS, len(real_fns)
    print("pico-option-field-readers: selftest OK")
    return 0


def main(argv):
    if len(argv) != 2 or argv[1] not in ("--check", "--selftest"):
        print("usage: pico_option_field_reader_gate.py --check | --selftest", file=sys.stderr)
        return 2
    return check() if argv[1] == "--check" else selftest()


if __name__ == "__main__":
    sys.exit(main(sys.argv))
