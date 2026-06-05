# SCE codegen gap — `--no-std` Policy struct still emits alloc `String` fields

**Status**: blocks watching-zenoh Track-2 carry ⓓ (run a generated SCE
statechart + `Engine` value-inject on the no-global-allocator MCU probe).
**Vendor pin observed**: `vendor/sce` = `d665780d9` (wz), SCE HEAD
`ae19d9434`.
**Project rule**: wz does not edit SCE. This report is the hand-off
artifact; SCE-side fix + push, then wz bumps the pin only
(precedent: R311gu, R311gw).

## What ⓓ needs

The `mcu-noheap-probe` (`deploy/mcu-noheap-probe`) is a Cortex-M binary
with **no `#[global_allocator]`** — any reachable reference to the
`alloc` crate is a hard link error, which is precisely what makes it a
whole-program no-heap proof. ⓓ would add a stage that drives the
generated switchboard `dispatch_switchboard(keyexpr, payload, &mut
Engine<P>)`: foreign wire bytes → primitive-only codec decode →
typed `_event.data` inject → native guard fires → state transition, all
with zero global allocator. This is the first place a generated SCE
*application statechart* + `Engine<P>` would be compiled and run on a
no-allocator target (mcu-qemu-demo links `embedded-alloc`; the probe
deliberately does not).

`sce-rust-runtime` already ships the enabling half: the `no_std` feature
(`#![no_std]` + `heapless`, "zero alloc dependency", `SceString =
heapless::String<N>`). So `Engine<P>` itself is allocator-free in no_std.

## The gap

`sce-codegen generate -l rust --no-std` emits a `{{Machine}}Policy`
struct that **unconditionally** carries three `alloc`-coupled `String`
fields, even in no_std mode:

`tools/codegen/templates/rust/state_machine.rs.jinja2`:

- line 228 — `pub session_id: Option<String>,`  *(outside any no_std gate)*
- line 256 — `{% if not no_std %}` … gates ONLY `parent_external_queue`
  … `{% endif %}` at line 263
- line 265 — `pub invoke_id: String,`        *(outside the gate)*
- line 267 — `pub child_session_id: String,` *(outside the gate)*

`parent_external_queue` was correctly given the `{% if not no_std %}`
treatment (the comment notes `<invoke>` is codegen-rejected under no_std,
so the `Arc<Mutex<Vec<…>>>` is omitted). The three sibling fields above
were not — they remain bare `String`.

These are `alloc::string::String`, **not** `SceString`/heapless, and the
generated file does not `use alloc::string::String` nor does
`sce-rust-runtime` re-export `String`. In SCE's own `sce-rust-tests`
the files compile because that crate is `std` (its prelude supplies
`String`), which masks the gap — there is no no_std/thumb build of a
generated machine in the SCE test tree to catch it.

## Empirical repro

```
sce-codegen --workspace-root <sce> generate -l rust --no-std \
  --output-dir <out> \
  sce-build/tests/fixtures/event_schema/statechart_minimal.scxml
```

Generated `statechart_minimal_sm.rs` (pin d665780d9):

- line 23  — `#![no_std]`                         *(no_std emission IS active)*
- line 86  — `use core::time::Duration;`
- line 156 — `pub session_id: Option<String>,`
- line 158 — `pub invoke_id: String,`
- line 160 — `pub child_session_id: String,`
- only `use` lines: `core::time::Duration` + `sce_rust_runtime::{Engine, StatePolicy}`
  (no `String` import, no `extern crate alloc`)
- `parent_external_queue` / `Arc` / `Mutex` correctly **absent**

So with `no_std=true` the header + `StateChain` alias + parent-queue
elision all fire, but the session/invoke `String` fields are left
alloc-coupled. The `--no-std` `--help` text ("today still generates
std-flavored code; flag's role is validation + future-intent") is now
stale for the header/heapless parts but accurate that emission is
incomplete here.

## Consequence

A no_std + no-allocator crate that instantiates `{{Machine}}Policy`
cannot link: `String` requires the `alloc` allocator symbols
(`__rust_alloc`/`__rust_dealloc`, referenced via `Drop for String`),
which the probe has no allocator to satisfy. Adding `embedded-alloc`
would link but defeats the whole purpose of the no-heap proof. So ⓓ is
blocked until the emission is allocator-free.

## Suggested SCE fix (SCE owns the decision)

Mirror the `parent_external_queue` pattern for the three remaining
fields. Either:

1. **Gate under `{% if not no_std %}`** — `invoke_id` /
   `child_session_id` are `<invoke>`/child-session machinery, dead under
   no_std (where `<invoke>` is codegen-rejected). `session_id` is
   "script engine + invoke tracking"; under no_std (no script engine, no
   invoke) it is likewise unused. Gating all three out is the minimal,
   precedented change.
2. **Or type them as `SceString`** (the heapless alias) if any are
   needed under no_std — keeps them allocator-free.

Option 1 is preferred unless a no_std consumer genuinely reads
`session_id` (none in the value-inject path does).

Also worth a no_std build smoke in `sce-rust-tests` (a single generated
fixture compiled for a thumb target with `--features no_std`) so this
class of gap is caught in SCE CI rather than downstream.

## wz-side status

Stopped per stop-first rule. No wz workaround, no SCE edit. Track-2
carry ⓔ (gc-3 switchboard generator) was found already complete and
pushed; ⓓ is the remaining convergence item and is parked on this fix.
