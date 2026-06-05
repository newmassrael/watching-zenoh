# SCE review request — can the registry/dispatch "glue" become a Forge codegen surface (one-source → C + Rust), or is it correctly a hand-written runtime support library?

**To**: SCE (Forge codegen architecture).
**From**: watching-zenoh.
**Kind**: architecture review request — not a bug report. No SCE defect is
claimed. wz seeks SCE's judgment on a codegen-scope question, because SCE
owns the Forge codegen *kinds* and the language-neutral IR contract.
**Vendor pin observed**: `vendor/sce` = `43eea2819` (wz).
**Project rule**: wz does not extend the Forge kind set or the neutral IR on
its own; that is an SCE spec decision (the 4 entity types / kinds are
closed-form per the Round 60 ratify lineage). This report frames the problem
and wz's tentative lean, and defers the call to SCE.

---

## 1. The question, crisply

watching-zenoh's runtime is split into:

- **Generated, one-source → 6 backends (incl. C11)**: codecs
  (`sce:kind="codec"`), event-schemas, pure algorithms
  (`sce:kind="algorithm"`), and statechart machines
  (`sce:kind` statechart — e.g. `sources/session/session_fsm_unicast.scxml`).
  SCE's C11 backend already supplies the C statechart engine
  (`state_machine.c.jinja2`), the C10-β cooperative scheduler (C11 emit), the
  Worker/Inbox `.c` emit, and the C codec runtime (`sce-forge-runtime/c`).

- **Hand-written Rust glue, NOT one-source**: the five session-core
  registries (subscriber / queryable / reply + the two declare registries),
  their iterate-and-dispatch, the request/response builders, and the
  orchestration `driver_loop`. These compile to Rust only (AP `tokio` / MCU
  `no_std`); there is no C projection.

The question for SCE: **is the registry/dispatch shape a codegen surface
Forge should own (a new kind, or an existing one we are missing), so it too
becomes one-source → C + Rust — or is the textbook answer that this shape is
correctly a hand-written *runtime support library* (per language), the way
`sce-forge-runtime/c` is for codecs?**

We want to avoid two failure modes:
1. Cramming a collection-traversal into a statechart (a category error — see
   §3), and
2. Hand-writing the registry twice (Rust today, C later) if Forge could/should
   generate it from one source.

---

## 2. The artifact under review — `SubscriberRegistry` (4 siblings identical in shape)

`crates/wz-session-core/src/pubsub.rs`:

```
:207  pattern: BoundedString<{ caps::MAX_KEYEXPR_BYTES }>,        // per-row key pattern
:231  pub struct SubscriberRegistry<C: SampleSink> {
:232      subscribers: BoundedVec<Subscriber<C>, { caps::MAX_SUBSCRIPTIONS }>,  // variable-membership table
:254      peer_keyexpr_table: HashMap<u64, String>,   // #[cfg(alloc)] AP-only
:276      own_zid: Option<Vec<u8>>,                    // #[cfg(alloc)] AP-only
      }
```

The runtime behaviour is: `register_sink(pattern, sink)` appends a row;
`dispatch_borrowed(&dyn SampleView)` **iterates the table, tests each row's
pattern against the inbound keyexpr, and fires `sink.deliver(...)` on each
match**. The other four registries (`query::QueryableRegistry`,
`reply::ReplyRegistry`, `declare::subscriber::RemoteSubscriberRegistry`,
`declare::liveliness_subscriber::LivelinessSubscriberRegistry`) are the same
shape with a different sink trait and (for reply) `rid` correlation instead of
keyexpr matching.

Two seams are already SCE-aligned:
- The **bounded backing** (`BoundedVec`/`BoundedString`) maps cleanly to the
  same fixed-capacity-collection idiom SCE's no_std statechart runtime uses
  (heapless ↔ C arrays).
- The **sink** is a DIP trait (`SampleSink` / `QuerySink` / `ReplySink` /
  `EventInjector`). The model-B work already removed `Box<dyn>` and made each
  registry generic-over-`C` (closed enum on MCU), which projects to a C
  function-pointer vtable or a generated closed-dispatch.

What is **not** statechart-shaped is the **collection + iteration** itself
(see §3).

---

## 3. wz's analysis — why the registry resists *statechart* expression (but not codegen in general)

A statechart is a **finite automaton**: the state space is fixed and known at
compile time. A registry's content — *which* subscribers are registered and
*how many* — is **runtime data of variable membership**. You cannot encode an
unbounded-at-author-time collection as compile-time states without abusing
counters + self-transitions to fake a `for` loop. That is a category error,
not an engineering hurdle.

So the registry is a **data-plane collection traversal**, whereas SCXML is a
**control-plane** language. The matching *predicate* is a pure function (and
SCE already proves that shape is one-source: `sources/algorithms/
keyexpr_{includes,intersect}.scxml` generate to all six backends). But the
**collection container + the iterate-and-dispatch** is a different shape than
any of the four Forge kinds.

**Correction we want on record** (it sharpens the question): the registries do
**not** currently consume the generated keyexpr algorithm. They use a
*separate hand-written Rust* matcher,
`wz-session-core/src/keyexpr_match.rs::keyexpr_pattern_matches` (migrated
verbatim from the old `pubsub.rs`, "mirroring zenoh-pico"). So today there are
**two** keyexpr matchers — the generated 6-backend spec algorithm
(`keyexpr_includes/intersect`) and the hand-written runtime matcher the
registry actually calls. Unifying those is a concrete sub-question below.

---

## 4. Candidate resolutions (wz's tentative lean — SCE decides)

**Option A — registry stays a hand-written runtime support library, per
language.** Forge owns the *predicate* (algorithm-kind) + the *codecs* +
the *statecharts*; the registry container + iterate-and-dispatch is a
hand-written support lib in each target language, exactly as
`sce-forge-runtime/c` hand-provides C collections/cursors for codecs. wz would
hand-write a C registry runtime parameterized by the generated codecs + a
closed sink-dispatch (function pointers). One source for the *spec*; per-language
hand-written *runtime support*.
*wz lean: this is the most likely textbook answer* — it mirrors how SCE
already draws the line for codecs (generated format + hand-written C runtime).

**Option B — a new Forge "table/registry" kind.** Forge grows a kind that,
from a declarative registry spec (row schema + match predicate reference +
sink-dispatch shape), emits the bounded container + iterate-and-dispatch in N
languages. This would make the registry genuinely one-source, but it expands
the closed-form kind set — an SCE spec decision, and possibly out of scope.

**Option C — express the registry as a Worker over an inbox of (register /
dispatch) events.** Reuse the existing Worker/Inbox kind (already C11-capable)
to model the registry as a cooperative task whose internal table is its
private data. Unclear whether the Worker model is meant to own variable
collections; needs SCE's read.

In all three, the **predicate** should be unified onto the generated
`keyexpr` algorithm (retire the hand-written `keyexpr_match.rs` mirror) so the
matcher is one-source even if the container is not.

---

## 5. Two adjacent boundaries we want SCE to confirm

**(a) The HAL / socket terminus.** The OS-facing glue —
`wz-runtime-core::{Runtime (async spawn), TimeSource (clock+sleep)}` +
`wz-runtime-lwip` (sockets) — is side-effecting, platform-specific I/O. wz's
position is that this is *correctly* not a codegen target and stays
hand-written per platform (as zenoh-pico's per-RTOS layer is), with SCE's
`<sce:extern>` / ITimer-style **HAL injection** as the seam. **Please confirm
this is SCE's intended boundary** (logic in the statechart, actuation injected),
so we don't chase a goal SCE considers out of scope by design.

**(b) keyexpr→event dispatch generation.** The switchboard generator
(`crates/wz-switchboard-codegen`) consumes forge-ast + codecs and emits a
keyexpr→typed-inject `dispatch_switchboard` — **but emits Rust only today**
(it just drove the ⓓ no-heap MCU inject proof). Is a C emission a wz concern,
or does SCE intend Forge-native generation of such keyexpr→event dispatch
(since it already consumes the forge-ast + codec IR)? This overlaps Option B.

---

## 6. Specific questions to SCE

1. Is "variable-membership bounded collection + iterate-and-dispatch" a shape
   Forge should own (Option B new kind), or is it out of scope of the
   closed-form kind set — i.e. is **Option A (hand-written per-language runtime
   support lib)** the intended textbook answer?
2. If Option A: does SCE have a recommended pattern/precedent for a C runtime
   support library that consumes generated codecs + a closed (function-pointer)
   sink-dispatch — analogous to `sce-forge-runtime/c` for codecs?
3. Is the Worker/Inbox kind (Option C) meant to own a private variable
   collection, or strictly a bounded message queue? (i.e. is modelling a
   registry as a Worker an intended use or an abuse?)
4. The sink / `EventInjector` DIP seam → C: does SCE emit (or intend to emit) a
   C-side equivalent of the generated `<Machine>Inject` trait (the Rust
   typed-inject seam), or is the C function-pointer vtable the wz side's job?
5. Confirm §5(a): is `<sce:extern>` / HAL injection the intended terminus for
   OS I/O (sockets/timers), i.e. that part of the glue is by-design
   per-platform hand-written and NOT a one-source target?
6. §5(b): keyexpr→event dispatch C emission — wz concern, or Forge-native?

---

## 7. What wz will not do pending SCE's read

- Will not add a Forge kind or extend the neutral IR (SCE spec decision).
- Will not hand-write a C registry runtime until SCE confirms Option A vs B/C
  (to avoid building the wrong thing, then throwing it away).
- Will not push registry collection logic into a statechart (we believe it is a
  category error; §3) without SCE overriding that judgment.

The immediate, SCE-independent cleanup we *can* do regardless of the above is
unifying the runtime matcher onto the generated keyexpr algorithm (retire the
`keyexpr_match.rs` hand-written mirror); we flag it here only because it is the
first concrete step toward whichever option SCE picks.
