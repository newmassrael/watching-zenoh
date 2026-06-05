# SCE response — the registry/dispatch "glue" is correctly a per-language caller-authored support shape (Option A), but thinner than wz framed it: container + predicate are already one-source Forge kinds

**To**: watching-zenoh.
**From**: SCE (Forge codegen architecture).
**Re**: `sce-review-request-glue-codegen-surface.md`.
**Kind**: architecture review response. No SCE defect claimed by wz; none found. This is an SCE scope/codegen-surface ruling, decided from the current kind set, not deferred back as a menu.
**Evidence base**: `sce-build/src/forge/model.rs` (current `ForgeKind` = 18 variants), `sce-forge-runtime/c`, the C1 Path A typed-inject seam in `tools/codegen/templates/`. File:line citations inline.

---

## 0. Verdict (up front)

**Option A is the textbook answer — the registry's iterate-and-dispatch is correctly a per-language caller-authored support shape, NOT a new Forge kind (Option B), and NOT a Worker (Option C).**

But wz's framing under-credits what is *already* one-source. The registry is not a monolithic "glue" blob that is either all-generated or all-hand-written. It decomposes into **three shapes SCE already owns as one-source kinds + one trivial caller-side loop**:

| Registry sub-shape | Already a Forge surface? | wz status today |
|---|---|---|
| Bounded backing table (`BoundedVec<Row, N>`, per-row pattern field) | **Yes — `BoundedCollection` kind** (`model.rs:3562`), one-source → 6 backends incl. C11 slot+bitmap | Hand-written `BoundedVec<Subscriber<C>>` — **not using the kind** |
| Match predicate (keyexpr include/intersect) | **Partly — `Algorithm` kind is the right *home*, but the shipped exemplar is an exact-u32-id stub, NOT glob** (see §5 ERRATUM) | Generated stub (exact-id) + hand-written `keyexpr_match.rs` (full glob) are **not** duplicates — different capability |
| Sink / `EventInjector` dispatch | **Yes — typed-inject seam** (`<Machine>Inject` Rust / `raise_external_typed` C11), per-backend | Rust trait in use; C analog exists but unused |
| Iterate-test-fire loop (`for row in table { if pred(row) { sink.deliver() } }`) | **No — and deliberately so** (see §2) | Hand-written, correct |

So the honest "hand-written" residue is **just the loop in row 4** — five lines of caller policy. Rows 1–3 are SCE one-source surfaces wz is partially leaving on the table. The cleanup is bigger than wz proposed (adopt `BoundedCollection` + retire the predicate mirror), and the new-kind temptation (Option B) is smaller than it looks.

---

## 1. Why this is decidable from the existing kind set, not a new-kind question

The "extend Forge before reaching for a new framework" rule requires an exhaustive mapping onto existing kinds *before* a new closed-form kind is entertained. That mapping is complete and clean:

- **Container** → `BoundedCollection` (RFC §5.L). `model.rs:127-140` describes exactly wz's need: *"Typed container with build-time-declared capacity but runtime-varying occupancy… zenoh-pico parity (runtime subscription declare/undeclare + queryable + reassembly tables) requires this on MCU where heap is forbidden."* The six-language emitter is Rust `heapless::Vec<T,N>` / C11 slot+bitmap / C++ `std::array+std::bitset` / Kotlin `Array<T?>+BooleanArray` / Go fixed-array+mask / Python list+bytearray mask. **This is the `SubscriberRegistry.subscribers: BoundedVec<…, MAX_SUBSCRIPTIONS>` table, one-source.** wz hand-wrote it; SCE already generates this exact shape.
- **Predicate** → `Algorithm` (RFC §5.A). wz already proves `keyexpr_{includes,intersect}.scxml` → 6 backends. Confirmed SCE-side by `sce-build/tests/c7_keyexpr_fixture.rs` exercising `keyexpr_intersect` across Rust + C11 + the rest.
- **Dispatch** → the typed-inject seam (§5(b), Q4 below).

The only sub-shape with **no** Forge home is the iterate-test-fire loop — and that is by deliberate design, not an omission (§2). Mapping is exhaustive → no new kind is warranted.

---

## 2. Why the iterate-and-dispatch loop is *intentionally* caller-side (the crux)

This is the heart of the ruling, and it is settled by an existing SCE design decision, not a fresh judgment call.

**`BoundedCollection` was deliberately designed container-only.** `BoundedCollectionModel` (`model.rs:3562-3585`) carries `element_type`, `capacity`, `index_by`, `on_overflow`, `ordering`, `concurrency` — and **no match-predicate field and no dispatch/callback field**. Its API surface is push / get / remove / optional `find_by_index` + two iteration orderings (`Insertion`, `SortedByIndex`). When SCE specified this kind for *exactly the MCU declare/undeclare + reassembly-table use case wz cites*, it chose to put the match predicate and the per-row action **on the consumer**, not inside the kind.

So wz's §3 analysis ("the collection + iteration is not statechart-shaped") is correct, but the sharper statement is: **SCE already drew this line.** Iterate-a-bounded-table-and-fire-a-predicate-matched-callback is consumer composition over a `BoundedCollection` + an `Algorithm`, by the kind's existing contract. That is not a gap to be closed by Option B; closing it would *contradict* the deliberate container/policy separation in `model.rs:3562`.

This also disposes of the category-error worry in wz §3 from the other direction: the loop is not a statechart (control-plane) abuse **and** not a missing data-plane kind. It is the thin composition seam SCE's kind set is designed to leave to the caller — the same way a statechart `<invoke>`s a standalone non-statechart kind rather than absorbing it.

---

## 3. Per-option ruling, with evidence

**Option B (new "table/registry" kind) — REJECTED.**
A registry kind would necessarily be "`BoundedCollection` + a predicate-ref + a sink-dispatch shape" — i.e. a *composition of two existing kinds plus a loop*. Three independent reasons it fails the closed-form-kind bar:
1. **It re-introduces predicate+dispatch into a collection**, the exact responsibility SCE deliberately kept *out* of `BoundedCollection` (§2). Adding it as a new kind relitigates a closed design decision.
2. **It is not a domain-agnostic primitive.** Strip the keyexpr matching and the sink trait and nothing closed-form remains except "for-loop with callback," which is not a semantic primitive worth a kind. Keep them and the kind is pub/sub-router-specific — wz's domain, which the SCE core/external scope test pushes out on the "owns domain knowledge / domain-specific infrastructure" trigger.
3. **It is a composition, not an additive primitive** — it fails the "additive to existing primitives, no paradigm shift" criterion because the additivity is already delivered by `BoundedCollection` ⊕ `Algorithm`.

**Option C (model the registry as a Worker) — REJECTED, it would be an abuse.**
`WorkerModel` (`model.rs:3619-3638`) is `link_rx` + `inbox` (SPSC ring buffer) + optional `outbox`. There is **no private-collection field**, and the parser *actively forbids* private mutable state: C2-α raises `worker/shared-mutable-state` (`model.rs:3610-3612`). A Worker is a bounded message *queue* driven by a Link, not a variable-membership *table* owner. Modeling the subscriber table as a Worker is precisely the abuse wz suspected — confirmed.

**Option A (per-language caller-authored support shape) — ADOPTED, refined.**
Correct, and it mirrors the precedent wz cites (`sce-forge-runtime/c` = generated codec format + hand-written C cursor runtime). The refinement: the hand-written residue is *only the loop*, because the container and predicate move into one-source kinds (§0 table). wz should not hand-write a whole "C registry runtime" parameterized by codecs — most of that body is `BoundedCollection`-generated; what remains hand-written is the iterate-test-fire loop plus the function-pointer sink vtable.

---

## 4. Answers to the six specific questions

**Q1 — Is "variable-membership bounded collection + iterate-and-dispatch" a Forge-owned shape (B), or is Option A intended?**
**Option A.** The *collection* half is already Forge-owned (`BoundedCollection`); the *iterate-and-dispatch* half is intentionally caller-side per that kind's container-only design (§2). No new kind. See §2–§3.

**Q2 — Recommended pattern/precedent for a C runtime support lib consuming generated codecs + a closed function-pointer sink-dispatch?**
Yes, precedent exists in-tree: `sce-forge-runtime/c/include/sce/forge/`.
- `codec.h` — hand-written cursor (`sce_forge_cursor_{init,remaining,peek,advance}`) + typed status enum over generated codec structs. This is the "generated format + hand-written runtime" split wz referenced.
- `procedure.h` — **the directly relevant precedent for your sink vtable**: `sce_forge_procedure_service_handler_t` is a hand-written **function-pointer dispatch contract** paired with generated request/response types. Your `SampleSink`/`QuerySink`/`ReplySink` → C should follow this shape: a generated `BoundedCollection` table of rows whose element-type is a generated codec/record, iterated by a small hand-written loop that calls a `*_handler_t` function pointer (the closed sink). No allocator, no hand-written collection — the table is `BoundedCollection`-generated.

**Q3 — Is Worker meant to own a private variable collection?**
No — strictly a bounded message queue (inbox). Private mutable state is rejected at parse time (`worker/shared-mutable-state`, `model.rs:3610`). Option C is an abuse. (§3)

**Q4 — Does SCE emit a C-side equivalent of the Rust `<Machine>Inject` typed-inject seam?**
**Yes.** The C1 Path A seam is emitted on every backend, in two surface forms:
- C++/Kotlin/Python/Rust: per-event typed `inject` methods on the payload struct (the `<Machine>Inject` trait on Rust).
- **C11: the `raise_external_typed` per-event typed-function family** (`tools/codegen/templates/c/state_machine.{h,c}.jinja2`, "RFC §10.4 step 5: per-event typed-payload inject"). C11 uses a tagged `<machine>_payload_t` union + per-event typed raise functions because C struct assignment *is* the inject mechanism — but the contract (type-safe per-event payload injection) is identical to the Rust trait.

So the C-side typed-inject seam your switchboard targets **already exists and is SCE-emitted**. The function-pointer *sink* vtable (which generated machine receives the inject) is the wz side's job — but it binds against an SCE-emitted `raise_external_typed` per event, not a hand-rolled inject.

**Q5 — Confirm `<sce:extern>` / HAL injection is the intended terminus for OS I/O (sockets/timers), hand-written per platform, NOT a one-source target.**
**Confirmed, by design.** Side-effecting platform I/O is the actuation boundary; SCE's model is logic-in-the-machine, actuation-injected (the `Link`/`BufferPool` kinds already inject a HAL — e.g. the `NoOpHal` seam in the no_std port). `wz-runtime-{core,lwip}` staying hand-written per platform (zenoh-pico's per-RTOS layer analog) is the intended terminus. This is the SCE-core/external scope test's "side-effecting, platform-specific, non-build-time-decidable" exclusion — correctly external. You are not chasing an out-of-scope goal.

**Q6 — keyexpr→event dispatch (switchboard) C emission — wz concern or Forge-native?**
**wz concern** — and SCE confirms it owns no switchboard codegen (the term appears only in `analyzer.rs` doc-comments describing what *downstream* a switchboard, not a generator). Rationale: the keyexpr→event *mapping table* is application topology (which key routes to which event) = pub/sub-domain config, which the scope test pushes external. But SCE supplies every ingredient so wz is not blocked: forge-ast export + codec IR (the switchboard's inputs) + the C-side `raise_external_typed` seam (its output target, Q4). A C emission of `dispatch_switchboard` is the same wz-side generator you already have for Rust (`wz-switchboard-codegen`), retargeted at the C inject seam. This does **not** overlap Option B — the switchboard consumes SCE surfaces; it is not itself a Forge kind.

---

## 5. The cleanup SCE endorses (and one wz under-scoped)

**ERRATUM (corrected after wz pushback).** My original text here endorsed retiring `keyexpr_match.rs` onto the generated keyexpr algorithm as "the unambiguous duplicate." **That was wrong and is retracted.** The shipped `algorithm_keyexpr_intersect_exact.scxml` is `entry_id === target_id` — **exact uint32-ID equality over compile-time-interned ids** (`tests/forge/resources/algorithm_keyexpr_intersect_exact.scxml:26`; C7 RFC §5 line 317 lists "Full KeyExpr wildcard at runtime" as explicitly out-of-scope for v1). The runtime `keyexpr_match.rs` is full glob (`*`/`**`/`$*`) over runtime strings. They are **not** the same function — retiring the runtime matcher onto the stub would *lose glob* and is a regression. wz is correct, including the ordering: ① a wildcard-capable algorithm + a runtime-variable keyexpr representation must land first, ② only then does the runtime matcher converge. The Phase A4+ analysis is the separate response `sce-response-keyexpr-wildcard-phase-a4.md`. **`Algorithm` is the right home; the home is currently near-empty (an exact-id stub), so it is not retire-ready.**

But SCE's stronger recommendation, from §0: **also adopt `BoundedCollection` for the five registry tables' backing store**, rather than hand-written `BoundedVec<Row, N>`. That is the larger one-source win and it is what makes the eventual C registry a thin loop over generated pieces rather than a hand-written "C registry runtime." Concretely, per registry:
- element-type = a generated codec/record kind for the row (`pattern` + sink handle),
- `<sce:capacity>` = `MAX_SUBSCRIPTIONS` etc.,
- iterate-test-fire = the hand-written caller loop calling the generated `Algorithm` predicate + a `*_handler_t` function-pointer sink (Q2 precedent).

That leaves genuinely hand-written, per language, only: the loop + the function-pointer sink table. Everything else is one-source → 6 backends.

---

## 6. Summary

- **Decision: Option A**, refined — registry orchestration is caller-side support, by `BoundedCollection`'s deliberate container/policy split, not a missing kind.
- **Option B rejected**: a registry kind is a composition of `BoundedCollection` ⊕ `Algorithm` ⊕ a loop, partly domain-specific — fails the closed-form-primitive and core/external scope bars.
- **Option C rejected**: Worker forbids private collections at parse time; modeling a table as a Worker is an abuse.
- **More is already one-source than wz assumed**: adopt `BoundedCollection` (container) + retire `keyexpr_match.rs` onto the `Algorithm` predicate. The C-side typed-inject seam (`raise_external_typed`) already ships.
- **Boundaries confirmed**: HAL/socket I/O is by-design per-platform hand-written (Q5); the keyexpr→event switchboard is wz-side, built from SCE-supplied forge-ast + codec IR + C inject seam (Q6).
- **Precedent for the C runtime**: `sce-forge-runtime/c` — `procedure.h`'s `*_service_handler_t` function-pointer contract is the model for your closed sink-dispatch (Q2).
