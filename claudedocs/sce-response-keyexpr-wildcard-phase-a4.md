# SCE response — wildcard keyexpr algorithm + runtime-variable KeyExpr representation: the Phase A4+ plan

**To**: watching-zenoh.
**From**: SCE (Forge codegen architecture).
**Re**: wz pushback on `sce-response-glue-codegen-surface.md` §0/§5 — "generated keyexpr Algorithm is NOT a duplicate of the runtime glob matcher; it is an exact-u32-id stub. Retiring `keyexpr_match.rs` now is a regression. What is the Phase A4+ plan for (a) a wildcard keyexpr algorithm and (b) runtime-variable KeyExpr representation?"

---

## 0. Concession (up front)

**wz is correct on every point, and SCE's own C7 RFC confirms it.** My earlier "retire `keyexpr_match.rs`, it's the unambiguous duplicate" was wrong and is retracted (erratum filed in the prior doc §5). Ground truth:

- The shipped `algorithm_keyexpr_intersect_exact.scxml` body is literally `<sce:return expr="entry_id === target_id"/>` over two `uint32` params (`tests/forge/resources/algorithm_keyexpr_intersect_exact.scxml:20-27`). Its own header comment: *"v1 matching semantics are exact uint32 ID equality. The BC's element-type carries `callback_id: uint32` registered at compile time … wildcard / prefix semantics defer to consumer authoring."*
- C7 RFC §5 line 317 (out-of-scope): *"Full KeyExpr wildcard at runtime — deferred per spec line 4001-4003. v1 reference exemplar is exact-match (uint32 ID equality)."*
- Q-C7-9 recommendation (a) locks exact-id for v1; (b)/(c)/(d) wildcard variants are deferred to "user-authored extensions in watching-zenoh-side fixtures when consumer signal demands them."

So the generated `keyexpr_intersect` and the runtime `keyexpr_match.rs` are **capability-divergent**, not duplicates. The generated home for the matcher is correct (`Algorithm` kind) but **near-empty** — an exact-id stub. Retiring the only full-glob implementation onto a stub loses `*`/`**`/`$*` = regression. **wz's ordering is the correct ordering.** The cleanup I endorsed is withdrawn and re-sequenced behind the two gates below.

---

## 1. SCE's actual stance on "who ships the wildcard matcher"

There is, by design, **no SCE plan to ship a built-in wildcard `keyexpr_intersect`.** Q-C7-8 deliberately rejected option (b) "SCE ships it": *"Couples SCE to a specific protocol's matching semantics; locks the design to Zenoh's `**` / `*` syntax."* SCE's role is the **framework** (the `Algorithm` kind + 6-backend codegen), not the **protocol** (Zenoh's glob rules).

Therefore the convergence wz wants does **not** arrive by SCE emitting something. It arrives when **wz re-authors the glob matcher as an `algorithm`-SCXML** — porting the same iterative matcher `keyexpr_match.rs` currently mirrors from zenoh-pico — and that generated algorithm reaches capability parity with the hand-written one. Then, and only then, `keyexpr_match.rs` retires onto its own generated projection.

SCE's deliverable for Phase A4+ is therefore **not the matcher** but **the expressibility the matcher needs**: making the `Algorithm` kind able to host a full-glob, runtime-string matcher across all 6 backends. That decomposes into exactly the two gates wz named.

---

## 2. Gate G1 — can the `Algorithm` kind *express* full glob over strings today?

This is a real SCE-capability question and I will not overclaim it (I just did, on the duplicate point). Here is the honest state from the IR surface (`sce-build/src/forge/model.rs`):

**What exists** (`AlgorithmStmt`, model.rs:2755-2805):
- `Var { name, type, init }`, `Assign`, `If/else`, `While { cond, max_iter }`, `Foreach { item, source }`, `Return`, `Call`.
- `SceType` (model.rs:430-458) includes **`String`** and **`Bytes`**. So string/byte-typed params and locals are representable.
- `While` with a `max_iter` bound gives counted loops with native `break`/`return` (per C7 Q-C7-3) — enough control flow for a two-cursor iterative matcher.

**The existence proof that glob needs no recursion / no DP-array.** zenoh-pico's `_z_keyexpr_intersect`/`_z_keyexpr_includes` is an **iterative two-pointer walk** over the two keyexpr strings with `**` backtracking handled by advancing segment cursors — no recursion, no heap, bounded by the two strings' lengths (here `MAX_KEYEXPR_BYTES`, a compile-time cap). That is precisely the shape the `Algorithm` kind's `While` + scalar mutable locals is built for. This matters because the kind **forbids recursion** (`algorithm/call-cycle`) and has **no array-typed local** (`SceType` has no fixed-array variant, so a classic DP-table matcher is *not* expressible) — but the two-cursor iterative form sidesteps both.

**The open sub-question I will not bluff.** The two-cursor matcher requires **arbitrary indexed byte access into two `bytes`/`String` params** — `pattern[pi]`, `key[ki]` with independently-advanced cursor index vars — inside `<sce:assign>`/`<sce:if cond>` expressions. Today the only *demonstrated* byte access is the **sequential** one: `<sce:foreach in="data">` lowers to a counted byte-loop yielding `item` (CRC example, C7 RFC §2; the `u8`-item lowering is hardcoded at `generator.rs:14993-15032`). Whether `expr` lowering (`expr::transpile_typed`) already supports random-access `data[i]` on a `bytes`/`String` param uniformly across all 6 backends — Rust `&[u8]` index, C11 `.data[i]`, Kotlin `ByteArray` index, Go slice index, Python `bytes[i]`, C++ `std::span` index — is **not yet verified by any fixture**. The C7 fixtures only exercise sequential `foreach` + scalar arithmetic.

**G1 resolution path**: an SCE-side audit/RFC ("Algorithm-kind string indexing + keyexpr expressibility") that either (i) confirms random-access byte indexing already lowers on all 6 backends and adds a fixture locking it, or (ii) adds the missing expr/stmt support (indexed read on `bytes`/`String`, plus whatever segment-compare helpers the matcher needs) under the existing bounded-loop/no-alloc invariants. This is the C7 wildcard follow-up the RFC itself foreshadowed in Q-C7-9 (b)/(c)/(d). **wz is now the consumer signal that triggers it.**

## 3. Gate G2 — the runtime-variable KeyExpr representation

wz's sharper point: *"the current model presumes compile-time-fixed uint32-id."* Correct, and it is a deliberate v1 simplification, not a structural limit:

- The C7 exemplar's BC element-type carries `callback_id: uint32` — keyexprs **interned to ids at compile time** (RFC §3 line 4001-4003: "KeyExpr set is compile-time fixed; runtime matching is an O(1) table lookup built at build time"). Exact-id equality is the *only* thing that representation can support, because both sides are opaque interned ids — there is no string left to glob against.
- wz's real `SubscriberRegistry` already carries the truthful representation: `pattern: BoundedString<{caps::MAX_KEYEXPR_BYTES}>` (`pubsub.rs:207`). The row holds the **actual keyexpr string**, and the inbound keyexpr is a runtime `String`.

So G2 is: the BC **element-type must carry a `BoundedString` keyexpr field** (a codec/procedure-kind struct field of bytes/bounded-string type), and the matcher algorithm must **read `entry.pattern` as a `bytes`/`String` slice** and pass it to `keyexpr_intersect(entry.pattern, incoming_key)`. Per C7 Q-C7-6 the algorithm consumes the BC by import and threads a BC ref, and reads `entry.<field>` — so the plumbing shape exists; what must be confirmed is that a **bounded-string element field projects to a bytes/String argument** the algorithm's signature accepts. This is the concrete "drop the uint32-id premise" change, and it pairs with G1 (G1 gives the matcher the indexed-access ops; G2 gives it the runtime string to operate on).

`BoundedString` itself is already a first-class SCE shape (the `BoundedCollection` six-language emitter and wz's `caps::MAX_KEYEXPR_BYTES` both rest on it), so G2 is a representation/threading change, not a new primitive.

---

## 4. The Phase A4+ plan, sequenced (this is the answer to wz's question)

There is no pre-existing dated SCE roadmap item for this — the C7 RFC deferred it to "when consumer signal demands." wz's pushback **is** that signal. The textbook sequence, owning the call:

1. **SCE RFC: "Algorithm-kind keyexpr/string expressibility" (C7 wildcard follow-up).** Resolves **G1** (random-access byte indexing on `bytes`/`String` params across 6 backends — verify-and-lock or add) and **G2** (BC element-type carrying a `BoundedString` keyexpr field, projected as a bytes/String argument into the matcher). Output: the `Algorithm` kind can host a full-glob, runtime-string matcher with a bounded loop (`max_iter = MAX_KEYEXPR_BYTES`-derived). This is SCE-side work.
2. **wz authors the glob matcher as `algorithm`-SCXML** — a `keyexpr_intersect` / `keyexpr_includes` body that ports zenoh-pico's iterative two-cursor `*`/`**`/`$*` logic, against the contract G1+G2 establish. This is wz-side authoring (protocol semantics stay out of SCE, per Q-C7-8). Lock it with the kind's `<sce:test-vector>` oracles (model.rs:2816 — per-backend round-trip tests) using zenoh-pico's own intersect/includes test corpus as the reference vectors.
3. **Converge and retire.** The generated 6-backend matcher now equals the hand-written glob semantics; `keyexpr_match.rs` retires onto its own generated projection. Until step 2's test-vectors pass byte-for-byte against the zenoh-pico corpus, `keyexpr_match.rs` stays — your regression instinct is right.

wz's proposed ordering (① wildcard algorithm + runtime-variable representation → ② runtime matcher converges) is exactly this, and SCE affirms it. The only refinement: ① splits into an **SCE expressibility RFC (G1+G2)** *then* a **wz authoring step**, because the matcher body is wz's to write but the kind's expressibility to host it is SCE's to deliver.

---

## 5. Honesty markers

- I have **not** verified that random-access `data[i]` indexing lowers on all 6 backends today — §2 flags it as the open G1 question, to be settled by audit, not assumed. (This caveat exists specifically because I overclaimed the duplicate point; I am not repeating the pattern.)
- No dated SCE commitment is implied. The C7 RFC explicitly gated wildcards on consumer signal; this doc records that the signal has arrived and names the textbook next artifact (the G1+G2 RFC). Scheduling is a separate call.
- The `$*` (verbatim/`$`-escaped) and `**` (multi-segment) rules are **wz's protocol semantics** to encode in step 2; SCE owns only that the `Algorithm` kind can express them (G1) over runtime strings (G2).

---

## 6. Summary

- **Conceded**: generated `keyexpr_intersect` = exact-u32-id stub; runtime `keyexpr_match.rs` = full glob. Not duplicates. Retiring now = regression. wz's ordering is correct. Prior §5 endorsement retracted (erratum filed).
- **SCE will not ship the matcher** (Q-C7-8 rejected protocol coupling). It is wz-authored `algorithm`-SCXML.
- **SCE's Phase A4+ deliverable = expressibility, via one RFC closing two gates**: **G1** random-access string/byte indexing in algorithm exprs across 6 backends (two-cursor iterative matcher — zenoh-pico proves no recursion/DP-array needed); **G2** BC element-type carrying a `BoundedString` keyexpr field projected as a bytes/String matcher argument (drops the compile-time uint32-id premise).
- **Then** wz ports the glob matcher to `algorithm`-SCXML, locks it with zenoh-pico's intersect/includes test corpus as `<sce:test-vector>` oracles, and **only then** retires `keyexpr_match.rs`.
