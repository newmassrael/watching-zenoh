# OQ-W15 (a) — Ratification summary for SCE maintainer sync

**One-page artifact.** Distilled from
`docs/intrinsics-runtime-symbols.md` §2.5 / [HMAC](intrinsics-runtime-symbols.md#26-hmac--oq-w15-a-initial-proposal-target-plugin) / §3 +
[`docs/session-fsm.md`: Accept-side hardening detail](session-fsm.md#27-accept-side-hardening-detail) (c) + `docs/rfc-open-questions-log.md`
OQ-W15 entry. Authoring date: 2026-05-01 후속 #6.

This document is intentionally *audience-segregated* — it is for the
SCE maintainer ratifying watching-zenoh's intrinsics whitelist
proposal. Source material lives in the watching-zenoh-internal docs
listed above; this summary is the agenda artifact for the sync.

---

## 1. Decision needed

Two binary decisions on `sce_intrinsics_runtime_*` core whitelist
membership:

1. **Add `sce_random_fill(buf, len) -> int` (RNG) to the core
   whitelist?** — **Yes / No**
2. **Keep `sce_hmac_sha256(key, key_len, msg, msg_len, out)` (HMAC)
   in target plugins (NOT in the core whitelist)?** — **Yes / No**

The two questions are coupled by their shared consumer
(`stateless_accept: cookie_hmac_sha256`) but are individually
decidable — RNG can land in the whitelist independently of where
HMAC lives.

---

## 2. Why this decision is needed now

**Hard block on public-Internet listener-bearing MCU deploys.**
RFC §5.K and [`docs/session-fsm.md`: Accept-side hardening detail](session-fsm.md#27-accept-side-hardening-detail) (c) make
`stateless_accept: cookie_hmac_sha256` **required** (not optional)
on any listener link with `domain_attrs.untrusted_source: true`.
Without it, the build refuses to emit
(`deploy/stateless-accept-required-on-untrusted-source` is a hard
error per RFC §5.K).

`stateless_accept` cannot be authored without the two primitives
this question concerns:

- The cookie HMAC body needs a `sce_hmac_sha256` symbol resolvable
  at codegen time.
- The HMAC key material is generated at session-FSM-instance
  startup from a `sce_random_fill` symbol per
  [`docs/session-fsm.md`: Accept-side hardening detail](session-fsm.md#27-accept-side-hardening-detail) (c) "HMAC key handling".

Until both symbols are placed (whitelist or plugin), no
public-Internet-facing MCU deploy can land. Phase A entry of any
MCU target whose listener link is exposed to an untrusted network
is gated on this decision.

Phase A entry of *private-LAN* MCU listeners is **not** gated —
those deploys omit `untrusted_source: true` and `stateless_accept`,
and the half-open capacity + accept-rate caps alone suffice (per
[session-fsm.md: Accept-side hardening detail](session-fsm.md#27-accept-side-hardening-detail) (a)+(b)). The blocker is exposure-class-
specific.

---

## 3. Initial proposal (watching-zenoh)

| Symbol | Proposed location | OQ-W15 option | Source |
|---|---|---|---|
| `sce_random_fill(buf, len) -> int` | **core whitelist** | option 1 | `docs/intrinsics-runtime-symbols.md` §2.5 |
| `sce_hmac_sha256(key, key_len, msg, msg_len, out)` | **target plugin** | option 2 | [`docs/intrinsics-runtime-symbols.md`: HMAC](intrinsics-runtime-symbols.md#26-hmac--oq-w15-a-initial-proposal-target-plugin) |

### 3.1 RNG → core whitelist (option 1) — three reasons

1. **Universality.** Every supported platform has *some* entropy
   source — CMSIS RNG IP on Cortex-M with hardware RNG, ADC noise
   sampling fallback on M0+, `getrandom(2)` on linux,
   `/dev/random` equivalent on QNX. The symbol shape
   `sce_random_fill(buf, len) -> int` is the smallest universal
   contract; the body differs per platform but the signature does
   not.
2. **No SoC-specific accelerator selection.** RNG implementations
   are bundled with SoC HAL — there is no
   "STM32H7 has HW RNG / STM32H7 has SW RNG" choice the deploy
   author needs to make. (HMAC, by contrast, *does* have such a
   choice — see §3.2.)
3. **Cooperative-scheduler WCET.** RNG calls inside session FSM
   `Accepting.*` cookie-key rotation must fit in
   `worker_slot_budget_us`. A canonical symbol with a per-platform
   `<sce:wcet-bound mode="measured" target=...>` is cleaner than
   per-deploy plugin symbols where authors must re-declare the
   bound for every plugin.

### 3.2 HMAC → target plugin (option 2) — three reasons

1. **Hardware-accelerator selection is genuinely per-SoC.** STM32H7
   has the `CRYP` IP; ESP32 has the `SHA` accelerator; Cortex-M0+
   has neither and uses software fallback. The choice is
   deploy-meaningful, not portable-by-construction.
2. **Software fallback is also authorable as an `algorithm` kind.**
   When no HW accelerator is available, HMAC can be expressed as
   `sources/algorithm/hmac_sha256.scxml` (OQ-W15 (a) option 3 as a
   fallback path). The target-plugin shape accepts both backings —
   the plugin row can `backed_by:
   stm32h7_cryp_hmac_sha256` (vendor binding) or
   `backed_by: sources/algorithm/hmac_sha256.scxml` (SCE-authored).
   Wire output is identical.
3. **Bounded blast radius for the whitelist.** Adding a 32-byte
   crypto primitive to the core whitelist would set precedent for
   adding more crypto primitives over time (BLAKE2s, SHA-3,
   AES-GCM) — each with its own SoC-accelerator selection
   problem. Keeping HMAC in target plugins keeps the core
   whitelist surface small and the precedent contained.

---

## 4. Counter-options (presented for context)

### 4.1 RNG counter-options

| Option | Description | Trade-off vs proposal |
|---|---|---|
| Option 2 | RNG → target plugin. Each deploy ships entropy source via plugin. | Loses the "every platform already has one" universality. Requires every public-Internet-listener-bearing deploy to ship a plugin even when the platform's entropy source is canonical (e.g. CMSIS RNG). |
| Option 3 | RNG → SCE-authored algorithm. | Not viable — entropy generation is irreducibly platform-coupled (cannot be expressed in `<sce:algorithm>` bounded loops over deterministic inputs). |

### 4.2 HMAC counter-options

| Option | Description | Trade-off vs proposal |
|---|---|---|
| Option 1 | HMAC → core whitelist. | Adds a 32-byte cryptographic primitive to the whitelist. Sets precedent (see §3.2 reason 3). HW-accelerator selection ergonomics survive (the whitelist would dispatch internally), but the precedent matters. |
| Option 3 | HMAC → SCE-authored `algorithm` kind, *no extern at all*. | Loses HW-accelerator access entirely (CRYP / SHA accelerators unused). Wire output identical, ~10× CPU cost on STM32H7. WCET headroom under burst is tighter on slow cores. However: zero plugin dependency for any deploy — Phase A entry on listener-bearing MCUs unblocked without plugin authoring. |

---

## 5. Blast radius (forward-compatibility implications)

### 5.1 If RNG joins the core whitelist (proposal)

- Future RNG-consuming features land "free" — passive-scouting
  jitter (deferred per OQ-W23), TLS nonces (Phase D+), session-id
  randomization for replay defense, etc. — without each feature
  re-declaring the entropy source.
- Plugin authoring for *non*-cookie deploys is unchanged.
- The "platform without entropy source" case
  (Cortex-M0 with no HW RNG and no ADC) becomes a build-time
  refusal (`extern/symbol-not-in-whitelist` if the platform's
  whitelist row is empty) — explicit and early, not a runtime
  surprise.

### 5.2 If HMAC stays in target plugins (proposal)

- Future crypto primitives (BLAKE2s, SHA-3, AES-GCM, ChaCha20-Poly1305)
  land in plugins by precedent — the whitelist surface remains small.
- Each MCU deploy that needs crypto carries a plugin file. For
  STM32H7 + listener-bearing watching-zenoh, the plugin file is
  ≈10 lines (HMAC binding + RNG row if RNG is *not* core).
- SoC-vendor crypto IP changes (new accelerator landing in a
  silicon revision) are absorbed in the plugin without RFC churn.

### 5.3 If RNG goes to plugin instead

- Every public-Internet-listener deploy carries a plugin even on
  platforms where the entropy source is canonical — duplicated
  authoring per deploy.
- Future RNG-needing features each re-state the plugin
  requirement.

### 5.4 If HMAC joins the whitelist instead

- Phase A entry on listener-bearing MCUs unblocks faster (no
  plugin needed for STM32H7 / ESP32 — the whitelist body uses the
  vendor accelerator internally).
- Precedent for additional crypto primitives in the whitelist is
  set; future additions of BLAKE2s / SHA-3 / AES-GCM each become
  a per-primitive RFC discussion.

---

## 6. Action requested

- **Ratify or reject §3 (proposal).** Yes/no per the two
  questions in §1.
- **If reject, provide counter-direction.** Pick from §4 or
  propose another shape; watching-zenoh side will follow up with a
  concrete RFC §5.I patch.
- **Decision artifact.** A short "decision recorded" note in
  `docs/rfc-open-questions-log.md` OQ-W15 entry — watching-zenoh
  side will land the patch; SCE side ratifies the symbol-table
  policy column in `docs/intrinsics-runtime-symbols.md` §2.5 / [HMAC](intrinsics-runtime-symbols.md#26-hmac--oq-w15-a-initial-proposal-target-plugin).

Independently of the decision, OQ-W15 (b) — the MCU/AP defaults
for `session_arming_quota` / `accept_rate_per_sec` /
`accept_rate_burst` / `cookie_lifetime_ms` / `key_rotation_s` —
needs HIL measurement of HMAC cycles per byte on Cortex-M0+/M4/M7
with and without crypto accelerators, and is **not** part of this
ratification ask. (b) settles when watching-zenoh authors the
empirical validation harness, post-Phase-A.

---

## 7. References (for the maintainer)

- `docs/intrinsics-runtime-symbols.md` §2.5 (RNG row), [HMAC row](intrinsics-runtime-symbols.md#26-hmac--oq-w15-a-initial-proposal-target-plugin), §3 (whitelist-vs-target-plugin policy matrix).
- [`docs/session-fsm.md`: Accept-side hardening detail](session-fsm.md#27-accept-side-hardening-detail) (c) (`stateless_accept` body) +
  G-SFM-5 (the question's origin).
- RFC §5.K `stateless_accept` block (lines 2275–2304) — the deploy
  schema that consumes both symbols.
- RFC §5.I — `sce:extern` whitelist host crate (`sce_intrinsics_
  runtime_*`) and the target_plugin escape hatch.
- `docs/rfc-open-questions-log.md` OQ-W15 entry — the canonical
  question record (status will move `open → answered` once this
  ratification lands).
