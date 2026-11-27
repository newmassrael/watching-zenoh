# Lane debt-repay: the code faults the land loop filed on 2026-11-28

The land loop filed six debts on 2026-11-28 (ledger round 4753). Three are code faults this lane
repays: `debt-session-core-unbuilt-combinations`, `debt-runtime-coop-doc-links-default-form` and
`debt-host-peer-advanced-comment-stale`. `debt-coop-admission-held-for-drop` is the heap-native
lane's, which owns `Core::_admission`. The branch is `debt-repay-1128`, from `99c88e8372`.

## 1. The reading

### 1.1 wz-session-core in the builds no lane made

The debt names three sites, each read on main `df994d7913`:

1. `--no-default-features --features session-slot,session-unicast,liveliness-token --lib` fails
   with E0392: `LentDeclaration<'a>` (`src/session_actions.rs`) has, in that build, the one
   variant `FinalReply { interest_id }`, which borrows nothing. The token reply of a session with
   no allocator, and of a lend-only one, did not go through `LentDeclaration` at all: each of its
   two forms called `dispatch_network_message_at` itself, with an encoder closure of its own and,
   with no allocator, a count of its own (`local_token::token_reply_len`). So the enum's own doc
   ("the kinds share one dispatch and one encoder") was not true of the token reply, and the
   lifetime had no use in the build where the token reply was the only declaration with text.
2. With `codec-declare` and `rx-control` (which `liveliness-token` turns on) and no session,
   `judge_chain`, `judge_entries`, `then_judge` and `judge_declare_chains`
   (`src/network_message.rs`) compiled with no caller. Each was gated on "the union of its
   callers", written out as a `cfg` expression of up to five terms, and the union had drifted
   from the callers' gates: `all(codec-declare, rx-control)` stood for a reader that is compiled
   only with a session reading a frame where it lies.
3. `tests/bounded_heapless_backing.rs` under `session-slot,liveliness-token --all-targets`: the
   module of the peer tables was gated on `codec-declare` alone, while each of its tables needs a
   feature of its own, so a build with the codec and no table held five imports and the fixture
   `declares` that nothing called.

No leg built any of these: Layer C1h builds the heap's forms or no session, and the slot profile
is clippied only in its largest set (every feature beside it).

### 1.2 wz-runtime-coop's crate doc

`src/lib.rs` linked `executor`, `join_handle`, `runtime_impl`, `time`, `timer` and items of
them, all compiled with `runtime` alone, and `wz_runtime_core`, an optional dependency of the same
feature. A build without `runtime` (the crate's defaults among them) fails to document it. Layer
C1bzr's ledger (`scripts/lib/reduced_docs_ledger.txt`) carried eleven such findings in
`lib.rs`, one in `group_transport.rs` (an unconditional module doc linking
`session_drive::SessionDatagramLink`) and two in `reassembly_rx.rs` (`reassembly` without
`runtime`, linking `executor` and `time::ClockSource`). The crate doc was also stale beyond its
links: it said a build with no feature has `sync` alone and that Cortex-M0+ has no heap runtime,
both untrue since the critical sections, the group seam and the atomic polyfill.

### 1.3 The release profiles' comment

`configs/profiles/host-peer.conf` and `host-peer-ext.conf` said the advanced plane's two
behaviours (`advanced-source-retention`, `advanced-node-clock`) are left off, while both turn them
on since `a65b209884` (the owner's decision of 2026-11-27: the release profiles keep the
behaviours zenoh-pico lacks, and the like-for-like comparison is the zenoh-pico preset's).
`host-peer.conf` also carried the send paragraph twice, and `host-peer-ext.conf` half a sentence
of it twice.

## 2. Steps

| Step | Commit | What it did |
|---|---|---|
| D1 | `798f8720aa` | `LentDeclaration::TokenReply`: the lent token reply is a declaration of its kind, sent by `dispatch_declare_lent`; `LentDeclaration::qos` says the QoS each kind's envelope states; `local_token::token_reply_len` is gone |
| D2 | `cec80c6d4e` | `judge_chain`, `judge_entries`, `then_judge`, `judge_declare_chains` move to `ext_admit`, public and ungated; every reader calls them there |
| D3 | `0eff690fd3` | the peer tables of `bounded_heapless_backing.rs` compile where one of their tables does; each table's module imports what it alone reads |
| D4 | `5dda657e55` | Layer C1h: four clippy arms of the slot profile's small builds (section 3) |
| D5 | `5e9b659c1c` | wz-runtime-coop's crate doc rewritten to link only what every build compiles; two module docs name a gated item as code; fourteen ledger lines dropped |
| D6 | `aa4f7db8c5` | both release profiles say the advanced behaviours are on and why |

### 2.1 Why D1 is the structure and not a marker on the lifetime

The lifetime was unused because the token reply had left the enum it belongs to, not because the
enum's shape was wrong: a declaration written from its parts with text is a borrowing variant.
Putting the token reply back gives the lifetime its use in every build that has the enum (every
variant set that holds `FinalReply` holds `TokenReply` or `SubscriberReply`), and makes the enum's
claim true: one dispatch, one encoder closure type, one count. The one thing the token reply has
that no other kind has is its envelope without `ext_qos` (`lent_control::token_reply_declaration`),
so it leaves at `QosLevel::DEFAULT` where every other kind leaves at `QOS_DECLARE`. That is now a
method of the declaration (`LentDeclaration::qos`) and not a constant of the dispatch, the same
reading the heap form makes off the owned message (`declare_ext_qos::read_declare_qos`). A
`PhantomData` variant, or a `cfg` on the generic parameter, would have kept the token reply's two
private dispatches and silenced the symptom.

### 2.2 Why D2 moves the combinators and does not narrow their gates

The order of a message's chains (the envelope's before the body's, the first offender reported)
is the admission rule's, which `ext_admit` already holds unconditionally for the reason its
module doc gives: every consumer reaches one copy of it. The combinators are generic, so in a
build that calls them nowhere they generate no code, and public items of the rule's module are no
dead code in any build. A narrower union of callers (the codec-scale branch's `b1032d3f2c`) would
have closed these four builds and left the next reader's gate to drift from it again; this closes
the class.

## 3. The gate leg

The leg that would have caught all three sites is a CLIPPY build of the slot profile with a few
planes, which is what a small image takes. Where it goes:

- `scripts/lib/nondefault-tests-gate.sh` runs the tests a non-default feature reaches; its header
  states that feature combinations are out of its reach, and a leg there runs tests, while site 1
  and 2 are library builds.
- `scripts/lib/nondefault-features-gate.sh` clippies a crate at `--all-features` or at the
  largest sets its manifest declares (`doc_feature_sets.py`); a set is "every feature but", so a
  set of three features cannot be declared there without listing every other.
- Layer C1h (`scripts/run-ci.sh`, `layer_c1h_arbitrary_subset_matrix`) is the lane whose design
  is exactly this: named coherent subsets of wz-session-core, clippy arms where the fault is dead
  code. It runs hosted in the session-planes job.

So the leg is four C1h arms (D4):

| Arm | Command (`cargo clippy`, `-- -D warnings`) | Holds |
|---|---|---|
| 19 | `-p wz-session-core --no-default-features --features session-slot,liveliness-token --lib` | site 2 |
| 20 | `-p wz-session-core --no-default-features --features session-slot,session-unicast,liveliness-token --lib` | site 1 |
| 21 | `-p wz-session-core --no-default-features --features session-slot,liveliness-token --all-targets` | site 3 |
| 22 | `-p wz-session-core --no-default-features --features session-slot,session-unicast,liveliness-token,codec-push,rx-push,codec-response,codec-response-final,rx-response,codec-request --lib` | a small slot node |

Not added, and why: `session-slot,session-unicast,liveliness-token --all-targets`. The debt read
the slot profile's test targets only without a session; whether the session's tests build in that
small form was not read, and an arm is added after the command it runs has been seen green.

## 4. What the landed steps test, and what turns each red

### 4.1 D1

`session_actions::lent_declaration_tests::a_token_reply_is_written_as_the_declaration_of_its_kind`,
compiled with `liveliness-token` and either no `alloc` or `tx-lend-only`:

- the bytes `LentDeclaration::TokenReply` writes are those `DeclareWire::encode_source` writes of
  `token_reply_declaration(token_id, keyexpr, interest_id)`. Red if the arm writes another kind
  (`token_declaration`, whose envelope carries `ext_qos` and no interest id) or swaps the two ids
  (3 and 7 here);
- `encoded_len` is the written length. Red if the count measures another declaration;
- `TokenReply::qos` is `QosLevel::DEFAULT` and `FinalReply::qos` is `QOS_DECLARE`. Red if `qos`
  answers one constant for every kind.

### 4.2 D2

`ext_admit::tests::the_envelope_is_judged_before_the_body_and_an_absent_chain_refuses_nothing`,
in every build:

- `then_judge` returns a refused first verdict without calling the second, and an `Unjudged` first
  verdict as it is; red if it reads the body past the envelope;
- `judge_entries` and `judge_chain` answer `Admissible` for no chain;
- `judge_declare_chains` reports the envelope's offender (`0x15`) before the declaration's
  (`0x14`), judges the declaration's chain when the envelope has none, and admits a chain whose
  only entry is not mandatory; red if it reads the body first.

The readers that call the combinators keep their own tests (`network_message`'s and its readers'),
unchanged.

### 4.3 D3 to D6

D3 is a test file's gates; its tests are unchanged. D4 is the leg itself. D5 and D6 are docs and a
profile's comments; D5's check is Layer C1bzr, whose ledger it lowers.

## 5. What the main session runs

Per commit, each a single command from the workspace root:

- D1: `cargo clippy --manifest-path crates/Cargo.toml -p wz-session-core --no-default-features --features session-slot,session-unicast,liveliness-token --lib -- -D warnings`;
  `cargo test --manifest-path crates/Cargo.toml -p wz-session-core --no-default-features --features session-slot,session-unicast,liveliness-token --lib lent_declaration_tests` (1 test);
  `cargo test --manifest-path crates/Cargo.toml -p wz-session-core --all-features --lib lent_declaration_tests` (1 test, the lend-only form with the heap).
- D2: `cargo clippy --manifest-path crates/Cargo.toml -p wz-session-core --no-default-features --features session-slot,liveliness-token --lib -- -D warnings`;
  `cargo test --manifest-path crates/Cargo.toml -p wz-session-core --lib ext_admit::`;
  `cargo test --manifest-path crates/Cargo.toml -p wz-session-core --lib network_message`.
- D3: `cargo clippy --manifest-path crates/Cargo.toml -p wz-session-core --no-default-features --features session-slot,liveliness-token --all-targets -- -D warnings`.
- D4: `bash scripts/run-ci.sh --layer C1h` (24 arms).
- D5: `cargo doc --manifest-path crates/Cargo.toml -p wz-runtime-coop --no-deps` with
  `RUSTDOCFLAGS=-D warnings`; Layer C1bzr for the ledger.
- D6: none (comments).

## 6. Left open

- `docs/win-budget/codec-scale.md` records the step that introduced `local_token::token_reply_len`;
  D1 removed it. That record is the codec-scale lane's and is left as written.
- The ledger keeps wz-runtime-coop's two `session_drive.rs` findings (a redundant explicit link
  target, `PoolStorage::owned`); they are not this class and not this debt.
