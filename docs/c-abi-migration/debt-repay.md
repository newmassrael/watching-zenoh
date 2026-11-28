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
4. Under the same command, `declare::local_token`'s unit tests: seven tests that hand
   `respond_to_interest` or `dispatch_messages` an owned `InterestOwned` were gated on
   `storage-profile` (one with `bounded-heapless`), while both readers are `alloc`, and the
   module imported `hashbrown::HashMap`, a dependency only `alloc` brings, for every build. The
   slot profile is `storage-profile` without `alloc`, so these named an unimported type and an
   absent crate. The main session's run of arm 21 after D3 found it; D3 alone did not make that
   arm green.
5. Under arm 21's features, with D7 in, the test build of the lib: the record walk
   (`try_for_each_record_while`, `walk_records`, `EachRecord`, `RecordForm`, the pull of
   `network_message/pull.rs`, the readers `read_declare`, `read_interest`, `read_oam`, their
   verdicts and `admit_lent`, and `is_transport_mid`), twenty items, compiled with no caller.
   Each was gated on `any(test, session-unicast, all(session-multicast, not(alloc)))`, while
   every test that walks records (`record_walk_tests`, `chain_saturation_tests`,
   `repeated_extension_tests`) is `alloc`'s, as `try_for_each_record` already said
   (`all(test, alloc)`). The compile errors of site 4 had hidden them, as errors hide lints.
   The same gates are on main `728fc45ec8`.
6. Arm 22's features with `--all-targets` (a test build of a slot node with a session and the
   data codecs, which no arm builds): three test modules read only what the heap profile has and
   were gated without it. `network_message::mandatory_extension_rule_tests` reads the owned
   message and the owned builders, `lent_control::tests` holds each writer to the owned builder
   it mirrors, and `reply::decode_isolation_tests` builds the heap registry
   (`ReplyRegistry::new`) and an owned Response; the last was gated on `storage-profile`, the
   slot profile's too. Eighty resolution errors, all in these three modules. On main as well.
7. Arm 21's features, `cargo test --lib`, with D9 in: four tests of `declare::local_token`,
   which no build of these features had compiled before, fail. Each expects the Interest pattern
   `group1/**` to match a token under `group1/`. `**` is the matcher's optional dialect
   (`keyexpr-wildcard-double`, a default feature the slot builds leave off, as the minimal MCU
   preset does), and without it `**` is a literal chunk
   (`keyexpr_match::tests::double_wildcard_off_degrades_to_literal`). The registry stages the
   same way in every build; what differed is the matcher it is handed. So the claim of each test
   was wrong for that build, and the code is right: `matching_token_stages_token_then_final` and
   `a_token_unregistered_between_stage_and_drain_resolves_to_none` staged no token,
   `multiple_matching_tokens_each_stage_a_token` staged none of its two, and
   `a_chain_that_does_not_fit_whole_is_refused_and_stages_nothing` met a one-item chain that
   fits. Three tests of the heap's owned parse (`tokens_interest_stages_matching_response`, the
   own-space pair) make the same assumption in a heap build without the dialect, and
   `unregister_removes_token_from_responses` and `future_only_interest_stages_nothing` pass
   there only because nothing matches.
8. Arm 22's features with `--all-targets`, with D9 in: the integration test
   `tests/lent_control_alloc.rs` was gated on the codecs of the writers it counts and not on
   `alloc`, while its control, the owned builders (`declare_build`, `response_final_build`,
   `interest_build::build_interest_*`), compiles only with it. Five resolution errors.
9. `cargo test --lib` of the slot profile with `liveliness-token`, alone and with
   `session-unicast`, with D11 in: every test of the lib runs (1209 and 1288), and one fails in
   both,
   `reply_acceptance::tests::a_get_admits_a_reply_keyed_with_its_own_text_before_the_walk`, on
   `reply_key_admitted("a/*", "a/b")`. Site 7's premise again: `*` as a chunk is the matcher's
   other optional dialect (`keyexpr-wildcard-single`, a default feature the slot builds leave
   off), and without it `a/*` is a literal key that `a/b` does not intersect
   (`keyexpr_match::tests::single_wildcard_off_degrades_to_literal`). The gate is right; the test
   claimed a wildcard where the build has none.

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
| D7 | `e5c7de0d22` | `local_token`'s tests of the owned Interest parse carry its gate, `alloc`; the peer map's import comes with `alloc` (site 4) |
| D8 | `4709f8e0ab` | the record walk and every item only it reads say `all(test, alloc)` where they said `test`; `is_transport_mid` and the `SceCursor` import drop `test`; `request_view_admission` is gated on its two readers (site 5) |
| D9 | `bf9b5f6516` | the three test modules of site 6 are gated on `alloc` |
| D10 | `c9567ce5d7` | `local_token`'s tests that expect a match use a literal key or match-all, so they hold the staging in every dialect (site 7) |
| D11 | `a8ab51d4b6` | `tests/lent_control_alloc.rs` is gated on `alloc` beside its codecs (site 8) |
| D12 | `d41ade75f4` | the reply gate's test keeps the own-text and refused-key cases, which hold in every dialect; the walk case moves to a test gated on `keyexpr-wildcard-single` (site 9) |

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
| 21 | `-p wz-session-core --no-default-features --features session-slot,liveliness-token --all-targets` | sites 3 and 4 |
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

### 4.3 D3 to D9

D3 is a test file's gates; its tests are unchanged. D7 is a test module's gates: `alloc`
implies `storage-profile`, so each moved test still compiles in every build that built it, and
leaves only the slot profile without `alloc`, which never could. That profile keeps the tests of
the no-heap staging (`respond_to_interest_borrowed`, the refused whole chain, the reply's
keyexpr bound). Arm 21 is its check; no arm is added. D4 is the leg itself. D5 and D6 are docs and a
profile's comments; D5's check is Layer C1bzr, whose ledger it lowers.

D8 changes gates only, and only in a test build that has neither `alloc` nor a session: there
every item it removes had no caller, and every other build compiles the same items as before
(`all(test, alloc)` is `test` where `alloc` is on, and a session's terms are unchanged).
`request_view_admission` keeps the reader tests of `request_read`, which build without `alloc`
(`all(test, request-put-del)`). The `cfg_attr` conditions of `PushRead` and `PushExts` that
name the walk narrow with it, which only widens where their `allow(dead_code)` applies. No test
changes; arm 21 is the check, and the heap build's test count must not move. D9 removes three
test modules from builds that could not compile them; every build that ran them still does.

### 4.4 D10

D10 changes fixtures, not code, and no test is gated: every test of the module runs where it ran.
A pattern a test expects to match is now a literal key (which matches itself in every dialect) or
match-all (`None`, the tokens Interest without a key). Wildcard matching stays the matcher's,
tested in `keyexpr_match`. Per test, in every build that compiles it:

- `matching_token_stages_token_then_final`: `Some("group1/zenoh-pico")` stages the token and
  then the `Final`; red if staging drops the token or puts the `Final` first;
- `a_token_unregistered_between_stage_and_drain_resolves_to_none`: the same pattern stages one
  token, which resolves to `None` after `unregister`; red if `keyexpr_for` reads a stale row;
- `unregister_removes_token_from_responses`: the pattern names the token's own key, so the
  `(0, 1)` it asserts is the unregister's and not a non-match; red if `unregister` keeps the row;
- `multiple_matching_tokens_each_stage_a_token`: two tokens on `group1/a` and one on
  `other/c`, pattern `group1/a`: two tokens staged, ids `[1, 2]` in table order, then the
  `Final`; red if staging stops at the first match or stages the token on another key;
- `a_chain_that_does_not_fit_whole_is_refused_and_stages_nothing`: match-all over two tokens is
  a chain of three into two free slots, refused with nothing staged; `group1/a` is a chain of
  two that fits; red if the chain is staged in part (the fixed backing and the slot profile);
- `future_only_interest_stages_nothing` and `tokens_interest_stages_matching_response` (heap):
  the Interest names `group1/zenoh-pico`, so the first's empty staging is the C bit's verdict
  and the second's `(1, 1)` holds without the dialect;
- the own-space pair (heap): id 7 resolves to `ours/tok` in our space and `theirs/tok` in the
  peer's; reading the wrong space stages token 2. Unchanged in what it discriminates.

### 4.5 D11

D11 is the test target's gate. Every build that compiled it has `alloc` (its owned builders
need it), so it runs where it ran; a build without `alloc` compiles it as an empty target. Its
one test is unchanged.

### 4.6 D12

Unlike D10, D12 gates a claim, because here the wildcard IS the claim: the walk case holds that
`reply_key_admitted` goes on to the walk when the texts differ, and only a wildcard get admits a
key other than its own text. Without `keyexpr-wildcard-single` a literal get intersects only its
own text, so the walk and the text comparison agree on every pair and no fixture could tell them
apart; a literal key in place of `a/*` would assert nothing the refused cases do not. So the
test is split, as `a_literal_query_intersects_only_its_own_key` and
`a_pattern_query_intersects_a_concrete_reply` already split the walk itself:

- `a_get_admits_a_reply_keyed_with_its_own_text_before_the_walk`, every build: `a/b` and
  `demo/**` are admitted with no walk counted, and `a/c`, `a` and `a/b/c` are refused under
  `a/b`; red if the text shortcut is left out (in the default build the own `**` text is
  walked), or if it compares
  the shorter length only (`a` or `a/b/c` admitted);
- `a_reply_keyed_otherwise_goes_on_to_the_walk`, with `keyexpr-wildcard-single` (a default
  feature): `a/b` admitted and `b/b` refused under `a/*`; red if the gate stops at the text
  comparison (`a/b` refused) or admits what the walk refuses (`b/b` admitted).

The default build runs both, one test more than before D12; the slot builds run the first.

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
- D5: `cargo rustdoc --manifest-path crates/Cargo.toml -p wz-runtime-coop --lib -- -D warnings`
  (one command: an environment assignment in front of `cargo` is not a program `bx` runs);
  Layer C1bzr for the ledger.
- D6: none (comments).
- D7: `cargo clippy --manifest-path crates/Cargo.toml -p wz-session-core --no-default-features --features session-slot,liveliness-token --all-targets -- -D warnings`;
  `cargo test --manifest-path crates/Cargo.toml -p wz-session-core --no-default-features --features session-slot,liveliness-token --lib local_token::`;
  `cargo test --manifest-path crates/Cargo.toml -p wz-session-core --lib local_token::` (the heap build keeps every test).
- D8: `cargo clippy --manifest-path crates/Cargo.toml -p wz-session-core --no-default-features --features session-slot,liveliness-token --all-targets -- -D warnings`;
  `cargo test --manifest-path crates/Cargo.toml -p wz-session-core --no-default-features --features session-slot,liveliness-token --lib local_token::`;
  `cargo test --manifest-path crates/Cargo.toml -p wz-session-core --lib` (the count before D8);
  `cargo clippy --manifest-path crates/Cargo.toml -p wz-session-core --all-features --all-targets -- -D warnings`.
- D9: `cargo clippy --manifest-path crates/Cargo.toml -p wz-session-core --no-default-features --features session-slot,session-unicast,liveliness-token,codec-push,rx-push,codec-response,codec-response-final,rx-response,codec-request --all-targets -- -D warnings`;
  `cargo test --manifest-path crates/Cargo.toml -p wz-session-core --lib mandatory_extension_rule_tests`;
  `cargo test --manifest-path crates/Cargo.toml -p wz-session-core --lib lent_control::`.
- D10: `cargo test --manifest-path crates/Cargo.toml -p wz-session-core --no-default-features --features session-slot,liveliness-token --lib local_token::`;
  `cargo test --manifest-path crates/Cargo.toml -p wz-session-core --lib local_token::` (the heap build, same count as before D10);
  `cargo clippy --manifest-path crates/Cargo.toml -p wz-session-core --no-default-features --features session-slot,liveliness-token --all-targets -- -D warnings`.
- D11: `cargo clippy --manifest-path crates/Cargo.toml -p wz-session-core --no-default-features --features session-slot,session-unicast,liveliness-token,codec-push,rx-push,codec-response,codec-response-final,rx-response,codec-request --all-targets -- -D warnings`;
  `cargo test --manifest-path crates/Cargo.toml -p wz-session-core --all-features --test lent_control_alloc` (1 test; the default features leave out the codecs it counts, so there it is 0).
- D12: the two runs of site 9 again, each with no failure and the same count as there (1209 and
  1288: the new test is not compiled without the wildcard), the first being
  `cargo test --manifest-path crates/Cargo.toml -p wz-session-core --no-default-features --features session-slot,liveliness-token --lib`;
  `cargo test --manifest-path crates/Cargo.toml -p wz-session-core --lib reply_acceptance::` (the default build, one test more than before D12).

## 6. Left open

- D1's `LentDeclaration::TokenReply` meets the group-link-writer lane's variant of the same name
  (link and group form) at the merge, which takes that lane's form; nothing here builds on D1's.
- `docs/win-budget/codec-scale.md` records the step that introduced `local_token::token_reply_len`;
  D1 removed it. That record is the codec-scale lane's and is left as written.
- Arm 22 stays `--lib`: its `--all-targets` form is sites 6 and 8, and an arm is added after
  the command it runs has been seen green.
- The two `cargo test --lib` runs of site 9 are the only slot-profile test runs of the whole
  lib so far; site 9 was their one failure. No `--all-targets` test run of the slot profile has
  been made, and its integration tests may assume a dialect as sites 7 and 9 did.
- `pubsub::decode_isolation_tests` has site 6's shape (gated on `storage-profile`, reads the
  owned Push and the heap registry); no build of this lane reached it, so it is left as read.
- The ledger keeps wz-runtime-coop's two `session_drive.rs` findings (a redundant explicit link
  target, `PoolStorage::owned`); they are not this class and not this debt.
