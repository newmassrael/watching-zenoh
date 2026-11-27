# Structural lane sz-put2: the put's remaining bytes, paired with zenoh-pico's write

Status: the reading of the put's path against zenoh-pico's, line by line, the steps that walk its
bytes without raising the put's or the receive's instructions, and the first step (S1) carried
in beside it; S2 to S5 and W-P1 carried after it (section 6), the plan's key with them (section 6.1), F1 left unwritten (section 7). Nothing here was built, run or measured by this lane: every byte figure is either
**read** from the size ledger's explain document named below or an **estimate** from the code, to
be read on that document after the merge.

## 1. The reading

The explain document of `pico-client-coop-nostd` (`wz-capi-pico-lib`, `os-host,link-udp`,
profile `capi-nostd`) dated 2026-11-27 (schema 5, pin `6a881c21dad1`), read on `main` with the
put lane (`arch-put.md`) landed: the case is 205,921 against zenoh-pico's 170,500. The sessions
lane (`base-sessions.md`, branch `base-sessions`) counts the put **hot** at +4,356 in the sessions
area. The nine bodies its row names add to 4,557 bytes there; two more are the put's too:
`write_filter_row_open` 304 (shared with the matching status) and `publish_filtered` 78.

zenoh-pico's sessions area holds only `_z_write` (328) and the two publisher bodies (130, 60): its
put is spread over its API's doors, its primitives, keyexpr, codec and transport. So this lane
reads the whole path in every area, and pairs each job with the zenoh-pico lines that do it.

The case builds no `threads` (`OTHER_THREADS` is a constant `false`, no `wz_round`), no
`listen`, `group`, `local-subscriber`, `shared-key-ids` or `transport-stats`. The engine is one
type, so `SessionEngine::put_plain_filtered` has no caller in the C ABI and is not linked. The
doors reach the put by two entries, `publish_filtered` (a publisher's put, with or without
options) and `publish_on_wire_all` (a session's put, and a publisher's bare put that is not
plain), and the put's one body takes the session apart for a put no leg held it for
(`decide_alone`).

## 2. The path, line by line

| # | zenoh-pico | wz |
|--:|------------|----|
| 1 | the session is open: `vendor/zenoh-pico/src/api/api.c` @ `_z_session_rc_t sess_rc = _z_session_weak_upgrade_if_open(&pub->_zn);` | the door's `is_closed`, then the take: `live_to_publish` (141), `live` (66), `LiveCore::drop` (11) |
| 2 | the filter, a state the declarations wrote: `vendor/zenoh-pico/src/api/api.c` @ `!_z_write_filter_active(&pub->_filter)` | `decide_put` under the take (inlined in `put_on_links`, again in `decide_alone` 481), the verdict cached by the peers' count (`write_filter_row_open` 304), the answer kept for the legs after (`Asked`) |
| 3 | the QoS byte: `vendor/zenoh-pico/src/net/primitives.c` @ `_z_qos_t qos = _z_n_qos_make(is_express, cong_ctrl == Z_CONGESTION_CONTROL_BLOCK, priority);` | `push_metadata` (126) for a put with options; a `PushMetadata` of the QoS alone and a `SendAs` built in the planned arm and again in the plain arm; `face_send::droppable`; `plain_put_params` (241) once at the declare |
| 4 | the destination: `vendor/zenoh-pico/src/net/primitives.c` @ `if (_z_locality_allows_remote(allowed_destination)) {` | `put_on_links`'s `remote`, `decide_put`'s `allows_remote` |
| 5 | the key's wire form: `vendor/zenoh-pico/src/net/primitives.c` @ `_z_wireexpr_t wireexpr = _z_declared_keyexpr_alias_to_wire(keyexpr, zn);` | `named_at` in `leg_of` and again in `keep_plan`, `NamedKey::by_head` in the planned put, `NamedKey::under_or_whole` (169, shared), `key_on_link` (the identity without `shared-key-ids`) |
| 6 | the message value: `vendor/zenoh-pico/src/net/primitives.c` @ `_z_n_msg_make_push_put(&msg, &wireexpr, payload, encoding, qos, timestamp, attachment, reliability,` | none: `PushParts` and its form (`send_push_qos`) write from the parts |
| 7 | the transport: `vendor/zenoh-pico/src/transport/common/tx.c` @ `if (zn->_mode == Z_WHATAMI_CLIENT) {` | the dial face's hold (`direct::on_faces`), the walk of the up links (`send_on_links` 387: `up_wires_at`, the face's mark, `Pass::face_send`, `publish_through`) |
| 8 | the transmit lock: `vendor/zenoh-pico/src/transport/common/tx.c` @ `ret = _z_transport_tx_mutex_lock(ztc, cong_ctrl == Z_CONGESTION_CONTROL_BLOCK);` | the face's send place (`hold_send`), the session's lock (row 1), the holder's mark (`SendingOn`) |
| 9 | the batch: `vendor/zenoh-pico/src/transport/common/tx.c` @ `bool batch_has_data = _z_transport_tx_batch_has_data(ztc);` and `vendor/zenoh-pico/src/transport/common/tx.c` @ `z_result_t ret = _z_network_message_encode(&ztc->_wbuf, n_msg);` | `dispatch_network_message_in` (1,715, every network message's), the writer of `send_push_at` (402), `write_push` (1,615), `write_plain_put` (42), the head's copy |
| 10 | the express flush: `vendor/zenoh-pico/src/transport/common/tx.c` @ `if (_z_transport_tx_get_express_status(n_msg)) {` | `flush_express` |
| 11 | the fragments: `vendor/zenoh-pico/src/transport/common/tx.c` @ `return _z_transport_tx_send_fragment(ztc, n_msg, reliability, sn, peers);` | the dispatch's chain (`transport-fragmentation`) |
| 12 | the session's own subscribers, off in the reference build: `vendor/zenoh-pico/src/net/primitives.c` @ `ret = _z_session_deliver_push_locally(zn, &keyexpr->_inner, payload, encoding, kind, qos, timestamp, attachment,` | `publish_to_subscribers`, off (`local-subscriber`) |
| 13 | none | wz's own: the answer (`Asked`, `FilteredPut`, `decide_alone`), the plan (`planned_put`, `keep_plan`, `send_epoch` read twice), the publish's run (`PublishRun`), the refusal of what the pico ABI cannot state (`StatementNotHonoured::of_publish`) |

## 3. The bytes, job by job

Read over every area (a body's lines in another area counted with it):

| part | wz bodies (bytes) | wz | zenoh-pico (bytes) | pico | kind |
|------|-------------------|---:|--------------------|-----:|------|
| the engine's put | `put_on_links` 3,141, `send_on_links` 849, `decide_alone` 518, `live_to_publish` 148, `push_metadata` 126, `publish_on_wire_all` 115, `publish_filtered` 78 | 4,975 | `_z_write` 361, `_z_send_n_msg` 459, `_z_session_weak_upgrade_if_open` 181 (shared), `_z_declared_keyexpr_alias_to_wire` 112 | 1,113 | rows 1 to 8 and 13: this lane |
| the message's writer | `send_push_at`'s writer 402, `write_push` 1,615, `write_publication` 218, `write_plain_put` 42 | 2,277 | `_z_n_msg_make_push_put` 434, `_z_n_msg_make_push_del` 181, `_z_push_encode` 274, `_z_push_body_encode` 742, `_z_put_encode` 185, `_z_del_encode` 145, `_z_network_message_encode` 89, the field encoders 470, the clears 111 | 2,631 | won (codec) |
| the transmit | `dispatch_network_message_in` 1,715, `flush_conduit` 201 | 1,916 | `_z_transport_tx_send_n_msg_inner` 1,341, `_z_transport_tx_send_fragment` 433, `__unsafe_z_prepare_wbuf` 86 | 1,860 | shared by every message: transport lane |
| the doors | `publisher_write` 794, `session_write` 783, `PutCarried::fold` 540, `wire_key_of` 238, `QosLevels` 157, `PublisherQos::apply` 139, `put_options` 72, `read_moved_bytes` 60, the exports 50 | 2,833 | `_z_publisher_put_impl` 483, `_z_publisher_delete_impl` 263, `z_put` 207, `z_delete` 155, the exports and option defaults 81 | 1,189 | doors lane |

The engine's put is the gap: +3,862. Its largest body, `put_on_links`, is attributed by owner as
`engine` 1,892, `session_tables` 381, `key_arena` 173, `slot_map` 120, `bounded` 115, the
atomics 91, `direct` 85, `metadata` 46, the driver's `faces` and `face_send` 43, `wz_capi_port` 43,
the rest under 40.
The split by job below is an **estimate** from those owners and the code; the line split
(`objdump -d -l --inlines` on the case) is the main session's to read before a step past S1 is
written on it.

| job | what wz does there | estimate | zenoh-pico | kind |
|-----|--------------------|---------:|------------|------|
| filter | the decision under the take, twice (the leg's, and `decide_alone`'s for a put no leg held the session for), the row looked up, the cached verdict asked (`write_filter_row_open`), the answer kept for the legs after | 1,300 to 1,600 | one load of a state the declarations' callbacks wrote | shape (the state's place) and work (the answer of a put no leg sent) |
| key resolution | `named_at` twice (the leg, the plan), the planned key, the plan's walk of the links | 400 to 600 | `_z_declared_keyexpr_alias_to_wire` 112 | shape |
| QoS | the plain put's facts made into its send twice, a put's options' metadata, the droppable bit | 200 to 350 | `_z_n_qos_make`, inline | shape |
| batch | none in the engine's put: the dispatch's | 0 | | transport lane |
| direct delivery | the dial face's hold, the walk of the up links, the holder's marks, the publish's run | 600 to 900 | `_z_send_n_msg`'s pick of the transport and the transmit lock | shape, of which the run is the `listen` build's (const-folded here, its calls kept) |
| the plan | `planned_put`, `keep_plan`, the send epoch read twice | 400 to 600 | none | work that buys the put's instructions (a planned put names nothing and asks nothing) |
| statements | `StatementNotHonoured::of_publish` | 60 to 150 | none: the pico ABI cannot state a set of links, a retry or the all-or-none form | work |
| the take and the entries | `live_to_publish`, the three entries' `PutOn`, the answer made a `FilteredPut` | 400 to 550 | the session check | shape |

The estimates add to about 3,400 to 4,800 of the engine's put's 4,975.

## 4. Steps, by expected bytes

"Put Ir" is the put side of the perf matrix (`cpu_ns_per_msg`) and the 8 B put of the opprofile
line (`z_publisher_put` with NULL options: the planned path); "receive Ir" is the receive at arm W
(W/P about 0.757), which no step touches: no receive or delivery body changes, and no step adds a
call to the put or to the receive. Each step is read on the case's total and `put_on_links`, and
reverted when they do not move by its expectation.

| step | job | change | bytes (estimate) | put Ir | receive Ir |
|------|-----|--------|-----------------:|--------|-----------|
| **S1 (carried here)** | filter | the put's decision hands its leg the head the row's plain way keeps (`PutGoes::Plain`, `PutGoes::Options`, `Publication::head`); `leg_of` looks the row up no more, and `decide_put` and `keep_plan` look it up through one body (`filter_row`) | -40 to -100 | planned put 0; a put with options one row lookup fewer (the id's handle, the slot's generation, the way's head); the first plain put at an epoch the same | 0 |
| S2 (carried, section 6) | key resolution | `put_leg` makes the put's leg (`leg_of`) and hands it to the fan-out and to `keep_plan`, which plans with the key the leg named in place of a `named_at` of its own; `fan_out_in` stays for `wait_for_slots` and the hand-off, whose session is let go between tries | -60 to -150 | planned put and put with options 0; the first plain put at an epoch one naming fewer | 0 |
| S3 (carried) | the plan | the send epoch `decide_put` read for the plan is the one the put plans at (`plan_at`); where a `wz_round` build sends what was handed between the two, a plan kept at the earlier epoch is never taken, which costs one more put that is not planned | -30 to -60 | the first plain put at an epoch one epoch read fewer | 0 |
| S4 (carried) | key resolution | `keep_plan` walks the links only where a link names a key its own way (`shared-key-ids`); without it every link names the key as the session does, and the row's own check (`WriteFilterRow::keep_plan`) is the plan's | -60 to -150 (the walk, its `SendTo` body) | the first plain put at an epoch the walk fewer | 0 |
| S5 (carried) | QoS | a plain put's facts made into its metadata and its `SendAs` at one site, before the planned and the plain arms part | -30 to -60 | 0 | 0 |
| W-P1 (carried as a feature, section 6) | statements | the publish statements (a set of links, a retry, the all-or-none form) a capability switch of `PublishOptions` the zenoh-pico preset turns off: `StatementNotHonoured::of_publish` and `plain_put_params`' checks of them leave the case | -60 to -150 | 0 | 0 |

S1 to S5 together about -220 to -520 bytes; with W-P1 about -280 to -670.

### 4.1 Not designed as a step

- **`decide_alone`'s copy of the decision** (481). An out-of-line decision would serve both, at a
  call and its return on every put; a leg run with no face for the put no leg held the session for
  still reaches the groups of a build that joins any. No form found removes the copy without a call
  on the put's path.
- **The filter's state where zenoh-pico keeps it** (F1). zenoh-pico's put reads a state its
  filter's callbacks wrote as the declarations arrived; wz asks a verdict cached by the peers'
  count under the take. Written where a declaration is dispatched, the state would make the put's
  filter a load, take `write_filter_row_open` off the put and leave `decide_alone` nothing but a
  put whose destination admits no peer: about -600 to -1,000. It moves a search onto the dispatch
  of a declaration, a receive, so it is judged on the receive arm before it is written.
- **The publication form's size worked out by a run of its writer** (`size_hint`, a put with
  options): the transport lane's.

## 5. S1 as carried

`crates/wz-capi-coop/src/engine.rs`: `decide_put` reads the row's plain way once, after the
filter's answer, and hands its head with `PutGoes::Plain(params, head)` and
`PutGoes::Options(head)`; `put_leg` puts it in `Publication::head` (which replaces the filter id
`plan`), and `leg_of` copies it into the leg. The planned path is unchanged (the plan is read before
the way). The head of a put that is not a plain Put is handed too and not written: a link's send
writes the head only for a plain Put that carries the head's QoS (`PushParts::form`), the check
`leg_of` made a second time. `filter_row` is the one lookup of a put's row (`decide_put`,
`keep_plan`); `decide_alone` and the groups' legs discard the head, whose read is dead in their
copy of the decision.

Tests, in `tests::plain_put`:

- new: `a_put_looks_its_write_filters_row_up_once`: a first bare put at an epoch looks the row
  up twice, a planned one once, one with options once and, in a build without `shared-key-ids`,
  is still written from the head; a publish no publisher made looks up none.
- kept: `a_put_on_a_declared_key_is_written_from_its_plain_ways_head` (a bare put and a given way
  written from the row's head), `a_plain_publish_of_a_publisher_is_written_from_its_plan` (a put
  with options of a publisher written from the head; one carrying an attachment and one no
  publisher made are not), and the module's plan tests.

Commit: Change-Id `I1cbd8ba48ce05de7a454d9005db4d7c6a265e7ba`.

What the main session reads to land it: the case's total and `put_on_links` (expected -40 to
-100), `decide_alone` (expected unchanged), the 8 B put on the opprofile line (expected unchanged)
and the put side of the perf matrix (not up), the receive at arm W (unchanged); the put's `cfg`
forms compile in the default build, `listen`, `group`, `local-subscriber`, `shared-key-ids` and
the `wz_round` form (`WZ_COOP_VALUE_LOCKS=off`, with `listen` and with `group`).

## 6. S2 to S5 and W-P1 as carried

Each step is one commit on the branch `put-next`, in the order of section 4. Nothing was built,
run or measured by this lane; the figures of section 4 stay estimates until the main session reads
them.

| step | Change-Id | what changed | where it departs from section 4 |
|------|-----------|--------------|---------------------------------|
| S2 | `I69acdc682f8d67e596390151ce59873197fd2a3c` | `put_leg` makes the put's leg once (`leg_of`) and sends it by `fan_out_leg` (inlined whole); `keep_plan` takes the key that leg named. `fan_out_in` is compiled only where `wait_for_slots` or the hand-off send through it (`listen`, or `wz_round` with `group`) | the plan was made of the filter's key (`row.key()`) under the put's declaration; it is now made of the key the put was sent on, which the row's own check (`WriteFilterRow::keep_plan`, the key's text against the row's) refuses when it is not the filter's: a bare put on a key other than its filter's was planned under the filter's key and its next put written there |
| S3 | `I60327d7598a7edf02f3e5198e369f6868e595fd4` | `decide_put` reads the send epoch once for a bare put of the row's way and hands the first leg that reading (`PlainBy::Named::plan_at`); `put_leg` reads it no second time | the epoch is read where no group the session joined takes the put the general way, so a session that joined a group, whose puts are never written from a plan, keeps none; before, it planned at an epoch read apart |
| S4 | `I6ac1b36f66e9f4ddbf44fcdc3671a232155d1841` | `keep_plan` asks the links up how they name the key only with `shared-key-ids`; without it the row's own check is the plan's | without `shared-key-ids` a plan is kept while a link up is not lent at that moment, which says nothing of how it names the key; a test seam counts the links a plan asked (`Core::plan_links`) |
| S5 | `I35029f8c70744a97c2bfb937e96be25777eb2aaa` | `PutGoes::Plain` carries the facts and `PlainBy` (`Planned`, `Named`); `put_leg` makes the metadata and the `SendAs` once, before the two arms part | none |
| W-P1 | `I53c10324b84f2ce513c88b2776afd87922d92f00` | `wz-session-core`'s feature `publish-statements` (on in its `default`) holds `PublishOptions::links`, `admission_retry`, `atomic_tx` and their setters; `PublishOptions::statement` names the first one made, a constant `None` without the feature; `StatementNotHonoured::of_publish` and `plain_put_params` read it alone | not a capability of `deploy/wz-config.toml`: the pico ABI has no door that states a set of links, a retry or the all-or-none form, so turning it on in a pico build would change nothing a program can reach, and there is no choice for a preset to make. It is a fact of the graph: `wz-capi-core` and `wz-capi-c`, whose doors and faces state and honour them, name it (the tokio runtime has it by the core's `default`); the pico graph (`wz-capi-pico`, `wz-capi-coop`, `wz-capi-port`, `wz-session-mcu`, `wz-runtime-coop`, every one without the core's defaults) leaves it off; the tests of `wz-capi-port` and `wz-capi-coop` name it on a dev-dependency. Off, the fields do not exist, so no caller can state what an engine would then ignore |

The tests, and the line whose change turns each red:

- S2: `tests::plain_put::a_put_plans_its_way_by_the_key_its_leg_named` (new): two bare puts of a
  publisher whose filter is on `demo/x`, made on `demo/z` under the declaration of `demo/x`, plan
  nothing and reach the router on `demo/z`; the first put on `demo/x` after them is named and
  plans, the second is planned. Red when `keep_plan` names `row.key()` again in place of the leg's
  `named`: the first put on `demo/x` is then written from a plan a put on `demo/z` made.
- S3: `tests::plain_put::a_bare_put_reads_the_send_epoch_once` (new): one read of the epoch for the
  first bare put at an epoch and one for a planned put; none for a put with options or a given way.
  Red when `put_leg` reads `send_epoch` again for `plan_at`.
- S4: `tests::plain_put::a_plan_asks_the_links_only_where_they_name_keys_their_own_way` (new): the
  one link is asked once with `shared-key-ids` and never without; the CONTROL second put is
  planned either way. Red when the walk in `keep_plan` loses its `cfg(feature = "shared-key-ids")`.
- S5: `tests::plain_put::a_bare_put_rides_as_its_way_says_named_or_planned` (new): a best-effort
  way's named put and its planned put both reach the router best-effort (the router stand-in now
  records each sample's reliability, `Seen::reliabilities`). Red when either arm makes its
  `SendAs` from anything but the way's facts.
- W-P1: `publish_options::plain_put_tests::each_statement_a_publish_makes_is_named_in_its_order`
  (new, with the feature) and `a_build_without_the_statements_states_none` (new, without it); the
  three tests of the statements and the plain lane are compiled with the feature; kept:
  `wz-capi-port`'s `each_statement_is_refused_by_its_name_and_the_defaults_pass` and
  `wz-capi-coop`'s `tests::link_sets`. Red when `statement` names a statement by another's
  name, or answers one where the options hold none.
- Kept for every step: the module's plan tests (`the_puts_of_a_publisher_at_one_send_epoch_are_written_from_its_plan`,
  `a_put_looks_its_write_filters_row_up_once`, `a_plan_is_not_taken_once_a_peer_retracts_what_opened_its_filter`,
  `a_plan_is_made_again_over_a_link_dialled_again`), `tests::shared_key_ids`, `tests::group`, `tests::local`.

### 6.1 The plan's key

The plan stood at a send epoch for the row, not for a key: `WriteFilterRow::planned_put` read the
epoch alone, so once a publisher's way was planned, a bare put through the same filter on another
key at that epoch was written from the plan, on the filter's key. The engine's entry takes any key
(`SessionEngine::publish_filtered`); the C ABI's publisher puts on its own alone
(`FilteredKey::keyexpr`), so no program reached it there. S2 kept a plan from being made of a put
on another key; nothing kept one from being taken by it.

- `WriteFilterRow::planned_put(epoch, key)` answers the plan only for a put on the row's key,
  compared by its place first and by its bytes only where the places differ; `decide_put` hands it
  the put's key.
- `WriteFilterRow::keep_plan` leaves a standing plan as it is for a put on another key, which says
  nothing of the row's way, and still drops it for the row's key named otherwise. Before, such a put
  dropped the plan, and the next put on the row's key was named and planned again.

The planned put's instructions (the 8 B put of the opprofile line, `z_publisher_put` with NULL
options): an **estimate** of +2 to +4 Ir, nothing measured. The grounds:

- the key that put hands the engine is the text the engine lent the publisher at its declaration
  from the filter's row itself (`CoopEngine::declare_write_filter` lends
  `RowKey::of(row.key(), row.own())`, and the door hands it back, `FilteredKey::keyexpr`), so the
  compare of the place, an address and a length, decides it, and the bytes are never compared on
  that path;
- the row's text was read on the planned path already, for the planned key
  (`NamedKey::by_head`); it is read once, before the compare, and that reading is reused;
- the epoch is compared first, so a put that is not planned (the first at an epoch, one with
  options, a given way) returns where it did and pays nothing;
- the change on the keep side moves no instruction of a put on the row's key: the same text compare,
  ahead of the head's.

Bytes: an **estimate** of +16 to +48 in `put_on_links`, where `decide_put` is inlined whole: the
two compares and their branch, and behind them the bytes compare (a length compare and a call of
`memcmp`), which only a key held elsewhere reaches.

The tests, and the line whose change turns each red:

- `tests::plain_put::a_plan_is_taken_for_its_filters_key_alone` (new): with the plan of `demo/x`
  standing, a bare put on `demo/z` is named, not planned, and reaches the router on `demo/z`; the
  put on `demo/x` after it is written from the plan. Red when `planned_put` loses its key compare
  (the put on `demo/z` is planned and reaches the router on `demo/x`), or when `keep_plan` drops
  the plan for a put on another key.
- `session_tables::tests::a_plain_way_is_planned_at_one_epoch_for_its_heads_key_alone` (extended):
  the plan is answered for the row's own text and for the same bytes held elsewhere, not for
  another key, and stands after `keep_plan` of another key. Red when the key is compared by its
  place alone, when the compare goes, or when `keep_plan` drops the plan for another key.
- `tests::plain_put::a_put_plans_its_way_by_the_key_its_leg_named` (S2, its assertion moved): with
  the key compare in place, a plan made of the filter's key at a put on `demo/z` is not taken by
  the next put on `demo/z` but by the first put on `demo/x`, so the test reads that put named and
  planning (`namings`, `plans`). Still red when `keep_plan` names `row.key()` in place of the
  leg's `named`.

## 7. F1 not written

F1 (section 4.1) is left unwritten, for the reason the section gives: it moves work onto the
dispatch of a declaration a peer sends, a receive, and the owner's rule is that a step raises no
receive's instructions; whether that work stays off the receive arm is a measurement this lane
cannot make. The code adds a second reason to measure first: the put's ask is already a compare
when nothing was declared since (`SessionTables::write_filter_row_open`: the verdict kept with the
peers' write count, `PeerDeclarations::written`, read again only when that count moved), so the
put's instructions F1 would save are a load and a compare on a put after a declaration, while its
cost is a walk of the write filters, each key matched against the declared one, on every
declaration that arrives. Its bytes (`write_filter_row_open` off the put, `decide_alone` left only
the put whose destination admits no peer) are the reason to design it once the receive arm of a
declaration is read.

## 8. What the main session reads to land S2 to S5 and W-P1

- The case's total and `put_on_links` in the explain document (expected together -180 to -420
  for S2 to S5, the sum of their rows in section 4, and W-P1's -60 to -150 where `StatementNotHonoured::of_publish` and
  `plain_put_params`' statement checks leave the case); `decide_alone` unchanged; the peer and api
  cases of C1cs lower or equal.
- The 8 B put on the opprofile line (the planned path) up by no more than the key compare of
  section 6.1 (estimated +2 to +4 Ir), the put side of the perf matrix not up, the receive at arm W unchanged: no receive or delivery body changed, and no step adds a call
  to the put (`fan_out_leg` is inlined whole).
- The put's `cfg` forms compile: the default (`threads`), `listen`, `group`, `local-subscriber`,
  `shared-key-ids`, `transport-stats`, the `wz_round` form (`WZ_COOP_VALUE_LOCKS=off`, with
  `listen` and with `group`), the D12 form and `tables-on-use`; `wz-session-core` with and without
  `publish-statements`; `wz-capi-core`, `wz-capi-c` and `wz-zenoh`, which state the statements.
- The generated feature model (`sources/features/wz-session-core.scxml`, `sce_feature_model` in its
  write mode), which names the new feature.
