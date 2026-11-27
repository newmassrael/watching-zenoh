# Migration lane arch-put: the engine's put as one body

Status: steps E2 to E4 of `docs/c-abi-migration/arch-engine-own.md` (branch `arch-engine-own`),
implemented on its E1, which this branch carries as a cherry-pick. That design's reading, its
layers held twice (O1 to O6) and its target form are not repeated here; this note says what was
built, where it departs from that plan and why, and what each step is expected to move. Nothing
here was built, run or measured by this lane: every byte and instruction figure is an
**estimate** from the code, to be read on the size ledger's explain document and on the
opprofile line.

The case is `pico-client-coop-nostd` (`os-host,link-udp`, profile `capi-nostd`): one thread
(`threads` off, so `OTHER_THREADS` is a constant `false` and no `wz_round`), the dial face alone
(no `listen`, no `group`), no `query`, no `local-subscriber`. The bodies the put takes there, as
the explain document of 2026-11-27 places them (read by the arch-engine-own lane):
`put_through_filter` 2,223, `send_on_links` 1,490, `publish_to_link` 1,252, `live_to_publish` 583,
`publish_filtered` 358, `publish_everywhere` 138.

## 1. Commits

| step | commit | what |
|------|--------|------|
| E1 | `bf509756e4` | cherry-pick of `f32020936e`: the Push's form decided once, in L2 (`PushParts`, `send_push_at`) |
| E2 | `603c67d972` | a put with options asks its write filter under the take its own leg makes |
| E3 | `dd3cead3f6` | one put body: `put_on_links` and its leg `put_leg` for every put |
| E3 | `19af79303c` | the put's decision inlined into its leg; the take of a put no leg answered out of line |
| E4 | `f7d5521e8d` | the plain way keeps no copy of the declaration that names the publisher's key |

## 2. The form built

`crates/wz-capi-coop/src/engine.rs`:

- **`PutOn` and `PutBy`.** Every put is handed to one body as its key, its wire key, its payload,
  its write filter (`None` for a publish no publisher made) and what it is sent by: its options
  (`PutBy::Options`), or a plain way (`PutBy::Plain`): the facts its caller gave
  (`SessionEngine::put_plain_filtered`) or, for `None`, the way its filter's row keeps
  (`SessionEngine::publish_filtered` with no options).
- **`put_on_links`**, the one body (out of line): the statement refusal of a publish, the take
  rule, the faces' legs (`on_faces`, or `on_publish_legs` where each face's leg is sent apart),
  the put's answer, then the session's own subscribers. `publish_filtered`, `put_plain_filtered`
  and `publish_on_wire_all` each build a `PutOn` and call it.
- **`put_leg`**, inlined into it: the pre-take rules of a publish, the take
  (`live_to_publish`), the decision (`decide_put`, inlined), then one of: the plan's send (the
  planned path, unchanged: `send_on_links` from the plan's head, nothing named), or one
  `Publication` sent by the publish's run (`PublishRun`, `fan_out_in`, `wait_for_slots`), and the
  plan kept after the first plain put of an epoch (`keep_plan`).
- **`decide_put`**: the filter's row looked up once, for the plan, the filter's answer and the
  plain way. The first leg asks the filter; a plain put is also asked whether it is plain on this
  node (a subscriber of the session that wants it, a group the general publish reaches) and
  whether its destination admits a peer.
- **`Asked`**: what the first leg that held the session answered (`Through`, `HeldBack`,
  `NotPlain`), so the legs after it neither take the session to learn it nor change it.
  `decide_alone` answers a put no leg held the session for (no link took it, its destination
  admits no peer, it was dropped first) by one take of its own, and a publish no publisher made by
  none.
- `Publication` carries the facts a link is sent by (`kind`, `meta`, `send`) in place of the
  options, so the plain put and the publish share `leg_of`, `fan_out_in`, `publish_alone` and
  `wait_for_slots`. Gone: `put_through_filter`, `put_through_filter_in`, `put_plain_in`,
  `plain_off_the_wire`, `put_plain_on_groups` (now `put_plain_groups_leg`), `put_planned`,
  `send_plain`, `publish_to_link`, `publish_to_link_on`, `publish_everywhere`, `Holding`,
  `fold_filtered` and its tests (replaced by `asked_tests`).

`crates/wz-session-core/src/session_tables.rs`: `PlainWay` is `{ params, head }`;
`keep_write_filter_plain` reads only the declaration's id, for the head.

## 3. Where this departs from the arch-engine-own plan

1. **A plain put keeps its take rule.** The plan had a threaded build drop a droppable bare put
   on a held face, as a publish is. The rules a publish follows before the session is taken (the
   try of a droppable put, the blocking put's wait for its link's room, its send with the face
   alone) need its reliability, congestion and priority before the take; a bare put's lie in its
   filter's row, read under the take, and reading them first is the second take E2 removes. So a
   plain put is taken as a put that may not be dropped and sent under the take, as it was; the
   pre-take rules act on a publish, whose options say how before it. A single-threaded build
   cannot tell the two apart. What lets the bare put follow them is its way readable without the
   lock (the send plan published with its droppable bit, `S-PLAN` of
   `docs/win-budget/ir-send-query.md`).
2. **A plain put is sent by the publish's run.** In a `wz_round` build with `listen` or `group`
   it now sends what was handed to the session before and after it, as a publish does; in a
   `listen` build whose links share fewer outbound slots than they are, a plain put that may not
   be dropped (read from its way under the take) probes and waits for a slot with nothing of the
   session held (`wait_for_slots`), where it waited under the session's lock. The planned path
   stays as it was: every face, each send the caller's own.
3. **E4's owner.** The plan made the filter's row the one owner of the publisher's way and had
   the door keep only the filter's id. A put with options must know before the take whether it
   may be dropped and on which priority it waits (point 1), so the door's declared QoS stays the
   owner of those facts, as zenoh-pico's publisher holds them and hands them to `_z_write`
   (`vendor/zenoh-pico/src/api/api.c` @ `ret = _z_write(session, &pub->_key, payload_bytes, &encoding, Z_SAMPLE_KIND_PUT, pub->_congestion_control,`).
   What was held three times is the declaration that names the publisher's key: the door's wire
   key, the row's own hold of it (`WriteFilterRow::own`) and the plain way's `key`. The last is
   gone: every put is named by the wire key its publisher hands (`wire.declared()`, since E3), and
   the way keeps only what it writes from it, the head. Left held twice: `PlainPutParams` in the
   row beside the door's `QosLevels`, until the bare put's facts are readable before the take.
4. **A publish's statement is refused before its filter is asked.** A publish that states a set
   of links, a retry or the all-or-none form was answered `Suppressed` when its filter held it
   back; it is now refused whatever the filter says, as a refusal of the call.
5. **A dropped put is counted before its filter is read.** A droppable put of a threaded build
   that finds its face or the session held is dropped (and counted by `transport-stats` as a
   drop) before any leg asked its filter; the put is still answered `Suppressed` when its filter,
   asked then, holds it back, as zenoh-pico's put is. A put handed off (`wz_round`) is handed only
   when its filter lets it through.

## 4. Steps: bytes, instructions and the tests that hold them

"Put Ir" is the 8 B put of the opprofile line (`z_publisher_put` with NULL options: the planned
path); "receive Ir" is the receive's slope (about 3,070 a message, W/P about 0.76), which no step
touches: no receive body changed.

| step | bodies read | case total (estimate) | put Ir (8 B) | put with options | receive Ir | tests that hold it |
|------|-------------|----------------------:|--------------|------------------|-----------|--------------------|
| E2 | `publish_filtered`, `publish_everywhere`, `publish_to_link` | -50 to +100 alone: the filter's separate take goes from `publish_filtered`, and `SessionEngine::write_filter_holds_back` has no caller left in the case (the querier's is `query`'s); the leg's check and the fallback take come in | 0 (not on its path) | one take of the session fewer | 0 | `tests::plain_put::a_put_with_options_asks_its_filter_under_its_own_take` (new); `tests::a_filtered_publish_is_held_back_then_sent` |
| E3 | `put_through_filter` 2,223, `publish_to_link` 1,252, `publish_filtered` 358, `publish_everywhere` 138 against `put_on_links`, `decide_alone` | -800 to -2,000 with E2: one take path, one row lookup, one key naming and one send site for every unplanned put; the plain put's own parts (the plan, its way, `keep_plan`) stay | equal within about 30: the same calls to take and let go (`live_to_publish`, `live`, the hold's drop in place of `hold_dial` and `DialHeld`'s drop), the `PutOn` and the answer's cell added | equal | 0 | new: `tests::plain_put::{a_put_with_no_link_up_is_answered_under_one_take, a_plain_put_for_the_session_alone_reaches_no_link}`, `engine::asked_tests::{the_first_leg_answers_the_put, a_put_answered_unsent_stops_the_legs_after_it}`; kept: every `tests::plain_put` test (takes, namings, plans, planned heads, face marks), `tests::shared_key_ids`, `tests::group::a_bare_put_through_its_filter_reaches_the_group_the_plain_way`, `tests::local` |
| E3 (inline) | `put_on_links`, `decide_alone` | 0 to +200: a second copy of the decision, in the out-of-line take of a put no leg answered | no call added: the decision is read in the leg's body | equal | 0 | as E3 |
| E4 | `keep_write_filter_plain` | -40 to -120, and one `KeyexprRef` less in each write filter row's plain way | 0 | 0 | 0 | `session_tables::tests::{a_key_is_named_at_its_declarations_row, a_plain_way_carries_the_head_of_its_declaration, a_plain_way_is_planned_at_one_epoch_for_its_heads_key_alone}`; the plan tests of `tests::plain_put` |

Together about -0.9 KB to -2.0 KB on the case (E1's -300 to -600 apart).

## 5. What the main session reads to land it

- The case's total and `put_on_links` in the explain document against the bodies of section 1:
  the total must fall.
- The 8 B put on the opprofile line, which may not rise, and the receive's slope, which does not
  move.
- The feature forms the put's `cfg` arms compile in: the default (`threads`, the dial face
  alone), `listen`, `group`, `local-subscriber`, `shared-key-ids`, `transport-stats`, and the
  `wz_round` form (`WZ_COOP_VALUE_LOCKS=off`, with `listen` and with `group`).

The notes under `docs/win-budget/` (`size.md`, `ir-send-query.md`, `ir-multicast.md`) name the
bodies this lane merged by their old names; their readings predate it.
