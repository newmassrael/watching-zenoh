# The C ABI library: target architecture

Status: decision of the owner, 2026-11-23 («비용 무시하고 가장 장기적으로 올바른 궁극적인 구조로 학술적으로
교과서적이게 설계해»). It extends `docs/c-abi-engine-and-memory.md` (one sans-I/O engine, no heap after
open) and `docs/c-abi-no-heap-pools.md` (the pools), and it is the reference every size and
structure change of the pico and zenoh-c presets is judged against.

## 1. Why a new structure: what is measured

The release form (`os-host`, no `std`, `capi-nostd` profile) against zenoh-pico
built as the same build, function bytes with aliases of one address counted once (int5, 2026-11-23):

| area | wz | zenoh-pico | ratio |
|---|---:|---:|---:|
| sessions, routing, entities (declare, subscribe, query, reply, interest) | 106,043 | 27,666 | 3.83 |
| C ABI doors (`z_*`, `zp_*`) | 77,243 | 16,926 | 4.56 |
| transport (establishment, tx, rx) | 65,315 | 18,731 | 3.49 |
| runtime / driver | 27,322 | 6,639 | 4.12 |
| key expressions | 19,914 | 13,284 | 1.50 |
| wire codec | 37,861 | 36,462 | 1.04 |
| language support (Rust core/alloc/drop glue; zenoh-pico's collections and buffers) | 35,627 | 32,570 | 1.09 |
| total | 379,112 | 170,500 | 2.22 |

The codec and the language support are at parity. The excess is in the four areas where wz has a
LAYER of its own above another layer that already holds the same fact: `wz-session-core`, written
for every engine, holds the session's tables; the cooperative engine (`wz-capi-coop`) holds a
registry, a target table, a key table and a delivery lane of its own over them; the port
(`wz-capi-port`) re-describes the engine as a trait; the doors (`wz-capi-pico`) keep marshals and
copies of what the engine already holds. Each layer has its own tables, its own dispatch and its
own owned copy of what crosses it. Local folding inside those layers removed 2 to 6 KB per change;
the structure itself costs the other 200 KB.

## 2. Principles

P1. **One fact, one owner.** Every piece of session state (a declaration, a subscription, a
pending query, a key, a link's sequence numbers) lives in exactly one table, in exactly one layer.
Other layers name it by a handle; none keeps a copy.

P2. **Sans-I/O cores, drivers outside.** The protocol is a pure state machine over bytes and time
(`process(input, now) -> effects`); it performs no I/O, takes no lock, spawns nothing. Drivers
(caller-driven, driver thread, async adapter, router thread-per-core) feed it. (Brett Cannon's
sans-I/O, the `quinn-proto` / `rustls` structure.)

P3. **Region memory.** A session is one region sized at build time from the limits
(`wz_config.py` generates the capacities) and reserved at open; every table is a fixed-capacity
pool inside it addressed by a generation-checked index (slot map). Exhaustion is an error code at
the call that asks, never a panic and never a growth. No reference counting inside a session:
one owner (the session), borrowed by its driver. A value several parts of the session reach (its
round of deliveries) lies in the region, owned by one `Placed` and reached by `PlacedRef`
handles that count nothing; whoever takes a handle (`Placed::share`) answers that no copy of it
is dereferenced after the owner is dropped or beside a `&mut` the owner gave, which the owner's
place among the session's fields, dropped after every holder of a handle, keeps.

P4. **Zero-copy views.** Received bytes are read where they lie; a decoded message is a view whose
lifetime is the receive buffer's. Outgoing bytes are encoded into a lent slot. An owned message
exists only where an application asks to keep one, and then in a pool.

P5. **Static composition.** A build links exactly one engine, one platform and one feature set;
generics are instantiated once (one `L, C` per build), trait objects appear only at the edges a
program supplies at run time (its transport, its callbacks). Shared logic over several types is a
non-generic core plus thin typed wrappers.

P6. **Total functions in release paths.** No panic is reachable from input: indexing is checked by
construction (`get`, iterators, views of known length), arithmetic is checked or saturating,
every refusal is a value. Enforced by lints on the core crates
(`clippy::indexing_slicing`, `unwrap_used`, `expect_used`, `panic`, `arithmetic_side_effects`,
and the other panicking macros `unreachable`, `todo` and `unimplemented`, in non-test code;
section 7) and by the size gate (the formatting machinery a panic path drags in is a symbol the
gate forbids). An `assert!` outside a test is a panic no lint names; it is converted with the
module that holds it.

P7. **The C ABI is a façade.** A door validates its arguments once, maps the C handle to a slot
handle, calls the session core, and maps the result to the C code. It owns no state but the
process pools of objects made before a session (configs, payloads, hellos; decision Q1) and keeps
no copy of anything the core holds.

P8. **Specification first.** Every state machine (transport establishment, lease, interest,
query lifecycle) is an SCXML document generated by SCE; hand-written code is the data plane
around it. Behaviour is fixed by differential tests against zenoh-pico (its own tests and
examples, run on the release library) and against upstream zenoh.

P9. **Measured budgets per area.** The size ledger of section 1 is a gate: each area has a ratio
ratchet against zenoh-pico's same area, so a change that grows an area is refused where it grows,
not only in the total.

P10. **Typed outcomes, no sentinels.** Every operation that can be refused returns
`Result<Handle, Refusal>` at every layer boundary (L3 to the port, the port to L4). A handle is a
generation-checked slot index whose index part is `NonZero`, so `Option<Handle>` costs nothing
and no value of the handle type means "refused". `Refusal` names the cause the caller can act on
(`TableFull`, `KeyTooLong`, `NoEntityId`, `Closed`, `NotBuilt`); each preset ABI maps it to its
own codes in ONE table owned by its façade (zenoh-pico: `_Z_ERR_SYSTEM_OUT_OF_MEMORY` for the
first three, `_Z_ERR_SESSION_CLOSED` for `Closed`). Measured why: a matching listener the
cooperative engine refused came back as id 0, which the AP engine hands out as a live id, so the
door could not tell a refusal from a listener and answered `Z_OK` for one that would never be
called.

P11. **A callback's lifetime is a property of its row.** A row holds its callback in an
`Fn`-shaped form (a C `(call, context, drop)` triple, or a shared Rust `Fn`), so a call is a
shared borrow and reentrance is sound, as zenoh-pico's is. Undeclaring a row returns after the
last running call of it has returned and its `drop` has run (zenoh-pico holds the entity's lock
across the call and clears the closure under it). The row, not each entity's door, carries that
protocol, so no entity can lack it. Measured why: the matching listener was the one entity whose
door did not wait, and zenoh-pico's own test of drop-on-undeclare found it.

P12. **zenoh-pico's programs are the behavioural specification.** Its API tests and examples run
on the release library in the environment its own CI gives them (a network namespace per
program, `lo` with multicast on). A program is judged only where it passes on zenoh-pico in that
same run (the control). A wz failure where the control passes is a defect of wz whatever its
cause. A program that fails on zenoh-pico itself by its construction is listed with that reason
and its feature is measured by a sibling program; it is never retried until it passes.

## 3. The layers

```
  C program
     │  z_* / zp_* / zext_*            L4  façade        wz-capi-pico (one crate per preset ABI)
     ▼
  session core: entities, keys, routing  L3  session       wz-session-core (one table set)
     ▼
  transport: establishment, lease, sn,   L2  transport     wz-session-core::transport (sans-I/O)
  batching, fragmentation, reassembly
     ▼
  wire codec: views and lent encoders    L1  codec         wz-codecs (SCE generated)
     ▼
  driver: wait set, timers, read task    L0  driver        wz-runtime-coop + wz-runtime-posix/windows/zephyr
```

- **L1 codec.** Already at parity. Remaining: the generator's per-file panic locations keep
  identical decode functions from folding (SCE proposal P1/P2, `peek_array`/`peek_u8`).
- **L2 transport.** One implementation of establishment, lease, sequence numbers, batching and
  reassembly, judged from views (`ControlFacts`), driven by the SCE transport machine. It owns the
  link records (one pool), the tx batch slots and the reassembly chains.
- **L3 session.** One table set: key arena, declared key expressions, local entities
  (publishers, subscribers, queryables, tokens, matching listeners), remote declarations per face,
  pending queries and replies, interests. Routing/matching is a function over these tables. The
  callback of a local entity is stored in the entity's row (a C function pointer and context, or
  a Rust closure in a pool row); delivery calls it from the row, holding the row pinned, with no
  intermediate lane and no copy. A callback is a `Fn`, called through a shared borrow: a C
  closure's function, context and drop held as they are, a Rust closure an `Arc<dyn Fn + Send +
  Sync>` as upstream zenoh's. So it is called with no lock held, from any thread and from inside
  itself, as zenoh-pico calls it (a put a callback makes on its own subscriber's key reaches it
  again at once; `wz_ext.h`, "callbacks"), and it is let go of once, after its last call.
- **L0 driver.** The wait set, the timer wheel and the read task. It owns no protocol state. One
  task table, reserved at open.
- **L4 façade.** As P7. The port trait (`wz-capi-port`) disappears from the release build: the
  façade calls L3 of the one engine the build has (P5). The trait remains only where a second
  engine is genuinely selected at build time, and then as a generic parameter instantiated once,
  not a trait object.

The AP (tokio) engine and the router are other DRIVERS of the same L2/L3 (the router adds a
routing table to L3 behind a feature). No engine keeps protocol tables of its own.

## 4. What moves (from the measured structure)

| today | target |
|---|---|
| `wz-capi-coop` registry, targets, keyexprs, held queries, delivery lane, its own key table | L3 rows (one table each); the lane is removed: delivery calls the row's callback |
| `wz-capi-port` trait objects between doors and engine | direct calls into L3 of the build's engine |
| door marshals copying keys, payloads, options | views lent for the length of the call; a copy only when the program keeps the object |
| owned `InboundFrame` for control messages | `ControlFacts` views (landed on branch size-handshake) |
| `Rc`/`Arc`/`Mutex` per entity and per callback | one session lock at the façade (as zenoh-pico's session mutex); rows are plain data |
| `HashMap` and `Vec` growth after open | slot maps and fixed tables in the session region |
| per-file panic locations, `expect` messages | total functions (P6) |

## 5. Migration

Each phase keeps every test green, is measured against the ledger, and lands on its own:

1. **Ledger gate (P9).** `scripts/lib/size_ledger_gate.py`: area classification of both
   libraries, a ratio ratchet per area in `deploy/size_ledger.json`, run in Layer C1cs beside the
   total. Each byte of a function goes to the source file its line table names (the innermost
   location, so a helper fat LTO inlined into a door stays in the helper's area; inlined Rust
   core, alloc and std code goes to its innermost caller outside them, as the same work in C is
   the caller's own operators and macros, and only an out-of-line standard library body is
   language support), read from the
   library's one build, which carries its line tables and is measured and shipped with its debug
   information taken off (its executable sections held to the build's byte for byte); that file's crate::module (wz) or export path (zenoh-pico) is placed by
   the owner rules, and bytes of no source line are counted apart under a limit of their own. The
   section 1 table was read the earlier way, a whole body to the area of its symbol, which put
   inlined helpers in their caller's area. Its `--explain` says what holds an area's bytes (wz
   modules, source files, bodies and generic copies, zenoh-pico files), with the symbol reading's
   bytes beside each area, and keeps the whole lists as JSON to diff.
2. **Totality lints (P6)** on `wz-session-core`, `wz-capi-coop`, `wz-capi-pico`,
   `wz-runtime-coop` in non-test code, debt rows for the sites that remain, paid largest first.
   The lints are denied at each crate root; the modules that remain are the register of
   section 7, held by `scripts/lib/totality_debt_gate.py`.
3. **Transport views (L2).** Landed. Every participant's receive reads a JOIN and a transport OAM
   (a ZBuf body and ZBuf extensions included) by its view and keeps nothing of it: in place, into
   the receive's slot (`InboundFrame::Refused`), and on a group's walk. The decode that keeps
   them whole is the observer's (`parse_inbound`).
4. **One table set (L3).** The cooperative engine's registry, targets and key table fold into
   the session core's rows; the delivery lane is removed (callback in the row). The largest phase:
   one entity kind at a time (subscribers, then queryables, then tokens, then queries/replies).
5. **Thin façade (L4).** Doors call L3 directly; marshals lend views; the port trait leaves the
   release build.
6. **Thin driver (L0).** The engine crate keeps only the wait set, timers and the read task.
   Each fact the cooperative engine holds today goes to the layer that owns it:

   | fact (today in `wz-capi-coop`) | owner |
   |---|---|
   | the session lock, the read task (`start_reader`), the wait set (`LinkWaits`, `IdleWait`, the waits of `LinkRooms`, the clock's wake), the task and timer tables, the reservation of the region | L0 |
   | each face's link lifecycle (`LinkSupervisor`'s link states, `poll_face`, `dial`, `redial_later`), making a link's session (`start_wire`: its parameters, cookie key, admission, gates, cells), the reassembly Router, the endpoints' rows, a face's send state (the held drop, `sending_on`) and the hand-off of a dropped publish to the other faces | L2 |
   | the entity tables and their counters, the keys and the shared key ids, the query plane and pending gets, the round of deliveries, the declaration watches, the face reports, what a face that comes up is told again (`replay`), which faces a publish goes to | L3 |
   | the places of the ABI's handle and objects | L4 |

   Steps, each landing on its own:
   - **6a region.** The arena's plan is the sum of each layer's rows (`TransportRows` for L2,
     `SessionRows` for L3, `PlaceRows` for L4); L0 adds them up, reserves the region and opens
     one `TableLender` over it, which each layer lends its own tables from, with one refusal asked
     at the end.
   - **6b face lifecycle.** L2 holds a sans-I/O transport value that answers each step with
     effects (dial, a link opened, a face gone); L0 carries them out over the stack and the task
     table.
   - **6c sending.** L3's routing names the faces; L2's face sends, drops or hands the publish off,
     the hand-off kept in rows of the region.
   - **6d session state and delivery.** With phase 4.
7. **SCE codegen totality** (SCE change, reviewed by an SCE session, then a pin move).

Targets: every area at or under zenoh-pico's ratio 1.0 locked; allocations after open 0 in every
family; every cell of the host performance matrix WIN, on Linux and on pc3-win.

## 6. Rejected alternatives

- **Keep the layers and diet each.** Measured: 2–6 KB per change against a 200 KB excess.
- **A second, MCU-only engine.** Two engines diverge (`c-abi-engine-and-memory.md` E1); the target
  is one L2/L3 with several drivers.
- **nightly `build-std` with `panic_immediate_abort`.** It removes the panic machinery's bytes
  without removing the panics; P6 removes the panics. It stays a possible addition, not the design.

## 7. Totality debt register

The six crates deny the totality lints outside a test build, at their roots:

```rust
#![cfg_attr(
    not(test),
    deny(
        clippy::indexing_slicing,
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::unreachable,
        clippy::todo,
        clippy::unimplemented,
        clippy::arithmetic_side_effects
    )
)]
```

A module not yet converted is allowed the lints it still needs by name, at its declaration in the
crate root, under the line that names its row here (`// Totality debt TD-NNN
(docs/c-abi-architecture.md section 7).`). Nothing else may allow a totality lint: no allow on an
item, no inner allow, no `cfg_attr` or `expect` form, no `clippy::restriction`. New code is total,
so the register only shrinks: `scripts/lib/totality_debt_gate.py` refuses a row past the last id
given (TD-229) and holds the register's lint cells (0) to its ratchet, which a paid row
lowers in its own commit. The ratchet moves up only when a crate is brought under the lints, in a
commit that adds that crate's rows and changes no code: `wz-session-mcu` came in so with TD-207 to
TD-227, and `wz-capi-port` with TD-228 and TD-229. For the lints a text read decides (`unwrap_used`, `expect_used` and the panicking macros)
it also holds each row to its module's sites, both ways; indexing and arithmetic are held by the
build's clippy alone.

A module leaves the register when its sites are total functions: `get`, iterators and views of a
known length for indexing; checked or saturating arithmetic where the operands are not bounded by
construction; a refusal returned as a value where the old code panicked. Paid in the change that
switched the lints on, on the release library's path (`pico-client-coop-nostd`): in
`wz-runtime-coop` the critical sections, the timer table, the link storage, the task table, the
in-place reassembly and the datagram link; in `wz-capi-coop` the arena plan and the datagram
scout. Paid by the generator: the buffer pools `session_slot_pool_mcu` and
`reassembly_pool_mcu`, whose slot tables SCE reaches through a slot type with no value out of
range; `keyexpr_match`, whose algorithms compute every operation the interval analysis proved
through the forge runtime's `proven` functions, a shift by a count below its width included
(`proven::shl` and `proven::shr` in `keyexpr_relation_dp`); and `reset_generations`, whose
tagged result answers the record of a case as an `Option` (`as_duplicate`) where it panicked on
another case. A module the text read found no site in is not in the register.

The classes: **open**, hand-written code not converted yet; **in flight**, a module another branch
is restructuring now (the cooperative engine of step 4, the session core's entity modules, the pico
doors of step 5), converted as it lands;
**generated**, SCE output, whose totality is the generator's (step 7). `sites` is the text count of candidate sites when the row was made, which
orders the payment (largest first) and is not a measurement of what clippy reports. The rows of
`wz-session-mcu` count clippy's own reports instead, over the crate's default build, its build
with every feature, and its build with every feature but `session-slot`, which takes three modules
out; those of `wz-capi-port` over its default build and its build with every feature.

The register holds no row: no module of the six crates is allowed a totality lint.

| id | crate | module | lints | sites | class |
|---|---|---|---|---:|---|

A `WZ_POLICY_*` value no policy takes is refused with neither a panic nor an index: the helpers of
`policy.rs` answer `None` for such a word, a policy's value is found by its word in arrays that
share their length by type, and `policy_generated.rs`, which `wz_config.py` writes, refuses the
`None` in a constant assertion, the form `caps.rs` refuses a misspelt `WZ_LIMIT_*` value in. A
generated key table is checked the other way: the library answers `try_new`, and the
image's own crate, which `wz_key_set.py` writes, turns a refusal into the build error.

SCE's forge runtime makes a list whose bounds the build checks with constructors that cannot
fail: `Bounded::one` for a list of one entry, `Bounded::proven` for an array, and
`Bounded::widened` for a list held within bounds as narrow or narrower, each checking its bounds
in a `const`. `held_list::one_entry` and its fixed-capacity twin `lent_control::chain_of` are `Bounded::one`,
and `NamedKeyexpr` holds its body as a buffer within `NAMED_KEYEXPR_BYTES`, which
`Bounded::widened` lends to the `ZBuf`'s u32 bound.
The one QoS entry of a Push's outer chain (`lent_push::put_with_qos`) is `Bounded::one` too.
A `SessionZid` holds its bytes within one to sixteen, the bounds of the codec's zid field, and
lends them through `Bounded::as_bytes` (`SessionZid::as_field`), so the Scout's zid
(`scouting_host`) needs no check.
The multicast beacon (`multicast_join`) is total the same way: its QoS SN body is an
`ArraySink` the build admits only where the array holds the widest write
(`[[Vle<u64>; 2]; Priority::NUM]`, whose most bytes size the array), lent to the `ZBuf` as
`Bytes` with no check, and its zid is `SessionZid::as_field`. `encode_join_into` then refuses
only what its sink refuses, and `encode_join`, over a `VecSink` that refuses nothing, has no
refusal left.

The transmit buffer names its refusal (`TxBuf::Error`, `CodecError` for every buffer today). A body
a send hands its dispatch can refuse its own message (a key or a payload past its protocol bound),
whatever buffer it is written into, so a heap send answers that refusal as a value
(`SendWireError::Codec`, `PushOutcome::Refused`); an owned message, which its writer cannot
refuse, is framed through the codec's own vector sink, which refuses no write.

`bounded` left the register with one panic no lint names: `BoundedVec::remove` keeps
`Vec::remove`'s documented panic for an index past the end (an `assert!` on the lent backing,
which guards the unsafe move). Its value form, `Option<T>`, moves the callers in the cooperative
engine and the entity modules, and is converted with them.

## 8. The read: every face read where it lies, no round

Status: decision of the owner, 2026-11-25. It replaces the round of deliveries and the executor's
per-message pass in every build, and it is the structure the L0 driver of section 5 step 6 keeps.

### 8.1 What is measured, and why the round goes

The shipped nostd form (the pico preset's `zenoh-pico_defconfig` limits, features `os-posix`,
`link-udp`, `scout`, `peer`, `multicast-transport`, `query`, `queryable`, `liveliness`,
`liveliness-get`, `multi-thread`) reads one received message in 6,097 instructions against
zenoh-pico's 2,941 (2026-11-25, callgrind, exclusive costs). The preset turns `multi-thread` on,
and with it `threads`, `listen` (`peer`) and `group` (`multicast-transport`): every shipped
build reads through the round. The executor's pass and the round account for about 1.2 K of the
3.2 K excess: `run_among`, `poll_erased`, `step_after`, `Core::idle_wait`, `hand_out`,
`RoundDelivery::deliver_ref`, `Round::writable`, the walk of every holder's deadlines
(`ManyHolders`, `keepalive_deadlines`) and the wait set gathered again for each message.

The round exists because a read stepped every face of the session under the session's lock as
tasks of one local set, so a record could not be handed to its callback where it was read: the
lock was held, and the next face's task was still to run. Once each face is read on its own, under
a lock of its own, nothing stands between the record and its callback.

### 8.2 The structure

As zenoh-pico's read task per transport (`_zp_unicast_read_task`, `_zp_multicast_read_task`)
and upstream zenoh's receive task per link, a link's read decodes what the link holds as soon as
the link is ready and hands each record to its subscribers where it is read: no queue between the
decode and the callback, and no pass of an executor per message.

- **With `threads`**: every face (the dial role's link, each link a port accepted, each group)
  has a read task of its own, blocked on that face's link alone and stepping that face's pump.
  Faces are read in parallel; one face is read by one thread at a time.
- **Without `threads`**: the program's read waits on one wait set of every face and port, and
  steps the pump of the face that is ready, at once.
- Both are one body: the read of a set of faces (`read_faces`), whose set is one face for a face's
  task and every face for the program's read. There is no second path chosen by configuration at
  run time and no path kept for a session of one face.
- **The executor keeps the timers alone**: keep-alive, lease, a get's deadline, the pace of a
  replay, the periodic jobs and the reassembly sweep. It holds no link task and runs nothing per
  message. With `threads` its turn is the lease task's (zenoh-pico's `_zp_lease_task`); without,
  it is the wait set's timeout and the look after the wait.

### 8.3 Who owns each face's read

| face | read slot holds | made | read by (threads / one thread) |
|---|---|---|---|
| dial role | the link's pump (receive state, sequence numbers, the Router it stages fragments in), its records, the dial under way | at the open, kept for the session's life | its task / the program's read |
| accepted | the same, for the accepted link | by the port's accept | its task, started by the accept / the program's read |
| group | the group's pump (the members' receive order, their leases, the JOIN it reads) | at the join | its task / the program's read |
| port | the listener | at the open | the port's task / the program's read |

A face is two places: its **read slot** (the pump and the records being read) and its **send
place** (the wire: the batch being written, the transmit sequence numbers, the link's send half).
A read holds the slot for the length of one step of the pump; a send holds the send place for the
length of one write. A record read holds no send place, so a callback that sends on the face it is
called from finds the send place free.

Each lock is the form's (`LockForm`): the host's or the kernel's mutex with `threads`, a flag
without. What a face lends its link's session (its link state, its actions) is held under the
runtime's lock kind (`LockKind`); with `threads` that kind is a lock per value on every target,
the kernel's where there is no host lock, because a face's read reaches those values without the
session's lock.

### 8.4 Lock order

```
read slot  ->  send place  ->  session (Core)  ->  a row's latch
```

- A thread takes a face's place before the session's lock, never after. A step of a pump holds the
  read slot, and takes the session's lock once for each record it dispatches, letting it go before
  the record's callbacks are called.
- No thread holds two faces' read slots. A publish that reaches several faces takes their send
  places one at a time, each let go before the next is taken.
- Every other operation that sends (a declaration, an undeclaration, a get, a reply) holds the
  send place of every face whose place holds a link, in the order of the face table, and then the
  session's lock, as the writer of a big-reader lock takes every reader's lock in one order: what
  it tells any face under the session's lock is written through a place it holds, so nothing is
  left owed to a face whose place another holder had, and no retraction has to be kept for later.
  The places are taken in one order and a publish holds one at a time, so no two holders wait on
  each other. A place that held no link when the faces were walked is not held and is reached by
  a try, which nothing else holds in a build of one thread. With `threads` the walk holds a place
  whether or not it holds a link (step 4), so a link seated after the walk is held too.
- A callback is called with no lock held but the read slot of the face its record came from.

### 8.5 A callback that calls the session

- **A put, a get, a reply** take send places and the session's lock: never the read slot, so they
  finish while the read that called the callback holds it.
- **Another thread's put that waits for something** (a get's reply, a full batch flushed) finishes
  too: no read slot is held by the thread it waits on, except the one whose callback runs, and that
  thread holds no session lock.
- **A read from inside a callback** reads nothing: the slot is held, and the slot's owner word (the
  thread that holds it) tells a read on the same thread to return at once rather than wait for
  itself. A read on another thread reads the other faces.
- **An undeclare** waits for the calls of the row in flight on other threads (the row's latch) and
  not for the call of its own thread, so an undeclare inside the row's own callback returns, and the
  row is told gone once: the latch's last release lets the callback go.
- **A close** ends every face's life under the session's lock and asks each read to stop. A face's
  read sees the end once its step returns, lets the pump go, and its task ends; the close does not
  wait for a read on its own thread.

### 8.6 A change of a face's site without a deadlock

A face is added, taken out or given a new link by a thread that may hold the session's lock (an
accept found while the session settles, a lost link seen by the lease timer). Taking the face's
place there would invert the order of 8.4. So a change of a site is written into the face table
under the session's lock as a debt of the face (its ledger), and carried out after the lock is let
go, by taking the face's place first and the session's lock after it. The read that holds the
place pays the face's debts when it lets the place go; a read that finds its face ended lets the
pump go and does not take the session for it. A redeclare told on a face that came up is a debt of
the same kind: its first lap is the face's to run, and a declaration made before that lap is told
once, by the lap.

### 8.7 The life of an accepted face

1. The port's read (its task, or the program's read on the port's readiness) accepts the link and,
   under the session's lock, takes a free row of the face table, which the open reserved; a full
   table refuses the link and closes it.
2. The face's read slot and send place are made in that row's place, the face's handshake runs on
   its read, and the face is told up under the session's lock (its tables, its replay).
3. With `threads` the accept starts the face's read task from the task table the open reserved
   (one entry per face); a table with no entry left refuses the link as a full face table does.
4. When the link is lost or its lease ends, the face's life ends under the session's lock; its read
   sees the end, lets the pump go and stops; the face's tables go under the face's place and then
   the session's lock (8.6), and the row is free for the next accept once its last hold went.

### 8.8 The read of a group

A group is one face over one socket shared by many members. Its read slot holds the group's pump:
each datagram is read whole, its source names the member, the member's receive order and lease are
the pump's, and each record is dispatched under the session's lock and handed out where it is read,
as a unicast face's. A JOIN admits a member under the session's lock. What the session sends on the
group is written through the group's send place by the sending thread, as zenoh-pico's put writes a
multicast message on its caller's thread; the timers send the JOIN beacon and sweep the members'
leases.

### 8.9 What the read costs

Per message, a read pays the decode, one take of the session's lock for the dispatch, and the
callbacks. Per datagram it pays one wait, one reading of the clock (the lease's last-heard time,
written by the read, read by the lease timer) and nothing else of the timers: no gathering of
deadlines, no division of a 64-bit number, no executor pass. Shipped nostd adds no runtime symbol.

### 8.10 Tests

Each holds for every form that builds it (`threads`, `listen`, `group`, and their absence):

- a callback in which another thread puts and waits for the put to be sent returns, and both end;
- a slow callback on one face does not hold up another thread's put on that face or another;
- an undeclare inside the row's own callback is told to the peer once, and the callback is let go
  once, after its last call;
- puts from several threads on one face reach the peer as whole frames, none interleaved;
- a listening peer delivers what each of its faces received in that face's order;
- a group's member is read and delivered with no unicast face open;
- the refusals: an accept past the face table, a read task past the task table, a read from inside
  a callback (reads nothing), a build without `threads` (the program's read steps every face).

### 8.11 Steps

Each lands on its own, builds and passes its tests:

1. **Locks.** The runtime's lock per value in every `threads` build, the kernel's mutex where there
   is no host lock; a hold of a place as a value (`HoldKind`) for the read slot and the send place.
2. **Accepted faces read directly.** The read slot and send place per face row; the port's accept
   and the face's read task; the site changes of 8.6.
3. **Groups read directly.**
4. **`threads` reads directly**: the read task per face; the executor keeps the timers.
5. **The round goes**: `round.rs`, `HandBack`, `RoundDelivery`'s round, the work form's step and
   its `cfg` (`wz_round`, `KEEP_THE_ROUND`).

Judged by the shipped form's instructions per message (the executor's and the round's 1.2 K gone),
its heap after open (none) and its text.

**Status (2026-11-26).** Only step 1 is under way, on the `direct-all` lane, and for the dial face:
a build without `threads`, `listen` and `group` reads its one dial face where it lies and builds
no round, since any of the three sets `wz_round`
(`crates/wz-capi-coop/build.rs @ const KEEP_THE_ROUND: &[&str] = &[`). The size ledger's case,
`pico-client-coop-nostd`, builds `os-posix,link-udp` alone
(`scripts/lib/capability_cost_gate.py @ Case("pico-client-coop-nostd", "wz-capi-pico", "libwz_capi_pico.so", "os-posix,link-udp",`),
so its text holds no round already, and the text budget gains nothing more from steps 2 to 5. The
shipped preset's form, the one the instruction cells measure, builds `peer` (`listen`),
`multicast-transport` (`group`) and `multi-thread` (`threads`) (the wz arm of
`target/pico-compare/opprofile-runs/host-20261125T224055/report.txt`), so `wz_round` is set there
and both instruction losses read through the round: the received message's executor pass and round
(8.1, about 1,170) and the queryable peer's 2,106 of 13,221
([ir-send-query](win-budget/ir-send-query.md) 4.2b, row 2: `RoundGate`, `RoundDelivery`,
`hand_out`, `step_after`). Those losses close with steps 2 to 5, not with step 1.

### 8.12 Rejected alternatives

- **A read path chosen at run time by configuration** (direct for one face, the round for more):
  two paths of delivery, each with its own ordering and reentrancy rules, both shipped.
- **A fast path for a session of one face**: the shipped preset is a listening peer in a group, and
  the one-face path would not be the one measured.
- **Keeping the executor and polling the link tasks less often**: the pass per message is what is
  measured; its count, not its rate, is the cost.

## 9. The win budget: heap, RSS, text and instructions per message under zenoh-pico

Status: decision of the owner, 2026-11-25 (win every LOSS metric against zenoh-pico in the
shipped form and in the std form, cost ignored). This section is the summary and the index; each
budget is worked out, stage by stage and row by row, in its own document under
`docs/win-budget/`. A number here is copied from those documents; where they disagree, the
document of the budget holds.

### 9.1 Where wz stands

The shipped nostd form is the one of 8.1 (the pico preset's `zenoh-pico_defconfig` limits);
zenoh-pico is built as the same build. Measured 2026-11-25 unless the cell gives another date; the
per-operation rows are `scripts/pico-compare.sh opprofile` on main `cf6ca0963`, 2026-11-26 (the run
`target/pico-compare/opprofile-runs/host-20261125T224055`, `report.txt`), net of the paced loop.
The receivers' lines of that run (the subscriber's, the queryable peer's) were biased on the pico
arm: a zenoh-pico peer with no peer wakes every 100 ms and spins its last 1 to 2 ms before each
wake-up, and the number of those wake-ups differs between the two runs of a slope with the host's
speed ([ir-receive](win-budget/ir-receive.md) 1). The harness of `f5f8ce646` counts the connected
window alone, net of an idle run of it; its reading on the same main (2026-11-26) is the second
figure of each row and the verdict.

| metric | wz | zenoh-pico | target | budget |
|---|---:|---:|---|---|
| instructions per received message (8 B payload, callgrind) | 6,097; 4,843.0 on main `cf6ca0963` (biased run); window 4,855.9, net 4,836.7 | 2,941; 2,840.6 (biased); window 4,049.2, net 4,042.4 | design 2,000; gate 4,042 (1.20 now; the biased 1.70 withdrawn) | [ir-receive](win-budget/ir-receive.md) |
| instructions per put, 8 B | 2,195 | 2,376 | at most zenoh-pico's: met (0.92, the window too); design 460 | [ir-send-query](win-budget/ir-send-query.md) 4.1, 9 |
| instructions per get, the querier | 19,146 | 11,910 | at most zenoh-pico's (1.61; 1.63 on the window; 1.49 on the branch `decl-row`) | [ir-send-query](win-budget/ir-send-query.md) 4.2 |
| instructions per get, the queryable peer | 13,221; window 12,883.3 | 2,859 (biased); window 10,167.8 | design 1,880; gate 10,168 (1.27 now) | [ir-send-query](win-budget/ir-send-query.md) 1, 4.2b |
| instructions per declare and retract: subscriber, publisher, queryable | 15,384; 9,577; 15,027 | 14,121; 11,280; 13,638 | at most zenoh-pico's: 1.09, 0.85, 1.10 on the window; 0.88, 0.67, 0.89 on `decl-row` | [ir-send-query](win-budget/ir-send-query.md) 4.3 |
| instructions per open and close | 142,795 | 173,336 | at most zenoh-pico's: met (0.82; 0.69 on the window); 1.37 with a heap-lane arena from a reused `calloc` chunk, which rss-zero takes back | [ir-send-query](win-budget/ir-send-query.md) 4.4, [heap](win-budget/heap.md) 7 |
| heap peak, subscriber program (massif, with the 4,096 B stdio buffer both pay) | 373.1 KB | about 17 KB | at most about 17 KB: wz's own at most 12.9 KB | [heap](win-budget/heap.md) |
| heap peak, publisher program | 262.8 KB | about 15 KB | at most about 15 KB: wz's own at most 10.9 KB | [heap](win-budget/heap.md) |
| RSS | 5,774 KiB; std form 1.42 of zenoh-pico's by `perf` (2026-11-26) | 4,888 KiB | at most 4,888 KiB | [heap](win-budget/heap.md) 7, [std-heap](win-budget/std-heap.md) |
| text, size ledger (`pico-client-coop-nostd`, by DWARF line) | 235,152; areas 218,547 on the sh2 reading (2026-11-26, the C-level root crate, landing); t-ext sessions -982, codec -253; SCE ADR 0137 codec +5,728 | 170,500 | at most 170,500 | [text](win-budget/text.md) 1, P9, 8.1 |
| text, parity preset (std) | 864,298 | 505,302 | at most 505,302 | [text](win-budget/text.md) 6, [std-heap](win-budget/std-heap.md) |
| instructions per received message, std form | 6,522 (biased run); window: measure, harness f5f8ce646; CPU per message 1.32 of zenoh-pico's by `perf` | 2,941 (biased); 4,042 on the window | at most 4,042 | [std-heap](win-budget/std-heap.md) |

What closes each gap:

- **Instructions.** On the window harness wz is 1.20 of zenoh-pico (4,837 against 4,042); section
  8 removes the executor's pass and the round (about 1,170), which alone takes it under. The rest
  is the read's own stages, each budgeted at or under zenoh-pico's: one blocking read per face,
  every whole batch handed out in one call, one generated pass from the record header to a flat
  push view, a declared key resolved by index with no string, the match set kept on the
  resource row, and the loaned sample the session's own view with no marshal copy.
- **Instructions per operation.** Put, open and the publisher's declaration already read under
  zenoh-pico's; on the branch `decl-row` the subscriber's and the queryable's declarations do too
  (0.88, 0.89). The queryable peer reads 1.27 on the window harness (the biased 4.62 withdrawn);
  its excess is the executor's pass and the round (2,106 of 13,221) and the reply key's canon check
  (1,218), which section 8 and the query lane Q-SERVE remove. The querier's 1.63 (1.49 on
  `decl-row`) is not read by stage yet ([ir-send-query](win-budget/ir-send-query.md) 4.2 and its
  cells).
- **Heap.** Every row is reserved at the open at its limit's capacity today. Under the ruling of
  9.4 it is reserved at the quota the open's configuration states, with small defaults; the
  rows shrink (the entity slab whose handle is the row, one pending-declaration pool for every
  face, reassembly into a payload block, no delivery rows once section 8 lands). At the
  recommended defaults the arena falls from 290,304 B to about 6.5 KB and the process pools
  from 78,160 B by staging and counting them from the configuration. On a host the arena is fresh
  pages of the system, never a reused allocator chunk that `calloc` zeroes whole (rss-zero).
- **RSS.** Resident memory follows the bytes written: an empty row is all-zero, a row is
  written when it is first taken, and the text and heap targets carry the rest.
- **Text.** Sessions 2.52, doors 2.16, transport 2.33 and driver 1.81 over zenoh-pico carry the
  excess; codec (0.99), key expressions (0.71) and language support (0.41) already win and are
  held. The sh2 reading (2026-11-26) moves the shipped root to a C-level crate, whose Rust-level
  symbols fat LTO may then make internal: about -15.6 KB with no code changed, the ratio 1.28
  ([text](win-budget/text.md) P9). A crate's size level does not survive fat LTO (M1, read
  2026-11-26): cold code is made small as one non-generic body, not by a crate at
  `opt-level = "s"` ([text](win-budget/text.md) P5). The std form's excess is the unwinder, the symbolizer and the
  rest of `std` (about 0.6 MB), which the std budget removes by giving the C libraries no std form.

### 9.2 The budgets

| document | what it fixes |
|---|---|
| [ir-receive](win-budget/ir-receive.md) | one received message in nine stages (socket and wait, stream framing, batch and frame header, record decode, key resolution, subscriber look-up, hand-out and callback marshal, timers, the executor and round of section 8): each stage's cost in both, its target and the structure that meets it; the SCE generator change it needs |
| [ir-send-query](win-budget/ir-send-query.md) | the same frame for a put, a get and its replies, a declare and its retraction, an open and its close |
| [heap](win-budget/heap.md) | the configuration's count keys, each row of the session arena and of the process pools (bytes, sizing formula, target formula, target bytes), resident memory, the refusals |
| [text](win-budget/text.md) | each area of the size ledger by symbol and owner, its target and the structure that shrinks it; where size and instructions meet |
| [std-heap](win-budget/std-heap.md) | the std form of the pico preset, the zenoh-c preset and the Rust API against the same four metrics |

### 9.3 Order and lanes

Each budget document names its lanes with the files each owns and what each depends on. The
order across them:

1. **No dependency, at once.** The measurement lanes (every cell to measure, 9.5); the SCE
   generator change (ir-receive R3, an SCE session's); the one writer per message kind
   (ir-send-query S-WRITE) and the gets' deadline index (Q-DEADLINE); the C ABI text rows
   (text T-ABI) and the generated runtime's inline attributes (T-SCE; its size-level probe, M1, is
   read: no level survives fat LTO); the std modules off `std` (std-heap SH1).
2. **After the heap decisions D2 and D3 of 9.4**: the configuration's count table (heap H1),
   which alone takes the arena to about 60 KB; then the entity slab, the shared
   pending-declaration pool, reassembly into a payload block and the staged pools (H2, H4, H5,
   H6), and the text rows that share their files (T-ROWS, T-DECL, T-DOORS, T-OPEN).
3. **Section 8's steps 3 to 5**, beside step 2's lanes: the put's plan and the get's one hold
   (S-PLAN, Q-HOLD) need only section 8 step 2, which has landed.
4. **After section 8's locks (8.11.1) and read tasks (8.11.4)**: socket, wait and framing (R1),
   key and match (R4), the timers (R6), the tasks an open starts (O-TASKS); after the round goes
   (8.11.5): direct delivery (R5), the reply's dispatch (Q-REPLY), the group as a face of the
   plan (S-GROUP), the face and link rows (H3), engine and runtime state (H7), the receive text
   rows (T-RX, T-READ, T-LINK), no process section per message (SH6). The frame header and
   record walk (R2) follow the SCE pin of R3.
5. **The std form** after the nostd lanes it rests on: the feature collapse and panic policy
   (SH2, SH3), stacks and allocation counts (SH4), all-zero rows after the heap row lanes
   (SH5), the zenoh-c preset (SH7) and the Rust API (SH8) on section 8's engine.

The files several lanes write are taken in this order, never side by side:

| file | lanes, in order |
|---|---|
| `wz-capi-coop/src/engine.rs` | S-PLAN, Q-HOLD, D-AFTER, R5, H7, the open's lanes |
| `wz-capi-coop/src/engine/direct.rs` | section 8, S-PLAN, H3, T-READ |
| `wz-capi-coop/src/arena.rs` | H1, H2, H4, H3, T-OPEN, SH5 |
| `wz-capi-pico/src/process_pool.rs` | H2, H5, H6 |
| `wz-session-core/src/drive.rs` | R6, R2 |
| `wz-session-core/src/session_actions.rs` | S-WRITE, R2, T-TX |
| `wz-runtime-coop/src/stream_link.rs` | S-WRITE, R1, T-LINK |
| `wz-session-core/src/network_message/push_read.rs` | R2, T-EXT |

A lane is judged by its own reading on the shipped form (the callgrind slope of its path, the
massif peak and row report, the ledger's area) and lands with its tests; a lane that trades one
metric for another states both readings (text O2).

### 9.4 The owner's decisions

**Decided** (owner's delegated ruling, 2026-11-26): the heap's capacity is set as DDS sets
`RESOURCE_LIMITS`, which is the capacity and quota of `limit_binding.rs`.

- A build's limit (the preset's value) is the capacity: the static ceiling its types can hold.
- What an open reserves is the quota its session's configuration states: wz keys of the open's
  configuration for the most of each entity kind, of declared key expressions, of faces and of
  payload blocks, each at most its capacity, or the open is refused under the limit's name.
- A configuration that states no quota gets a small default, written in the preset's contract,
  not the capacity.
- No heap after the open holds: the quota is reserved once at the open, and a declaration past
  it is refused with the error code zenoh-pico gives when its allocation fails.
- The process pools (one per process, `process_limits.rs`) take their quotas from the first
  open's configuration or from a configuration given to the process's initialisation.
- Smaller rows and nothing reserved twice go on apart from this: they lower each quota's bytes.

**Decided** (2026-11-26 under the owner's delegation, by the main session):

- **No crate is a size boundary** ([text](win-budget/text.md) O1, P5). In `capi-nostd` a crate's
  `opt-level` does not survive fat LTO (M1: -1,899 / +1,875, and the `&dyn` adapter of the move
  +880). Cold code is one non-generic body at the root's level, out of line, with no adapter made
  for it; the rows that leaned on a size level (text S3, S10, R2, D7, X3) are designed on that
  form. The `capi-nostd` profile rows of `wz-app-schema`, `wz-auth` and `wz-tls-pem` are its
  residue (text M1b).
- **A get's ResponseFinal waits in its face's `TxBatch` and the batch is flushed once when the
  read stage ends** ([ir-send-query](win-budget/ir-send-query.md) D6). No send window is open while
  a callback runs, and one `send` carries the Response, its final and whatever else the stage
  wrote to that face. The lane t-tx implements it.

**Open**, each argued and recommended in its document:

| question | documents | recommended there |
|---|---|---|
| the data path and a put take no session lock: a record is matched against an epoch-stamped match set, a face's key forms and up state change only under its send place (amends 8.4) | ir-receive D1, ir-send-query D2 | yes |
| with `threads`, a face's read is one blocking read with no poll and no clock read; liveness is a heard flag (amends 8.9) | ir-receive D2 | yes |
| the loaned sample is the session's own view behind the opaque C type | ir-receive D3 | yes |
| the generated decode of one pass is taken by an SCE session, and wz moves its pin | ir-receive D4 | yes |
| one sequence number per face (a Frame header per face past the first) rather than zenoh-pico's one for all | ir-send-query D1 | per face |
| a group is a face of the put's plan | ir-send-query D3 | yes |
| the default quotas of every count (the most one of zenoh-pico's examples holds at once), held replies of a get among them | heap D2, ir-send-query D4 | measured by heap M2 |
| the numbered key range of the wz counts in `zp_config_insert` and the typed door's name | heap D3 | to be named |
| the preset's default batch, 2,048 or 1,024 (fewer bytes, more batches for long messages) | heap D4 | 1,024 |
| one reassembly chain by default, or none | heap D5 | 1 |
| process pools staged and fixed after the first open, or a segment per later open | heap D6 | to be chosen |
| the opprofile line per operation, whole process, both forms, is the verdict of an operation | ir-send-query D5 | yes |
| instructions on the message path never rise for text; at equal instructions, text decides | text O2 | yes |
| a move of code into tables is graded by `.text` plus `.rodata` | text O4 | yes |
| the C libraries have no std form; `std` stays in the Rust API and the tools | std-heap 1 | yes |
| a panic aborts at every C boundary (the parity preset's panic strategy) | std-heap 2, text O3 | yes |
| the Rust API's budgets are differences against the same program without wz | std-heap 3 | yes |
| the Rust API runs on the cooperative engine; tokio becomes an adapter | std-heap 4 | yes |
| thread stacks sized by the stack-bound gate | std-heap 5 | yes |
| an empty row is all-zero and the open writes no row it does not use | std-heap 6 | yes |

Two of them interact: a batch of 1,024 (heap D4) costs instructions on messages longer than a
batch, which the receive budget weighs, and the quota defaults (heap D2) decide whether the
publisher program's last 0.5 KB is won.

### 9.5 Cells to measure

Every cell is read on both arms, shipped nostd form first, then std; none is read in the design.

| document | cells |
|---|---|
| all | every receiver's line (subscriber, queryable peer) read in its connected window, net of an idle run: measure, harness f5f8ce646 |
| ir-receive 14 | M1, M2 each stage's inclusive cost on both arms; M7 the same in the window; M3 the std form; M4 messages per batch and batches per read call; M5 a group member's read; M6 a key with a suffix |
| ir-send-query 8 | by `pico-opprofile`: the paced loop alone; put at 8 B and 1 KiB; put with a group; put to two faces; get on both sides; declare of subscriber, publisher, queryable; open |
| heap 11 | M1 the row report of the preset's own features; M2 the counts zenoh-pico's examples hold; M3 zenoh-pico's peak by site; M4 each estimated row after its lane; M5 the lodging places; M6 engine and runtime state by field; M7 the pools by pool; M8 resident memory of both arms, and the open after rss-zero |
| text 9 | M0 the explain document's build; M1 the size level under fat LTO (read: none), M1b the same on the C-level root and the residual profile rows; M11 coop-resolver-pay and SCE ADR 0138; M12 each text lane's lines on the window harness; M2 the receive and send slopes around each text lane; M3 the explain document of the std case; M4 to M7 the bodies, instances and tables the rows name |
| std-heap 4 | the std form's RSS, heap and text under the preset's limits; zenoh-pico under the same massif options; the extra copy's caller; the malloc arenas of both; the zenoh-c and upstream zenoh cells; zenoh-pico's read task by the difference of two runs |
