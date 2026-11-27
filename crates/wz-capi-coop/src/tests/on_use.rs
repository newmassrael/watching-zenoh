// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! A session whose tables take their memory at their first row (`tables-on-use`), against the
//! router stand-in: its keys are counted against a budget of the session's `KEY_ARENA_BYTES`, a
//! declaration's key as the block the key arena would give it, given back with the declaration;
//! the keys the program's objects hold are copies of their own; a subscriber declared after the
//! open is told to the router and handed what it pushes; and the state the session's own values and
//! its key budget lie in is taken from the allocator apart from its arena.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use wz_capi_port::{KeyAsk, KeyNotHeld, SessionEngine, SessionKeys, SubscriberSink, WireKey};
use wz_session_core::key_arena::block_bytes;
use wz_session_core::limits::SessionLimits;
use wz_session_core::locality::Locality;
use wz_session_core::sink::SampleView;

use super::{open, until, CatchAll, Command, Engine, Router};
use crate::EngineHold;

/// What the engine answers its objects' keys through.
fn keys(engine: &Engine) -> &dyn SessionKeys {
    engine
        .key_arena()
        .expect("the engine answers its objects' keys")
}

/// The session's keys are counted against a budget of its `KEY_ARENA_BYTES`: a key expression it
/// declares takes the block the key arena would give it, and gives it back with its last hold.
/// Turned red by an open that hands the session's state a budget of other bytes than its limits
/// state (`OwnState::place`), by a declaration whose key the budget does not count, or by one
/// whose bytes do not go back with it.
#[test]
fn a_declarations_key_is_counted_against_the_sessions_budget_and_given_back() {
    let router = Router::start(CatchAll::None);
    let engine = open(&router);
    let opened = engine.key_counts();
    assert_eq!(
        opened.bytes,
        SessionLimits::defaults().key_arena_bytes(),
        "the budget is the session's KEY_ARENA_BYTES"
    );
    let declaration = engine
        .acquire_keyexpr("demo/on-use/key")
        .expect("a declaration");
    let block = block_bytes("demo/on-use/key".len()).expect("a short key's block");
    assert_eq!(
        engine.key_counts().used,
        opened.used + block,
        "the key is counted as its block"
    );
    declaration.release(&*engine);
    assert_eq!(
        engine.key_counts().used,
        opened.used,
        "and given back with the declaration"
    );
}

/// The program's objects hold their keys as copies of their own where the session keeps no key
/// arena: a hold reads back its text and takes nothing of the session's budget, a share is another
/// copy, a release lets each go, and a key past the session's `MAX_KEYEXPR_BYTES` is refused as too
/// long, as the arena refuses it. Turned red by a hold that is not a copy of its own, by one counted
/// against the budget, or by a hold past the bound that is kept.
#[test]
fn an_objects_key_is_a_copy_of_its_own_and_refused_past_the_sessions_bound() {
    let router = Router::start(CatchAll::None);
    let engine = open(&router);
    let before = engine.key_counts().used;
    let held = keys(&engine)
        .key(KeyAsk::Hold("demo/held"))
        .expect("room for a copy")
        .expect("a hold answers its key");
    assert!(held.is_own());
    assert_eq!(held.as_str(), "demo/held");
    assert_eq!(
        engine.key_counts().used,
        before,
        "a copy takes nothing of the budget"
    );
    let shared = keys(&engine)
        .key(KeyAsk::Share(&held))
        .expect("room for a copy")
        .expect("a share answers its key");
    assert!(shared.is_own());
    assert_eq!(shared.as_str(), "demo/held");
    assert!(matches!(keys(&engine).key(KeyAsk::Release(held)), Ok(None)));
    assert!(matches!(
        keys(&engine).key(KeyAsk::Release(shared)),
        Ok(None)
    ));
    let long = "k".repeat(wz_session_core::caps::MAX_KEYEXPR_BYTES + 1);
    assert!(matches!(
        keys(&engine).key(KeyAsk::Hold(&long)),
        Err(KeyNotHeld::TooLong)
    ));
}

/// A subscriber declared on a session whose tables took no row at the open is told to the router
/// and handed what the router pushes on its key when the program steps the session. Turned red by
/// a registry whose subscribers' table refuses its first row (a table counted none), or by a
/// receive that does not reach a table of the on-use policy.
#[test]
fn a_subscriber_declared_after_the_open_is_told_and_handed_a_push() {
    let router = Router::start(CatchAll::None);
    let engine = open(&router);
    let received = Arc::new(AtomicUsize::new(0));
    let declares = router.seen(|s| s.declares);
    engine
        .declare_subscriber_on_wire("demo/**", WireKey::literal(), Locality::Any, None, {
            let received = received.clone();
            SubscriberSink::shared(move |sample: &dyn SampleView| {
                assert_eq!(sample.payload(), b"hello");
                received.fetch_add(1, Ordering::SeqCst);
            })
        })
        .expect("the session declares the subscriber");
    until(&engine, "the router to see the subscriber", || {
        router.seen(|s| s.declares) > declares
    });
    router.send(Command::Push("demo/a", b"hello"));
    until(&engine, "the push", || received.load(Ordering::SeqCst) == 1);
}

/// A session whose tables take their memory on use holds its engine and its faces' rooms each in an
/// allocation of its own, the engine's claimed beside its row before its arena is reserved, and
/// neither at a place of the arena, where the D12 forms' test of the same accessor in
/// `tests::arena` finds their engine. Turned red by an open that writes the engine at a place the
/// arena lends (`SessionArena::engine_place` and `Shared::placed_with` in `CoopEngine::engine_of`),
/// or the rooms (`Arena::vacant` in `CoopEngine::assemble`).
#[test]
fn an_on_use_engine_and_its_rooms_lie_apart_from_its_arena() {
    let router = Router::start(CatchAll::None);
    let engine = open(&router);
    assert!(
        !engine.arena_holds(EngineHold::as_ptr(&engine).cast()),
        "the engine lies apart from the arena"
    );
    assert!(
        !engine.arena_holds(engine.rooms_place()),
        "the rooms lie apart from the arena"
    );
}

/// A session whose tables take their memory on use makes the read slot of a face past its dial
/// role's at the place's first face: none at the open, one once a face is attached, which then
/// comes up. Turned red by an open that makes every place's slot (`DirectFaces::taken` making its
/// rows' faces), or by an attach that makes none (`DirectFaces::made_at` left out of
/// `CoopEngine::attach_face`): the attached face then has no slot a read turns and never comes
/// up.
#[cfg(all(feature = "listen", not(wz_round)))]
#[test]
#[cfg_attr(miri, ignore = "the interpreter has no host sockets")]
fn an_on_use_face_takes_its_read_slot_at_its_places_first_face() {
    let first = Router::start(CatchAll::None);
    let second = Router::start_as(0xc5, CatchAll::None);
    let engine = open(&first);
    assert_eq!(
        engine.faces_made(),
        0,
        "no face past the dial role's holds a read slot at the open"
    );
    engine
        .attach_face(&second.endpoint())
        .expect("the second router is dialled");
    assert_eq!(engine.faces_made(), 1, "the attached face's slot is made");
    until(&engine, "both faces to be up", || engine.faces_up() == 2);
}

/// A session whose tables take their memory on use holds the place of a face's room from the
/// face's first hold of a wait, and none for a place no face held: with its one face up it holds
/// one place, whatever the rows its plan counts (one for each face it may hold at once where it
/// listens). Turned red by an open that makes every row's place (`RoomTable::over` making a place
/// for each row, as the forms that lay the places out write one), or by a face that comes up and
/// makes none (`RoomTable::taken` reading through `row_mut` in place of `made_mut`).
#[test]
#[cfg_attr(miri, ignore = "the interpreter has no host sockets")]
fn an_on_use_session_with_one_face_holds_one_room_place() {
    let router = Router::start(CatchAll::None);
    let engine = open(&router);
    until(&engine, "the face to be up", || engine.faces_up() == 1);
    let (made, rows) = engine.room_places_made();
    assert!(rows >= 1, "CONTROL: a row for the dial role's face");
    assert_eq!(made, 1, "one place, the face's");
}

/// A session whose tables take their memory on use holds the admission its links ask while their
/// handshakes run in an allocation of its own, apart from its arena. Turned red by an open that
/// places the admission in the arena (`Arena::place` in `CoopEngine::assemble`).
#[cfg(feature = "link-admission")]
#[test]
#[cfg_attr(miri, ignore = "the interpreter has no host sockets")]
fn an_on_use_sessions_link_admission_lies_apart_from_its_arena() {
    let router = Router::start(CatchAll::None);
    let engine = open(&router);
    let admission = engine.link_admission();
    let at: *const dyn wz_session_core::link_admission::LinkAdmission = &*admission;
    assert!(
        !engine.arena_holds(at.cast()),
        "the admission lies apart from the arena"
    );
}

/// The plan of a session whose tables take their memory on use lays out no place for its engine,
/// its faces' rooms or its runtime, which lie in allocations of their own, and no table of its
/// links' cells, whose parts are made on the heap as each link opens, while the CONTROL row,
/// the count the arena is kept by, is laid out as the D12 plan lays it beside the runtime's span.
/// Turned red by `lay_out_open` laying the engine's place (`ArenaPlan::lay_engine`), a place of
/// the rooms (`ArenaPlan::lay_rooms`, of any bytes) or the runtime's span
/// (`ArenaPlan::lay_runtime`) in the on-use form, whose holds name none of their bytes, or by one
/// that leaves the count out with the span (`ArenaPlan::lay_keep`).
#[test]
fn an_on_use_plan_lays_out_no_place_for_the_engine_the_rooms_or_the_runtime() {
    use crate::arena::{ArenaPart, ArenaPlan, HeldPlaces, PlanShape};
    let mut plan = ArenaPlan::planned(
        PlanShape::dial_only(1, 1024, &wz_session_core::policy::SessionPolicy::defaults()),
        &SessionLimits::BUILD,
    )
    .expect("the build's client");
    crate::engine::lay_out_open(
        &mut plan,
        &crate::engine::OpenHolds {
            held: &HeldPlaces::NONE,
            engine: 64,
            planes: crate::engine::SessionPlanes::OF_BUILD,
        },
    )
    .expect("the holds lay out");
    let laid = |part: ArenaPart| plan.rows().any(|row| row.part() == part.part());
    assert!(
        laid(ArenaPart::ArenaKeep),
        "CONTROL: the count the arena is kept by is laid out"
    );
    assert!(!laid(ArenaPart::RuntimeState), "the runtime lies apart");
    assert!(!laid(ArenaPart::EngineState), "the engine lies apart");
    assert!(!laid(ArenaPart::LinkRooms), "the rooms lie apart");
    for cells in [
        ArenaPart::LinkCells,
        ArenaPart::LinkGates,
        ArenaPart::LinkActions,
        ArenaPart::LinkHalves,
    ] {
        assert!(!laid(cells), "a link's parts lie on the heap");
    }
}

/// A session whose tables take their memory on use makes each part of a link on the heap as the
/// link opens: with its link up, neither its gates nor its actions' halves lie in a cell of a
/// table; the CONTROL is the face, up. Turned red by an open that lends its transport a table of
/// cells on use (`cells` in `CoopEngine::assemble`), which its links' kind would then have to
/// name.
#[test]
#[cfg_attr(miri, ignore = "the interpreter has no host sockets")]
fn an_on_use_sessions_link_parts_lie_on_the_heap() {
    let router = Router::start(CatchAll::None);
    let engine = open(&router);
    until(&engine, "CONTROL: the face to be up", || {
        engine.faces_up() == 1
    });
    assert_eq!(
        engine.link_halves_in_use(),
        None,
        "the actions' halves lie on the heap"
    );
    assert_eq!(
        engine.link_gates_in_use(),
        None,
        "no table of gates is lent"
    );
}

/// A session whose tables take their memory on use lays out no row of the tables it counts in the
/// plan an open lays out from its config, whether the build's plans are laid out at the open
/// (`runtime-plan`) or not, and whether it takes faces beside its dial role's or not: none of the
/// session's one table set, the key arena, the faces' sets and the index of the held ones, a peer's
/// tables, the tokens the faces that went owe, the places of the rooms or of a step, the
/// declaration watchers, the gets' tables, the held Finals or the round's tables, each counted from
/// the plan and taking its memory at its first row; the CONTROL rows, the endpoints' texts and the
/// links' receive buffers, are laid out.
/// Turned red by a row of those tables put where the build lays its plans out at the open
/// (`feature = "runtime-plan"`) rather than where the policy lends them (`wz_lent`), as
/// `ArenaPlan::put_entities` was put, in a build of both features.
#[test]
fn an_on_use_plan_from_the_config_lays_out_no_row_of_the_tables_it_counts() {
    use crate::arena::ArenaPlan;
    let config = crate::CoopConfig {
        endpoints: vec!["tcp/127.0.0.1:7447".to_owned()],
        ..super::client_config()
    };
    let plan = ArenaPlan::of(&config, &config.limits).expect("the client's limits lay a plan out");
    let laid = |part: &str| plan.rows().any(|row| row.part() == part);
    assert!(
        laid("endpoint texts") && laid("link receive buffers"),
        "CONTROL: the transport's rows are laid out"
    );
    for part in [
        "session tables",
        "key arena",
        "face tables",
        "held faces",
        "peer tables",
        "owed tokens",
        "room places",
        "router lend",
        "registry lend",
        "declaration watchers",
        "pending gets",
        "ended legs",
        "leg callbacks",
        "pending legs",
        "held replies",
        "held finals",
        "refused finals",
        "delivery records",
        "delivery callbacks",
        "delivery keys",
        "delivery round",
    ] {
        assert!(!laid(part), "{part} is counted, not laid out");
    }
}

/// A session whose tables take their memory on use takes the state its own values and its key
/// budget lie in from the allocator, apart from its arena: its memory is asked for one block, the
/// arena its plan lays out and nothing before it, and every plane the state owns lies in that
/// state and not in the arena. Turned red by an open that lays the state at the head of the
/// arena's block (`SessionArena::reserve_after`), which asks the memory for the state's bytes too,
/// or by a plane placed anywhere but the state.
#[test]
#[cfg_attr(miri, ignore = "the interpreter has no host sockets")]
fn an_on_use_open_asks_its_memory_for_the_arena_alone_and_holds_its_state_apart() {
    use super::{host_links, LOOPBACK};
    use crate::arena::{
        AllocatorMemory, ArenaMemory, ArenaRegion, HeldPlaces, OpenRegion, OpenStorage, PlanFrom,
        PlanShape,
    };
    use wz_runtime_posix::stream::PosixTcpDial;
    use wz_runtime_posix::{PosixClock, PosixEntropy};
    use wz_session_core::bounded::ARENA_ALIGN;

    /// The allocator, counting its reservations and keeping the bytes it was last asked for.
    struct Counted {
        reserves: AtomicUsize,
        last: AtomicUsize,
    }

    impl ArenaMemory for Counted {
        fn reserve(&self, layout: core::alloc::Layout) -> Option<core::ptr::NonNull<u8>> {
            self.reserves.fetch_add(1, Ordering::SeqCst);
            self.last.store(layout.size(), Ordering::SeqCst);
            AllocatorMemory.reserve(layout)
        }

        unsafe fn release(&self, base: core::ptr::NonNull<u8>, layout: core::alloc::Layout) {
            // SAFETY: the caller's contract: the allocator gave `base` for `layout`, given back
            // once.
            unsafe { AllocatorMemory.release(base, layout) }
        }
    }

    static BLOCK: Counted = Counted {
        reserves: AtomicUsize::new(0),
        last: AtomicUsize::new(0),
    };
    let router = Router::start(CatchAll::None);
    let config = super::config(&router);
    let region: &'static OpenRegion = Box::leak(Box::new(
        Engine::open_region(
            ArenaRegion::of(PlanShape::of(&config), config.limits)
                .expect("the client's limits lay a region out"),
            HeldPlaces::NONE,
        )
        .expect("the engine's places lay out"),
    ));
    let engine = Engine::open_made_in(
        host_links(LOOPBACK, PosixTcpDial).waited_by_owner(),
        PosixClock,
        PosixEntropy,
        || super::config(&router),
        wz_session_core::policy::SessionPolicy::defaults(),
        crate::OpenKeyIds::none(),
        OpenStorage {
            memory: &BLOCK,
            plan: PlanFrom::Region(region),
        },
    )
    .expect("the session opens");
    assert_eq!(
        BLOCK.reserves.load(Ordering::SeqCst),
        1,
        "one block, the arena's"
    );
    assert_eq!(
        BLOCK.last.load(Ordering::SeqCst),
        engine.arena_bytes().max(ARENA_ALIGN),
        "the block is the plan's arena alone"
    );
    #[cfg(any(feature = "queryable", feature = "query", feature = "connectivity"))]
    for at in engine.plane_places() {
        assert!(engine.state_holds(at), "the plane lies in the state");
        assert!(!engine.arena_holds(at), "and not in the arena");
    }
}
