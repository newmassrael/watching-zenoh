// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! A session whose tables take their memory at their first row (`tables-on-use`), against the
//! router stand-in: its keys are counted against a budget of the session's `KEY_ARENA_BYTES`, a
//! declaration's key as the block the key arena would give it, given back with the declaration;
//! the keys the program's objects hold are copies of their own; a subscriber declared after the
//! open is told to the router and handed what it pushes; and the state the session's own values and
//! its key budget lie in is the one block its open reserves of the memory it is handed: no arena.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use wz_capi_port::{KeyAsk, KeyNotHeld, SessionEngine, SessionKeys, SubscriberSink, WireKey};
use wz_session_core::key_arena::block_bytes;
use wz_session_core::limits::SessionLimits;
use wz_session_core::locality::Locality;
use wz_session_core::sink::SampleView;

use super::sim::{Sim, SimEngine, StandIn};
use super::CatchAll;
use crate::EngineHold;

/// The simulation's seed.
const SEED: u64 = 0x0e5e;

/// A router stand-in and the session the simulation opens against it.
fn opened(sim: &Sim) -> (StandIn, EngineHold<SimEngine>) {
    let stand_in = sim.stand_in(CatchAll::None);
    let engine = sim.open(sim.config());
    (stand_in, engine)
}

/// What the engine answers its objects' keys through.
fn keys(engine: &SimEngine) -> &dyn SessionKeys {
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
    let sim = Sim::new(SEED);
    let (_router, engine) = opened(&sim);
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
    let sim = Sim::new(SEED);
    let (_router, engine) = opened(&sim);
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
    let sim = Sim::new(SEED);
    let (router, engine) = opened(&sim);
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
    sim.steps_until(&engine, 0, "the stand-in to see the subscriber", || {
        router.seen(|s| s.declares) > declares
    });
    router.push("demo/a", b"hello");
    sim.steps_until(&engine, 0, "the push", || {
        received.load(Ordering::SeqCst) == 1
    });
}

/// A session whose tables take their memory on use makes the read slot of a face past its dial
/// role's at the place's first face: none at the open, one once a face is attached, which then
/// comes up. Turned red by an open that makes every place's slot (`DirectFaces::counted` making
/// the faces of its rows past the dial role's), or by an attach that makes none (`DirectFaces::made_at` left out of
/// `CoopEngine::attach_face`): the attached face then has no slot a read turns and never comes
/// up.
#[cfg(all(feature = "listen", not(wz_round)))]
#[test]
fn an_on_use_face_takes_its_read_slot_at_its_places_first_face() {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    /// Where the second node accepts, beside the first stand-in's address.
    const SECOND_AT: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3)), 7447);
    let sim = Sim::new(SEED);
    let (_first, engine) = opened(&sim);
    let _second = sim.stand_in_as(SECOND_AT, 0xc5, CatchAll::None);
    assert_eq!(
        engine.faces_made(),
        0,
        "no face past the dial role's holds a read slot at the open"
    );
    engine
        .attach_face(&format!("udp/{SECOND_AT}"))
        .expect("the second stand-in is dialled");
    assert_eq!(engine.faces_made(), 1, "the attached face's slot is made");
    sim.steps_until(&engine, 0, "both faces to be up", || engine.faces_up() == 2);
}

/// A session whose tables take their memory on use makes no place of its faces' rooms at its open,
/// and none for a face whose link names no wait for room: with its one face up over a datagram
/// end, which names none (`SimEnd` answers no `room_wait`, as the host's `UdpDriver` does not),
/// it holds no place of the rows its plan counts. That a face's first hold of a wait makes its
/// place, and that one alone, is
/// `congestion::an_on_use_rooms_place_is_made_at_its_faces_first_hold`'s to hold. Turned red by
/// an open that makes every row's place (`RoomTable::over` making a place for each row, as the
/// forms that lay the places out write one), or by a face that comes up and makes a place for a
/// wait its link does not name.
#[test]
fn an_on_use_session_makes_no_room_place_its_faces_do_not_hold() {
    let sim = Sim::new(SEED);
    let (_router, engine) = opened(&sim);
    sim.steps_until(&engine, 0, "the face to be up", || engine.faces_up() == 1);
    let (made, rows) = engine.room_places_made();
    assert!(rows >= 1, "CONTROL: a row for the dial role's face");
    assert_eq!(made, 0, "a datagram link names no wait for room: no place");
}

/// The plan of a session whose tables take their memory on use lays out no row at all once the
/// open has laid out its holds: no place for its engine, its faces' rooms or its runtime, which
/// lie in allocations of their own, no table of its links' cells, whose parts are made on the heap
/// as each link opens, and no count of an arena, which the open reserves none of; the CONTROL is
/// the plan's count of the chains, which sizes the chains' table on use. Turned red by
/// `lay_out_open` laying the engine's place (`ArenaPlan::lay_engine`), a place of the rooms
/// (`ArenaPlan::lay_rooms`, of any bytes) or a count of the arena in the on-use form, or by any
/// table of the plan laid out on use.
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
    assert!(
        plan.reassembly().1 > 0,
        "CONTROL: the plan counts the chains"
    );
    let laid = |part: ArenaPart| plan.rows().any(|row| row.part() == part.part());
    assert!(!laid(ArenaPart::ArenaKeep), "no arena is kept");
    assert!(!laid(ArenaPart::RuntimeState), "the runtime lies apart");
    assert!(!laid(ArenaPart::EngineState), "the engine lies apart");
    assert!(!laid(ArenaPart::LinkRooms), "the rooms lie apart");
    for cells in [
        ArenaPart::LinkCells,
        ArenaPart::LinkGates,
        ArenaPart::LinkActions,
    ] {
        assert!(!laid(cells), "a link's parts lie on the heap");
    }
    assert_eq!(plan.rows().count(), 0, "no row is laid out");
    assert_eq!(plan.reserved_bytes(), Some(0), "and no byte of an arena");
}

/// A session whose tables take their memory on use makes each part of a link on the heap as the
/// link opens: with its link up, neither its gates nor its actions, with the halves beside them,
/// lie in a cell of a table; the CONTROL is the face, up. Turned red by an open that lends its transport a table of
/// cells on use (`cells` in `CoopEngine::assemble`), which its links' kind would then have to
/// name.
#[test]
fn an_on_use_sessions_link_parts_lie_on_the_heap() {
    let sim = Sim::new(SEED);
    let (_router, engine) = opened(&sim);
    sim.steps_until(&engine, 0, "CONTROL: the face to be up", || {
        engine.faces_up() == 1
    });
    assert_eq!(
        engine.link_actions_in_use(),
        None,
        "the actions and their halves lie on the heap"
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
/// the plan and taking its memory at its first row, nor the links' buffers and places, which each
/// link takes of the heap as it opens, nor the endpoints' texts, which each role's table takes as
/// its first is written, nor the reassembly buffers, which each chain takes as it starts; the
/// CONTROL is the plan's count of the chains, which their Routers are sized by.
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
        plan.reassembly().1 > 0,
        "CONTROL: the plan counts the transport's chains"
    );
    assert!(
        !laid("endpoint texts"),
        "the endpoints' texts take their own rows"
    );
    for part in [
        "link receive flags",
        "link receive buffers",
        "link transmit flags",
        "link transmit slots",
        "link places",
        "reassembly flags",
        "reassembly buffers",
    ] {
        assert!(!laid(part), "{part} lies on the heap, each link's own");
    }
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

/// A session whose tables take their memory on use hands each of its reassembly Routers the length
/// of a chain's own buffer, the session's bound on a rejoined message, and the most chains one
/// holds open at once, its share of the chains up to those a Router stages at once
/// (`LENT_CHAINS`), and counts its chains and the messages kept against a table of as many
/// buffers as the lent table the plan counts, none taken yet: the transport's tables are counted
/// from the plan and asked of no lender. Turned red by a transport lent a table of chains on use,
/// or sized or counted to another length or count than the plan's (`TransportRows::counted`).
#[test]
fn an_on_use_sessions_chains_are_sized_by_the_plan_and_lent_no_table() {
    use crate::arena::ArenaPlan;
    use wz_runtime_coop::reassembly_rx::LENT_CHAINS;

    let config = crate::CoopConfig {
        endpoints: vec!["tcp/127.0.0.1:7447".to_owned()],
        ..super::client_config()
    };
    let plan = ArenaPlan::of(&config, &config.limits).expect("the client's limits lay a plan out");
    let (bytes, chains) = plan.reassembly();
    assert!(chains > 0, "CONTROL: the plan counts the chains");
    // The plan's count is a share for each face read where it lies, each with a Router of its own.
    let faces = if cfg!(wz_round) || !cfg!(feature = "listen") {
        1
    } else {
        plan.peers().sets()
    };
    let share = chains / faces;
    let transport = plan
        .transport()
        .counted()
        .expect("the allocator has the count");
    let source = &transport.reassembly;
    assert_eq!(
        (source.bytes(), source.buffers(), source.chains()),
        (bytes, chains, share.min(LENT_CHAINS))
    );
}

/// A session whose tables take their memory on use lends its links the heap as where their
/// buffers are taken, each link a receive buffer of the batch the session advertises and
/// `LINK_TX_SLOTS` slots of it, as its tables would lend each link and as zenoh-pico's transport
/// takes one buffer of each; a report of its memory reads that for each link it may hold, as no
/// link shares a pool. Turned red by a transport lent tables on use, by a source of another size
/// than the plan's batch (`TransportRows::counted`), or by a report that reads a receive pool a
/// session on use holds none of (`LINKS_SHARE_POOLS`).
#[test]
fn an_on_use_sessions_links_take_their_batch_of_the_heap() {
    use crate::arena::{link_buffers, links_of, ArenaPlan, LINK_TX_SLOTS};
    use wz_runtime_coop::link_storage::HeapBuffers;

    let config = crate::CoopConfig {
        endpoints: vec!["tcp/127.0.0.1:7447".to_owned()],
        ..super::client_config()
    };
    let plan = ArenaPlan::of(&config, &config.limits).expect("the client's limits lay a plan out");
    let batch = usize::from(config.batch_size);
    let transport = plan
        .transport()
        .counted()
        .expect("the allocator has the count");
    assert_eq!(
        transport.links,
        HeapBuffers::sized(batch, LINK_TX_SLOTS),
        "each link takes a buffer and its slots of the session's batch"
    );
    let links = links_of(&config).expect("within the address space");
    let report = link_buffers(links, config.max_faces, config.batch_size, &config.limits)
        .expect("the plan's batch");
    // A listening session's links share the outbound slots in either form: on use as a count
    // each link's own slot is sent under (`TransportRows::bound_links`).
    let transmit = if cfg!(feature = "listen") {
        wz_session_core::caps::TX_POOL_SLOTS.min(links)
    } else {
        links
    };
    assert_eq!(
        (report.receive, report.transmit, report.bytes),
        (links, transmit, batch),
        "a buffer of the batch for each link, and the slots they share"
    );
}

/// A listening session whose tables take their memory on use bounds its links by the outbound
/// slots they share, as the lent form's pool does: with one slot for more links than one the plan
/// reads the pool short, and the links' source, unbounded as counted (CONTROL), is bounded by a
/// count of one over every link. Turned red by a plan that counts no slots on use
/// (`pooled_buffers` holding the outbound slots to the receive pools' `LINKS_SHARE_POOLS`), by
/// `tx_pool_short` answering never on use, or by a source the bound is not handed
/// (`TransportRows::bound_links`).
#[cfg(feature = "listen")]
#[test]
fn an_on_use_listeners_links_are_bounded_by_the_slots_they_share() {
    use crate::arena::{links_of, ArenaPlan, LinkSlotFlag};
    use wz_session_core::caps;

    let mut limits = SessionLimits::defaults();
    if limits.select_tx_pool_slots(1).is_err() {
        // A build that keeps the build's value alone has no pool of one slot to try.
        return;
    }
    let config = crate::CoopConfig {
        whatami: wz_session_core::WhatAmI::Peer,
        listen: vec!["tcp/127.0.0.1:0".to_owned()],
        limits,
        ..super::client_config()
    };
    let links = links_of(&config).expect("within the address space");
    assert!(links > 1, "CONTROL: the listener holds more links than one");
    let plan = ArenaPlan::of(&config, &config.limits).expect("the limits lay a plan out");
    assert!(plan.tx_pool_short(), "one slot for more links than one");
    let transport = plan
        .transport()
        .counted()
        .expect("the allocator has the count");
    assert_eq!(
        transport.links.bound(),
        None,
        "CONTROL: counted, no bound yet"
    );
    let flags: [LinkSlotFlag; caps::TX_POOL_SLOTS] = core::array::from_fn(|_| Default::default());
    // SAFETY: the flags are this test's, each free, reached by nothing else, and they outlive the
    // source, which is read and dropped here.
    let bounded = unsafe {
        plan.transport()
            .bound_links(transport.links, core::ptr::NonNull::from(&flags).cast())
    };
    assert_eq!(
        bounded.bound(),
        Some((1, links)),
        "a count of one over every link"
    );
}

/// A session whose tables take their memory on use reserves no arena: the one block its open asks
/// the memory it is handed for is the state its own values and its key budget lie in, and every
/// plane the state owns lies in that block; the session reports no byte of an arena. Turned red by
/// an open that reserves an arena on use (`SessionArena::reserve` in `lend_session`), which asks
/// the memory for a second block, by a state taken of the allocator and not of the open's memory
/// (`OwnBlock::take`), which asks it for none, or by a plane placed anywhere but the state.
#[test]
fn an_on_use_open_asks_its_memory_for_its_state_alone() {
    use crate::arena::{
        AllocatorMemory, ArenaMemory, ArenaRegion, HeldPlaces, OpenRegion, OpenStorage, PlanFrom,
        PlanShape,
    };

    /// The allocator, counting its reservations and keeping the address of the first it gave.
    struct Counted {
        reserves: AtomicUsize,
        first: AtomicUsize,
    }

    impl ArenaMemory for Counted {
        fn reserve(&self, layout: core::alloc::Layout) -> Option<core::ptr::NonNull<u8>> {
            let base = AllocatorMemory.reserve(layout)?;
            if self.reserves.fetch_add(1, Ordering::SeqCst) == 0 {
                self.first.store(base.as_ptr() as usize, Ordering::SeqCst);
            }
            Some(base)
        }

        unsafe fn release(&self, base: core::ptr::NonNull<u8>, layout: core::alloc::Layout) {
            // SAFETY: the caller's contract: the allocator gave `base` for `layout`, given back
            // once.
            unsafe { AllocatorMemory.release(base, layout) }
        }
    }

    static BLOCK: Counted = Counted {
        reserves: AtomicUsize::new(0),
        first: AtomicUsize::new(0),
    };
    let sim = Sim::new(SEED);
    let _router = sim.stand_in(CatchAll::None);
    let config = sim.config();
    let region: &'static OpenRegion = Box::leak(Box::new(
        SimEngine::open_region(
            ArenaRegion::of(PlanShape::of(&config), config.limits)
                .expect("the client's limits lay a region out"),
            HeldPlaces::NONE,
        )
        .expect("the engine's places lay out"),
    ));
    let engine = sim.open_made_in(
        config,
        OpenStorage {
            memory: &BLOCK,
            plan: PlanFrom::Region(region),
        },
    );
    assert_eq!(
        BLOCK.reserves.load(Ordering::SeqCst),
        1,
        "one block, the state's"
    );
    assert_eq!(engine.arena_bytes(), 0, "no arena is reserved");
    let first = BLOCK.first.load(Ordering::SeqCst) as *const u8;
    assert!(!first.is_null(), "the block was given");
    #[cfg(any(feature = "queryable", feature = "connectivity"))]
    {
        assert!(engine.state_holds(first), "the block is the state");
        for at in engine.plane_places() {
            assert!(engine.state_holds(at), "the plane lies in the state");
        }
    }
}
