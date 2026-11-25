// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The keys the program's objects hold in the session's key arena: one block with the session's
//! own record of the same key, given back with the last holder, refused past the arena or past the
//! session's key bound, and shared and let go of after the session closed with no lock taken.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use wz_capi_port::{
    HeldKey, KeyAsk, KeyHold, KeyNotHeld, SessionDrive, SessionEngine, SessionKeys, SubscriberSink,
    WireKey,
};
use wz_session_core::declare_form::RetractionKey;
use wz_session_core::key_arena::block_bytes;
use wz_session_core::limit_binding::Quota;
use wz_session_core::locality::Locality;
use wz_session_core::sink::SampleView;
use wz_session_core::wire_id::ExprId;

use super::entity_tables::{lowered, open_under};
use super::{open, CatchAll, Engine, Router};

/// The engine's key arena, which the cooperative engine always keeps.
fn keys(engine: &Engine) -> &dyn SessionKeys {
    engine
        .key_arena()
        .expect("the cooperative engine keeps a key arena")
}

/// `text` held in the engine's key arena, or why not.
fn hold(engine: &Engine, text: &str) -> Result<HeldKey, KeyNotHeld> {
    keys(engine)
        .key(KeyAsk::Hold(text))
        .map(|key| key.expect("a hold answers its key"))
}

/// Another holder of `key`.
fn share(engine: &Engine, key: &HeldKey) -> HeldKey {
    keys(engine)
        .key(KeyAsk::Share(key))
        .ok()
        .flatten()
        .expect("a share answers its key")
}

/// Let go of `key`.
fn release(engine: &Engine, key: HeldKey) {
    assert!(matches!(keys(engine).key(KeyAsk::Release(key)), Ok(None)));
}

/// Counts its own drop.
struct Dropped(Arc<AtomicUsize>);

impl Drop for Dropped {
    fn drop(&mut self) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

/// A subscriber's callback that counts its drop in `dropped`.
fn sink(dropped: &Arc<AtomicUsize>) -> SubscriberSink {
    let guard = Dropped(dropped.clone());
    SubscriberSink::shared(move |_sample: &dyn SampleView| {
        let _held = &guard;
    })
}

/// A held key reads back as its text and takes one block; a share takes none, and the block goes
/// back with the last holder.
#[test]
fn a_held_key_reads_back_and_its_last_holder_gives_the_block_back() {
    let router = Router::start(CatchAll::None);
    let engine = open(&router);
    let before = engine.key_counts().used;
    let held = hold(&engine, "demo/held/one").expect("room for a key");
    assert_eq!(held.as_str(), "demo/held/one");
    let block = block_bytes("demo/held/one".len()).expect("a short key");
    assert_eq!(engine.key_counts().used, before + block);
    let shared = share(&engine, &held);
    assert_eq!(
        engine.key_counts().used,
        before + block,
        "a share takes no block"
    );
    release(&engine, held);
    assert_eq!(shared.as_str(), "demo/held/one", "the share still reads it");
    assert_eq!(engine.key_counts().used, before + block);
    release(&engine, shared);
    assert_eq!(
        engine.key_counts().used,
        before,
        "the last holder gave the block back"
    );
}

/// A key the session's record keeps already is held in the record's block: the program's object
/// and the declaration take one block between them, and the hold keeps it when the declaration
/// goes.
#[test]
fn a_key_the_record_keeps_is_held_in_the_same_block() {
    let router = Router::start(CatchAll::None);
    let engine = open(&router);
    let before = engine.key_counts().used;
    let declaration = engine
        .acquire_keyexpr("demo/held/shared")
        .expect("a declaration");
    let declared = engine.key_counts().used;
    assert_eq!(
        declared,
        before + block_bytes("demo/held/shared".len()).expect("a short key")
    );
    let held = hold(&engine, "demo/held/shared").expect("room for a key");
    assert_eq!(
        engine.key_counts().used,
        declared,
        "the record's block is shared"
    );
    declaration.release(&*engine);
    assert_eq!(
        held.as_str(),
        "demo/held/shared",
        "the hold keeps the block"
    );
    assert_eq!(engine.key_counts().used, declared);
    release(&engine, held);
    assert_eq!(engine.key_counts().used, before);
}

/// A key the key arena has no room for is refused and counted, and takes nothing; a key past the
/// session's `MAX_KEYEXPR_BYTES` is refused as too long before any room is asked.
#[test]
fn a_key_past_the_arena_or_the_bound_is_refused_and_takes_nothing() {
    let block = block_bytes("demo/k/1".len()).expect("a short key");
    let router = Router::start(CatchAll::None);
    let engine = open_under(&router, lowered(|l| l.select_key_arena_bytes(2 * block)));
    let first = hold(&engine, "demo/k/1").expect("room for one");
    let second = hold(&engine, "demo/k/2").expect("room for two");
    let full = engine.key_counts();
    assert_eq!(hold(&engine, "demo/k/3").err(), Some(KeyNotHeld::NoRoom));
    let refused = engine.key_counts();
    assert_eq!(refused.used, full.used, "a refusal takes nothing");
    assert_eq!(refused.refused, full.refused + 1, "and is counted");
    release(&engine, first);
    let third = hold(&engine, "demo/k/3").expect("the block given back takes it");
    release(&engine, second);
    release(&engine, third);

    let other = Router::start(CatchAll::None);
    let bounded = open_under(
        &other,
        lowered(|l| l.select_max_keyexpr_bytes(Quota::at_most(8))),
    );
    let asked = bounded.key_counts();
    assert_eq!(
        hold(&bounded, "demo/k/too/long").err(),
        Some(KeyNotHeld::TooLong)
    );
    assert_eq!(bounded.key_counts(), asked, "a key too long asks no room");
    assert!(hold(&bounded, "demo/k/1").is_ok(), "CONTROL");
}

/// Holds let go of, and subscribers declared and undeclared, many times past what the key arena
/// holds at once, each take the room the one before gave back: none is refused, and the arena ends
/// as it began.
#[test]
fn holds_and_declarations_past_the_arena_leave_it_as_they_found_it() {
    let block = block_bytes("demo/c/0".len()).expect("a short key");
    // Room for one subscriber at a time: the engine's record and the application's table each
    // keep its key.
    let router = Router::start(CatchAll::None);
    let engine = open_under(&router, lowered(|l| l.select_key_arena_bytes(2 * block)));
    let before = engine.key_counts();
    let dropped = Arc::new(AtomicUsize::new(0));
    for round in 0..10 {
        let key = format!("demo/c/{round}");
        let held = hold(&engine, &key).expect("the room given back");
        release(&engine, held);
        let id = engine
            .declare_subscriber_on_wire(
                &key,
                WireKey::literal(),
                Locality::Any,
                None,
                sink(&dropped),
            )
            .expect("the room given back takes the subscriber");
        engine.undeclare_subscriber(id);
    }
    let after = engine.key_counts();
    assert_eq!(after.used, before.used, "every block went back");
    assert_eq!(after.refused, before.refused, "none was refused");
    assert_eq!(
        dropped.load(Ordering::SeqCst),
        10,
        "each callback let go of with its undeclaration"
    );
}

/// After the session closed, a held key still reads, a share of it reads, and letting go of either
/// gives nothing back and takes no lock; a key asked for then is refused as the session's.
#[test]
fn a_closed_sessions_keys_are_read_shared_and_let_go_of() {
    let router = Router::start(CatchAll::None);
    let engine = open(&router);
    let held = hold(&engine, "demo/closed/key").expect("room for a key");
    SessionDrive::close(&*engine);
    assert_eq!(held.as_str(), "demo/closed/key");
    let shared = share(&engine, &held);
    assert_eq!(shared.as_str(), "demo/closed/key");
    let closed = engine.key_counts();
    release(&engine, shared);
    release(&engine, held);
    assert_eq!(
        engine.key_counts().used,
        closed.used,
        "a closed session gives no block back"
    );
    assert_eq!(
        hold(&engine, "demo/closed/other").err(),
        Some(KeyNotHeld::Closed)
    );
}

/// Two holds of one text, and a declaration of it, take one block between them, whichever came
/// first: the arena finds a text it keeps already whoever holds it. The block goes back with the
/// last of them.
#[test]
fn holds_of_one_text_share_its_block_whoever_holds_it() {
    let router = Router::start(CatchAll::None);
    let engine = open(&router);
    let before = engine.key_counts().used;
    let first = hold(&engine, "demo/held/twice").expect("room for a key");
    let block = block_bytes("demo/held/twice".len()).expect("a short key");
    let second = hold(&engine, "demo/held/twice").expect("the same block");
    assert_eq!(
        engine.key_counts().used,
        before + block,
        "one block for both holds"
    );
    let declaration = engine
        .acquire_keyexpr("demo/held/twice")
        .expect("a declaration");
    assert_eq!(
        engine.key_counts().used,
        before + block,
        "the declaration finds the held block"
    );
    let other = hold(&engine, "demo/held/other").expect("room for a key");
    assert_eq!(
        engine.key_counts().used,
        before + block + block_bytes("demo/held/other".len()).expect("a short key"),
        "CONTROL: another text takes a block of its own"
    );
    release(&engine, first);
    declaration.release(&*engine);
    assert_eq!(second.as_str(), "demo/held/twice");
    release(&engine, second);
    release(&engine, other);
    assert_eq!(engine.key_counts().used, before, "every block went back");
}

/// The holds of a declaration the session handed out and was not given back, counted whether the
/// session is open or closed (`Takes::holds`): a hold given back to a closed session is still one
/// given back.
fn live_holds(engine: &Engine) -> isize {
    engine.takes.holds.load(Ordering::SeqCst)
}

/// A declaration the session's rows name stays declared until the last of them goes, whatever
/// order the program lets go of its own key in: a subscriber whose key is named by it and one
/// whose retraction names it and one whose key states it as its own each hold it in the session's
/// one count, the keys they were declared on hold nothing, and the close lets every row go with no
/// hold left live. Turned red by a row that holds the declaration its retraction names nowhere
/// (gone at the first undeclaration), by one that ignores the declaration its key states (gone at
/// the second), by a key that takes a hold of its own (two live after the declarations), and by
/// a close that leaves a callback undropped.
#[test]
fn a_declaration_outlives_the_program_key_until_the_last_row_naming_it_goes() {
    let router = Router::start(CatchAll::None);
    let engine = open(&router);
    let program = engine
        .acquire_keyexpr("demo/holds")
        .expect("room for a declaration");
    let id = program.mapping_id();
    let dropped = Arc::new(AtomicUsize::new(0));
    let named_by_key = engine
        .declare_subscriber_on_wire(
            "demo/holds/a",
            WireKey::aliased_tail(id, "/a".len()),
            Locality::Any,
            Some(RetractionKey::declared(id, "/a")),
            sink(&dropped),
        )
        .expect("declared");
    let named_by_retraction = engine
        .declare_subscriber_on_wire(
            "demo/holds/b",
            WireKey::literal(),
            Locality::Any,
            Some(RetractionKey::declared(id, "/b")),
            sink(&dropped),
        )
        .expect("declared");
    let named_as_own = engine
        .declare_subscriber_on_wire(
            "demo/holds/o",
            WireKey::literal().with_own(id),
            Locality::Any,
            None,
            sink(&dropped),
        )
        .expect("declared");
    assert_eq!(live_holds(&engine), 1, "the program's hold alone");
    program.release(&*engine);
    assert_eq!(
        engine.keyexpr_declarations(),
        vec![(id, "demo/holds".to_owned())],
        "the rows hold it past the program's release"
    );
    engine.undeclare_subscriber(named_by_key);
    assert_eq!(
        engine.keyexpr_declarations(),
        vec![(id, "demo/holds".to_owned())],
        "the row whose retraction names it holds it still"
    );
    engine.undeclare_subscriber(named_by_retraction);
    assert_eq!(
        engine.keyexpr_declarations(),
        vec![(id, "demo/holds".to_owned())],
        "the row whose key states it as its own holds it still"
    );
    engine.undeclare_subscriber(named_as_own);
    assert!(
        engine.keyexpr_declarations().is_empty(),
        "and lets it go with the last row"
    );

    let program = engine
        .acquire_keyexpr("demo/holds")
        .expect("room for a declaration");
    let again = program.mapping_id();
    engine
        .declare_subscriber_on_wire(
            "demo/holds/c",
            WireKey::aliased_tail(again, "/c".len()),
            Locality::Any,
            None,
            sink(&dropped),
        )
        .expect("declared");
    SessionDrive::close(&*engine);
    program.release(&*engine);
    assert_eq!(live_holds(&engine), 0, "no hold is live after the close");
    assert_eq!(
        dropped.load(Ordering::SeqCst),
        4,
        "each callback let go of with its row"
    );
}

/// A subscriber's row holds the declaration its key is named by for as long as it stands, and is
/// the one holder the subscriber has of it: the key it was declared on holds nothing, the
/// declaration outlives the program's hold while the subscriber stands, and it goes with the
/// subscriber once nothing else holds it. Turned red by a row that holds the declaration nowhere
/// (gone at the program's release).
#[test]
fn a_subscribers_row_is_the_one_holder_of_the_declaration_its_key_is_named_by() {
    let router = Router::start(CatchAll::None);
    let engine = open(&router);
    let program = engine
        .acquire_keyexpr("demo/named")
        .expect("room for a declaration");
    let id = program.mapping_id();
    let dropped = Arc::new(AtomicUsize::new(0));
    let subscriber = engine
        .declare_subscriber_on_wire(
            "demo/named/x",
            WireKey::aliased_tail(id, "/x".len()),
            Locality::Any,
            None,
            sink(&dropped),
        )
        .expect("declared");
    assert_eq!(
        live_holds(&engine),
        1,
        "the program's hold alone: the row holds the declaration"
    );
    program.release(&*engine);
    assert_eq!(
        engine.keyexpr_declarations(),
        vec![(id, "demo/named".to_owned())],
        "the subscriber's row holds it past the program's release"
    );
    engine.undeclare_subscriber(subscriber);
    assert!(
        engine.keyexpr_declarations().is_empty(),
        "and lets it go with the subscriber"
    );
    assert_eq!(live_holds(&engine), 0, "no hold is live");
    assert_eq!(
        dropped.load(Ordering::SeqCst),
        1,
        "the callback went with it"
    );
}

/// A liveliness subscriber's row holds the declaration its Interest names the key by, as a
/// subscriber's does: the declaration outlives the program's hold while the subscriber stands, and
/// it goes with the subscriber once nothing else holds it. Turned red by a row given no
/// declaration in the tables (gone at the program's release).
#[cfg(feature = "liveliness")]
#[test]
fn a_liveliness_subscribers_row_holds_the_declaration_its_interest_names() {
    use wz_session_core::declare::liveliness_sample::LivelinessSample;

    let router = Router::start(CatchAll::None);
    let engine = open(&router);
    let program = engine
        .acquire_keyexpr("demo/alive")
        .expect("room for a declaration");
    let id = program.mapping_id();
    let subscriber = engine
        .declare_liveliness_subscriber_on_wire(
            "demo/alive/**",
            WireKey::aliased_tail(id, "/**".len()),
            false,
            wz_capi_port::LivelinessSink::shared(|_: LivelinessSample<'_>| {}),
        )
        .expect("the engine has liveliness");
    assert_eq!(
        live_holds(&engine),
        1,
        "the program's hold alone: the row holds the declaration"
    );
    program.release(&*engine);
    assert_eq!(
        engine.keyexpr_declarations(),
        vec![(id, "demo/alive".to_owned())],
        "the subscriber's row holds it past the program's release"
    );
    engine.undeclare_subscriber(subscriber);
    assert!(
        engine.keyexpr_declarations().is_empty(),
        "and lets it go with the subscriber"
    );
    assert_eq!(live_holds(&engine), 0, "no hold is live");
}

/// A queryable's row holds the declaration its key is named by for as long as it stands, and is
/// the one holder the queryable has of it, and the declaration outlives the program's hold while
/// the queryable stands. A queryable the tables refuse holds nothing. Turned red by a row that
/// holds the declaration nowhere (gone at the program's release), and by a refusal that leaves a
/// hold in the count (the declaration still listed after the undeclaration).
#[cfg(feature = "queryable")]
#[test]
fn a_queryables_row_is_the_one_holder_of_the_declaration_its_key_is_named_by() {
    use wz_capi_port::{QueryHolder, QueryableSink};
    use wz_session_core::query_sink::{QueryView, ReplyOut};

    let limits = lowered(|l| l.select_max_queryables(Quota::at_most(1)));
    let router = Router::start(CatchAll::None);
    let engine = open_under(&router, limits);
    let program = engine
        .acquire_keyexpr("demo/named")
        .expect("room for a declaration");
    let id = program.mapping_id();
    let dropped = Arc::new(AtomicUsize::new(0));
    let sink = || -> QueryableSink {
        let guard = Dropped(dropped.clone());
        QueryableSink::shared(
            move |_query: &dyn QueryView, _out: &mut dyn ReplyOut, _holder: &dyn QueryHolder| {
                let _held = &guard;
            },
        )
    };
    let declare = |rest: &str| {
        engine.declare_queryable_on_wire(
            &format!("demo/named{rest}"),
            WireKey::aliased_tail(id, rest.len()),
            false,
            Locality::Any,
            None,
            sink(),
        )
    };
    let queryable = declare("/x").expect("declared");
    assert_eq!(
        live_holds(&engine),
        1,
        "the program's hold alone: the row holds the declaration"
    );
    assert!(declare("/y").is_err(), "CONTROL: the one row is taken");
    assert_eq!(
        live_holds(&engine),
        1,
        "the refused queryable's key held nothing"
    );
    program.release(&*engine);
    assert_eq!(
        engine.keyexpr_declarations(),
        vec![(id, "demo/named".to_owned())],
        "the queryable's row holds it past the program's release"
    );
    engine.undeclare_queryable(queryable);
    assert!(
        engine.keyexpr_declarations().is_empty(),
        "and lets it go with the queryable"
    );
    assert_eq!(live_holds(&engine), 0, "no hold is live");
    assert_eq!(
        dropped.load(Ordering::SeqCst),
        2,
        "the refused callback at once, the other with its row"
    );
}

/// A hold gives itself back by the row it was taken in, not by its id: once its declaration went,
/// and a later declaration took the same id after the ids wrapped, giving it back lets go of
/// nothing. The hold that outlives its declaration is a second hold of a count of one, as a holder
/// is whose declaration another holder's going retracted. The ids are minted from the last, so
/// they wrap at the next declaration and the id comes again within as many as it is from 1.
/// Turned red by a hold given back by its id (`KeyHold::release` or
/// `KeyHolds::release_keyexpr` looking the id up), which retracts the new declaration.
#[test]
fn a_hold_whose_declaration_went_spares_the_one_that_took_its_id_again() {
    let router = Router::start(CatchAll::None);
    let engine = open(&router);
    let program = engine
        .acquire_keyexpr("demo/held/old")
        .expect("room for a declaration");
    let old = program.mapping_id();
    let outlived = KeyHold::taken(old, program.row().expect("a hold the session took"));
    program.release(&*engine);
    assert!(
        engine.keyexpr_declarations().is_empty(),
        "CONTROL: the count of one went with the program's hold"
    );
    // The last id, then 1 onward: declarations made and let go of come to the id again. The
    // session is stepped with each, so what it sends the router is read as it goes.
    engine.expr_ids_from(ExprId::MAX);
    let again = (0..=old)
        .find_map(|_| {
            let hold = engine
                .acquire_keyexpr("demo/held/new")
                .expect("an id is free");
            let _ = SessionDrive::read(&*engine, false);
            if hold.mapping_id() == old {
                return Some(hold);
            }
            hold.release(&*engine);
            None
        })
        .expect("the id is minted again");
    outlived.release(&*engine);
    assert_eq!(
        engine.keyexpr_declarations(),
        vec![(old, "demo/held/new".to_owned())],
        "the new declaration stands after the outlived hold went"
    );
    again.release(&*engine);
    assert!(engine.keyexpr_declarations().is_empty());
}
