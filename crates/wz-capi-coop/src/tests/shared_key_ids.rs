// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Two sessions that hold one dictionary of key ids name a key by its id with no declaration
//! first: a put, a subscriber's declaration and a get, each by an id the other end was never
//! declared, reach that end over loopback. The CONTROL of the put and of the declaration is the
//! same id sent to a session that holds no dictionary, which drops it as upstream does. The ids
//! and keys are synthetic.

use std::sync::{Arc, Mutex};

use wz_capi_port::{
    FilterPlane, QueryCallback, QueryHolder, ReplyCallback, SessionEngine, WireKey,
};
use wz_runtime_posix::links::PosixLinks;
use wz_runtime_posix::stream::PosixTcpDial;
use wz_runtime_posix::{PosixClock, PosixEntropy};
use wz_session_core::locality::Locality;
use wz_session_core::policy::{KeyWireForm, SessionPolicy};
use wz_session_core::publish_options::PublishOptions;
use wz_session_core::query_sink::{QueryView, ReplyOut};
use wz_session_core::reply_sink::ReplyView;
use wz_session_core::shared_key_ids::{KeyIds, SharedKeyIds};
use wz_session_core::sink::SampleView;
use wz_session_core::WhatAmI;

use super::get::remote_get;
use super::listen::{eventually, Stepped};
use super::{client_config, Engine, LOOPBACK};
use crate::{CoopConfig, KeyWireFormRefused, OpenError};

/// The dictionary both ends hold: a key, a key below it, and a prefix a get names a key under.
fn dictionary() -> SharedKeyIds {
    Arc::new(
        KeyIds::new([(40, "lab/rig"), (41, "lab/rig/alpha"), (43, "lab/q")])
            .expect("a valid dictionary"),
    )
}

/// The defaults, with `form` as the key-wire form.
fn policy_of(form: KeyWireForm) -> SessionPolicy {
    let mut policy = SessionPolicy::defaults();
    policy
        .select_key_wire_form(form)
        .expect("a host build allows every value of the key-wire form");
    policy
}

fn open_keyed(
    config: CoopConfig,
    ids: Option<SharedKeyIds>,
    policy: SessionPolicy,
) -> Result<Arc<Engine>, OpenError> {
    Engine::open_with_key_ids(
        PosixLinks::new(LOOPBACK, PosixTcpDial).waited_by_owner(),
        PosixClock,
        PosixEntropy,
        config,
        policy,
        ids,
    )
}

/// A peer listening on a loopback port the kernel picks, holding `ids`, stepped by its read task,
/// with the endpoint it is bound to.
fn listener(ids: Option<SharedKeyIds>, form: KeyWireForm) -> (Stepped, String) {
    let engine = open_keyed(
        CoopConfig {
            whatami: WhatAmI::Peer,
            zid: Some(vec![0xa1; 4]),
            listen: vec!["tcp/127.0.0.1:0".to_owned()],
            ..client_config()
        },
        ids,
        policy_of(form),
    )
    .expect("the listener opens");
    let endpoint = engine.listening().pop().expect("one port is bound");
    (Stepped::new(engine), endpoint)
}

/// A client that dials `endpoint` holding the dictionary, under `shared`, once its face is up at
/// `listener`.
fn dialler(listener: &Stepped, endpoint: &str) -> Stepped {
    let client = Stepped::new(
        open_keyed(
            CoopConfig {
                endpoints: vec![endpoint.to_owned()],
                zid: Some(vec![0xc1; 4]),
                ..client_config()
            },
            Some(dictionary()),
            policy_of(KeyWireForm::Shared),
        )
        .expect("the client opens"),
    );
    eventually("the listener to hold the client's face", || {
        listener.faces_up() == 1
    });
    client
}

/// A subscriber of `engine` on `pattern`, declared as `wire` names it, and the keys it hears.
fn hear(engine: &Engine, pattern: &str, wire: WireKey) -> Arc<Mutex<Vec<String>>> {
    let heard = Arc::new(Mutex::new(Vec::new()));
    let into = heard.clone();
    engine
        .declare_subscriber_on_wire(
            pattern.to_owned(),
            wire,
            Locality::Any,
            None,
            Arc::new(move || {
                let into = into.clone();
                Box::new(move |sample: &dyn SampleView| {
                    into.lock().unwrap().push(sample.keyexpr().to_owned());
                })
            }),
        )
        .expect("a session with ids left declares");
    heard
}

fn remote() -> PublishOptions {
    PublishOptions::put().with_locality(Locality::Remote)
}

#[test]
fn a_put_by_a_shared_id_reaches_a_session_that_holds_the_dictionary() {
    let (listener, endpoint) = listener(Some(dictionary()), KeyWireForm::Shared);
    let heard = hear(&listener, "lab/**", WireKey::literal());
    let client = dialler(&listener, &endpoint);
    client
        .publish_on_wire_all(
            "lab/rig/alpha",
            &WireKey::aliased(41, None),
            b"one",
            &remote(),
        )
        .expect("a put the link carries");
    client
        .publish_on_wire_all(
            "lab/rig/gamma",
            &WireKey::aliased(40, Some("/gamma".to_owned())),
            b"two",
            &remote(),
        )
        .expect("a put the link carries");
    eventually("the listener to hear both puts", || {
        heard.lock().unwrap().len() == 2
    });
    assert_eq!(*heard.lock().unwrap(), ["lab/rig/alpha", "lab/rig/gamma"]);
}

#[test]
fn a_session_without_the_dictionary_drops_a_put_by_a_shared_id() {
    let (listener, endpoint) = listener(None, KeyWireForm::Declared);
    let heard = hear(&listener, "lab/**", WireKey::literal());
    let client = dialler(&listener, &endpoint);
    client
        .publish_on_wire_all(
            "lab/rig/alpha",
            &WireKey::aliased(41, None),
            b"one",
            &remote(),
        )
        .expect("a put the link carries");
    // The literal put after it on the same reliable link is the mark that the first has arrived.
    client
        .publish_on_wire_all("lab/mark", &WireKey::literal(), b"mark", &remote())
        .expect("a put the link carries");
    eventually("the listener to hear the literal put", || {
        !heard.lock().unwrap().is_empty()
    });
    assert_eq!(
        *heard.lock().unwrap(),
        ["lab/mark"],
        "an id the session was never declared, with no dictionary, names nothing"
    );
}

/// Whether the listener counts a subscriber the client declares by the dictionary's id. A write
/// filter on the key is open once a peer's subscriber matches it; a second subscriber declared
/// as the literal after it, and the filter on its key, are the mark that the first has arrived.
fn counts_a_subscriber_declared_by_id(ids: Option<SharedKeyIds>, form: KeyWireForm) -> bool {
    let (listener, endpoint) = listener(ids, form);
    let filter = |key: &str| {
        listener
            .declare_write_filter(
                FilterPlane::Subscribers,
                key.to_owned(),
                &WireKey::literal(),
                None,
                false,
            )
            .expect("a session with ids left declares")
    };
    let (by_id, mark) = (filter("lab/rig/alpha"), filter("lab/mark"));
    assert!(
        listener.write_filter_active(by_id) && listener.write_filter_active(mark),
        "CONTROL: no peer has declared anything yet"
    );
    let client = dialler(&listener, &endpoint);
    let _by_id = hear(&client, "lab/rig/alpha", WireKey::aliased(41, None));
    let _mark = hear(&client, "lab/mark", WireKey::literal());
    eventually("the literal declaration to count", || {
        !listener.write_filter_active(mark)
    });
    !listener.write_filter_active(by_id)
}

#[test]
fn a_subscriber_declared_by_a_shared_id_counts_where_the_dictionary_is_held() {
    assert!(counts_a_subscriber_declared_by_id(
        Some(dictionary()),
        KeyWireForm::Shared
    ));
}

#[test]
fn a_subscriber_declared_by_a_shared_id_counts_nowhere_else() {
    assert!(!counts_a_subscriber_declared_by_id(
        None,
        KeyWireForm::Declared
    ));
}

#[test]
fn a_get_by_a_shared_id_and_the_rest_is_answered_where_the_dictionary_is_held() {
    let (listener, endpoint) = listener(Some(dictionary()), KeyWireForm::Shared);
    let client = dialler(&listener, &endpoint);
    let asked = Arc::new(Mutex::new(Vec::<String>::new()));
    let into = asked.clone();
    client
        .declare_queryable_on_wire(
            "lab/q/**".to_owned(),
            WireKey::literal(),
            false,
            Locality::Any,
            None,
            Arc::new(move |_: Arc<dyn QueryHolder>| {
                let into = into.clone();
                Box::new(move |query: &dyn QueryView, out: &mut dyn ReplyOut| {
                    into.lock().unwrap().push(query.keyexpr().to_owned());
                    out.reply_keyed(query.keyexpr(), b"answer")
                        .expect("a reply on the query's own key");
                }) as QueryCallback
            }),
        )
        .expect("the engine has queryables in this build");
    let replies = Arc::new(Mutex::new(Vec::<(String, Vec<u8>)>::new()));
    let ended = Arc::new(Mutex::new(0usize));
    struct End(Arc<Mutex<usize>>);
    impl Drop for End {
        fn drop(&mut self) {
            *self.0.lock().unwrap() += 1;
        }
    }
    let issued = listener.get_on_wire(
        "lab/q/x",
        &WireKey::aliased(43, Some("/x".to_owned())),
        &remote_get(),
        None,
        &mut || {
            let end = End(ended.clone());
            let into = replies.clone();
            Box::new(move |view: &dyn ReplyView| {
                let _held = &end;
                into.lock()
                    .unwrap()
                    .push((view.keyexpr().to_owned(), view.payload().to_vec()));
            }) as ReplyCallback
        },
    );
    assert_eq!(issued, Some(1), "one leg for the one face");
    eventually("the leg to end", || *ended.lock().unwrap() == 1);
    assert_eq!(
        *asked.lock().unwrap(),
        ["lab/q/x"],
        "the queryable read the dictionary's prefix and the rest"
    );
    assert_eq!(
        *replies.lock().unwrap(),
        [("lab/q/x".to_owned(), b"answer".to_vec())]
    );
}

#[test]
fn the_session_names_a_key_as_its_form_says() {
    let (shared, _) = listener(Some(dictionary()), KeyWireForm::Shared);
    let exact = shared
        .key_wire_by_form("lab/rig/alpha")
        .expect("the shared form names the key");
    assert_eq!((exact.mapping_id, exact.suffix), (41, None));
    let below = shared
        .key_wire_by_form("lab/rig/gamma")
        .expect("the shared form names the key");
    assert_eq!(
        (below.mapping_id, below.suffix.as_deref()),
        (40, Some("/gamma"))
    );
    let elsewhere = shared
        .key_wire_by_form("elsewhere/x")
        .expect("the shared form names the key");
    assert!(
        elsewhere.is_literal(),
        "a key the dictionary does not cover"
    );

    let (literal, _) = listener(None, KeyWireForm::Literal);
    assert!(literal
        .key_wire_by_form("lab/rig/alpha")
        .expect("the literal form names the key")
        .is_literal());

    let (declared, _) = listener(Some(dictionary()), KeyWireForm::Declared);
    assert!(
        declared.key_wire_by_form("lab/rig/alpha").is_none(),
        "the declared form leaves the key to the ABI, as upstream's"
    );
}

#[test]
fn the_session_declares_no_key_expression_under_an_id_of_the_dictionary() {
    let held = Arc::new(KeyIds::new([(1, "lab/one"), (2, "lab/two")]).expect("valid"));
    let (with, _) = listener(Some(held), KeyWireForm::Shared);
    assert_eq!(with.acquire_keyexpr("lab/x".to_owned()), Some(3));
    assert_eq!(with.acquire_keyexpr("lab/y".to_owned()), Some(4));
    let (without, _) = listener(None, KeyWireForm::Declared);
    assert_eq!(
        without.acquire_keyexpr("lab/x".to_owned()),
        Some(1),
        "CONTROL: without a dictionary the first id is 1"
    );
}

#[test]
fn a_shared_form_without_a_dictionary_is_refused_before_anything_is_dialled() {
    assert_eq!(
        open_keyed(client_config(), None, policy_of(KeyWireForm::Shared)).err(),
        Some(OpenError::KeyWireForm(KeyWireFormRefused::NoDictionary))
    );
    // The other forms need no dictionary: the open goes on, and fails for the endpoint the
    // config does not name.
    for form in [KeyWireForm::Literal, KeyWireForm::Declared] {
        assert_eq!(
            open_keyed(client_config(), None, policy_of(form)).err(),
            Some(OpenError::NoEndpoint)
        );
    }
}
