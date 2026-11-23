// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Two sessions that hold one dictionary of key ids name a key by its id with no declaration
//! first: a put, a subscriber's declaration and a get, each by an id the other end was never
//! declared, reach that end over loopback. The CONTROL of the put and of the declaration is the
//! same id sent to a session that holds no dictionary, which drops it as upstream does. The ids
//! and keys are synthetic.

use std::sync::{Arc, Mutex};

use wz_capi_port::{
    FilterPlane, QueryCallback, QueryHolder, ReplyCallback, SessionEngine, SubscriberSink, WireKey,
};
use wz_runtime_posix::links::PosixLinks;
use wz_runtime_posix::stream::PosixTcpDial;
use wz_runtime_posix::{PosixClock, PosixEntropy};
use wz_session_core::declare_form::InterestForm;
use wz_session_core::limit_binding::Quota;
use wz_session_core::locality::Locality;
use wz_session_core::policy::{KeyWireForm, SessionPolicy};
use wz_session_core::publish_options::PublishOptions;
use wz_session_core::query_sink::{QueryView, ReplyOut};
use wz_session_core::reply_sink::ReplyView;
use wz_session_core::shared_key_ids::{KeyIds, KeyIdsAtOpen, SharedKeyIds};
use wz_session_core::sink::SampleView;
use wz_session_core::wire_id::ExprId;
use wz_session_core::WhatAmI;

use super::get::remote_get;
use super::listen::{eventually, Stepped};
use super::{client_config, Engine, LOOPBACK};
use crate::{CoopConfig, KeyWireFormRefused, OpenError, OpenKeyIds};

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
    open_with_keys(
        config,
        ids.map_or_else(OpenKeyIds::none, OpenKeyIds::shared),
        policy,
    )
}

fn open_with_keys(
    config: CoopConfig,
    key_ids: OpenKeyIds,
    policy: SessionPolicy,
) -> Result<Arc<Engine>, OpenError> {
    Engine::open_with_key_ids(
        PosixLinks::new(LOOPBACK, PosixTcpDial).waited_by_owner(),
        PosixClock,
        PosixEntropy,
        config,
        policy,
        key_ids,
    )
}

/// The endpoint every listener here is configured with: a loopback port the kernel picks. A link
/// it takes is the one a form stated for this text names.
const LISTEN: &str = "tcp/127.0.0.1:0";

/// A peer listening on [`LISTEN`], holding `ids`, stepped by its read task, with the endpoint it
/// is bound to.
fn listener(ids: Option<SharedKeyIds>, form: KeyWireForm) -> (Stepped, String) {
    listener_with(ids.map_or_else(OpenKeyIds::none, OpenKeyIds::shared), form)
}

/// [`listener`] opened with `key_ids`, which may state the form of its endpoint apart.
fn listener_with(key_ids: OpenKeyIds, form: KeyWireForm) -> (Stepped, String) {
    let engine = open_with_keys(
        CoopConfig {
            whatami: WhatAmI::Peer,
            zid: Some(vec![0xa1; 4]),
            listen: vec![LISTEN.to_owned()],
            ..client_config()
        },
        key_ids,
        policy_of(form),
    )
    .expect("the listener opens");
    let endpoint = engine.listening().pop().expect("one port is bound");
    (Stepped::new(engine), endpoint)
}

/// A client that dials `endpoint` holding the dictionary, under `shared`, once its face is up at
/// `listener`.
fn dialler(listener: &Stepped, endpoint: &str) -> Stepped {
    dialler_with(
        listener,
        endpoint,
        OpenKeyIds::shared(dictionary()),
        KeyWireForm::Shared,
    )
}

/// [`dialler`] opened with `key_ids` under `form`.
fn dialler_with(
    listener: &Stepped,
    endpoint: &str,
    key_ids: OpenKeyIds,
    form: KeyWireForm,
) -> Stepped {
    let client = Stepped::new(
        open_with_keys(
            CoopConfig {
                endpoints: vec![endpoint.to_owned()],
                zid: Some(vec![0xc1; 4]),
                ..client_config()
            },
            key_ids,
            policy_of(form),
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
        .declare_subscriber_on_wire(pattern, wire, Locality::Any, None, {
            let into = into.clone();
            SubscriberSink::shared(move |sample: &dyn SampleView| {
                into.lock().unwrap().push(sample.keyexpr().to_owned());
            })
        })
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
                key,
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
            "lab/q/**",
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
            ReplyCallback::shared(move |view: &dyn ReplyView| {
                let _held = &end;
                into.lock()
                    .unwrap()
                    .push((view.keyexpr().to_owned(), view.payload().to_vec()));
            })
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
fn a_session_says_when_its_links_may_name_keys_their_own_way() {
    let (shared, _) = listener(Some(dictionary()), KeyWireForm::Shared);
    assert!(shared.names_keys_by_link());
    let (literal, _) = listener(None, KeyWireForm::Literal);
    assert!(literal.names_keys_by_link());
    let (declared, _) = listener(None, KeyWireForm::Declared);
    assert!(
        !declared.names_keys_by_link(),
        "upstream's form with no dictionary names every key as the ABI does"
    );
    let stated = OpenKeyIds::new(KeyIdsAtOpen {
        ids: None,
        links: vec![(LISTEN.to_owned(), KeyWireForm::Literal)],
    });
    let (apart, _) = listener_with(stated, KeyWireForm::Declared);
    assert!(
        apart.names_keys_by_link(),
        "one link stated apart is enough"
    );
}

/// What a client that holds no dictionary hears of a put on `lab/rig/alpha` from a listener whose
/// session form is `shared`, when the listener's endpoint is stated `endpoint_form` or not stated,
/// followed by a put on `lab/mark`, which no dictionary entry covers and which every form sends as
/// the literal.
fn heard_from_a_shared_listener(endpoint_form: Option<KeyWireForm>) -> Vec<String> {
    let at_open = KeyIdsAtOpen {
        ids: Some(dictionary()),
        links: endpoint_form
            .map(|form| vec![(LISTEN.to_owned(), form)])
            .unwrap_or_default(),
    };
    let (listener, endpoint) = listener_with(OpenKeyIds::new(at_open), KeyWireForm::Shared);
    let client = dialler_with(
        &listener,
        &endpoint,
        OpenKeyIds::none(),
        KeyWireForm::Declared,
    );
    let heard = hear(&client, "lab/**", WireKey::literal());
    for key in ["lab/rig/alpha", "lab/mark"] {
        listener
            .publish_on_wire_all(key, &WireKey::literal(), b"value", &remote())
            .expect("a put the link carries");
    }
    eventually("the client to hear the literal put", || {
        heard.lock().unwrap().iter().any(|key| key == "lab/mark")
    });
    let heard = heard.lock().unwrap().clone();
    heard
}

#[test]
fn a_link_stated_literal_names_its_keys_whole_under_a_shared_session() {
    assert_eq!(
        heard_from_a_shared_listener(Some(KeyWireForm::Literal)),
        ["lab/rig/alpha", "lab/mark"]
    );
}

#[test]
fn a_link_left_to_the_shared_session_names_its_keys_by_the_dictionary() {
    assert_eq!(
        heard_from_a_shared_listener(None),
        ["lab/mark"],
        "CONTROL: the shared form sent the dictionary's id, which a client without it drops"
    );
}

#[test]
fn a_dialled_link_stated_declared_keeps_the_abis_form_under_a_shared_session() {
    let (listener, endpoint) = listener(None, KeyWireForm::Declared);
    let heard = hear(&listener, "lab/**", WireKey::literal());
    let at_open = KeyIdsAtOpen {
        ids: Some(dictionary()),
        links: vec![(endpoint.clone(), KeyWireForm::Declared)],
    };
    let client = dialler_with(
        &listener,
        &endpoint,
        OpenKeyIds::new(at_open),
        KeyWireForm::Shared,
    );
    client
        .publish_on_wire_all("lab/rig/alpha", &WireKey::literal(), b"value", &remote())
        .expect("a put the link carries");
    eventually("the listener to hear the put", || {
        !heard.lock().unwrap().is_empty()
    });
    assert_eq!(*heard.lock().unwrap(), ["lab/rig/alpha"]);
}

#[test]
fn an_endpoint_stated_twice_is_refused_at_the_open() {
    let at_open = KeyIdsAtOpen {
        ids: Some(dictionary()),
        links: vec![
            (LISTEN.to_owned(), KeyWireForm::Literal),
            (LISTEN.to_owned(), KeyWireForm::Shared),
        ],
    };
    assert_eq!(
        open_with_keys(
            client_config(),
            OpenKeyIds::new(at_open),
            policy_of(KeyWireForm::Declared)
        )
        .err(),
        Some(OpenError::KeyWireForm(KeyWireFormRefused::LinkStatedTwice))
    );
    let shared_without = KeyIdsAtOpen {
        ids: None,
        links: vec![(LISTEN.to_owned(), KeyWireForm::Shared)],
    };
    assert_eq!(
        open_with_keys(
            client_config(),
            OpenKeyIds::new(shared_without),
            policy_of(KeyWireForm::Declared)
        )
        .err(),
        Some(OpenError::KeyWireForm(KeyWireFormRefused::NoDictionary)),
        "an endpoint stated shared needs the dictionary as the session does"
    );
}

/// How the reply to a query a peer asks by the dictionary's id 43 and the rest `/x` names its key
/// on the wire, when the session that answers is opened under `form`: the peer is a stand-in that
/// records each Response as it arrived.
fn reply_key_under(
    form: KeyWireForm,
) -> Vec<(wz_session_core::wire_id::ExprId, Option<String>, bool)> {
    let router = super::Router::start_peer();
    let engine = open_keyed(super::config(&router), Some(dictionary()), policy_of(form))
        .expect("the session opens");
    engine
        .declare_queryable_on_wire(
            "lab/q/**",
            WireKey::literal(),
            false,
            Locality::Any,
            None,
            Arc::new(|_: Arc<dyn QueryHolder>| {
                Box::new(|query: &dyn QueryView, out: &mut dyn ReplyOut| {
                    out.reply_keyed(query.keyexpr(), b"answer")
                        .expect("a reply on the query's own key");
                }) as QueryCallback
            }),
        )
        .expect("the engine has queryables in this build");
    router.send(super::Command::QueryById(9, 43, "/x"));
    super::until(&engine, "the peer to hear the reply", || {
        router.seen(|seen| seen.reply_keys.len()) == 1
    });
    router.seen(|seen| seen.reply_keys.clone())
}

#[test]
fn a_reply_to_a_query_by_a_shared_id_repeats_its_form_with_the_bit_turned() {
    assert_eq!(
        reply_key_under(KeyWireForm::Shared),
        [(43, Some("/x".to_owned()), false)]
    );
}

#[test]
fn a_reply_under_the_declared_form_names_its_key_whole() {
    assert_eq!(
        reply_key_under(KeyWireForm::Declared),
        [(0, Some("lab/q/x".to_owned()), true)],
        "CONTROL: the same query and reply under upstream's form"
    );
}

#[test]
fn the_session_declares_no_key_expression_under_an_id_of_the_dictionary() {
    let held = Arc::new(KeyIds::new([(1, "lab/one"), (2, "lab/two")]).expect("valid"));
    let (with, _) = listener(Some(held), KeyWireForm::Shared);
    assert_eq!(with.acquire_keyexpr("lab/x"), Some(3));
    assert_eq!(with.acquire_keyexpr("lab/y"), Some(4));
    let (without, _) = listener(None, KeyWireForm::Declared);
    assert_eq!(
        without.acquire_keyexpr("lab/x"),
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

/// The dictionary is held to the session's `MAX_SHARED_KEY_IDS` the config states: one entry past
/// it refuses the open before anything is dialled, and at it the open goes on (and fails for the
/// endpoint the config does not name).
#[test]
fn a_dictionary_over_the_configs_limit_is_refused_at_the_open() {
    let stated = |most: usize| {
        let mut config = client_config();
        config
            .limits
            .select_max_shared_key_ids(Quota::at_most(most))
            .map(|()| config)
    };
    let Ok(two) = stated(2) else {
        // A build that keeps the build's value alone states no other.
        return;
    };
    assert_eq!(
        open_keyed(two, Some(dictionary()), policy_of(KeyWireForm::Declared)).err(),
        Some(OpenError::KeyIdsOverLimit {
            stated: 3,
            limit: 2
        })
    );
    let three = stated(3).expect("inside the domain");
    assert_eq!(
        open_keyed(three, Some(dictionary()), policy_of(KeyWireForm::Declared)).err(),
        Some(OpenError::NoEndpoint)
    );
}

/// The key every Interest below asks about: an entry of the dictionary of its own (id 41).
const ASKED: &str = "lab/rig/alpha";

/// An id, and the rest of the key after it, as an Interest named its key on the wire.
type InterestKey = (ExprId, Option<String>);

/// How the Interest that `ask` makes names its key on the wire, from a session opened under
/// `form` (holding `ids`) to a stand-in that announces itself a peer and records each Interest
/// that names a key. `ask` is handed the engine and the id of the session's own declaration of
/// [`ASKED`], which it names the key by, as a pico ABI does for a declared key. Answers that id
/// and what the stand-in recorded.
fn interest_keys_under(
    ids: Option<SharedKeyIds>,
    form: KeyWireForm,
    ask: impl FnOnce(&Engine, ExprId),
) -> (ExprId, Vec<InterestKey>) {
    let router = super::Router::start_peer();
    let engine =
        open_keyed(super::config(&router), ids, policy_of(form)).expect("the session opens");
    let declared = engine
        .acquire_keyexpr(ASKED)
        .expect("a session with ids left declares");
    ask(&engine, declared);
    super::until(&engine, "the peer to see the Interest", || {
        router.seen(|seen| seen.interest_keys.len()) == 1
    });
    (declared, router.seen(|seen| seen.interest_keys.clone()))
}

/// A write filter on [`ASKED`] that asks by the declaration `declared`, as a pico publisher asks.
fn filter_by(engine: &Engine, declared: ExprId) {
    engine
        .declare_write_filter(
            FilterPlane::Subscribers,
            ASKED,
            &WireKey::aliased(declared, None),
            Some(InterestForm {
                mapping_id: declared,
                suffix: None,
                aggregate: false,
            }),
            false,
        )
        .expect("a session with ids left declares");
}

#[test]
fn a_write_filters_interest_on_a_literal_link_names_its_key_whole() {
    let (_, keys) = interest_keys_under(None, KeyWireForm::Literal, filter_by);
    assert_eq!(keys, [(0, Some(ASKED.to_owned()))]);
}

#[test]
fn a_write_filters_interest_on_a_shared_link_names_the_dictionary_id() {
    let (_, keys) = interest_keys_under(Some(dictionary()), KeyWireForm::Shared, filter_by);
    assert_eq!(keys, [(41, None)]);
}

#[test]
fn a_write_filters_interest_on_a_declared_link_names_the_declaration() {
    let (declared, keys) = interest_keys_under(None, KeyWireForm::Declared, filter_by);
    assert_eq!(
        keys,
        [(declared, None)],
        "CONTROL: upstream's form keeps the key as the ABI named it"
    );
}

/// A liveliness subscriber on [`ASKED`], declared by the declaration `declared`.
#[cfg(feature = "liveliness")]
fn tokens_by(engine: &Engine, declared: ExprId) {
    use wz_session_core::declare::liveliness_sample::LivelinessSample;

    let sink = wz_capi_port::LivelinessSink::shared(|_: LivelinessSample<'_>| {});
    engine
        .declare_liveliness_subscriber_on_wire(ASKED, WireKey::aliased(declared, None), false, sink)
        .expect("the engine has liveliness");
}

#[cfg(feature = "liveliness")]
#[test]
fn a_liveliness_subscribers_interest_follows_the_links_form() {
    let (_, keys) = interest_keys_under(None, KeyWireForm::Literal, tokens_by);
    assert_eq!(keys, [(0, Some(ASKED.to_owned()))]);
    let (declared, keys) = interest_keys_under(None, KeyWireForm::Declared, tokens_by);
    assert_eq!(keys, [(declared, None)], "CONTROL: upstream's form");
}

/// A liveliness get on [`ASKED`], asked by the declaration `declared`.
#[cfg(feature = "liveliness-get")]
fn alive_by(engine: &Engine, declared: ExprId) {
    let issued = engine.liveliness_get_on_wire(
        ASKED,
        &WireKey::aliased(declared, None),
        5_000,
        None,
        &mut || ReplyCallback::shared(|_: &dyn ReplyView| {}),
    );
    assert_eq!(issued, Some(1), "one leg for the one face");
}

#[cfg(feature = "liveliness-get")]
#[test]
fn a_liveliness_gets_interest_follows_the_links_form() {
    let (_, keys) = interest_keys_under(None, KeyWireForm::Literal, alive_by);
    assert_eq!(keys, [(0, Some(ASKED.to_owned()))]);
    let (declared, keys) = interest_keys_under(None, KeyWireForm::Declared, alive_by);
    assert_eq!(keys, [(declared, None)], "CONTROL: upstream's form");
}
