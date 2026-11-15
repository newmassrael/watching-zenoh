// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! What a session applies itself, above the links it opens: the part of its configuration that
//! upstream applies in its session and its runtime and not in the transport it configures.
//!
//! * [`PublicationQos`], `qos/publication`: the QoS a publication on a key the configuration names
//!   is given over what the publication states, when a publisher is declared and when a put or a
//!   delete is made (`zenoh/src/api/builders/publisher.rs` @
//!   `pub(crate) fn apply_qos_overwrites(self) -> Self {`).
//! * [`ShmInit`], `transport/shared_memory/mode`: whether the open makes the shared-memory
//!   subsystem of the process ([`init_shared_memory`]) or leaves it to the first buffer
//!   (`zenoh/src/net/runtime/mod.rs` @ `zenoh_config::ShmInitMode::Init => zenoh_shm::init::init(),`).
//! * [`ShmPromotion`], `transport/shared_memory/transport_optimization/message_size_threshold`
//!   and `messages`: which plain payloads are copied into the session's provider so that they
//!   cross a link that negotiated shared memory as a descriptor
//!   (`io/zenoh-transport/src/common/shm/interop.rs` @ `fn wrap_in_place<const ID: u8>(`).
//! * [`DeclarationAggregation`], `aggregation/subscribers` and `aggregation/publishers`: the keys
//!   the session declares its subscribers and asks for its publishers' subscribers under, one
//!   declaration per aggregate (`zenoh/src/api/session.rs` @ `.aggregated_subscribers`). The
//!   registry of faces gives it to every session it holds, and a node, whose own entities are
//!   entries of its tables and not declarations of a session, refuses it by name
//!   (`crate::drive::router_refused_ask`).
//!
//! One value, [`SessionDefaults`], is compiled from the configuration by the open plan, carried by
//! the open into the session it makes (the registry of faces or a node), and read from there by
//! every ABI that publishes through the session: the C ABI and the Rust API preset decide each of
//! these the same way because they ask the same value the same question. What differs between
//! them is only the provider a promoted payload is copied into, which is each ABI's own until the
//! process holds one shared-memory system (`docs/shm-transport.md`, section 6).

use wz_runtime_tokio::declaration_aggregation::DeclarationAggregation;
use wz_runtime_tokio::keyexpr_match::keyexpr_includes_target;
use wz_runtime_tokio::locality::Locality;
use wz_runtime_tokio::qos::{CongestionControl, Priority};
use wz_runtime_tokio::session::PublishOptions;
use wz_runtime_tokio::Reliability;

/// What a session applies itself, compiled once from its configuration.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SessionDefaults {
    /// `qos/publication`.
    pub publication_qos: PublicationQos,
    /// `transport/shared_memory/mode`.
    pub shm_init: ShmInit,
    /// `transport/shared_memory/transport_optimization/{message_size_threshold,messages}`.
    pub shm_promotion: ShmPromotion,
    /// `aggregation/{subscribers,publishers}`.
    pub aggregation: DeclarationAggregation,
}

/// What a `qos/publication` rule sets on a publication: each field stated replaces what the
/// publication states, and a field left `None` leaves it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PublicationDefaults {
    /// The congestion control.
    pub congestion_control: Option<CongestionControl>,
    /// The priority.
    pub priority: Option<Priority>,
    /// The express flag.
    pub express: Option<bool>,
    /// The reliability.
    pub reliability: Option<Reliability>,
    /// The destinations the publication may reach.
    pub allowed_destination: Option<Locality>,
}

impl PublicationDefaults {
    /// `options` with what these defaults state written over it.
    pub fn apply_to(&self, options: PublishOptions) -> PublishOptions {
        let mut options = options;
        if let Some(congestion) = self.congestion_control {
            options = options.with_congestion_control(congestion);
        }
        if let Some(priority) = self.priority {
            options = options.with_priority(priority);
        }
        if let Some(express) = self.express {
            options = options.with_express(express);
        }
        if let Some(reliability) = self.reliability {
            options = options.with_reliability(reliability);
        }
        if let Some(destination) = self.allowed_destination {
            options = options.with_locality(destination);
        }
        options
    }
}

/// The rules of `qos/publication`: for each key expression a rule names, what it sets.
///
/// One rule per key expression, in the order the configuration writes them. A key expression
/// written twice keeps the place it was first written at and the settings it was last given, as
/// upstream's tree keeps the last value inserted at one key (`commons/zenoh-config/src/qos.rs` @
/// `tree.insert(&key_expr, conf.config.clone());`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PublicationQos {
    rules: Vec<(String, PublicationDefaults)>,
}

/// The rule [`PublicationQos::find`] applies to a key, and the others that include the key too.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicationQosMatch<'a> {
    /// The key expression of the rule applied.
    pub key_expr: &'a str,
    /// What it sets.
    pub defaults: PublicationDefaults,
    /// The key expressions of the other rules that include the key, which are not applied.
    pub also_including: Vec<&'a str>,
}

impl PublicationQos {
    /// The rules of `items`, each the key expressions of one item and what that item sets.
    pub fn new(items: impl IntoIterator<Item = (Vec<String>, PublicationDefaults)>) -> Self {
        let mut rules: Vec<(String, PublicationDefaults)> = Vec::new();
        for (key_exprs, defaults) in items {
            for key_expr in key_exprs {
                match rules.iter_mut().find(|rule| rule.0 == key_expr) {
                    Some(rule) => rule.1 = defaults,
                    None => rules.push((key_expr, defaults)),
                }
            }
        }
        Self { rules }
    }

    /// Whether no rule is stated, so that no publication is given anything.
    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    /// The rule that applies to a publication on `key`: the first whose key expression includes
    /// `key`, with the others that include it as well. Upstream applies one of several by the
    /// order of its tree and warns that it did; wz applies the first written, which is the order
    /// an operator reads, and reports the others for the same warning.
    pub fn find(&self, key: &str) -> Option<PublicationQosMatch<'_>> {
        let chunks: Vec<&str> = key.split('/').collect();
        let mut including = self
            .rules
            .iter()
            .filter(|rule| keyexpr_includes_target(&rule.0, &chunks));
        let (key_expr, defaults) = including.next()?;
        Some(PublicationQosMatch {
            key_expr: key_expr.as_str(),
            defaults: *defaults,
            also_including: including.map(|rule| rule.0.as_str()).collect(),
        })
    }

    /// What a publication on `key` is given: the settings of the rule [`Self::find`] applies, or
    /// nothing.
    pub fn defaults_for(&self, key: &str) -> PublicationDefaults {
        self.find(key)
            .map_or_else(PublicationDefaults::default, |found| found.defaults)
    }

    /// `options` of a publication on `key`, with what the configuration sets for that key
    /// written over them.
    pub fn apply(&self, key: &str, options: PublishOptions) -> PublishOptions {
        if self.is_empty() {
            return options;
        }
        self.defaults_for(key).apply_to(options)
    }
}

/// When the shared-memory subsystem of the process is made (`transport/shared_memory/mode`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ShmInit {
    /// At the first buffer the process allocates or receives: upstream's `lazy`, its default.
    #[default]
    Lazy,
    /// When a session opens: upstream's `init`.
    Init,
}

/// Make the shared-memory subsystem now when `mode` asks for it. The open of every session the
/// engine makes calls it, a node's as well; a build without the shared-memory transport has no
/// subsystem to make, as upstream's built without shared memory has none.
pub fn init_shared_memory(mode: ShmInit) {
    #[cfg(feature = "transport-shm")]
    if mode == ShmInit::Init {
        wz_runtime_tokio::shm_provider::init();
    }
    #[cfg(not(feature = "transport-shm"))]
    let _ = mode;
}

/// A kind of message whose payload the implicit optimisation can copy into shared memory:
/// upstream's `DataMessage` without the delete, which carries no payload.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PromotedMessage {
    /// A put.
    Put,
    /// The value of a query.
    Query,
    /// A reply.
    Reply,
}

/// The kinds of message a promotion is made for, or a session makes one for.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PromotedMessages {
    /// Puts.
    pub put: bool,
    /// The values of queries.
    pub query: bool,
    /// Replies.
    pub reply: bool,
}

impl PromotedMessages {
    /// Every kind: upstream's default list.
    pub const ALL: Self = Self {
        put: true,
        query: true,
        reply: true,
    };

    /// No kind.
    pub const NONE: Self = Self {
        put: false,
        query: false,
        reply: false,
    };

    /// Whether `message` is one of these.
    pub fn contains(self, message: PromotedMessage) -> bool {
        match message {
            PromotedMessage::Put => self.put,
            PromotedMessage::Query => self.query,
            PromotedMessage::Reply => self.reply,
        }
    }

    /// Whether some kind is one of these.
    pub fn any(self) -> bool {
        self.put || self.query || self.reply
    }

    /// Whether every kind is one of these.
    pub fn all(self) -> bool {
        self == Self::ALL
    }
}

/// Which plain payloads a session copies into its provider, so that a link that negotiated
/// shared memory carries them as a descriptor.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ShmPromotion {
    /// The size in bytes from which a payload is copied.
    pub threshold: usize,
    /// The messages a payload is copied for.
    pub messages: PromotedMessages,
}

impl Default for ShmPromotion {
    /// Upstream's: from 3072 bytes, for a put, a query's value and a reply
    /// (`commons/zenoh-config/src/defaults.rs` @ `message_size_threshold: 3072,`).
    fn default() -> Self {
        Self {
            threshold: 3072,
            messages: PromotedMessages::ALL,
        }
    }
}

impl ShmPromotion {
    /// Whether a payload of `len` bytes carried by `message` is to be copied: the list names the
    /// message and the payload is not empty and at least the threshold, as upstream's `if
    /// slice.len() >= self.message_size_threshold` reads. Whether some peer could read the copy,
    /// and whether the provider is there, are the caller's to ask after this, because both cost
    /// more than this does.
    pub fn admits(&self, message: PromotedMessage, len: usize) -> bool {
        self.messages.contains(message) && len > 0 && len >= self.threshold
    }
}

/// A copy of `bytes` in a chunk of `provider`, as the transport's and not the application's: a
/// link that negotiated shared memory is sent its descriptor and any other its bytes, and a
/// receiver of the sending session itself is handed the bytes, as upstream's, which copies at the
/// link, hands them. `None` when the provider has no room for it, after the collection and the
/// defragmentation upstream's copy allows itself (`io/zenoh-transport/src/common/shm/interop.rs` @
/// `.with_unsafe_policy::<Defragment<GarbageCollect<JustAlloc, JustAlloc, ConstBool<false>>>>()`);
/// the message is then sent as it is.
#[cfg(feature = "transport-shm")]
pub fn transport_copy(
    provider: &wz_runtime_tokio::shm_provider::ShmProvider,
    bytes: &[u8],
) -> Option<wz_session_core::extshm::ShmSendHandle> {
    use std::sync::Arc;
    use wz_runtime_tokio::shm_backend::MemoryLayout;
    use wz_runtime_tokio::shm_provider::AllocPolicy;

    let layout = MemoryLayout::of_size(bytes.len()).ok()?;
    let policy = AllocPolicy::defragment(
        AllocPolicy::GarbageCollect {
            inner: Box::new(AllocPolicy::JustAlloc),
            alt: Box::new(AllocPolicy::JustAlloc),
            safe: false,
        },
        AllocPolicy::JustAlloc,
    );
    let mut chunk = provider.alloc(layout, &policy).ok()?;
    chunk.write(bytes);
    Some(wz_session_core::extshm::ShmSendHandle::new(Arc::new(
        TransportCopy(Arc::new(chunk)),
    )))
}

/// A chunk the transport copied a payload into ([`transport_copy`]).
#[cfg(feature = "transport-shm")]
struct TransportCopy(std::sync::Arc<wz_runtime_tokio::shm_provider::ShmBackedPayload>);

#[cfg(feature = "transport-shm")]
impl wz_session_core::extshm::ShmSendBuffer for TransportCopy {
    fn bytes(&self) -> &[u8] {
        self.0.bytes()
    }

    fn protocol(&self) -> u32 {
        self.0.protocol()
    }

    fn receiver_view(&self) -> Option<wz_session_core::link::RxBytes> {
        // `None` is what the engine hands a receiver of the session the bytes for.
        None
    }

    fn reserve_for_receiver(
        self: std::sync::Arc<Self>,
    ) -> Box<dyn wz_session_core::extshm::ShmReservation> {
        // Named by its trait: a build that brings the trait into scope another way would find
        // this file's own `use` unused, and a build that does not would not find the method.
        wz_session_core::extshm::ShmSendBuffer::reserve_for_receiver(std::sync::Arc::clone(&self.0))
    }
}

/// One case of what `qos/publication` gives a publication: the list a configuration states, the
/// key the publication is made on, and what it is given. Every surface that applies the key runs
/// these cases through its own path, so that the C ABI and the Rust API preset are held to one
/// answer.
#[derive(Clone, Copy, Debug)]
pub struct PublicationQosCase {
    /// The value of `qos/publication`, as json5.
    pub rules: &'static str,
    /// The key the publication is made on.
    pub key: &'static str,
    /// What the publication is given.
    pub expected: PublicationDefaults,
    /// Whether the case states a setting the Rust API carries only with `unstable` (the
    /// reliability and the destination of a publisher).
    pub unstable: bool,
}

/// The cases every surface that applies `qos/publication` is held to.
pub const PUBLICATION_QOS_CASES: &[PublicationQosCase] = &[
    PublicationQosCase {
        rules: r#"[{ key_exprs: ["demo/**"], config: { congestion_control: "block", priority: "real_time", express: true } }]"#,
        key: "demo/a",
        expected: PublicationDefaults {
            congestion_control: Some(CongestionControl::Block),
            priority: Some(Priority::RealTime),
            express: Some(true),
            reliability: None,
            allowed_destination: None,
        },
        unstable: false,
    },
    PublicationQosCase {
        rules: r#"[{ key_exprs: ["demo/**"], config: { congestion_control: "block", priority: "real_time", express: true } }]"#,
        key: "other/a",
        expected: PublicationDefaults {
            congestion_control: None,
            priority: None,
            express: None,
            reliability: None,
            allowed_destination: None,
        },
        unstable: false,
    },
    PublicationQosCase {
        rules: r#"[{ key_exprs: ["demo/a"], config: { priority: "data_low" } }, { key_exprs: ["demo/a"], config: { express: true } }]"#,
        key: "demo/a",
        expected: PublicationDefaults {
            congestion_control: None,
            priority: None,
            express: Some(true),
            reliability: None,
            allowed_destination: None,
        },
        unstable: false,
    },
    PublicationQosCase {
        rules: r#"[{ key_exprs: ["demo/*"], config: { reliability: "best_effort", allowed_destination: "session_local" } }]"#,
        key: "demo/a",
        expected: PublicationDefaults {
            congestion_control: None,
            priority: None,
            express: None,
            reliability: Some(Reliability::BestEffort),
            allowed_destination: Some(Locality::SessionLocal),
        },
        unstable: true,
    },
];

#[cfg(test)]
mod tests {
    use super::*;

    /// The rules of one item per entry, each naming one key expression.
    fn rules(items: &[(&str, PublicationDefaults)]) -> PublicationQos {
        PublicationQos::new(
            items
                .iter()
                .map(|(key, defaults)| (vec![(*key).to_owned()], *defaults)),
        )
    }

    const BLOCK: PublicationDefaults = PublicationDefaults {
        congestion_control: Some(CongestionControl::Block),
        priority: None,
        express: None,
        reliability: None,
        allowed_destination: None,
    };

    const EXPRESS: PublicationDefaults = PublicationDefaults {
        congestion_control: None,
        priority: None,
        express: Some(true),
        reliability: None,
        allowed_destination: None,
    };

    /// A rule applies to the keys its key expression includes and to no other.
    #[test]
    fn a_rule_applies_to_the_keys_it_includes() {
        let qos = rules(&[("demo/**", BLOCK)]);
        assert_eq!(qos.defaults_for("demo/a/b"), BLOCK);
        assert_eq!(qos.defaults_for("demo"), BLOCK);
        assert_eq!(
            qos.defaults_for("other/a"),
            PublicationDefaults::default(),
            "a key no rule includes is given nothing"
        );
        assert!(qos.find("other/a").is_none());
    }

    /// A key expression written twice keeps its first place and its last settings, whole: the
    /// second replaces the first and does not merge into it.
    #[test]
    fn a_key_expression_written_twice_keeps_its_last_settings_whole() {
        let qos = rules(&[("demo/a", BLOCK), ("demo/a", EXPRESS)]);
        assert_eq!(qos.defaults_for("demo/a"), EXPRESS);
        assert_eq!(qos.rules.len(), 1);
    }

    /// Of several rules that include a key, the first written applies and the others are named.
    #[test]
    fn of_several_including_rules_the_first_written_applies() {
        let qos = rules(&[("demo/**", BLOCK), ("demo/a", EXPRESS)]);
        let found = qos.find("demo/a").expect("two rules include the key");
        assert_eq!(found.key_expr, "demo/**");
        assert_eq!(found.defaults, BLOCK);
        assert_eq!(found.also_including, ["demo/a"]);
        // A key only the first includes names no other.
        assert!(qos
            .find("demo/b")
            .expect("one rule includes it")
            .also_including
            .is_empty());
    }

    /// The settings stated replace the publication's own, and the ones left unset leave them.
    #[test]
    fn what_a_rule_states_replaces_the_publications_own_and_nothing_else() {
        let stated = PublishOptions::put()
            .with_priority(Priority::DataHigh)
            .with_congestion_control(CongestionControl::Drop)
            .with_express(false)
            .with_reliability(Reliability::Reliable)
            .with_locality(Locality::Any);
        let given = PublicationDefaults {
            congestion_control: Some(CongestionControl::Block),
            priority: None,
            express: Some(true),
            reliability: Some(Reliability::BestEffort),
            allowed_destination: Some(Locality::Remote),
        }
        .apply_to(stated.clone());
        let qos = given.qos.expect("a QoS stated");
        assert_eq!(qos.congestion(), CongestionControl::Block);
        assert!(qos.is_express());
        assert_eq!(
            qos.priority(),
            Priority::DataHigh,
            "a priority the rule leaves unset is the publication's"
        );
        assert_eq!(given.reliability, Reliability::BestEffort);
        assert_eq!(given.allowed_destination, Locality::Remote);

        // No rule: the options are the publication's, untouched.
        let untouched = PublicationQos::default().apply("demo/a", stated.clone());
        assert_eq!(untouched.qos, stated.qos);
        assert_eq!(untouched.reliability, stated.reliability);
        assert_eq!(untouched.allowed_destination, stated.allowed_destination);
    }

    /// The threshold is inclusive, an empty payload is never copied, and a kind the list does not
    /// name is not copied whatever its size.
    #[test]
    fn the_promotion_admits_what_upstream_copies() {
        let promotion = ShmPromotion {
            threshold: 4,
            messages: PromotedMessages {
                put: true,
                query: false,
                reply: true,
            },
        };
        assert!(
            promotion.admits(PromotedMessage::Put, 4),
            "the threshold itself"
        );
        assert!(promotion.admits(PromotedMessage::Reply, 5));
        assert!(
            !promotion.admits(PromotedMessage::Put, 3),
            "under the threshold"
        );
        assert!(
            !promotion.admits(PromotedMessage::Query, 1 << 20),
            "a kind the list does not name"
        );
        let zero = ShmPromotion {
            threshold: 0,
            messages: PromotedMessages::ALL,
        };
        assert!(!zero.admits(PromotedMessage::Put, 0), "an empty payload");
        assert!(zero.admits(PromotedMessage::Put, 1));
        // Upstream's default.
        assert_eq!(ShmPromotion::default().threshold, 3072);
        assert!(ShmPromotion::default().messages.all());
        assert!(!PromotedMessages::NONE.any());
    }

    /// The copy is the transport's: its bytes are the payload's, and a receiver of the session
    /// itself is handed no view of the chunk, so that it is given the bytes.
    #[cfg(all(feature = "transport-shm", target_os = "linux"))]
    #[test]
    fn a_transport_copy_holds_the_bytes_and_offers_the_session_no_view() {
        let layout =
            wz_runtime_tokio::shm_backend::MemoryLayout::of_size(1 << 16).expect("a layout");
        let provider =
            wz_runtime_tokio::shm_provider::ShmProvider::pool(&layout).expect("a provider");
        let bytes = [7u8; 4096];
        let copy = transport_copy(&provider, &bytes).expect("room for the copy");
        assert_eq!(copy.bytes(), &bytes[..]);
        assert!(copy.receiver_view().is_none());
        // CONTROL: a chunk the application allocated is handed to the session as itself.
        let mut own = provider
            .alloc(
                wz_runtime_tokio::shm_backend::MemoryLayout::of_size(16).expect("a layout"),
                &wz_runtime_tokio::shm_provider::AllocPolicy::JustAlloc,
            )
            .expect("a chunk");
        own.write(&[1u8; 16]);
        assert!(std::sync::Arc::new(own)
            .send_handle()
            .receiver_view()
            .is_some());
    }
}
