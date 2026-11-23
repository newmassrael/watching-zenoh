// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The liveliness plane on the cooperative engine: the tokens the session holds, and the
//! subscribers that hear the ones its peer holds.
//!
//! A token is announced to the peer the session's link reaches, and again over each link that
//! comes up after; it is also registered with the observer's local tokens, so a peer that asks
//! for the tokens alive later is answered with it, as zenoh-pico keeps every token it declares
//! (`vendor/zenoh-pico/src/net/liveliness.c` @
//! `_z_declared_keyexpr_intmap_insert(&_Z_RC_IN_VAL(zn)->_local_tokens, id, ke_on_heap) == NULL) {`).
//!
//! A liveliness subscriber is the observer's, registered under the id its Interest carries, and
//! its Interest is sent again over each new link. What the observer hands its sink happens under
//! the session's lock, and a C callback never runs there (decision D8), so the sink only holds
//! each sample in the session's round of deliveries (`crate::round`): a token declared, retracted
//! or gone with a lost link. The deliveries hand them out with no lock held; the tokens alive when
//! the subscriber asked for its history are handed on the declaring thread.

use alloc::sync::Arc;

use wz_capi_port::{SubId, TokenId, WireKey};
#[cfg(feature = "group")]
use wz_runtime_coop::session_drive::SessionLinks;
use wz_runtime_coop::ClockSource;
use wz_session_core::declare::liveliness_sample::{BoxedLivelinessSampleSink, LivelinessSample};
#[cfg(feature = "group")]
use wz_session_core::declare_form::RetractionKey;
use wz_session_core::named_key::NamedKey;
#[cfg(feature = "group")]
use wz_session_core::session_tables::WireForm;
use wz_session_core::wire_id::ExprId;
use wz_session_mcu::dial::McuActions;

use super::LivelinessCallback;
#[allow(unused_imports)]
use crate::prelude::*;
use crate::round::Round;

/// The ABI's form of a key the session's tables name `form` on the wire, for a group told the
/// entity it names.
#[cfg(feature = "group")]
fn wire_key_of(form: WireForm<'_>) -> WireKey {
    if form.mapping == 0 {
        return WireKey::literal();
    }
    WireKey::aliased(
        form.mapping,
        (!form.suffix.is_empty()).then(|| String::from(form.suffix)),
    )
}

/// Announce the token `id` the session holds on `key` over `actions`, its key named as the
/// session's tables name it or as the link's key-wire form says: whether the link took it.
pub(super) fn declare_token<C: ClockSource + 'static>(
    actions: &McuActions<C>,
    id: TokenId,
    key: NamedKey<'_>,
) -> bool {
    actions
        .send_declare_token(id, super::key_on_link(actions, key))
        .is_ok()
}

#[cfg(feature = "group")]
impl<L: SessionLinks + 'static, C: ClockSource + Clone + 'static> super::Core<L, C> {
    /// Tell each group the session joined of the token `handle` names, as its row in the
    /// session's tables states it (`group`).
    pub(super) fn announce_token_to_groups(
        &self,
        handle: wz_session_core::session_tables::TokenHandle,
    ) {
        let tables = super::tables(&self.registry);
        let Some(row) = tables.tokens().get(handle) else {
            return;
        };
        let form = tables.wire_of(row.key());
        let wire = wire_key_of(form);
        let retraction = row.key().names_key().then(|| RetractionKey {
            mapping_id: form.mapping,
            suffix: String::from(form.suffix),
        });
        self.announce_to_groups(super::group::GroupEntity {
            what: wz_session_core::declare_form::GroupDeclaration::Token,
            entity: row.id(),
            keyexpr: row.key().as_str(),
            wire: &wire,
            retraction: retraction.as_ref(),
            allowed_origin: wz_session_core::locality::Locality::Any,
        });
    }
}

/// Retract the token `id` over `actions`, naming its key as `names` says (the declaration's id
/// and the rest of the key) when its declaration asked to.
pub(super) fn retract_token<C: ClockSource + 'static>(
    actions: &McuActions<C>,
    id: TokenId,
    names: Option<(ExprId, &str)>,
) {
    let id = u64::from(id);
    match names {
        Some((mapping, suffix)) => actions.send_undeclare_token_naming(id, mapping, suffix),
        None => actions.send_undeclare_token(id),
    }
}

/// A liveliness subscriber the session holds: what its Interest asks, kept to ask it again over a
/// new link.
pub(super) struct LiveSubEntry {
    /// Its id, which is also its Interest's, as zenoh-pico's subscription id is.
    pub(super) id: SubId,
    pub(super) keyexpr: super::RowKey,
    pub(super) wire: WireKey,
    pub(super) history: bool,
    /// Its callback, which the registry's sink shares: retired when the subscriber is undeclared
    /// or its session closed, and let go of with no lock held.
    pub(super) callback: LivelinessCallback,
}

impl LiveSubEntry {
    /// Send this subscriber's Interest over `actions`: the tokens to come, and with `history` the
    /// ones alive now, its key named as the link's key-wire form says: whether the link took it.
    pub(super) fn ask<C: ClockSource + 'static>(&self, actions: &McuActions<C>) -> bool {
        let id = u64::from(self.id);
        let wire = super::on_link(actions, &self.keyexpr, &self.wire);
        if wire.is_literal() {
            actions.send_interest_liveliness_subscriber(id, self.history, 0, Some(&self.keyexpr))
        } else {
            actions.send_interest_liveliness_subscriber(
                id,
                self.history,
                wire.mapping_id,
                wire.suffix.as_deref(),
            )
        }
        .is_ok()
    }
}

/// The sink a liveliness subscriber is registered with, holding its `callback`: each sample is held
/// for the callback in the session's round of deliveries, its key read where it lies or written
/// into the round (`Round::offer_liveliness`).
pub(super) fn sample_sink(
    callback: &LivelinessCallback,
    round: &Arc<Round>,
) -> BoxedLivelinessSampleSink {
    let round = Arc::clone(round);
    let callback = Arc::clone(callback);
    BoxedLivelinessSampleSink::new(move |sample: LivelinessSample<'_>| {
        // SAFETY: the registry hands its sinks a token under the session's lock.
        unsafe { round.offer_liveliness(&callback, &sample) };
    })
}
