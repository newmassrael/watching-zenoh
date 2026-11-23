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
use wz_runtime_coop::ClockSource;
use wz_session_core::declare::liveliness_sample::{BoxedLivelinessSampleSink, LivelinessSample};
use wz_session_core::declare_form::RetractionKey;
use wz_session_mcu::dial::McuActions;

use super::LivelinessCallback;
#[allow(unused_imports)]
use crate::prelude::*;
use crate::round::Round;

/// A token the session holds: what its declaration says on the wire, kept to announce it again
/// over a new link; holding the key also keeps alive what it holds.
pub(super) struct TokenEntry {
    pub(super) id: TokenId,
    pub(super) keyexpr: super::RowKey,
    pub(super) wire: WireKey,
    pub(super) retraction: Option<RetractionKey>,
}

impl TokenEntry {
    /// Announce this token over `actions`: whether the link took it.
    pub(super) fn declare<C: ClockSource + 'static>(&self, actions: &McuActions<C>) -> bool {
        let wire = super::on_link(actions, &self.keyexpr, &self.wire);
        if wire.is_literal() {
            actions.send_declare_token(self.id, 0, Some(&self.keyexpr))
        } else {
            actions.send_declare_token(self.id, wire.mapping_id, wire.suffix.as_deref())
        }
        .is_ok()
    }

    /// Retract this token over `actions`, naming its key when its declaration asked to.
    pub(super) fn retract<C: ClockSource + 'static>(&self, actions: &McuActions<C>) {
        let id = u64::from(self.id);
        match &self.retraction {
            Some(key) => actions.send_undeclare_token_naming(id, key.mapping_id, &key.suffix),
            None => actions.send_undeclare_token(id),
        }
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
