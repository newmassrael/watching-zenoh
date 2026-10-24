// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! This engine as the port's [`SessionEngine`]: every operation is the face registry's own, so
//! an ABI that holds `Arc<dyn SessionEngine>` gets exactly what it got by naming
//! [`SharedSession`] (`docs/capi-pico-on-coop-engine.md`, step 2).

use wz_capi_port::{
    FanoutError, FilterId, FilterPlane, FilteredPut, MatchId, MatchingSink, SessionEngine, SubId,
    SubscriberSink, WireKey,
};
use wz_session_core::declare_form::{InterestForm, RetractionKey};
use wz_session_core::locality::Locality;
use wz_session_core::publish_options::{PlainPutParams, PublishOptions};

use crate::faces::SharedSession;

impl SessionEngine for SharedSession {
    fn is_closed(&self) -> bool {
        SharedSession::is_closed(self)
    }

    fn zid(&self) -> [u8; 16] {
        SharedSession::zid(self)
    }

    fn next_entity_id(&self) -> u64 {
        SharedSession::next_entity_id(self)
    }

    fn publish_on_wire_all(
        &self,
        keyexpr: &str,
        wire: &WireKey,
        payload: &[u8],
        opts: &PublishOptions,
    ) -> Result<usize, FanoutError> {
        SharedSession::publish_on_wire_all(self, keyexpr, wire, payload, opts)
    }

    fn declare_subscriber_on_wire(
        &self,
        keyexpr: String,
        wire: WireKey,
        allowed_origin: Locality,
        retraction: Option<RetractionKey>,
        sink: SubscriberSink,
    ) -> SubId {
        SharedSession::declare_subscriber_on_wire(
            self,
            keyexpr,
            wire,
            allowed_origin,
            retraction,
            sink,
        )
    }

    fn undeclare_subscriber(&self, id: SubId) {
        SharedSession::undeclare_subscriber(self, id)
    }

    fn acquire_keyexpr(&self, keyexpr: String) -> Option<u64> {
        SharedSession::acquire_keyexpr(self, keyexpr)
    }

    fn release_keyexpr(&self, mapping_id: u64) {
        SharedSession::release_keyexpr(self, mapping_id)
    }

    fn keyexpr_declarations(&self) -> Vec<(u64, String)> {
        SharedSession::keyexpr_declarations(self)
    }

    fn declare_matching_listener_counting_local(
        &self,
        keyexpr: String,
        sink: MatchingSink,
        count_local: bool,
    ) -> MatchId {
        SharedSession::declare_matching_listener_counting_local(self, keyexpr, sink, count_local)
    }

    fn undeclare_matching_listener(&self, id: MatchId) {
        SharedSession::undeclare_matching_listener(self, id)
    }

    fn declare_write_filter(
        &self,
        plane: FilterPlane,
        keyexpr: String,
        wire: &WireKey,
        ask: Option<InterestForm>,
        count_local: bool,
    ) -> FilterId {
        SharedSession::declare_write_filter(self, plane, keyexpr, wire, ask, count_local)
    }

    fn write_filter_active(&self, id: FilterId) -> bool {
        SharedSession::write_filter_active(self, id)
    }

    fn write_filter_holds_back(&self, id: FilterId) -> bool {
        SharedSession::write_filter_holds_back(self, id)
    }

    fn undeclare_write_filter(&self, id: FilterId) {
        SharedSession::undeclare_write_filter(self, id)
    }

    fn put_plain_filtered(
        &self,
        filter: FilterId,
        keyexpr: &str,
        mapping_id: u64,
        payload: &[u8],
        params: &PlainPutParams,
    ) -> FilteredPut {
        SharedSession::put_plain_filtered(self, filter, keyexpr, mapping_id, payload, params)
    }

    fn batch_start_all(&self) -> usize {
        SharedSession::batch_start_all(self)
    }

    fn batch_flush_all(&self) -> usize {
        SharedSession::batch_flush_all(self)
    }

    fn batch_stop_all(&self) -> usize {
        SharedSession::batch_stop_all(self)
    }
}
