// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The wz-only statements of a call, as C doors: the links an entity may use, a publish's retry
//! and all-or-none form, and the node a query is addressed to.
//!
//! ## Why doors beside the `z_*` functions and not fields of their option structs
//!
//! The option structs of `z_put`, `z_get`, `z_declare_subscriber` and the rest are upstream's
//! layout, held to the installed header by the footprint gate, and a field added to one would
//! move it. The `z_` / `zc_` / `ze_` exports are held to the reference library's symbol set. So
//! the statements are made through `wz_capi_c_*_ext` doors: each takes what its `z_*` twin takes
//! and one more argument, a pointer to a struct of the statements that call may make. A null
//! pointer and a struct filled by its `_default` function state nothing, and a call that states
//! nothing is the call the `z_*` function makes (it is the same body, which takes the statement
//! as an argument).
//!
//! ## What a build whose policy is off does
//!
//! Each statement is a policy of the session model (`entity-link-restriction`,
//! `publisher-admission-retry`, `multi-route-atomic-tx`, `targeted-query`), off in a build made as
//! upstream is. A stated value is passed through the model's own `admit_in_build` before anything
//! is sent or declared: with the policy off the door answers
//! [`WZ_CAPI_C_E_POLICY_OFF`](crate::result::WZ_CAPI_C_E_POLICY_OFF), and a declaration leaves
//! its out-parameter in the gravestone state. A value the policy would take but that no engine
//! can hold (a retry of zero passes, a target of no bytes, more passes or milliseconds than a
//! retry carries) is `Z_EINVAL`. Nothing stated is never refused, whatever the policy.
//!
//! The closure a declaration or a get is given, the payload of a put and the owned fields of its
//! options are consumed on a refusal as on a success, which is what the `z_*` twins do on every
//! path.
//!
//! ## A session that is a node
//!
//! The data plane behind a node session (`router-node`) writes to its faces by its own tables and
//! reads none of these statements. A call that states one on such a session answers
//! `Z_EUNAVAILABLE`, the code every other operation a node does not carry answers, and sends or
//! declares nothing; a call that states nothing is carried as its `z_*` twin is.

use std::ffi::c_char;

use wz_session_core::admission_retry::{self, AdmissionRetry, AdmissionRetryError};
use wz_session_core::atomic_tx::{self, AtomicTxError};
use wz_session_core::link_restriction::{LinkRestriction, LinkRestrictionError, LINK_SLOTS};
use wz_session_core::peer_target::{self, PeerTargetError};

use crate::abi::{
    z_loaned_keyexpr_t, z_loaned_session_t, z_moved_bytes_t, z_moved_closure_query_t,
    z_moved_closure_reply_t, z_moved_closure_sample_t, z_owned_publisher_t, z_owned_querier_t,
    z_owned_queryable_t, z_owned_subscriber_t,
};
use crate::get::z_get_options_t;
use crate::publisher::z_publisher_options_t;
use crate::put::{z_delete_options_t, z_put_options_t};
use crate::querier::z_querier_options_t;
use crate::query::z_queryable_options_t;
use crate::result::{ZResult, WZ_CAPI_C_E_POLICY_OFF, Z_EINVAL};
use crate::statement::{PublishStatement, QueryStatement};
use crate::sub::z_subscriber_options_t;
use crate::zid::{z_id_t, Z_ID_SIZE};

/// What a subscriber or a queryable declaration states: the links the entity may use.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct wz_capi_c_entity_ext_t {
    /// One bit per link slot: bit `i` set allows slot `i` (slot 0 is the link the session dialled,
    /// listener `n` is slot `n + 1`). Zero allows every link, which is no restriction.
    pub link_mask: u64,
}

/// What a put, a delete or a publisher declaration states.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct wz_capi_c_publish_ext_t {
    /// The links the publish may be sent on, as in [`wz_capi_c_entity_ext_t::link_mask`].
    pub link_mask: u64,
    /// How many further passes a publish makes when no link had room; zero states no retry. A
    /// retry holds at most 255.
    pub attempts: u32,
    /// How long to wait before each further pass, in milliseconds; at least 1 beside a non-zero
    /// `attempts`, at most 65535.
    pub delay_ms: u32,
    /// Non-zero states that the publish reaches every link it may use or none of them.
    pub all_or_none: u8,
}

/// What a get or a querier declaration states.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct wz_capi_c_query_ext_t {
    /// The links the query may be asked on, as in [`wz_capi_c_entity_ext_t::link_mask`].
    pub link_mask: u64,
    /// Non-zero addresses the query to the node `target` names; `target` is read only then.
    pub has_target: u8,
    /// The identity of the node, as `z_id_t` spells it.
    pub target: z_id_t,
}

impl wz_capi_c_entity_ext_t {
    /// The statement of nothing.
    const OFF: Self = Self { link_mask: 0 };
}

impl wz_capi_c_publish_ext_t {
    /// The statement of nothing.
    const OFF: Self = Self {
        link_mask: 0,
        attempts: 0,
        delay_ms: 0,
        all_or_none: 0,
    };
}

impl wz_capi_c_query_ext_t {
    /// The statement of nothing.
    const OFF: Self = Self {
        link_mask: 0,
        has_target: 0,
        target: z_id_t {
            id: [0u8; Z_ID_SIZE],
        },
    };
}

/// Write the statement of nothing into `this_`: no link restriction, the declaration of an entity
/// as `z_declare_subscriber` and `z_declare_queryable` make it.
///
/// # Safety
/// `this_` must be null or valid and writable.
#[no_mangle]
pub unsafe extern "C" fn wz_capi_c_entity_ext_default(this_: *mut wz_capi_c_entity_ext_t) {
    if this_.is_null() {
        return;
    }
    // SAFETY: the caller's contract.
    unsafe { *this_ = wz_capi_c_entity_ext_t::OFF };
}

/// Write the statement of nothing into `this_`: no link restriction, no retry, no all-or-none
/// form.
///
/// # Safety
/// `this_` must be null or valid and writable.
#[no_mangle]
pub unsafe extern "C" fn wz_capi_c_publish_ext_default(this_: *mut wz_capi_c_publish_ext_t) {
    if this_.is_null() {
        return;
    }
    // SAFETY: the caller's contract.
    unsafe { *this_ = wz_capi_c_publish_ext_t::OFF };
}

/// Write the statement of nothing into `this_`: no link restriction and no target node.
///
/// # Safety
/// `this_` must be null or valid and writable.
#[no_mangle]
pub unsafe extern "C" fn wz_capi_c_query_ext_default(this_: *mut wz_capi_c_query_ext_t) {
    if this_.is_null() {
        return;
    }
    // SAFETY: the caller's contract.
    unsafe { *this_ = wz_capi_c_query_ext_t::OFF };
}

/// The restriction a mask states: no bit is no restriction, and a set bit allows its slot.
fn restriction_of(mask: u64) -> Result<LinkRestriction, LinkRestrictionError> {
    if mask == 0 {
        return Ok(LinkRestriction::Any);
    }
    LinkRestriction::only((0..LINK_SLOTS).filter(|slot| mask & (1u64 << *slot) != 0))
}

/// The code a refused restriction answers.
fn link_refusal(refusal: LinkRestrictionError) -> ZResult {
    match refusal {
        LinkRestrictionError::PolicyOff => WZ_CAPI_C_E_POLICY_OFF,
        LinkRestrictionError::Empty | LinkRestrictionError::SlotOutOfRange(_) => Z_EINVAL,
    }
}

/// The restriction a mask states, admitted by this build's `entity-link-restriction` policy.
fn admit_links(mask: u64) -> Result<LinkRestriction, ZResult> {
    restriction_of(mask)
        .and_then(LinkRestriction::admit_in_build)
        .map_err(link_refusal)
}

/// The retry two numbers state: none when both are zero. The value is built as stated, so that
/// the model refuses a retry of no passes or of no delay itself; one that does not fit what a
/// retry holds cannot be built and is `Z_EINVAL`.
fn retry_value(attempts: u32, delay_ms: u32) -> Result<Option<AdmissionRetry>, ZResult> {
    if attempts == 0 && delay_ms == 0 {
        return Ok(None);
    }
    let (Ok(attempts), Ok(delay_ms)) = (u8::try_from(attempts), u16::try_from(delay_ms)) else {
        return Err(Z_EINVAL);
    };
    Ok(Some(AdmissionRetry { attempts, delay_ms }))
}

/// The code a refused retry answers.
fn retry_refusal(refusal: AdmissionRetryError) -> ZResult {
    match refusal {
        AdmissionRetryError::PolicyOff => WZ_CAPI_C_E_POLICY_OFF,
        AdmissionRetryError::ZeroAttempts | AdmissionRetryError::ZeroDelay => Z_EINVAL,
    }
}

/// The retry, admitted by this build's `publisher-admission-retry` policy.
fn admit_retry(retry: Option<AdmissionRetry>) -> Result<(), ZResult> {
    admission_retry::admit_in_build(retry).map_err(retry_refusal)
}

/// The code a refused all-or-none statement answers.
fn atomic_refusal(refusal: AtomicTxError) -> ZResult {
    match refusal {
        AtomicTxError::PolicyOff => WZ_CAPI_C_E_POLICY_OFF,
    }
}

/// The all-or-none statement, admitted by this build's `multi-route-atomic-tx` policy.
fn admit_atomic(stated: bool) -> Result<(), ZResult> {
    atomic_tx::admit_in_build(stated).map_err(atomic_refusal)
}

/// The bytes the engine names the node `id` by: the identity with its trailing zero bytes cut, as
/// the wire carries it, which is what a face records and a target is matched against. An identity
/// of zero bytes only has none.
fn target_bytes(id: &[u8; Z_ID_SIZE]) -> Vec<u8> {
    let len = id.iter().rposition(|b| *b != 0).map_or(0, |last| last + 1);
    id[..len].to_vec()
}

/// The code a refused target answers.
fn target_refusal(refusal: PeerTargetError) -> ZResult {
    match refusal {
        PeerTargetError::PolicyOff => WZ_CAPI_C_E_POLICY_OFF,
        PeerTargetError::Empty | PeerTargetError::TooLong(_) => Z_EINVAL,
    }
}

/// The target, admitted by this build's `targeted-query` policy.
fn admit_target(target: Option<&[u8]>) -> Result<(), ZResult> {
    peer_target::admit_in_build(target).map_err(target_refusal)
}

/// What a declaration of an entity states, admitted: no pointer states nothing.
fn entity_links(ext: Option<&wz_capi_c_entity_ext_t>) -> Result<LinkRestriction, ZResult> {
    match ext {
        None => Ok(LinkRestriction::Any),
        Some(ext) => admit_links(ext.link_mask),
    }
}

/// What a publish states, admitted: the links, then the retry, then the all-or-none form, the
/// first refusal answering.
fn publish_statement(ext: Option<&wz_capi_c_publish_ext_t>) -> Result<PublishStatement, ZResult> {
    let Some(ext) = ext else {
        return Ok(PublishStatement::default());
    };
    let links = admit_links(ext.link_mask)?;
    let retry = retry_value(ext.attempts, ext.delay_ms)?;
    admit_retry(retry)?;
    let atomic = ext.all_or_none != 0;
    admit_atomic(atomic)?;
    Ok(PublishStatement {
        links,
        retry,
        atomic,
    })
}

/// What a query states, admitted: the links, then the target, the first refusal answering.
fn query_statement(ext: Option<&wz_capi_c_query_ext_t>) -> Result<QueryStatement, ZResult> {
    let Some(ext) = ext else {
        return Ok(QueryStatement::default());
    };
    let links = admit_links(ext.link_mask)?;
    let target_peer = if ext.has_target != 0 {
        let zid = target_bytes(&ext.target.id);
        admit_target(Some(zid.as_slice()))?;
        Some(zid)
    } else {
        None
    };
    Ok(QueryStatement { links, target_peer })
}

/// `z_put`, stating more than its options do (`ext`, null for nothing). See the module note for
/// the refusals: `WZ_CAPI_C_E_POLICY_OFF`, `Z_EINVAL`, and `Z_EUNAVAILABLE` for a session that is
/// a node. The payload and the options' owned fields are consumed on every path.
///
/// # Safety
/// As `z_put`; `ext` must be null or a valid statement.
#[no_mangle]
pub unsafe extern "C" fn wz_capi_c_put_ext(
    session: *const z_loaned_session_t,
    key_expr: *const z_loaned_keyexpr_t,
    payload: *mut z_moved_bytes_t,
    options: *mut z_put_options_t,
    ext: *const wz_capi_c_publish_ext_t,
) -> ZResult {
    // SAFETY: the caller's contract for `ext`.
    let statement = publish_statement(unsafe { ext.as_ref() });
    // SAFETY: the caller's contract, delegated.
    unsafe { crate::put::put_stated(session, key_expr, payload, options, statement) }
}

/// `z_delete`, stating more than its options do (`ext`, null for nothing); refused as
/// [`wz_capi_c_put_ext`] is.
///
/// # Safety
/// As `z_delete`; `ext` must be null or a valid statement.
#[no_mangle]
pub unsafe extern "C" fn wz_capi_c_delete_ext(
    session: *const z_loaned_session_t,
    key_expr: *const z_loaned_keyexpr_t,
    options: *mut z_delete_options_t,
    ext: *const wz_capi_c_publish_ext_t,
) -> ZResult {
    // SAFETY: the caller's contract for `ext`.
    let statement = publish_statement(unsafe { ext.as_ref() });
    // SAFETY: the caller's contract, delegated.
    unsafe { crate::put::delete_stated(session, key_expr, options, statement) }
}

/// `z_declare_publisher`, stating more than its options do (`ext`, null for nothing): every put
/// and delete on the publisher is made as stated. A refused declaration leaves `publisher` in its
/// gravestone state; refused as [`wz_capi_c_put_ext`] is.
///
/// # Safety
/// As `z_declare_publisher`; `ext` must be null or a valid statement.
#[no_mangle]
pub unsafe extern "C" fn wz_capi_c_declare_publisher_ext(
    session: *const z_loaned_session_t,
    publisher: *mut z_owned_publisher_t,
    key_expr: *const z_loaned_keyexpr_t,
    options: *mut z_publisher_options_t,
    ext: *const wz_capi_c_publish_ext_t,
) -> ZResult {
    // SAFETY: the caller's contract for `ext`.
    let statement = publish_statement(unsafe { ext.as_ref() });
    // SAFETY: the caller's contract, delegated.
    unsafe {
        crate::publisher::declare_publisher_stated(session, publisher, key_expr, options, statement)
    }
}

/// `z_get`, stating more than its options do (`ext`, null for nothing). The closure is consumed on
/// every path; refused as [`wz_capi_c_put_ext`] is.
///
/// # Safety
/// As `z_get`; `ext` must be null or a valid statement.
#[no_mangle]
pub unsafe extern "C" fn wz_capi_c_get_ext(
    session: *const z_loaned_session_t,
    key_expr: *const z_loaned_keyexpr_t,
    parameters: *const c_char,
    callback: *mut z_moved_closure_reply_t,
    options: *mut z_get_options_t,
    ext: *const wz_capi_c_query_ext_t,
) -> ZResult {
    // SAFETY: the caller's contract for `ext`.
    let stated = query_statement(unsafe { ext.as_ref() });
    // SAFETY: the caller's contract, delegated; the selector is read as `z_get` reads it.
    unsafe {
        crate::get::get_with_selector(
            session,
            key_expr,
            crate::get::nul_terminated(parameters),
            callback,
            options,
            stated,
        )
    }
}

/// `z_declare_querier`, stating more than its options do (`ext`, null for nothing): every get on
/// the querier is asked as stated. A refused declaration leaves `querier` in its gravestone state;
/// refused as [`wz_capi_c_put_ext`] is.
///
/// # Safety
/// As `z_declare_querier`; `ext` must be null or a valid statement.
#[no_mangle]
pub unsafe extern "C" fn wz_capi_c_declare_querier_ext(
    session: *const z_loaned_session_t,
    querier: *mut z_owned_querier_t,
    key_expr: *const z_loaned_keyexpr_t,
    options: *mut z_querier_options_t,
    ext: *const wz_capi_c_query_ext_t,
) -> ZResult {
    // SAFETY: the caller's contract for `ext`.
    let stated = query_statement(unsafe { ext.as_ref() });
    // SAFETY: the caller's contract, delegated.
    unsafe { crate::querier::declare_querier_stated(session, querier, key_expr, options, stated) }
}

/// `z_declare_subscriber`, limited to the links `ext` names (null for no limit): it is declared to
/// the nodes behind those links only, and a link that comes up later is declared to only if its
/// slot is named. The closure is consumed on every path and a refused declaration leaves
/// `subscriber` in its gravestone state; refused as [`wz_capi_c_put_ext`] is.
///
/// # Safety
/// As `z_declare_subscriber`; `ext` must be null or a valid statement.
#[no_mangle]
pub unsafe extern "C" fn wz_capi_c_declare_subscriber_ext(
    session: *const z_loaned_session_t,
    subscriber: *mut z_owned_subscriber_t,
    key_expr: *const z_loaned_keyexpr_t,
    callback: *mut z_moved_closure_sample_t,
    options: *mut z_subscriber_options_t,
    ext: *const wz_capi_c_entity_ext_t,
) -> ZResult {
    // SAFETY: the caller's contract for `ext`.
    let links = entity_links(unsafe { ext.as_ref() });
    // SAFETY: the caller's contract, delegated.
    unsafe {
        crate::sub::declare_subscriber_on(session, subscriber, key_expr, callback, options, links)
    }
}

/// `z_declare_queryable`, limited to the links `ext` names (null for no limit), as
/// [`wz_capi_c_declare_subscriber_ext`] limits a subscriber.
///
/// # Safety
/// As `z_declare_queryable`; `ext` must be null or a valid statement.
#[no_mangle]
pub unsafe extern "C" fn wz_capi_c_declare_queryable_ext(
    session: *const z_loaned_session_t,
    queryable: *mut z_owned_queryable_t,
    key_expr: *const z_loaned_keyexpr_t,
    callback: *mut z_moved_closure_query_t,
    options: *mut z_queryable_options_t,
    ext: *const wz_capi_c_entity_ext_t,
) -> ZResult {
    // SAFETY: the caller's contract for `ext`.
    let links = entity_links(unsafe { ext.as_ref() });
    // SAFETY: the caller's contract, delegated.
    unsafe {
        crate::query::declare_queryable_on(session, queryable, key_expr, callback, options, links)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::result::Z_ENULL;
    use wz_session_core::policy::SessionPolicy;

    fn links_on() -> bool {
        SessionPolicy::from_build().entity_link_restriction
    }

    fn retry_on() -> bool {
        SessionPolicy::from_build().publisher_admission_retry
    }

    fn atomic_on() -> bool {
        SessionPolicy::from_build().multi_route_atomic_tx
    }

    fn target_on() -> bool {
        SessionPolicy::from_build().targeted_query
    }

    fn some_id() -> z_id_t {
        let mut id = [0u8; Z_ID_SIZE];
        id[0] = 0xc7;
        id[1] = 0xd1;
        z_id_t { id }
    }

    /// The answer the build's policy gives a stated value: the value when the policy is on, the
    /// policy's code when it is off.
    fn decided<T: std::fmt::Debug + PartialEq>(on: bool, when_on: T, got: Result<T, ZResult>) {
        if on {
            assert_eq!(got, Ok(when_on), "a build with the policy on takes it");
        } else {
            assert_eq!(
                got,
                Err(WZ_CAPI_C_E_POLICY_OFF),
                "a build with the policy off refuses it"
            );
        }
    }

    #[test]
    fn the_default_functions_write_the_statement_of_nothing() {
        let mut entity = wz_capi_c_entity_ext_t {
            link_mask: u64::MAX,
        };
        // SAFETY: a live local.
        unsafe { wz_capi_c_entity_ext_default(&mut entity) };
        assert_eq!(entity, wz_capi_c_entity_ext_t { link_mask: 0 });

        let mut publish = wz_capi_c_publish_ext_t {
            link_mask: u64::MAX,
            attempts: u32::MAX,
            delay_ms: u32::MAX,
            all_or_none: u8::MAX,
        };
        // SAFETY: a live local.
        unsafe { wz_capi_c_publish_ext_default(&mut publish) };
        assert_eq!(
            publish,
            wz_capi_c_publish_ext_t {
                link_mask: 0,
                attempts: 0,
                delay_ms: 0,
                all_or_none: 0
            }
        );

        let mut query = wz_capi_c_query_ext_t {
            link_mask: u64::MAX,
            has_target: u8::MAX,
            target: z_id_t {
                id: [0xff; Z_ID_SIZE],
            },
        };
        // SAFETY: a live local.
        unsafe { wz_capi_c_query_ext_default(&mut query) };
        assert_eq!(query.link_mask, 0);
        assert_eq!(query.has_target, 0);
        assert_eq!(query.target.id, [0u8; Z_ID_SIZE]);

        // A null pointer is no write and no fault.
        // SAFETY: null is allowed.
        unsafe {
            wz_capi_c_entity_ext_default(std::ptr::null_mut());
            wz_capi_c_publish_ext_default(std::ptr::null_mut());
            wz_capi_c_query_ext_default(std::ptr::null_mut());
        }
    }

    #[test]
    fn the_structs_have_the_layout_the_header_declares() {
        use std::mem::{offset_of, size_of};
        assert_eq!(size_of::<wz_capi_c_entity_ext_t>(), 8);
        assert_eq!(size_of::<wz_capi_c_publish_ext_t>(), 24);
        assert_eq!(offset_of!(wz_capi_c_publish_ext_t, link_mask), 0);
        assert_eq!(offset_of!(wz_capi_c_publish_ext_t, attempts), 8);
        assert_eq!(offset_of!(wz_capi_c_publish_ext_t, delay_ms), 12);
        assert_eq!(offset_of!(wz_capi_c_publish_ext_t, all_or_none), 16);
        assert_eq!(size_of::<wz_capi_c_query_ext_t>(), 32);
        assert_eq!(offset_of!(wz_capi_c_query_ext_t, link_mask), 0);
        assert_eq!(offset_of!(wz_capi_c_query_ext_t, has_target), 8);
        assert_eq!(offset_of!(wz_capi_c_query_ext_t, target), 9);
    }

    #[test]
    fn a_mask_without_a_bit_is_no_restriction_and_each_bit_names_its_slot() {
        assert_eq!(restriction_of(0), Ok(LinkRestriction::Any));
        assert_eq!(
            restriction_of(1 << 5),
            Ok(LinkRestriction::only([5]).expect("one slot"))
        );
        assert_eq!(
            restriction_of(0b101),
            Ok(LinkRestriction::only([0, 2]).expect("two slots"))
        );
        // The last slot is the top bit, and every bit set names every slot.
        assert_eq!(
            restriction_of(1 << 63),
            Ok(LinkRestriction::only([63]).expect("the last slot"))
        );
        assert_eq!(
            restriction_of(u64::MAX),
            Ok(LinkRestriction::Only(u64::MAX))
        );
    }

    #[test]
    fn a_retry_is_built_as_stated_and_one_that_does_not_fit_is_not_built() {
        assert_eq!(retry_value(0, 0), Ok(None));
        assert_eq!(
            retry_value(3, 20),
            Ok(Some(AdmissionRetry {
                attempts: 3,
                delay_ms: 20
            }))
        );
        assert_eq!(
            retry_value(255, 65535),
            Ok(Some(AdmissionRetry {
                attempts: 255,
                delay_ms: 65535
            }))
        );
        assert_eq!(retry_value(256, 20), Err(Z_EINVAL));
        assert_eq!(retry_value(3, 65536), Err(Z_EINVAL));
        // Half a retry is built as stated, for the model to refuse.
        assert_eq!(
            retry_value(0, 5),
            Ok(Some(AdmissionRetry {
                attempts: 0,
                delay_ms: 5
            }))
        );
        assert_eq!(
            retry_value(5, 0),
            Ok(Some(AdmissionRetry {
                attempts: 5,
                delay_ms: 0
            }))
        );
    }

    #[test]
    fn a_target_is_the_identity_without_its_trailing_zero_bytes() {
        assert_eq!(target_bytes(&some_id().id), vec![0xc7, 0xd1]);
        let mut inner = [0u8; Z_ID_SIZE];
        inner[1] = 0xd1;
        assert_eq!(target_bytes(&inner), vec![0x00, 0xd1]);
        let mut full = [0x11u8; Z_ID_SIZE];
        full[15] = 0x22;
        assert_eq!(target_bytes(&full).len(), 16);
        assert!(target_bytes(&[0u8; Z_ID_SIZE]).is_empty());
    }

    #[test]
    fn every_refusal_of_the_model_has_its_code() {
        assert_eq!(
            link_refusal(LinkRestrictionError::PolicyOff),
            WZ_CAPI_C_E_POLICY_OFF
        );
        assert_eq!(link_refusal(LinkRestrictionError::Empty), Z_EINVAL);
        assert_eq!(
            link_refusal(LinkRestrictionError::SlotOutOfRange(64)),
            Z_EINVAL
        );
        assert_eq!(
            retry_refusal(AdmissionRetryError::PolicyOff),
            WZ_CAPI_C_E_POLICY_OFF
        );
        assert_eq!(retry_refusal(AdmissionRetryError::ZeroAttempts), Z_EINVAL);
        assert_eq!(retry_refusal(AdmissionRetryError::ZeroDelay), Z_EINVAL);
        assert_eq!(
            atomic_refusal(AtomicTxError::PolicyOff),
            WZ_CAPI_C_E_POLICY_OFF
        );
        assert_eq!(
            target_refusal(PeerTargetError::PolicyOff),
            WZ_CAPI_C_E_POLICY_OFF
        );
        assert_eq!(target_refusal(PeerTargetError::Empty), Z_EINVAL);
        assert_eq!(target_refusal(PeerTargetError::TooLong(17)), Z_EINVAL);
    }

    #[test]
    fn nothing_stated_is_admitted_whatever_the_policy() {
        assert_eq!(entity_links(None), Ok(LinkRestriction::Any));
        assert_eq!(
            entity_links(Some(&wz_capi_c_entity_ext_t::OFF)),
            Ok(LinkRestriction::Any)
        );
        assert_eq!(publish_statement(None), Ok(PublishStatement::default()));
        assert_eq!(
            publish_statement(Some(&wz_capi_c_publish_ext_t::OFF)),
            Ok(PublishStatement::default())
        );
        assert_eq!(query_statement(None), Ok(QueryStatement::default()));
        assert_eq!(
            query_statement(Some(&wz_capi_c_query_ext_t::OFF)),
            Ok(QueryStatement::default())
        );
        // A target left unstated is not read, whatever its bytes say.
        let mut unread = wz_capi_c_query_ext_t::OFF;
        unread.target = some_id();
        assert_eq!(
            query_statement(Some(&unread)),
            Ok(QueryStatement::default())
        );
    }

    #[test]
    fn a_link_mask_is_admitted_only_when_the_policy_is_on() {
        let stated = wz_capi_c_entity_ext_t { link_mask: 0b110 };
        decided(
            links_on(),
            LinkRestriction::only([1, 2]).expect("two slots"),
            entity_links(Some(&stated)),
        );
        let mut publish = wz_capi_c_publish_ext_t::OFF;
        publish.link_mask = 0b110;
        decided(
            links_on(),
            PublishStatement {
                links: LinkRestriction::only([1, 2]).expect("two slots"),
                ..PublishStatement::default()
            },
            publish_statement(Some(&publish)),
        );
        let mut query = wz_capi_c_query_ext_t::OFF;
        query.link_mask = 0b110;
        decided(
            links_on(),
            QueryStatement {
                links: LinkRestriction::only([1, 2]).expect("two slots"),
                target_peer: None,
            },
            query_statement(Some(&query)),
        );
    }

    #[test]
    fn a_retry_is_admitted_only_when_the_policy_is_on_and_its_numbers_are_a_retry() {
        let mut publish = wz_capi_c_publish_ext_t::OFF;
        publish.attempts = 3;
        publish.delay_ms = 20;
        decided(
            retry_on(),
            PublishStatement {
                retry: Some(AdmissionRetry {
                    attempts: 3,
                    delay_ms: 20,
                }),
                ..PublishStatement::default()
            },
            publish_statement(Some(&publish)),
        );
        // The policy answers before the numbers do: a build without it says so for half a retry.
        for (attempts, delay_ms) in [(0, 5), (5, 0)] {
            let mut half = wz_capi_c_publish_ext_t::OFF;
            half.attempts = attempts;
            half.delay_ms = delay_ms;
            let got = publish_statement(Some(&half));
            if retry_on() {
                assert_eq!(got, Err(Z_EINVAL), "{attempts} passes, {delay_ms} ms");
            } else {
                assert_eq!(got, Err(WZ_CAPI_C_E_POLICY_OFF));
            }
        }
        // A number past what a retry holds is no retry, whatever the policy.
        let mut wide = wz_capi_c_publish_ext_t::OFF;
        wide.attempts = 256;
        wide.delay_ms = 1;
        assert_eq!(publish_statement(Some(&wide)), Err(Z_EINVAL));
    }

    #[test]
    fn all_or_none_is_admitted_only_when_the_policy_is_on() {
        let mut publish = wz_capi_c_publish_ext_t::OFF;
        publish.all_or_none = 1;
        decided(
            atomic_on(),
            PublishStatement {
                atomic: true,
                ..PublishStatement::default()
            },
            publish_statement(Some(&publish)),
        );
        // Any non-zero byte states it.
        publish.all_or_none = 0x80;
        decided(
            atomic_on(),
            PublishStatement {
                atomic: true,
                ..PublishStatement::default()
            },
            publish_statement(Some(&publish)),
        );
    }

    #[test]
    fn a_target_is_admitted_only_when_the_policy_is_on_and_names_a_node() {
        let mut query = wz_capi_c_query_ext_t::OFF;
        query.has_target = 1;
        query.target = some_id();
        decided(
            target_on(),
            QueryStatement {
                links: LinkRestriction::Any,
                target_peer: Some(vec![0xc7, 0xd1]),
            },
            query_statement(Some(&query)),
        );
        // An identity of no byte names no node.
        query.target = z_id_t {
            id: [0u8; Z_ID_SIZE],
        };
        let got = query_statement(Some(&query));
        if target_on() {
            assert_eq!(got, Err(Z_EINVAL));
        } else {
            assert_eq!(got, Err(WZ_CAPI_C_E_POLICY_OFF));
        }
    }

    #[test]
    fn a_publish_stating_several_things_is_refused_when_any_policy_is_off() {
        let mut publish = wz_capi_c_publish_ext_t::OFF;
        publish.link_mask = 1;
        publish.attempts = 2;
        publish.delay_ms = 10;
        publish.all_or_none = 1;
        let all_on = links_on() && retry_on() && atomic_on();
        let got = publish_statement(Some(&publish));
        if all_on {
            assert_eq!(
                got,
                Ok(PublishStatement {
                    links: LinkRestriction::only([0]).expect("one slot"),
                    retry: Some(AdmissionRetry {
                        attempts: 2,
                        delay_ms: 10
                    }),
                    atomic: true,
                })
            );
        } else {
            assert_eq!(got, Err(WZ_CAPI_C_E_POLICY_OFF));
        }
    }

    /// The doors on handles that are not there: a statement of nothing is `Z_ENULL` as the `z_*`
    /// twin answers, and a stated one is refused by the build's policy before the handles are
    /// read when it is off.
    #[test]
    fn the_doors_refuse_a_statement_before_the_handles_and_answer_the_twin_for_none() {
        let refused_or_null = |on: bool| if on { Z_ENULL } else { WZ_CAPI_C_E_POLICY_OFF };

        let mut retry = wz_capi_c_publish_ext_t::OFF;
        retry.attempts = 2;
        retry.delay_ms = 10;
        let mut mask = wz_capi_c_entity_ext_t::OFF;
        mask.link_mask = 1;
        let mut target = wz_capi_c_query_ext_t::OFF;
        target.has_target = 1;
        target.target = some_id();

        // SAFETY: every handle is null, which each door answers; the owned out-parameters and the
        // moved closures are zeroed locals, which are gravestones.
        unsafe {
            let none_publish = std::ptr::null::<wz_capi_c_publish_ext_t>();
            let none_query = std::ptr::null::<wz_capi_c_query_ext_t>();
            let none_entity = std::ptr::null::<wz_capi_c_entity_ext_t>();
            let session = std::ptr::null::<z_loaned_session_t>();
            let key = std::ptr::null::<z_loaned_keyexpr_t>();

            assert_eq!(
                wz_capi_c_put_ext(
                    session,
                    key,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    none_publish
                ),
                Z_ENULL
            );
            assert_eq!(
                wz_capi_c_put_ext(
                    session,
                    key,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    &retry
                ),
                refused_or_null(retry_on())
            );
            assert_eq!(
                wz_capi_c_delete_ext(session, key, std::ptr::null_mut(), none_publish),
                Z_ENULL
            );
            assert_eq!(
                wz_capi_c_delete_ext(session, key, std::ptr::null_mut(), &retry),
                refused_or_null(retry_on())
            );

            let mut publisher: z_owned_publisher_t = std::mem::zeroed();
            assert_eq!(
                wz_capi_c_declare_publisher_ext(
                    session,
                    &mut publisher,
                    key,
                    std::ptr::null_mut(),
                    none_publish
                ),
                Z_ENULL
            );
            assert_eq!(
                wz_capi_c_declare_publisher_ext(
                    session,
                    &mut publisher,
                    key,
                    std::ptr::null_mut(),
                    &retry
                ),
                refused_or_null(retry_on())
            );

            let mut reply: z_moved_closure_reply_t = std::mem::zeroed();
            assert_eq!(
                wz_capi_c_get_ext(
                    session,
                    key,
                    std::ptr::null(),
                    &mut reply,
                    std::ptr::null_mut(),
                    none_query
                ),
                Z_ENULL
            );
            assert_eq!(
                wz_capi_c_get_ext(
                    session,
                    key,
                    std::ptr::null(),
                    &mut reply,
                    std::ptr::null_mut(),
                    &target
                ),
                refused_or_null(target_on())
            );

            let mut querier: z_owned_querier_t = std::mem::zeroed();
            assert_eq!(
                wz_capi_c_declare_querier_ext(
                    session,
                    &mut querier,
                    key,
                    std::ptr::null_mut(),
                    none_query
                ),
                Z_ENULL
            );
            assert_eq!(
                wz_capi_c_declare_querier_ext(
                    session,
                    &mut querier,
                    key,
                    std::ptr::null_mut(),
                    &target
                ),
                refused_or_null(target_on())
            );

            let mut sample: z_moved_closure_sample_t = std::mem::zeroed();
            let mut subscriber: z_owned_subscriber_t = std::mem::zeroed();
            assert_eq!(
                wz_capi_c_declare_subscriber_ext(
                    session,
                    &mut subscriber,
                    key,
                    &mut sample,
                    std::ptr::null_mut(),
                    none_entity
                ),
                Z_ENULL
            );
            assert_eq!(
                wz_capi_c_declare_subscriber_ext(
                    session,
                    &mut subscriber,
                    key,
                    &mut sample,
                    std::ptr::null_mut(),
                    &mask
                ),
                refused_or_null(links_on())
            );

            let mut query: z_moved_closure_query_t = std::mem::zeroed();
            let mut queryable: z_owned_queryable_t = std::mem::zeroed();
            assert_eq!(
                wz_capi_c_declare_queryable_ext(
                    session,
                    &mut queryable,
                    key,
                    &mut query,
                    std::ptr::null_mut(),
                    none_entity
                ),
                Z_ENULL
            );
            assert_eq!(
                wz_capi_c_declare_queryable_ext(
                    session,
                    &mut queryable,
                    key,
                    &mut query,
                    std::ptr::null_mut(),
                    &mask
                ),
                refused_or_null(links_on())
            );
        }
    }
}

/// The bodies the doors share, on a session that is a node: the data plane behind it reads no
/// statement, so a call that states one is not carried, whatever the build's policy says. The
/// doors cannot reach these arms in a build whose policy is off (they refuse first), so the test
/// hands the bodies a statement the policy has already admitted.
#[cfg(all(test, feature = "router-node"))]
mod node_tests {
    use super::*;
    use std::ffi::CString;

    use crate::abi::{
        z_moved_config_t, z_moved_queryable_t, z_moved_session_t, z_moved_subscriber_t,
        z_owned_bytes_t, z_owned_config_t, z_owned_session_t, z_view_keyexpr_t,
    };
    use crate::bytes::z_bytes_copy_from_str;
    use crate::config::{z_config_default, z_config_loan_mut, zc_config_insert_json5};
    use crate::keyexpr::{z_view_keyexpr_from_str, z_view_keyexpr_loan};
    use crate::result::{Z_EUNAVAILABLE, Z_OK};
    use crate::session::{z_close, z_open, z_session_drop, z_session_loan, z_session_loan_mut};
    use wz_runtime_tokio_test_support::free_port;

    /// A router whose south is partitioned by subregions, which a config opens as a node.
    unsafe fn open_node() -> z_owned_session_t {
        let entries = [
            ("scouting/multicast/enabled", String::from("false")),
            ("mode", String::from("\"router\"")),
            (
                "listen/endpoints",
                format!("[\"tcp/127.0.0.1:{}\"]", free_port()),
            ),
            (
                "gateway",
                String::from(r#"{ south: [ { filters: [ { modes: ["peer"] } ] } ] }"#),
            ),
        ];
        let mut cfg: z_owned_config_t = std::mem::zeroed();
        assert_eq!(z_config_default(&mut cfg), Z_OK);
        for (key, value) in entries {
            let key = CString::new(key).unwrap();
            let value = CString::new(value).unwrap();
            assert_eq!(
                zc_config_insert_json5(z_config_loan_mut(&mut cfg), key.as_ptr(), value.as_ptr()),
                Z_OK
            );
        }
        let mut session: z_owned_session_t = std::mem::zeroed();
        assert_eq!(
            z_open(
                &mut session,
                (&mut cfg as *mut z_owned_config_t).cast::<z_moved_config_t>(),
                std::ptr::null()
            ),
            Z_OK
        );
        session
    }

    unsafe fn payload_of(text: &str) -> z_owned_bytes_t {
        let text = CString::new(text).unwrap();
        let mut payload: z_owned_bytes_t = std::mem::zeroed();
        assert_eq!(z_bytes_copy_from_str(&mut payload, text.as_ptr()), Z_OK);
        payload
    }

    #[test]
    fn a_node_carries_a_call_that_states_nothing_and_refuses_one_that_states_something() {
        let atomic = PublishStatement {
            atomic: true,
            ..PublishStatement::default()
        };
        let one_link = LinkRestriction::only([1]).expect("one slot");
        let links_only = QueryStatement {
            links: one_link,
            target_peer: None,
        };
        let target_only = QueryStatement {
            links: LinkRestriction::Any,
            target_peer: Some(vec![0x01]),
        };

        // SAFETY: a session this test opened and closes, loaned for each call; every owned
        // out-parameter and moved closure is a local.
        unsafe {
            let mut session = open_node();
            let key_text = CString::new("wz/switch-doors/node").unwrap();
            let mut view: z_view_keyexpr_t = std::mem::zeroed();
            assert_eq!(z_view_keyexpr_from_str(&mut view, key_text.as_ptr()), Z_OK);
            let key = z_view_keyexpr_loan(&view);
            let loaned = z_session_loan(&session);

            let mut payload = payload_of("v");
            assert_eq!(
                crate::put::put_stated(
                    loaned,
                    key,
                    (&mut payload as *mut z_owned_bytes_t).cast::<z_moved_bytes_t>(),
                    std::ptr::null_mut(),
                    Ok(atomic)
                ),
                Z_EUNAVAILABLE,
                "a put that states all-or-none"
            );
            let mut payload = payload_of("v");
            assert_eq!(
                crate::put::put_stated(
                    loaned,
                    key,
                    (&mut payload as *mut z_owned_bytes_t).cast::<z_moved_bytes_t>(),
                    std::ptr::null_mut(),
                    Ok(PublishStatement::default())
                ),
                Z_OK,
                "a put that states nothing"
            );

            assert_eq!(
                crate::put::delete_stated(loaned, key, std::ptr::null_mut(), Ok(atomic)),
                Z_EUNAVAILABLE,
                "a delete that states all-or-none"
            );
            assert_eq!(
                crate::put::delete_stated(
                    loaned,
                    key,
                    std::ptr::null_mut(),
                    Ok(PublishStatement::default())
                ),
                Z_OK,
                "a delete that states nothing"
            );

            let mut publisher: z_owned_publisher_t = std::mem::zeroed();
            assert_eq!(
                crate::publisher::declare_publisher_stated(
                    loaned,
                    &mut publisher,
                    key,
                    std::ptr::null_mut(),
                    Ok(atomic)
                ),
                Z_EUNAVAILABLE
            );
            assert!(!crate::publisher::z_internal_publisher_check(&publisher));

            let mut reply: z_moved_closure_reply_t = std::mem::zeroed();
            for stated in [links_only, target_only.clone()] {
                assert_eq!(
                    crate::get::get_with_selector(
                        loaned,
                        key,
                        None,
                        &mut reply,
                        std::ptr::null_mut(),
                        Ok(stated)
                    ),
                    Z_EUNAVAILABLE
                );
            }

            let mut querier: z_owned_querier_t = std::mem::zeroed();
            assert_eq!(
                crate::querier::declare_querier_stated(
                    loaned,
                    &mut querier,
                    key,
                    std::ptr::null_mut(),
                    Ok(target_only)
                ),
                Z_EUNAVAILABLE
            );
            assert!(!crate::querier::z_internal_querier_check(&querier));

            let mut sample: z_moved_closure_sample_t = std::mem::zeroed();
            let mut subscriber: z_owned_subscriber_t = std::mem::zeroed();
            assert_eq!(
                crate::sub::declare_subscriber_on(
                    loaned,
                    &mut subscriber,
                    key,
                    &mut sample,
                    std::ptr::null_mut(),
                    Ok(one_link)
                ),
                Z_EUNAVAILABLE
            );
            assert!(!crate::sub::z_internal_subscriber_check(&subscriber));
            assert_eq!(
                crate::sub::declare_subscriber_on(
                    loaned,
                    &mut subscriber,
                    key,
                    &mut sample,
                    std::ptr::null_mut(),
                    Ok(LinkRestriction::Any)
                ),
                Z_OK,
                "a subscriber that states no link"
            );
            assert_eq!(
                crate::sub::z_undeclare_subscriber(
                    (&mut subscriber as *mut z_owned_subscriber_t).cast::<z_moved_subscriber_t>()
                ),
                Z_OK
            );

            let mut handler: z_moved_closure_query_t = std::mem::zeroed();
            let mut queryable: z_owned_queryable_t = std::mem::zeroed();
            assert_eq!(
                crate::query::declare_queryable_on(
                    loaned,
                    &mut queryable,
                    key,
                    &mut handler,
                    std::ptr::null_mut(),
                    Ok(one_link)
                ),
                Z_EUNAVAILABLE
            );
            assert!(!crate::query::z_internal_queryable_check(&queryable));
            assert_eq!(
                crate::query::declare_queryable_on(
                    loaned,
                    &mut queryable,
                    key,
                    &mut handler,
                    std::ptr::null_mut(),
                    Ok(LinkRestriction::Any)
                ),
                Z_OK,
                "a queryable that states no link"
            );
            assert_eq!(
                crate::query::z_undeclare_queryable(
                    (&mut queryable as *mut z_owned_queryable_t).cast::<z_moved_queryable_t>()
                ),
                Z_OK
            );

            let _ = z_close(z_session_loan_mut(&mut session), std::ptr::null_mut());
            z_session_drop((&mut session as *mut z_owned_session_t).cast::<z_moved_session_t>());
        }
    }
}
