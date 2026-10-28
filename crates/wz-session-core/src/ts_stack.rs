// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The timestamp stack a message may carry: the interceptions recorded on its way, at the node that
//! sends it, at each node that routes it and at the node that receives it.
//!
//! Zenoh declares it as an extension of the Push, the Request and the Response, id `0x7`, a ZBuf
//! the receiver may skip (`zenoh-protocol` `network/push.rs` @ `zextzbuf!(0x7, false)`), so a node
//! that does not know it passes the message on with it. This module owns the extension's body and
//! its place in a chain; which node records what, and with what clock, is the host's.
//!
//! ```text
//! +-+-+-+-+-+-+-+-+
//! |X|X|X|X|X|E|R|S|   conf_flags: which points are instrumented
//! +---------------+
//! ~  count: zint   ~
//! +---------------+
//! ~ [Interception] ~   flags (U|point), then the timestamp as a length-prefixed byte string
//! +---------------+
//! ```

use alloc::vec::Vec;

use sce_forge_runtime::codec::{CodecStorage, SceByteBuf};
use wz_codecs::ext_entry::{ExtEntryOwned, ExtEntryOwnedVariant};
use wz_codecs::ext_zbuf::ExtZbufOwned;

use crate::ext_header::{ext_eid, EXT_ENC_ZBUF};
use crate::ext_nodeid::apply_chain_z_bits;
use crate::ext_view::ExtEntryView;

/// The extension's id on a Push, a Request and a Response alike.
pub const TS_STACK_EXT_ID: u8 = 0x07;
/// The extension's header with no extension after it: id `0x7` and the ZBuf encoding, not
/// mandatory.
pub const TS_STACK_EXT_HEADER: u8 = TS_STACK_EXT_ID | EXT_ENC_ZBUF;

/// The most interceptions a stack holds; a longer one is refused by a decoder.
pub const MAX_STACK_SIZE: usize = 255;

/// The points a message is intercepted at, as the bits of `conf_flags` and of an interception's
/// flags.
pub mod point {
    /// The message leaves the node that publishes or replies.
    pub const SEND: u8 = 0b0000_0001;
    /// The message passes a node that routes it.
    pub const ROUTE: u8 = 0b0000_0010;
    /// The message reaches the node that delivers it to the application.
    pub const RECEIVE: u8 = 0b0000_0100;
    /// Set in an interception's flags when its timestamp is the bytes of a user callback and not a
    /// UHLC timestamp.
    pub const IS_CUSTOM_TS: u8 = 0b1000_0000;
}

/// One interception: the flags it was recorded with and the timestamp bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Interception {
    /// The point, and [`point::IS_CUSTOM_TS`] when the bytes are a user's.
    pub flags: u8,
    /// The timestamp as the bytes the flags say.
    pub timestamp: Vec<u8>,
}

/// The body of the extension: which points are instrumented and what has been recorded so far.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TsStack {
    /// The points that are instrumented, which a node reads to know whether to record.
    pub conf_flags: u8,
    /// The interceptions, in the order the message met them.
    pub stack: Vec<Interception>,
}

impl TsStack {
    /// An empty stack for the points `conf_flags` names.
    pub fn new(conf_flags: u8) -> Self {
        Self {
            conf_flags,
            stack: Vec::new(),
        }
    }

    /// Whether the point `point` is instrumented on this message.
    pub fn is_instrumented(&self, at: u8) -> bool {
        self.conf_flags & at != 0
    }

    /// Record `timestamp` at the point `at`, if the point is instrumented, the timestamp is not
    /// empty (a callback that gives nothing records nothing) and the stack has room. Returns
    /// whether it was recorded.
    pub fn record(&mut self, at: u8, timestamp: Vec<u8>, is_custom: bool) -> bool {
        if !self.is_instrumented(at) || timestamp.is_empty() || self.stack.len() >= MAX_STACK_SIZE {
            return false;
        }
        let flags = at | if is_custom { point::IS_CUSTOM_TS } else { 0 };
        self.stack.push(Interception { flags, timestamp });
        true
    }

    /// The bytes of the extension's body.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(2 + self.stack.len() * 18);
        out.push(self.conf_flags);
        push_zint(&mut out, self.stack.len() as u64);
        for interception in &self.stack {
            out.push(interception.flags);
            push_zint(&mut out, interception.timestamp.len() as u64);
            out.extend_from_slice(&interception.timestamp);
        }
        out
    }

    /// The stack the bytes of an extension's body say, or `None` when they are not one: no
    /// instrumented point, more than [`MAX_STACK_SIZE`] interceptions, or bytes that stop short
    /// or go on after it.
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        let (&conf_flags, rest) = bytes.split_first()?;
        if conf_flags == 0 {
            return None;
        }
        let (count, used) = wz_codecs::vle::decode_zint(rest)?;
        let mut rest = &rest[used..];
        let count = usize::try_from(count)
            .ok()
            .filter(|n| *n <= MAX_STACK_SIZE)?;
        let mut stack = Vec::with_capacity(count);
        for _ in 0..count {
            let (&flags, tail) = rest.split_first()?;
            let (len, used) = wz_codecs::vle::decode_zint(tail)?;
            let len = usize::try_from(len).ok()?;
            let tail = &tail[used..];
            if tail.len() < len {
                return None;
            }
            stack.push(Interception {
                flags,
                timestamp: tail[..len].to_vec(),
            });
            rest = &tail[len..];
        }
        rest.is_empty().then_some(Self { conf_flags, stack })
    }
}

fn push_zint(out: &mut Vec<u8>, value: u64) {
    let mut buf = [0u8; 10];
    let n = wz_codecs::vle::encode_zint(&mut buf, value);
    out.extend_from_slice(&buf[..n]);
}

/// The stack a chain of extensions carries, or `None` when it carries none or one that does not
/// decode (a node that cannot read it behaves as if it were not there).
pub fn read_ts_stack<E: ExtEntryView>(extensions: impl IntoIterator<Item = E>) -> Option<TsStack> {
    extensions
        .into_iter()
        .find(|ext| ext.eid() == ext_eid(TS_STACK_EXT_HEADER))
        .and_then(|ext| ext.plain_zbuf().and_then(TsStack::decode))
}

/// Put `stack` in a chain of extensions, in place of the one it carries, and say whether the chain
/// now holds an extension. `None` takes the stack out. The `Z` bits of the chain are made right.
pub fn set_ts_stack<S: CodecStorage>(
    extensions: &mut Option<Vec<ExtEntryOwned<S>>>,
    stack: Option<&TsStack>,
) -> bool {
    let want = ext_eid(TS_STACK_EXT_HEADER);
    if let Some(list) = extensions.as_mut() {
        list.retain(|e| ext_eid(e.header) != want);
    }
    if let Some(stack) = stack {
        let bytes = stack.encode();
        // Under `alloc` the container is unbounded and this cannot fail; the `32` is only the
        // capacity of a profile with no allocator, which has no timestamp stack.
        if let Ok(value) = <S::Bytes<32> as SceByteBuf>::from_slice(&bytes) {
            let entry = ExtEntryOwned {
                header: TS_STACK_EXT_HEADER,
                body: ExtEntryOwnedVariant::CodecZenohExtZbuf(ExtZbufOwned {
                    value_len: bytes.len() as u64,
                    value,
                }),
            };
            extensions.get_or_insert_with(Vec::new).push(entry);
        }
    }
    match extensions.as_mut() {
        Some(list) if !list.is_empty() => {
            apply_chain_z_bits(list);
            true
        }
        _ => {
            *extensions = None;
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stamped(conf_flags: u8) -> TsStack {
        let mut stack = TsStack::new(conf_flags);
        assert!(stack.record(point::SEND, alloc::vec![1, 2, 3], false));
        assert!(stack.record(point::RECEIVE, alloc::vec![9], true));
        stack
    }

    #[test]
    fn a_stack_decodes_to_what_it_encoded() {
        let stack = stamped(point::SEND | point::RECEIVE);
        assert_eq!(TsStack::decode(&stack.encode()), Some(stack));
    }

    #[test]
    fn the_bytes_are_those_zenoh_writes() {
        // conf_flags, the count, then for each interception its flags, the length of its timestamp
        // and the timestamp (`zenoh-codec` `network/timestamp_stack.rs`).
        let stack = stamped(point::SEND | point::RECEIVE);
        assert_eq!(
            stack.encode(),
            [
                0b101,
                2,
                point::SEND,
                3,
                1,
                2,
                3,
                point::RECEIVE | 0x80,
                1,
                9
            ]
        );
    }

    #[test]
    fn a_point_that_is_not_instrumented_records_nothing() {
        let mut stack = TsStack::new(point::SEND);
        assert!(!stack.record(point::ROUTE, alloc::vec![1], false));
        assert!(stack.stack.is_empty());
    }

    #[test]
    fn an_empty_timestamp_records_nothing() {
        let mut stack = TsStack::new(point::SEND);
        assert!(!stack.record(point::SEND, Vec::new(), true));
    }

    #[test]
    fn a_stack_holds_no_more_than_the_codec_reads() {
        let mut stack = TsStack::new(point::ROUTE);
        for _ in 0..MAX_STACK_SIZE {
            assert!(stack.record(point::ROUTE, alloc::vec![1], false));
        }
        assert!(!stack.record(point::ROUTE, alloc::vec![1], false));
        assert!(TsStack::decode(&stack.encode()).is_some());
    }

    #[test]
    fn bytes_that_are_not_a_stack_are_refused() {
        let good = stamped(point::SEND | point::RECEIVE).encode();
        assert_eq!(TsStack::decode(&[]), None, "nothing");
        assert_eq!(TsStack::decode(&[0, 0]), None, "no point instrumented");
        assert_eq!(TsStack::decode(&good[..good.len() - 1]), None, "short");
        let mut long = good.clone();
        long.push(0);
        assert_eq!(TsStack::decode(&long), None, "something after it");
        assert_eq!(TsStack::decode(&[1, 0xff, 0xff, 0x7f]), None, "too many");
    }

    #[test]
    fn the_extension_is_set_read_and_taken_out() {
        let mut chain: Option<Vec<ExtEntryOwned>> = None;
        let stack = stamped(point::SEND | point::RECEIVE);
        assert!(set_ts_stack(&mut chain, Some(&stack)));
        assert_eq!(
            chain.as_ref().unwrap()[0].header & 0x7f,
            TS_STACK_EXT_HEADER
        );
        assert_eq!(
            read_ts_stack(chain.as_ref().unwrap().iter()),
            Some(stack.clone())
        );

        let longer = {
            let mut longer = stack.clone();
            longer.record(point::RECEIVE, alloc::vec![7], false);
            longer
        };
        assert!(set_ts_stack(&mut chain, Some(&longer)));
        assert_eq!(
            chain.as_ref().unwrap().len(),
            1,
            "it replaces the one it carries"
        );
        assert_eq!(read_ts_stack(chain.as_ref().unwrap().iter()), Some(longer));

        assert!(!set_ts_stack(&mut chain, None));
        assert!(chain.is_none());
    }
}
