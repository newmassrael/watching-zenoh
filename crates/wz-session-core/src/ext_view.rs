// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! What a reader of an extension chain asks of one entry, and the two kinds of
//! entry that can be asked.
//!
//! R3044 -- a Query's chain no longer holds the generic `ExtEntry` the rest of
//! the tree's chains hold. Upstream reads the ZBuf extension a Query carries its
//! value in differently after a shared-memory marker (`query_value_zbuf.scxml`),
//! and nothing inside one entry can know what came before it, so the Query's
//! chain has an entry of its own whose ZBuf arm takes that as an input
//! (`query_ext_entry.scxml`). The helpers that read the attachment, the source
//! info and the value of a message do not care which of the two it is, and they
//! are shared with the Put, the Push and the Reply, so they ask this trait and
//! not either type.
//!
//! The trait asks four things, which is everything those helpers used: the
//! entry's header, its identifier, its encoding, and the bytes of a ZBuf body that is a plain
//! run of bytes. A ZBuf body that is a list of slices is not that, and says so by
//! answering `None`: a helper that wants the plain bytes of a value must not be
//! handed the descriptor of a shared-memory buffer as though it were them.

use sce_forge_runtime::codec::{CodecStorage, SceByteBuf};
use wz_codecs::ext_entry::{ExtEntryOwned, ExtEntryOwnedVariant};

/// An entry of an extension chain, as a reader of the chain sees it.
pub trait ExtEntryView {
    /// The extension's header byte, the chain flag included.
    fn header(&self) -> u8;

    /// The extension's identifier: the low four bits of its header.
    fn ext_id(&self) -> u8;

    /// The encoding of the extension's body: bits 5 and 6 of its header (0 unit,
    /// 1 z64, 2 ZBuf).
    fn enc(&self) -> u8;

    /// The bytes of a ZBuf-encoded entry whose body is a plain run of bytes.
    /// `None` for any other entry, and for a ZBuf body that is a list of slices.
    fn plain_zbuf(&self) -> Option<&[u8]>;
}

impl<S: CodecStorage> ExtEntryView for ExtEntryOwned<S> {
    fn header(&self) -> u8 {
        self.header
    }

    fn ext_id(&self) -> u8 {
        ExtEntryOwned::ext_id(self)
    }

    fn enc(&self) -> u8 {
        ExtEntryOwned::enc(self)
    }

    fn plain_zbuf(&self) -> Option<&[u8]> {
        match &self.body {
            ExtEntryOwnedVariant::CodecZenohExtZbuf(z) => Some(SceByteBuf::as_slice(&z.value)),
            _ => None,
        }
    }
}

#[cfg(feature = "codec-request")]
mod query {
    use super::{CodecStorage, ExtEntryOwned, ExtEntryOwnedVariant, ExtEntryView, SceByteBuf};
    use wz_codecs::query_ext_entry::{QueryExtEntryOwned, QueryExtEntryOwnedVariant};
    use wz_codecs::query_value_zbuf::QueryValueZbufOwned;

    impl<S: CodecStorage> ExtEntryView for QueryExtEntryOwned<S> {
        fn header(&self) -> u8 {
            self.header
        }

        fn ext_id(&self) -> u8 {
            QueryExtEntryOwned::ext_id(self)
        }

        fn enc(&self) -> u8 {
            QueryExtEntryOwned::enc(self)
        }

        fn plain_zbuf(&self) -> Option<&[u8]> {
            match &self.body {
                // `value` is populated for the plain shape only: the sliced shape
                // has an encoding and a list of slices instead.
                QueryExtEntryOwnedVariant::CodecZenohQueryValueZbuf(z) => {
                    z.value.as_ref().map(SceByteBuf::as_slice)
                }
                _ => None,
            }
        }
    }

    /// A generic extension entry as the entry of a Query's chain. The three
    /// entries a Query is built with (the value, the source info, the
    /// attachment) are all plain, so a ZBuf body becomes the plain shape of the
    /// Query's own ZBuf body, with the length and the bytes it had and no
    /// encoding and no slices; the unit and z64 arms and an unknown encoding
    /// carry over unchanged.
    pub fn query_ext_from_generic<S: CodecStorage>(ext: ExtEntryOwned<S>) -> QueryExtEntryOwned<S> {
        let body = match ext.body {
            ExtEntryOwnedVariant::CodecZenohExtUnit(unit) => {
                QueryExtEntryOwnedVariant::CodecZenohExtUnit(unit)
            }
            ExtEntryOwnedVariant::CodecZenohExtZint(zint) => {
                QueryExtEntryOwnedVariant::CodecZenohExtZint(zint)
            }
            ExtEntryOwnedVariant::CodecZenohExtZbuf(z) => {
                QueryExtEntryOwnedVariant::CodecZenohQueryValueZbuf(QueryValueZbufOwned {
                    value_len: z.value_len,
                    value: Some(z.value),
                    encoding: None,
                    slice_count: None,
                    slices: None,
                })
            }
            ExtEntryOwnedVariant::Default { tag, body } => {
                QueryExtEntryOwnedVariant::Default { tag, body }
            }
        };
        QueryExtEntryOwned {
            header: ext.header,
            body,
        }
    }
}

#[cfg(feature = "codec-request")]
pub use query::query_ext_from_generic;
