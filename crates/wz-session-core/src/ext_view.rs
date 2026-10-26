// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
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
use wz_codecs::ext_entry::{ExtEntry, ExtEntryOwned, ExtEntryOwnedVariant, ExtEntryVariant};

/// An entry of an extension chain, as a reader of the chain sees it.
pub trait ExtEntryView {
    /// The extension's header byte, the chain flag included.
    fn header(&self) -> u8;

    /// The extension's identifier: the low four bits of its header.
    ///
    /// This is the id COLUMN, not what tells one extension from another: two
    /// extensions may share it and differ in the mandatory bit or the encoding.
    /// A reader that picks an extension out of a chain asks [`Self::eid`].
    fn ext_id(&self) -> u8;

    /// The extension's identity: its header without the chain flag, which is
    /// upstream's `iext::eid` and is what upstream matches a received extension
    /// by ([`crate::ext_header::ext_eid`]). Compare it against an identity
    /// constant ([`crate::ext_header::body_eid`]), never against a bare id.
    fn eid(&self) -> u8 {
        crate::ext_header::ext_eid(self.header())
    }

    /// The encoding of the extension's body: bits 5 and 6 of its header (0 unit,
    /// 1 z64, 2 ZBuf).
    fn enc(&self) -> u8;

    /// The bytes of a ZBuf-encoded entry whose body is a plain run of bytes.
    /// `None` for any other entry, and for a ZBuf body that is a list of slices.
    fn plain_zbuf(&self) -> Option<&[u8]>;

    /// The value of a z64-encoded entry, `None` for any other entry. What the
    /// QoS reader of a received chain needs (`crate::sample::extract_qos_in`),
    /// on the owned chain and on one read where its frame lies alike.
    fn zint(&self) -> Option<u64>;
}

/// The first entry of `extensions` whose identity is `eid`.
///
/// The one place a reader picks an extension out of a received chain. Upstream
/// tells a received extension apart by its identity (`commons/zenoh-codec/src/zenoh/put.rs`
/// @ `Ok(match iext::eid(ext) {`), so a reader that wants the extension named by
/// `eid` finds it here and never by the id field, which an extension that
/// differs in the mandatory bit or the encoding shares with it.
pub fn find_by_eid<E: ExtEntryView>(extensions: &[E], eid: u8) -> Option<&E> {
    extensions.iter().find(|ext| ext.eid() == eid)
}

/// A reference to an entry answers as the entry does, so that a reader written over the entries a
/// chain YIELDS (`impl IntoIterator<Item: ExtEntryView>`) is the same reader for a slice
/// (`slice.iter()` yields references) and for a chain read where its frame lies (a
/// [`ListView`](sce_forge_runtime::view::ListView) yields entries by value).
impl<T: ExtEntryView + ?Sized> ExtEntryView for &T {
    fn header(&self) -> u8 {
        (**self).header()
    }

    fn ext_id(&self) -> u8 {
        (**self).ext_id()
    }

    fn enc(&self) -> u8 {
        (**self).enc()
    }

    fn plain_zbuf(&self) -> Option<&[u8]> {
        (**self).plain_zbuf()
    }

    fn zint(&self) -> Option<u64> {
        (**self).zint()
    }
}

/// An entry whose plain ZBuf bytes outlive the value that answers for them: [`ExtEntryView::plain_zbuf`]
/// borrows from the entry it is asked of, which is no use to a reader that is handed entries one at a
/// time and must give back bytes that stay where they lie (the attachment and the value of a Query
/// read in place). `'c` is how long the bytes live: the slice a reference came from, or the frame a
/// view was read from.
pub trait ExtEntryBytes<'c>: ExtEntryView {
    /// [`ExtEntryView::plain_zbuf`], for as long as `'c`.
    fn plain_zbuf_in(&self) -> Option<&'c [u8]>;
}

impl<'c, T: ExtEntryView + ?Sized> ExtEntryBytes<'c> for &'c T {
    fn plain_zbuf_in(&self) -> Option<&'c [u8]> {
        // `self` is a `&&'c T`; the inner reference is `Copy` and outlives this call.
        let entry: &'c T = self;
        entry.plain_zbuf()
    }
}

/// The entries of an optional chain a record carries where its frame lies, in order, each decoded as
/// the walk reaches it: nothing for a record with no chain. What the readers written over the
/// entries a chain yields are handed, in place of the slice a held chain would give them.
///
/// `W` is the list's walk marker (`ExtEntryWalk` for an extension chain), which says how an entry is
/// read and names the entry view it yields.
pub fn walked<'a, W: sce_forge_runtime::codec::ListWalk<K> + 'a, const K: usize>(
    chain: Option<&sce_forge_runtime::codec::ListView<'a, W, K>>,
) -> impl Iterator<Item = W::Entry<'a>> + 'a {
    chain.map(|list| list.iter()).into_iter().flatten()
}

/// [`find_by_eid`] over the entries a chain yields, by value or by reference: the first whose
/// identity is `eid`.
pub fn find_by_eid_in<'c, T: ExtEntryBytes<'c>>(
    extensions: impl IntoIterator<Item = T>,
    eid: u8,
) -> Option<T> {
    extensions.into_iter().find(|ext| ext.eid() == eid)
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

    fn zint(&self) -> Option<u64> {
        match &self.body {
            ExtEntryOwnedVariant::CodecZenohExtZint(z) => Some(z.value),
            _ => None,
        }
    }
}

/// The entry as it is decoded, where its frame lies: what the receive path that
/// dispatches a record without copying it (`drive::dispatch_datagram`) reads the
/// chains of a record through. It answers every question exactly as the owned
/// entry projected from it does; a ZBuf body is the frame's own bytes.
impl ExtEntryView for ExtEntry<'_> {
    fn header(&self) -> u8 {
        self.header
    }

    fn ext_id(&self) -> u8 {
        ExtEntry::ext_id(self)
    }

    fn enc(&self) -> u8 {
        ExtEntry::enc(self)
    }

    fn plain_zbuf(&self) -> Option<&[u8]> {
        match &self.body {
            ExtEntryVariant::CodecZenohExtZbuf(z) => Some(z.value),
            _ => None,
        }
    }

    fn zint(&self) -> Option<u64> {
        match &self.body {
            ExtEntryVariant::CodecZenohExtZint(z) => Some(z.value),
            _ => None,
        }
    }
}

/// The entry of a chain that is not held but WALKED (`wz_codecs::ext_entry::ExtEntryView`, the
/// codec's view of an entry: this trait's name and that type's coincide, the type is spelled in
/// full here for that reason). It answers every question as the entry it was read as does.
impl ExtEntryView for wz_codecs::ext_entry::ExtEntryView<'_> {
    fn header(&self) -> u8 {
        self.header
    }

    fn ext_id(&self) -> u8 {
        wz_codecs::ext_entry::ExtEntryView::ext_id(self)
    }

    fn enc(&self) -> u8 {
        wz_codecs::ext_entry::ExtEntryView::enc(self)
    }

    fn plain_zbuf(&self) -> Option<&[u8]> {
        use wz_codecs::ext_entry::ExtEntryViewVariant;
        match &self.body {
            ExtEntryViewVariant::CodecZenohExtZbuf(z) => Some(z.value),
            _ => None,
        }
    }

    fn zint(&self) -> Option<u64> {
        use wz_codecs::ext_entry::ExtEntryViewVariant;
        match &self.body {
            ExtEntryViewVariant::CodecZenohExtZint(z) => Some(z.value),
            _ => None,
        }
    }
}

impl<'a> ExtEntryBytes<'a> for wz_codecs::ext_entry::ExtEntryView<'a> {
    fn plain_zbuf_in(&self) -> Option<&'a [u8]> {
        use wz_codecs::ext_entry::ExtEntryViewVariant;
        match &self.body {
            ExtEntryViewVariant::CodecZenohExtZbuf(z) => Some(z.value),
            _ => None,
        }
    }
}

#[cfg(feature = "codec-request")]
mod query {
    use super::{
        CodecStorage, ExtEntryBytes, ExtEntryOwned, ExtEntryOwnedVariant, ExtEntryView, SceByteBuf,
    };
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

        fn zint(&self) -> Option<u64> {
            match &self.body {
                QueryExtEntryOwnedVariant::CodecZenohExtZint(z) => Some(z.value),
                _ => None,
            }
        }
    }

    /// A Query's entry as it is decoded, where its frame lies: what the receive
    /// path that dispatches a Request without copying it reads the Query's chain
    /// through. It answers every question exactly as the owned entry projected
    /// from it does; a plain ZBuf body is the frame's own bytes.
    impl ExtEntryView for wz_codecs::query_ext_entry::QueryExtEntry<'_> {
        fn header(&self) -> u8 {
            self.header
        }

        fn ext_id(&self) -> u8 {
            wz_codecs::query_ext_entry::QueryExtEntry::ext_id(self)
        }

        fn enc(&self) -> u8 {
            wz_codecs::query_ext_entry::QueryExtEntry::enc(self)
        }

        fn plain_zbuf(&self) -> Option<&[u8]> {
            use wz_codecs::query_ext_entry::QueryExtEntryVariant;
            match &self.body {
                // As on the owned entry: only the plain shape has `value`.
                QueryExtEntryVariant::CodecZenohQueryValueZbuf(z) => z.value,
                _ => None,
            }
        }

        fn zint(&self) -> Option<u64> {
            use wz_codecs::query_ext_entry::QueryExtEntryVariant;
            match &self.body {
                QueryExtEntryVariant::CodecZenohExtZint(z) => Some(z.value),
                _ => None,
            }
        }
    }

    /// A Query's entry as the walk of a chain yields it (`QueryExtEntryView`): the Query's chain read
    /// where its frame lies and not held. The same answers as the entry it was read as.
    impl ExtEntryView for wz_codecs::query_ext_entry::QueryExtEntryView<'_> {
        fn header(&self) -> u8 {
            self.header
        }

        fn ext_id(&self) -> u8 {
            wz_codecs::query_ext_entry::QueryExtEntryView::ext_id(self)
        }

        fn enc(&self) -> u8 {
            wz_codecs::query_ext_entry::QueryExtEntryView::enc(self)
        }

        fn plain_zbuf(&self) -> Option<&[u8]> {
            use wz_codecs::query_ext_entry::QueryExtEntryViewVariant;
            match &self.body {
                // As on the owned entry: only the plain shape has `value`.
                QueryExtEntryViewVariant::CodecZenohQueryValueZbuf(z) => z.value,
                _ => None,
            }
        }

        fn zint(&self) -> Option<u64> {
            use wz_codecs::query_ext_entry::QueryExtEntryViewVariant;
            match &self.body {
                QueryExtEntryViewVariant::CodecZenohExtZint(z) => Some(z.value),
                _ => None,
            }
        }
    }

    impl<'a> ExtEntryBytes<'a> for wz_codecs::query_ext_entry::QueryExtEntryView<'a> {
        fn plain_zbuf_in(&self) -> Option<&'a [u8]> {
            use wz_codecs::query_ext_entry::QueryExtEntryViewVariant;
            match &self.body {
                QueryExtEntryViewVariant::CodecZenohQueryValueZbuf(z) => z.value,
                _ => None,
            }
        }
    }

    /// How many payload bytes the VALUE of a Query carries, as upstream counts
    /// them (`commons/zenoh-protocol/src/network/request.rs` @
    /// `q.ext_body.as_ref().map_or(0, |b| b.payload.len())`), and `0` for a
    /// Query that has none: the bytes after the encoding when the value is a
    /// plain run of bytes, and the length of the buffer each slice names when it
    /// is a list of slices, which is how a sliced Put's payload is counted
    /// ([`crate::put_payload::slices_len`]). The statistics and the low-pass
    /// size limit both ask this, so a value in shared memory is as large to one
    /// as to the other.
    #[cfg(feature = "alloc")]
    pub fn query_value_payload_len<S: CodecStorage>(extensions: &[QueryExtEntryOwned<S>]) -> usize {
        use sce_forge_runtime::codec::SceList;
        super::find_by_eid(extensions, crate::ext_header::body_eid::QUERY_VALUE).map_or(0, |ext| {
            match &ext.body {
                QueryExtEntryOwnedVariant::CodecZenohQueryValueZbuf(z) => {
                    match (&z.value, &z.slices) {
                        (Some(bytes), _) => {
                            crate::encoding::split_value_body(SceByteBuf::as_slice(bytes))
                                .map_or(0, |(_, payload)| payload.len())
                        }
                        (None, Some(slices)) => {
                            crate::put_payload::slices_len(SceList::as_slice(slices))
                        }
                        (None, None) => 0,
                    }
                }
                _ => 0,
            }
        })
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
#[cfg(all(feature = "codec-request", feature = "alloc"))]
pub use query::query_value_payload_len;
