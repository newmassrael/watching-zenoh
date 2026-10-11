// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Where hand-written text goes: any sink that takes `&str` and `char`, and a
//! fixed one that refuses what does not fit (fixed-memory step S9b).
//!
//! The admin space writes JSON by hand (no `serde_json`, so the session kernel
//! stays `no_std`). Until this module every one of those writers took a
//! `&mut String`, so a node that wanted its admin reply without an allocator
//! could not have it: the body, each reply key, the config document and the
//! surface manifest were all `String`s that grew on the heap. [`crate::text_out::TextOut`] is the
//! one seam they now write through, and it has two sinks:
//!
//! - `String` (with `alloc`): grows, never refuses, is what the AP has always
//!   used, and writes the same bytes it always wrote;
//! - [`crate::text_out::FixedText`]: `N` bytes inline, no allocation on any build, and a write that
//!   does not fit is NOT dropped and NOT cut short silently. It is recorded: the
//!   sink stops taking text (so what it holds is a prefix, never a prefix with a
//!   hole), keeps COUNTING the bytes the writer asked for, and
//!   [`crate::text_out::FixedText::finish`] answers `Err(Overflow { needed, capacity })`, which is
//!   what the caller refuses and counts.
//!
//! The writers stay infallible in signature ([`crate::text_out::TextOut::push_str`] returns
//! nothing), because a document of three hundred `push_str` calls with a `?` on
//! each would hide its shape, and because a single check at the end is both
//! cheaper and impossible to forget: [`crate::text_out::FixedText::finish`] is the only way to
//! take the text out as a result, and it cannot answer `Ok` after a refused
//! write. `core::fmt::Write` is the supertrait, so `write!` works on both sinks
//! and a refusal surfaces there as `fmt::Error` too.

use core::fmt;

/// A sink for hand-written text. See the module documentation.
///
/// `fmt::Write` is the supertrait so a writer can `write!` into any sink and so
/// the trait is object safe: a `&mut dyn TextOut` is how a writer that does not
/// care which sink it has takes one.
pub trait TextOut: fmt::Write {
    /// Append `s`. A sink that cannot take it records the refusal itself
    /// ([`FixedText::overflow`]); the call never panics and never allocates on a
    /// fixed sink.
    fn push_str(&mut self, s: &str) {
        let _ = self.write_str(s);
    }

    /// Append one character, as [`Self::push_str`] appends a string.
    fn push(&mut self, c: char) {
        let _ = self.write_char(c);
    }
}

#[cfg(feature = "alloc")]
impl TextOut for alloc::string::String {}

/// A writer that was handed `&mut W` writes through it as it would through `W`, so
/// a function generic over the sink can pass its own `&mut W` on without caring
/// that the callee takes the sink by value or by reference.
impl<W: TextOut + ?Sized> TextOut for &mut W {}

/// The bytes a fixed sink was asked to hold and what it can hold.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Overflow {
    /// Every byte the writer asked the sink for, the ones that did not fit
    /// included: the capacity the document would have needed.
    pub needed: usize,
    /// The sink's capacity, `N`.
    pub capacity: usize,
}

impl fmt::Display for Overflow {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "wrote {} bytes into a buffer of {}",
            self.needed, self.capacity
        )
    }
}

/// `N` bytes of text, inline, that refuse what does not fit. See the module
/// documentation for the contract; the short form is: a prefix is never
/// delivered as if it were the whole, and nothing is ever allocated.
///
/// Built on `heapless::String`, the repo's fixed string primitive, and not on
/// [`crate::bounded::BoundedString`], whose bound is only advisory on the
/// growable backing: a buffer a caller chose for its bound must hold that bound
/// on every build.
#[derive(Debug)]
pub struct FixedText<const N: usize> {
    text: heapless::String<N>,
    /// Bytes asked for since the last [`Self::clear`], whether they fit or not.
    demanded: usize,
}

impl<const N: usize> FixedText<N> {
    /// An empty buffer. `const`, so one can sit in a `static`.
    pub const fn new() -> Self {
        Self {
            text: heapless::String::new(),
            demanded: 0,
        }
    }

    /// Empty the buffer and forget the refusal, ready for the next document.
    pub fn clear(&mut self) {
        self.text.clear();
        self.demanded = 0;
    }

    /// The capacity, `N`.
    pub const fn capacity(&self) -> usize {
        N
    }

    /// How many bytes were asked for since the last [`Self::clear`].
    pub fn demanded(&self) -> usize {
        self.demanded
    }

    /// Whether a write was refused since the last [`Self::clear`].
    pub fn overflowed(&self) -> bool {
        self.demanded > N
    }

    /// The refusal, if there was one.
    pub fn overflow(&self) -> Option<Overflow> {
        self.overflowed().then_some(Overflow {
            needed: self.demanded,
            capacity: N,
        })
    }

    /// The text taken out as a result: `Ok` only if nothing was refused.
    ///
    /// This is the way to read a document that was written into the buffer. It
    /// cannot answer `Ok` with a cut-short text.
    pub fn finish(&self) -> Result<&str, Overflow> {
        match self.overflow() {
            None => Ok(self.text.as_str()),
            Some(overflow) => Err(overflow),
        }
    }

    /// What the buffer holds, WITHOUT asking whether something was refused. After
    /// a refusal it is a prefix of the document, which is why this is not the way
    /// to take a reply out: use [`Self::finish`].
    pub fn prefix(&self) -> &str {
        self.text.as_str()
    }
}

impl<const N: usize> Default for FixedText<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> fmt::Write for FixedText<N> {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        let wanted = self.demanded.saturating_add(s.len());
        if wanted > N {
            // Counted, and from here on nothing is written, so the text stays a
            // prefix and `needed` stays the size the whole document needs.
            self.demanded = wanted;
            return Err(fmt::Error);
        }
        // `wanted <= N` and nothing was refused before, so this always fits.
        let _ = self.text.push_str(s);
        self.demanded = wanted;
        Ok(())
    }
}

impl<const N: usize> TextOut for FixedText<N> {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_document_that_fits_is_the_text_and_a_document_of_exactly_n_bytes_fits() {
        let mut t: FixedText<8> = FixedText::new();
        t.push_str("abcd");
        t.push('e');
        t.push_str("fgh");
        assert_eq!(t.finish(), Ok("abcdefgh"));
        assert_eq!(t.demanded(), 8);
        assert!(!t.overflowed());
    }

    #[test]
    fn one_byte_more_is_refused_and_the_size_it_needs_is_reported() {
        let mut t: FixedText<8> = FixedText::new();
        t.push_str("abcdefgh");
        t.push('i');
        assert_eq!(
            t.finish(),
            Err(Overflow {
                needed: 9,
                capacity: 8
            })
        );
        // The text is the prefix that fit, never a prefix with a hole in it.
        assert_eq!(t.prefix(), "abcdefgh");
    }

    #[test]
    fn nothing_is_written_after_a_refusal_so_a_short_write_cannot_fill_the_gap() {
        let mut t: FixedText<6> = FixedText::new();
        t.push_str("abcd");
        t.push_str("efgh"); // refused: 8 > 6
        t.push('x'); // would fit in the two bytes left, and must not
        assert_eq!(t.prefix(), "abcd");
        assert_eq!(
            t.overflow(),
            Some(Overflow {
                needed: 9,
                capacity: 6
            })
        );
    }

    #[test]
    fn clear_makes_the_buffer_ready_for_the_next_document() {
        let mut t: FixedText<4> = FixedText::new();
        t.push_str("abcde");
        assert!(t.overflowed());
        t.clear();
        t.push_str("wxyz");
        assert_eq!(t.finish(), Ok("wxyz"));
    }

    #[test]
    fn write_macro_reaches_the_sink_and_a_refusal_is_a_fmt_error() {
        use core::fmt::Write as _;
        let mut t: FixedText<4> = FixedText::new();
        assert!(write!(t, "{}", 123).is_ok());
        assert!(write!(t, "{}", 45).is_err());
        assert_eq!(t.overflow().map(|o| o.needed), Some(5));
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn a_string_takes_any_amount_and_writes_the_same_bytes() {
        fn document(out: &mut dyn TextOut) {
            out.push_str("{\"k\":");
            out.push('1');
            out.push('}');
        }
        let mut s = alloc::string::String::new();
        document(&mut s);
        let mut f: FixedText<16> = FixedText::new();
        document(&mut f);
        assert_eq!(f.finish(), Ok(s.as_str()));
    }
}
