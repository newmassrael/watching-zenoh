// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
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
use core::net::{IpAddr, Ipv4Addr, SocketAddr};

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

    /// Append `n` in decimal, as `{n}` prints it, without going through `core::fmt`: the
    /// formatting machinery (`Formatter::pad`, `pad_integral`, `fmt::write`) is some 1.6 KB of
    /// code that an image with no other formatting caller would not carry.
    fn push_u64(&mut self, n: u64) {
        let mut digits = [0u8; 20];
        self.push_str(decimal(n, &mut digits));
    }

    /// Append `n` in lowercase hexadecimal with no leading zeros, as `{n:x}` prints it, without
    /// going through `core::fmt`.
    fn push_hex_u128(&mut self, n: u128) {
        let mut nibbles = [0u8; 32];
        self.push_str(hexadecimal(n, &mut nibbles));
    }

    /// Append `ip` as `{ip}` prints it, without going through `core::fmt`: dotted decimal for
    /// IPv4, and for IPv6 the RFC 5952 text `Ipv6Addr`'s `Display` writes (lowercase hexadecimal
    /// groups, the first longest run of two or more zero groups as `::`, an IPv4-mapped address
    /// as `::ffff:a.b.c.d`). A link names its ends in this text, and zenoh names them with that
    /// `Display`, so the two read the same.
    fn push_ip(&mut self, ip: IpAddr) {
        match ip {
            IpAddr::V4(v4) => push_ipv4(self, v4),
            IpAddr::V6(v6) => {
                if let Some(v4) = v6.to_ipv4_mapped() {
                    self.push_str("::ffff:");
                    push_ipv4(self, v4);
                    return;
                }
                let groups = v6.segments();
                // The first longest run of zero groups: a later run of the same length keeps the
                // first, as `Display` keeps it.
                let (mut best_at, mut best_len, mut run_at, mut run_len) =
                    (0usize, 0usize, 0usize, 0usize);
                for (at, &group) in groups.iter().enumerate() {
                    if group == 0 {
                        if run_len == 0 {
                            run_at = at;
                        }
                        run_len = run_len.saturating_add(1);
                        if run_len > best_len {
                            (best_at, best_len) = (run_at, run_len);
                        }
                    } else {
                        run_len = 0;
                    }
                }
                if best_len > 1 {
                    push_groups(self, groups.get(..best_at).unwrap_or_default());
                    self.push_str("::");
                    let after = best_at.saturating_add(best_len);
                    push_groups(self, groups.get(after..).unwrap_or_default());
                } else {
                    push_groups(self, &groups);
                }
            }
        }
    }

    /// Append `at` as `{at}` prints it, without going through `core::fmt`: `a.b.c.d:port` for
    /// IPv4, `[ip]:port` for IPv6 and `[ip%scope]:port` when it names a scope.
    fn push_socket_addr(&mut self, at: SocketAddr) {
        match at {
            SocketAddr::V4(v4) => push_ipv4(self, *v4.ip()),
            SocketAddr::V6(v6) => {
                self.push_str("[");
                self.push_ip(IpAddr::V6(*v6.ip()));
                if v6.scope_id() != 0 {
                    self.push_str("%");
                    self.push_u64(u64::from(v6.scope_id()));
                }
                self.push_str("]");
            }
        }
        self.push_str(":");
        self.push_u64(u64::from(at.port()));
    }
}

/// `a.b.c.d`, as [`TextOut::push_ip`] writes an IPv4 address.
fn push_ipv4<W: TextOut + ?Sized>(out: &mut W, ip: Ipv4Addr) {
    for (at, octet) in ip.octets().into_iter().enumerate() {
        if at > 0 {
            out.push_str(".");
        }
        out.push_u64(u64::from(octet));
    }
}

/// IPv6 groups in hexadecimal, colon separated, as [`TextOut::push_ip`] writes either side of a
/// `::`.
fn push_groups<W: TextOut + ?Sized>(out: &mut W, groups: &[u16]) {
    for (at, &group) in groups.iter().enumerate() {
        if at > 0 {
            out.push_str(":");
        }
        out.push_hex_u128(u128::from(group));
    }
}

/// `n` in decimal, as `{n}` prints it, written at the end of `digits`: the text of the digits.
/// One body for every sink, out of line, so what a sink's [`TextOut::push_u64`] carries is a call
/// and a write. A separator is written as text and not as a `char` for the same reason: a `char`
/// is encoded as UTF-8 in each sink that is handed one.
#[inline(never)]
fn decimal(mut n: u64, digits: &mut [u8; 20]) -> &str {
    let mut start = digits.len();
    for slot in digits.iter_mut().rev() {
        // A remainder of ten is below ten, so the byte is an ASCII digit.
        *slot = b'0'.wrapping_add((n % 10) as u8);
        n /= 10;
        start = start.saturating_sub(1);
        if n == 0 {
            break;
        }
    }
    ascii(digits.get(start..))
}

/// `n` in lowercase hexadecimal with no leading zeros, as `{n:x}` prints it, written at the end
/// of `nibbles`: the text of the digits. Out of line, as [`decimal`] is.
#[inline(never)]
fn hexadecimal(mut n: u128, nibbles: &mut [u8; 32]) -> &str {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut start = nibbles.len();
    for slot in nibbles.iter_mut().rev() {
        // A nibble is below sixteen, so it names one of the digits.
        *slot = DIGITS.get((n & 0xf) as usize).copied().unwrap_or(b'0');
        n >>= 4;
        start = start.saturating_sub(1);
        if n == 0 {
            break;
        }
    }
    ascii(nibbles.get(start..))
}

/// The digits a writer above wrote, as text: they are ASCII, so they always are; an empty text
/// stands for what no writer above hands it.
fn ascii(digits: Option<&[u8]>) -> &str {
    core::str::from_utf8(digits.unwrap_or_default()).unwrap_or_default()
}

#[cfg(feature = "alloc")]
impl TextOut for alloc::string::String {}

/// A writer that was handed `&mut W` writes through it as it would through `W`, so
/// a function generic over the sink can pass its own `&mut W` on without caring
/// that the callee takes the sink by value or by reference.
impl<W: TextOut + ?Sized> TextOut for &mut W {}

/// One piece of a console line: text, or a number printed in decimal.
///
/// A console line is handed over as pieces and not as `fmt::Arguments`: the line a lab reads is
/// the same bytes, and the firmware that says it carries no `core::fmt` for it (the machinery is
/// some 3 KB of code that a node with no other formatting caller would not have). A piece is data,
/// so a platform renders it where it likes: [`write_parts`] into a sink, which is how the Zephyr
/// console builds its line and the host builds its own.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogPart<'a> {
    /// Text, written as it is.
    Str(&'a str),
    /// A number, written in decimal as `{n}` writes it.
    U64(u64),
    /// A 32-bit value, written as `{n:#010x}` writes it: `0x` and eight hexadecimal digits, as an
    /// address is printed.
    Hex32(u32),
}

macro_rules! log_part_from_narrower {
    ($($int:ty),*) => {$(
        impl From<$int> for LogPart<'_> {
            fn from(n: $int) -> Self {
                LogPart::U64(u64::from(n))
            }
        }
    )*};
}

log_part_from_narrower!(u8, u16, u32);

impl From<u64> for LogPart<'_> {
    fn from(n: u64) -> Self {
        LogPart::U64(n)
    }
}

impl From<usize> for LogPart<'_> {
    fn from(n: usize) -> Self {
        // A `usize` is at most 64 bits on every target this builds for.
        LogPart::U64(n as u64)
    }
}

impl<'a> From<&'a str> for LogPart<'a> {
    fn from(text: &'a str) -> Self {
        LogPart::Str(text)
    }
}

/// Write `parts` to `out`, in order, as the line they make.
pub fn write_parts<W: TextOut + ?Sized>(out: &mut W, parts: &[LogPart<'_>]) {
    for part in parts {
        match *part {
            LogPart::Str(text) => out.push_str(text),
            LogPart::U64(n) => out.push_u64(n),
            LogPart::Hex32(n) => {
                const DIGITS: &[u8; 16] = b"0123456789abcdef";
                let mut text = *b"0x00000000";
                for (at, digit) in text[2..].iter_mut().enumerate() {
                    *digit = DIGITS[((n >> (28 - 4 * at)) & 0xf) as usize];
                }
                // The bytes are `0x` and ASCII hex digits, so they are valid text.
                if let Ok(text) = core::str::from_utf8(&text) {
                    out.push_str(text);
                }
            }
        }
    }
}

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
    // Out of line: every piece a writer pushes is a call of this, and a body inlined at each
    // would be a copy of it per separator and per number of a document.
    #[inline(never)]
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
    fn the_number_writers_print_what_the_formatter_prints() {
        for n in [0u64, 1, 9, 10, 99, 100, 65_535, 4_294_967_295, u64::MAX] {
            let mut t: FixedText<24> = FixedText::new();
            t.push_u64(n);
            assert_eq!(t.finish(), Ok(std::format!("{n}").as_str()), "decimal {n}");
        }
        for n in [0u128, 1, 0xf, 0x10, 0xabcd, u64::MAX as u128, u128::MAX] {
            let mut t: FixedText<40> = FixedText::new();
            t.push_hex_u128(n);
            assert_eq!(t.finish(), Ok(std::format!("{n:x}").as_str()), "hex {n}");
        }
    }

    /// Every shape `Display` gives an address: each zero-run case of RFC 5952 (none, one group
    /// alone, a run at either end, two runs of which the first or the longer wins), the
    /// unspecified, loopback and IPv4-mapped forms, and a scope.
    #[test]
    fn an_address_is_written_as_the_formatter_writes_it() {
        use core::net::{Ipv6Addr, SocketAddrV6};
        let v6 = [
            Ipv6Addr::UNSPECIFIED,
            Ipv6Addr::LOCALHOST,
            Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1),
            Ipv6Addr::new(0xfe80, 0, 0, 0, 0x0211, 0x22ff, 0xfe33, 0x4455),
            Ipv6Addr::new(0x2001, 0xdb8, 0, 1, 0, 0, 0, 1),
            Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 1, 0, 0, 1),
            Ipv6Addr::new(0x2001, 0xdb8, 1, 0, 1, 1, 1, 1),
            Ipv6Addr::new(1, 0, 0, 0, 0, 0, 0, 0),
            Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0xc000, 0x0280),
            Ipv6Addr::new(0, 0, 0, 0, 0, 0xffff, 0xc000, 0x0280),
            Ipv6Addr::new(
                0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff,
            ),
        ];
        for ip in v6 {
            let mut t: FixedText<64> = FixedText::new();
            t.push_ip(IpAddr::V6(ip));
            assert_eq!(t.finish(), Ok(std::format!("{ip}").as_str()), "{ip:?}");
        }
        let at = [
            SocketAddr::from(([0, 0, 0, 0], 0)),
            SocketAddr::from(([192, 168, 1, 50], 7447)),
            SocketAddr::from(([255, 255, 255, 255], 65535)),
            SocketAddr::from((Ipv6Addr::LOCALHOST, 7447)),
            SocketAddr::V6(SocketAddrV6::new(
                Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1),
                7446,
                0,
                3,
            )),
            SocketAddr::V6(SocketAddrV6::new(
                Ipv6Addr::new(
                    0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff,
                ),
                65535,
                0,
                u32::MAX,
            )),
        ];
        for at in at {
            let mut t: FixedText<64> = FixedText::new();
            t.push_socket_addr(at);
            assert_eq!(t.finish(), Ok(std::format!("{at}").as_str()), "{at:?}");
        }
    }

    #[test]
    fn a_line_of_parts_is_the_line_the_formatter_makes() {
        let mut t: FixedText<64> = FixedText::new();
        write_parts(
            &mut t,
            &[
                LogPart::Str("stack: peak "),
                LogPart::U64(3524),
                LogPart::Str(" of "),
                LogPart::U64(32768),
                LogPart::Str(" bytes"),
            ],
        );
        assert_eq!(
            t.finish(),
            Ok(std::format!("stack: peak {} of {} bytes", 3524, 32768).as_str())
        );
    }

    #[test]
    fn an_address_part_is_what_the_padded_alternate_hex_format_prints() {
        for n in [0u32, 1, 0xf, 0x10, 0x2000_0000, 0xdead_beef, u32::MAX] {
            let mut t: FixedText<16> = FixedText::new();
            write_parts(&mut t, &[LogPart::Hex32(n)]);
            assert_eq!(t.finish(), Ok(std::format!("{n:#010x}").as_str()), "{n}");
        }
    }

    #[test]
    fn the_integers_and_text_convert_into_the_part_they_are() {
        assert_eq!(LogPart::from(7u8), LogPart::U64(7));
        assert_eq!(LogPart::from(65_535u16), LogPart::U64(65_535));
        assert_eq!(LogPart::from(u32::MAX), LogPart::U64(u64::from(u32::MAX)));
        assert_eq!(LogPart::from(u64::MAX), LogPart::U64(u64::MAX));
        assert_eq!(LogPart::from(12usize), LogPart::U64(12));
        assert_eq!(LogPart::from("x"), LogPart::Str("x"));
    }

    #[test]
    fn a_number_that_does_not_fit_is_refused_and_counted_like_any_text() {
        let mut t: FixedText<3> = FixedText::new();
        t.push_u64(12_345);
        assert_eq!(
            t.finish(),
            Err(Overflow {
                needed: 5,
                capacity: 3
            })
        );
    }

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
