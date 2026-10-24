// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The ABI stamp an artifact carries: its family, its revision and its layout arm, as one ELF
//! note a reader finds without running the artifact.
//!
//! # Why a note, and why this form
//!
//! A tool that describes an artifact for a device unlike its own host (`docs/target-build-contract.md`)
//! cannot call a door of it: an artifact compiled for another operating system does not run here.
//! The number a consumer needs has to be in the bytes. An ELF note is the form every ELF reader
//! already has a place for, it is not a symbol (so stripping a binary does not remove it, and an
//! executable does not have to export it), and it is a section of its own that a reader finds by
//! name.
//!
//! # What the note holds
//!
//! One JSON object, written once by [`stamp!`], in a fixed key order:
//!
//! ```text
//! {"schema":1,"family":"capi-pico","revision":1,"layout":{"multi_thread":true,"unstable_api":true}}
//! ```
//!
//! `schema` is the version of THIS format. `family` names which contract the number belongs to
//! (the pico C ABI, the zenoh-c drop-in, the session-node executable's argument and document
//! surface); a number means something only inside its family. `revision` is the family's one
//! integer. `layout` is the set of switches that move the C types a program allocates, so a
//! program is told when it links the arm it did not compile against. A family with no such switch
//! writes an empty object.
//!
//! The words (the family and each layout key) are ASCII `[a-z0-9_-]`: the writer does no
//! escaping, and a word outside that set is a compile error, not a stamp a reader cannot parse.
//!
//! # The facts note
//!
//! A second note, written by [`facts!`], carries what a build contains that a reader cannot learn by
//! running it: named lists of words, in the same alphabet. The executable puts the driver roles it
//! plays there, computed at compile time from its own role table, so a tool that describes it for
//! another operating system reads the list from the file and keeps no second copy of the table.
//!
//! ```text
//! {"schema":1,"lists":{"driver_roles":["publish","subscribe"]}}
//! ```
//!
//! # Where it exists
//!
//! The note is emitted on the ELF targets of `wz_cdylib_build::SONAME_TARGET_OS`. Elsewhere
//! [`stamp!`] expands to nothing, and an artifact for such a target carries no stamp: the entry
//! of `docs/target-build-contract.md` does not target one.

#![no_std]

/// The version of the stamp's own format, written as `schema`.
pub const SCHEMA: u32 = 1;

/// The owner name of the note, as ELF writes it: NUL included in `namesz`.
pub const NOTE_OWNER: &str = "wz";

/// The note type of an ABI stamp. A reader that finds another type under the owner `wz` skips it.
pub const NOTE_TYPE_ABI_STAMP: u32 = 1;

/// The section the note lives in.
pub const NOTE_SECTION: &str = ".note.wz.abi";

/// The note type of a facts note: what this build contains that a reader cannot learn by running
/// it, as named lists of words (the driver roles an executable plays).
pub const NOTE_TYPE_FACTS: u32 = 2;

/// The section the facts note lives in.
pub const FACTS_SECTION: &str = ".note.wz.facts";

/// What a word may be made of. The writer does no escaping, so this is what keeps the object
/// parseable.
const fn is_word_byte(b: u8) -> bool {
    matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'_' | b'-')
}

const fn check_word(word: &str) {
    let bytes = word.as_bytes();
    assert!(!bytes.is_empty(), "an ABI stamp word is empty");
    let mut i = 0;
    while i < bytes.len() {
        assert!(
            is_word_byte(bytes[i]),
            "an ABI stamp word is outside [a-z0-9_-]"
        );
        i += 1;
    }
}

/// Write `bytes` at `pos` into `buf`, ignoring what falls outside it, and return the buffer and
/// the position after. Run with an empty buffer, it counts.
const fn put<const N: usize>(mut buf: [u8; N], pos: usize, bytes: &[u8]) -> ([u8; N], usize) {
    let mut i = 0;
    while i < bytes.len() {
        if pos + i < N {
            buf[pos + i] = bytes[i];
        }
        i += 1;
    }
    (buf, pos + bytes.len())
}

/// Write `value` in decimal.
const fn put_u32<const N: usize>(buf: [u8; N], pos: usize, value: u32) -> ([u8; N], usize) {
    let mut digits = [0u8; 10];
    let mut count = 0;
    let mut rest = value;
    loop {
        digits[count] = b'0' + (rest % 10) as u8;
        count += 1;
        rest /= 10;
        if rest == 0 {
            break;
        }
    }
    let mut out = [0u8; 10];
    let mut i = 0;
    while i < count {
        out[i] = digits[count - 1 - i];
        i += 1;
    }
    let (head, _) = out.split_at(count);
    put(buf, pos, head)
}

/// The JSON object, written into `buf` and counted: the returned position is its length whatever
/// the buffer's own.
const fn fill<const N: usize>(
    buf: [u8; N],
    family: &str,
    revision: u32,
    layout: &[(&str, bool)],
) -> ([u8; N], usize) {
    check_word(family);
    let (buf, pos) = put(buf, 0, b"{\"schema\":");
    let (buf, pos) = put_u32(buf, pos, SCHEMA);
    let (buf, pos) = put(buf, pos, b",\"family\":\"");
    let (buf, pos) = put(buf, pos, family.as_bytes());
    let (buf, pos) = put(buf, pos, b"\",\"revision\":");
    let (buf, pos) = put_u32(buf, pos, revision);
    let (mut buf, mut pos) = put(buf, pos, b",\"layout\":{");
    let mut i = 0;
    while i < layout.len() {
        check_word(layout[i].0);
        if i > 0 {
            (buf, pos) = put(buf, pos, b",");
        }
        (buf, pos) = put(buf, pos, b"\"");
        (buf, pos) = put(buf, pos, layout[i].0.as_bytes());
        (buf, pos) = put(buf, pos, b"\":");
        let value: &[u8] = if layout[i].1 { b"true" } else { b"false" };
        (buf, pos) = put(buf, pos, value);
        i += 1;
    }
    put(buf, pos, b"}}")
}

/// The length of the JSON object for these inputs, without the closing NUL.
pub const fn json_len(family: &str, revision: u32, layout: &[(&str, bool)]) -> usize {
    fill::<0>([], family, revision, layout).1
}

/// The facts object, written into `buf` and counted like [`fill`]: named lists of words, each
/// word and each name held to the same alphabet as the stamp's.
const fn fill_facts<const N: usize>(buf: [u8; N], lists: &[(&str, &[&str])]) -> ([u8; N], usize) {
    let (buf, pos) = put(buf, 0, b"{\"schema\":");
    let (buf, pos) = put_u32(buf, pos, SCHEMA);
    let (mut buf, mut pos) = put(buf, pos, b",\"lists\":{");
    let mut i = 0;
    while i < lists.len() {
        check_word(lists[i].0);
        if i > 0 {
            (buf, pos) = put(buf, pos, b",");
        }
        (buf, pos) = put(buf, pos, b"\"");
        (buf, pos) = put(buf, pos, lists[i].0.as_bytes());
        (buf, pos) = put(buf, pos, b"\":[");
        let words = lists[i].1;
        let mut j = 0;
        while j < words.len() {
            check_word(words[j]);
            if j > 0 {
                (buf, pos) = put(buf, pos, b",");
            }
            (buf, pos) = put(buf, pos, b"\"");
            (buf, pos) = put(buf, pos, words[j].as_bytes());
            (buf, pos) = put(buf, pos, b"\"");
            j += 1;
        }
        (buf, pos) = put(buf, pos, b"]");
        i += 1;
    }
    put(buf, pos, b"}}")
}

/// The length of the facts object for these lists, without the closing NUL.
pub const fn facts_len(lists: &[(&str, &[&str])]) -> usize {
    fill_facts::<0>([], lists).1
}

/// The size of the note's descriptor for a JSON object of `json_len` bytes: the object, one NUL,
/// and the padding that brings it to a multiple of four, which an ELF note requires.
pub const fn desc_size(json_len: usize) -> usize {
    (json_len + 1).div_ceil(4) * 4
}

/// One ELF note, laid out as the format has it: three words, the owner padded to four bytes and
/// the descriptor padded to four.
///
/// `D` is the padded descriptor size; [`desc_size`] computes it from the object's length, and
/// [`stamp!`] is the one place that does.
#[repr(C, align(4))]
pub struct Note<const D: usize> {
    namesz: u32,
    descsz: u32,
    kind: u32,
    name: [u8; 4],
    desc: [u8; D],
}

impl<const D: usize> Note<D> {
    /// The note for these inputs. `D` must be [`desc_size`] of the object's length, which a
    /// const assertion holds.
    pub const fn new(family: &str, revision: u32, layout: &[(&str, bool)]) -> Self {
        let len = json_len(family, revision, layout);
        assert!(
            D == desc_size(len),
            "a note's descriptor size is not the padded object size"
        );
        let (desc, _) = fill::<D>([0u8; D], family, revision, layout);
        Note {
            namesz: (NOTE_OWNER.len() + 1) as u32,
            descsz: (len + 1) as u32,
            kind: NOTE_TYPE_ABI_STAMP,
            name: [b'w', b'z', 0, 0],
            desc,
        }
    }

    /// The facts note for these lists, which a const assertion holds `D` to the size of.
    pub const fn new_facts(lists: &[(&str, &[&str])]) -> Self {
        let len = facts_len(lists);
        assert!(
            D == desc_size(len),
            "a note's descriptor size is not the padded object size"
        );
        let (desc, _) = fill_facts::<D>([0u8; D], lists);
        Note {
            namesz: (NOTE_OWNER.len() + 1) as u32,
            descsz: (len + 1) as u32,
            kind: NOTE_TYPE_FACTS,
            name: [b'w', b'z', 0, 0],
            desc,
        }
    }

    /// The JSON object the note carries.
    pub fn json(&self) -> &str {
        let len = self.descsz as usize - 1;
        core::str::from_utf8(&self.desc[..len]).unwrap_or("")
    }
}

/// Put an ABI stamp in this artifact.
///
/// ```ignore
/// wz_abi_stamp::stamp!(
///     family = "capi-pico",
///     revision = 1,
///     layout = [
///         ("multi_thread", cfg!(feature = "multi-thread")),
///         ("unstable_api", cfg!(feature = "unstable-api")),
///     ],
/// );
/// ```
///
/// Call it once, at module level, in the crate that is the artifact (the cdylib or the binary),
/// and not in a dependency: a note in a library the artifact links is kept or dropped by the
/// linker as that library is. `revision` and each layout value are constant expressions.
#[macro_export]
macro_rules! stamp {
    (
        family = $family:expr,
        revision = $revision:expr,
        layout = [ $( ($key:expr, $value:expr) ),* $(,)? ] $(,)?
    ) => {
        $crate::__on_elf! {
            const _: () = {
                const LAYOUT: &[(&str, bool)] = &[ $( ($key, $value) ),* ];
                const LEN: usize = $crate::json_len($family, $revision, LAYOUT);
                #[used]
                #[link_section = ".note.wz.abi"]
                static ABI_STAMP: $crate::Note<{ $crate::desc_size(LEN) }> =
                    $crate::Note::new($family, $revision, LAYOUT);
            };
        }
    };
}

/// Put a facts note in this artifact: named lists of words that say what this build contains.
///
/// ```ignore
/// wz_abi_stamp::facts!(lists = [("driver_roles", &["publish", "subscribe"])]);
/// ```
///
/// Each list is a constant expression of type `&[&str]`, so a build can compute it from its own
/// tables (the roles whose feature is on). Call it once, in the artifact, like [`stamp!`].
#[macro_export]
macro_rules! facts {
    ( lists = [ $( ($name:expr, $words:expr) ),* $(,)? ] $(,)? ) => {
        $crate::__on_elf! {
            const _: () = {
                const LISTS: &[(&str, &[&str])] = &[ $( ($name, $words) ),* ];
                const LEN: usize = $crate::facts_len(LISTS);
                #[used]
                #[link_section = ".note.wz.facts"]
                static BUILD_FACTS: $crate::Note<{ $crate::desc_size(LEN) }> =
                    $crate::Note::new_facts(LISTS);
            };
        }
    };
}

/// The items it wraps, on the ELF targets only: the one place that list is written.
#[doc(hidden)]
#[macro_export]
macro_rules! __on_elf {
    ( $( $item:item )* ) => {
        $(
            #[cfg(any(
                target_os = "android",
                target_os = "dragonfly",
                target_os = "freebsd",
                target_os = "fuchsia",
                target_os = "haiku",
                target_os = "illumos",
                target_os = "linux",
                target_os = "netbsd",
                target_os = "nto",
                target_os = "openbsd",
                target_os = "redox",
                target_os = "solaris",
            ))]
            $item
        )*
    };
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;

    #[test]
    fn the_object_is_the_documented_one() {
        const LAYOUT: &[(&str, bool)] = &[("multi_thread", true), ("local_subscriber", false)];
        const LEN: usize = json_len("capi-pico", 12, LAYOUT);
        let note = Note::<{ desc_size(LEN) }>::new("capi-pico", 12, LAYOUT);
        assert_eq!(
            note.json(),
            r#"{"schema":1,"family":"capi-pico","revision":12,"layout":{"multi_thread":true,"local_subscriber":false}}"#
        );
    }

    #[test]
    fn a_family_with_no_layout_writes_an_empty_object() {
        const LEN: usize = json_len("ap-demo-surface", 1, &[]);
        let note = Note::<{ desc_size(LEN) }>::new("ap-demo-surface", 1, &[]);
        assert_eq!(
            note.json(),
            r#"{"schema":1,"family":"ap-demo-surface","revision":1,"layout":{}}"#
        );
    }

    #[test]
    fn the_descriptor_is_padded_to_four_and_the_sizes_say_so() {
        assert_eq!(desc_size(0), 4);
        assert_eq!(desc_size(3), 4);
        assert_eq!(desc_size(4), 8);
        const LEN: usize = json_len("capi-c", 6, &[]);
        let note = Note::<{ desc_size(LEN) }>::new("capi-c", 6, &[]);
        assert_eq!(note.descsz as usize, LEN + 1);
        assert_eq!(note.namesz, 3);
        assert_eq!(note.kind, NOTE_TYPE_ABI_STAMP);
        assert_eq!(core::mem::size_of_val(&note) % 4, 0);
        assert_eq!(core::mem::align_of_val(&note), 4);
    }

    #[test]
    fn the_largest_revision_renders_in_ten_digits() {
        const LEN: usize = json_len("capi-c", u32::MAX, &[]);
        let note = Note::<{ desc_size(LEN) }>::new("capi-c", u32::MAX, &[]);
        assert!(note.json().contains("\"revision\":4294967295,"));
        const ZERO: usize = json_len("capi-c", 0, &[]);
        let zero = Note::<{ desc_size(ZERO) }>::new("capi-c", 0, &[]);
        assert!(zero.json().contains("\"revision\":0,"));
    }

    #[test]
    fn the_macro_leaves_a_note_in_the_test_binary() {
        stamp!(
            family = "stamp-test",
            revision = 7,
            layout = [("flag", true)]
        );
    }

    #[test]
    fn a_facts_note_lists_words_by_name() {
        const LISTS: &[(&str, &[&str])] =
            &[("driver_roles", &["publish", "subscribe"]), ("empty", &[])];
        const LEN: usize = facts_len(LISTS);
        let note = Note::<{ desc_size(LEN) }>::new_facts(LISTS);
        assert_eq!(
            note.json(),
            r#"{"schema":1,"lists":{"driver_roles":["publish","subscribe"],"empty":[]}}"#
        );
        assert_eq!(note.kind, NOTE_TYPE_FACTS);
        assert_eq!(note.descsz as usize, LEN + 1);
    }

    #[test]
    fn a_facts_note_with_no_list_writes_an_empty_object() {
        const LEN: usize = facts_len(&[]);
        let note = Note::<{ desc_size(LEN) }>::new_facts(&[]);
        assert_eq!(note.json(), r#"{"schema":1,"lists":{}}"#);
    }

    #[test]
    fn the_facts_macro_leaves_a_note_in_the_test_binary() {
        facts!(lists = [("roles", &["a", "b-c"])]);
    }
}
