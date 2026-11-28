// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! What an open reads its session's config from: the config, which counts the endpoints the
//! session dials and listens on, and their texts where the ABI keeps them, each read as the ABI's
//! form says and written once into the row the open lent for it in the session's arena
//! (`wz_runtime_coop::faces::EndpointTexts`), before anything is dialled or bound.
//!
//! A host hands the open a config that holds the texts (`CoopConfig`, whose lists are
//! `Vec<String>`): the open counts them and reads them as written ([`OpenSource`]). An ABI that
//! keeps the texts in a form of its own hands an input of its own: its config counts them and
//! holds none (`CoopConfig<Counted>`, a type that has no texts to hold), and its
//! [`OpenEndpoints`] name where it keeps them and how one is read, so no text is a value of the
//! heap at the open either. Either way the one body that writes the rows is the engine's, and the
//! rows are the one place the session reads an endpoint from once it is open.

use alloc::string::String;
use alloc::vec::Vec;

use wz_runtime_coop::faces::{EndpointTextRefused, EndpointTexts};
use wz_session_core::locator_directory::LocatorText;

use crate::arena::ArenaRefused;
use crate::engine::{CoopConfig, EndpointRefusal, OpenError, Refusal};

/// Which of a session's endpoints a text is: one it dials, or one it listens on.
pub use wz_runtime_coop::faces::EndpointRole;

/// What a config holds of a list of endpoints: how many there are, and how many of them are
/// `udp/` ones.
pub trait EndpointList {
    /// How many endpoints the list names.
    fn count(&self) -> usize;

    /// How many of them are `udp/` endpoints: what a session that listens on the list binds a
    /// udp port for, each port reading into the datagram slots its arena lends
    /// (`crate::arena::PlanShape::udp_listens`).
    fn udp(&self) -> usize;
}

/// Whether `endpoint` is a `udp/` one: the scheme the stack opens a udp port for when a session
/// listens on it (`wz_runtime_coop::ip_stack`).
pub fn is_udp(endpoint: &str) -> bool {
    endpoint.starts_with("udp/")
}

/// The host's form: the texts themselves.
impl EndpointList for Vec<String> {
    fn count(&self) -> usize {
        self.len()
    }

    fn udp(&self) -> usize {
        self.iter().filter(|endpoint| is_udp(endpoint)).count()
    }
}

/// A list of endpoints of which a config holds only how many there are and how many of them are
/// `udp/` ones: the texts are where the ABI keeps them, which its [`OpenEndpoints`] name.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Counted {
    /// How many endpoints the list names.
    pub count: usize,
    /// How many of them are `udp/` endpoints.
    pub udp: usize,
}

impl Counted {
    /// The count of `texts`.
    pub fn of<'a>(texts: impl IntoIterator<Item = &'a str>) -> Self {
        texts
            .into_iter()
            .fold(Self::default(), |counted, endpoint| Self {
                count: counted.count.saturating_add(1),
                udp: counted.udp.saturating_add(usize::from(is_udp(endpoint))),
            })
    }
}

impl EndpointList for Counted {
    fn count(&self) -> usize {
        self.count
    }

    fn udp(&self) -> usize {
        self.udp
    }
}

/// How an ABI reads one of its endpoints' texts into the text the session dials or listens on:
/// the answer is `endpoint` itself, or a text the reading made in `kept`, a row of the open's
/// stack. A text the reading refuses is answered as written, for the open to refuse by name.
pub type EndpointReading = for<'t> fn(&'t str, &'t mut LocatorText) -> &'t str;

/// The reading of a text that is the session's as written: a host's.
pub fn as_written<'t>(endpoint: &'t str, _kept: &'t mut LocatorText) -> &'t str {
    endpoint
}

/// The texts of one list of an open's endpoints where the ABI keeps them: those it holds as
/// views, then those it holds as strings, read in that order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EndpointTextList<'a> {
    /// The texts held as views, read first.
    pub views: &'a [&'a str],
    /// The texts held as strings, read after the views.
    pub strings: &'a [String],
}

impl<'a> EndpointTextList<'a> {
    /// A list that names no endpoint.
    pub const NONE: Self = Self {
        views: &[],
        strings: &[],
    };

    /// The texts in the order the open writes them.
    fn texts(self) -> impl Iterator<Item = &'a str> {
        self.views
            .iter()
            .copied()
            .chain(self.strings.iter().map(String::as_str))
    }
}

/// The texts of a session's endpoints where the ABI keeps them, and how one is read: the
/// endpoints to dial, in the order the session dials them, then those to listen on. A value of no
/// type of the ABI's, so the open writes the rows in one body for every ABI.
#[derive(Clone, Copy)]
pub struct OpenEndpoints<'a> {
    /// The endpoints to dial.
    pub dial: EndpointTextList<'a>,
    /// The endpoints to listen on.
    pub listen: EndpointTextList<'a>,
    /// How each text is read into the one the session dials or listens on.
    pub reading: EndpointReading,
}

impl OpenEndpoints<'static> {
    /// A session that dials and listens on nothing, as one that joins a group only.
    pub const NONE: Self = Self {
        dial: EndpointTextList::NONE,
        listen: EndpointTextList::NONE,
        reading: as_written,
    };
}

impl OpenEndpoints<'_> {
    /// Read each text and write it into `rows`, the rows the open lent, every one to dial and
    /// then every one to listen on, or answer the refusal of the first that has no row, by the
    /// role it is written as. Out of line and generic over nothing: the one body of every ABI
    /// and every engine the open is made over.
    #[inline(never)]
    pub(crate) fn write_into(
        &self,
        rows: &mut EndpointTexts<crate::StatePolicy>,
    ) -> Result<(), OpenError> {
        let lists = [
            (EndpointRole::Dial, self.dial),
            (EndpointRole::Listen, self.listen),
        ];
        for (role, list) in lists {
            for endpoint in list.texts() {
                write_text(rows, role, self.reading, endpoint)?;
            }
        }
        Ok(())
    }
}

/// Read `endpoint` as `reading` reads it and write it into the next row of `role` in `rows`, or
/// answer why it has no row (`unwritten`). Out of line: the walks over the two roles' lists,
/// each over the texts held as views and those held as strings, are each a call of this one body,
/// and the reading's row lies in its frame alone.
#[inline(never)]
fn write_text(
    rows: &mut EndpointTexts<crate::StatePolicy>,
    role: EndpointRole,
    reading: EndpointReading,
    endpoint: &str,
) -> Result<(), OpenError> {
    let mut kept = LocatorText::new();
    let text = reading(endpoint, &mut kept);
    rows.write(role, text)
        .map_err(|why| unwritten(text, why, role))?;
    Ok(())
}

/// The open's refusal of the endpoint `text` of `role` that has no row: one longer than a row is
/// refused as an endpoint to listen on or to dial, as its role is; one past the rows the open
/// lent, which its config counted, as an arena that does not hold what the input names; one whose
/// rows the allocator had no room for, where they are taken at the first text, as the memory that
/// had none to give.
fn unwritten(text: &str, why: EndpointTextRefused, role: EndpointRole) -> OpenError {
    match why {
        EndpointTextRefused::TooLong { .. } => {
            let refusal = EndpointRefusal::new(text, Refusal::TextTooLong);
            match role {
                EndpointRole::Listen => OpenError::Listen(refusal),
                EndpointRole::Dial => OpenError::Unreachable(refusal),
            }
        }
        EndpointTextRefused::Full => OpenError::Arena(ArenaRefused::TooLarge),
        EndpointTextRefused::NoMemory { bytes } => {
            OpenError::Arena(ArenaRefused::NoMemory { bytes })
        }
    }
}

/// What an engine is opened from, a value of no type of the ABI's: the config, which counts the
/// endpoints and holds none of their texts, and where the texts are kept. The open moves the
/// config into the session and writes the texts into the rows it lends for them before it dials
/// or binds anything.
pub struct OpenInput<'a> {
    /// The session's config.
    pub config: CoopConfig<Counted>,
    /// Its endpoints' texts, which the open reads and writes into its rows.
    pub endpoints: OpenEndpoints<'a>,
}

/// What a host's open reads its session's config from, once: the input, handed to `open`, whose
/// texts are the source's until `open` returns.
pub trait OpenSource {
    /// `open` of the input: the config, which counts the endpoints, and where their texts are.
    fn open_with<R>(self, open: impl FnOnce(OpenInput<'_>) -> R) -> R;
}

/// A host's maker of a config that holds the texts: the open counts them and reads them as
/// written from the config's lists, which are let go of once the open has written them.
impl<F: FnOnce() -> CoopConfig> OpenSource for F {
    fn open_with<R>(self, open: impl FnOnce(OpenInput<'_>) -> R) -> R {
        let (config, dial, listen) = self().counted();
        open(OpenInput {
            config,
            endpoints: OpenEndpoints {
                dial: EndpointTextList {
                    views: &[],
                    strings: &dial,
                },
                listen: EndpointTextList {
                    views: &[],
                    strings: &listen,
                },
                reading: as_written,
            },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{as_written, EndpointRole, EndpointTextList, OpenEndpoints};
    use crate::arena::ArenaRefused;
    use crate::engine::{EndpointRefusal, OpenError, Refusal};
    #[cfg(not(wz_on_use))]
    use alloc::boxed::Box;
    use alloc::format;
    use alloc::string::String;
    #[cfg(not(wz_on_use))]
    use core::ptr::NonNull;
    use wz_runtime_coop::faces::EndpointTexts;
    #[cfg(not(wz_on_use))]
    use wz_session_core::bounded::Arena;
    use wz_session_core::caps::MAX_LOCATOR_LEN;
    use wz_session_core::locator_directory::LocatorText;

    /// The rows of a session lent `dials` rows to dial and `listens` to listen on, in a test's
    /// own memory, none written.
    #[cfg(not(wz_on_use))]
    fn session_rows(dials: usize, listens: usize) -> EndpointTexts<crate::StatePolicy> {
        const BYTES: usize = 4096;
        #[repr(C, align(16))]
        struct Memory([u8; BYTES]);

        let memory: &'static mut Memory = Box::leak(Box::new(Memory([0; BYTES])));
        // SAFETY: the memory is leaked, so it outlives the arena and every row it lends; it is
        // aligned as an arena's spans start, BYTES long, and used by nothing else.
        let mut arena = unsafe { Arena::over(NonNull::from(memory).cast::<u8>(), BYTES) };
        EndpointTexts::over(
            arena.lend(dials).expect("the memory holds the dial rows"),
            arena
                .lend(listens)
                .expect("the memory holds the listen rows"),
        )
    }

    /// The rows of a session that names `dials` endpoints to dial and `listens` to listen on,
    /// where the tables take their memory on use: counted to them, none taken or written.
    #[cfg(wz_on_use)]
    fn session_rows(dials: usize, listens: usize) -> EndpointTexts<crate::StatePolicy> {
        EndpointTexts::counted(dials, listens)
    }

    /// A reading that keeps a text up to its first `#`, made in `kept`: an ABI's form.
    fn up_to_hash<'t>(endpoint: &'t str, kept: &'t mut LocatorText) -> &'t str {
        let bare = endpoint.split('#').next().unwrap_or(endpoint);
        match wz_session_core::bounded::push_text(kept, bare) {
            Ok(()) => kept.as_str(),
            Err(_) => endpoint,
        }
    }

    /// Endpoints whose texts are `dial` and `listen`, read as written.
    fn written<'a>(dial: &'a [&'a str], listen: &'a [&'a str]) -> OpenEndpoints<'a> {
        OpenEndpoints {
            dial: EndpointTextList {
                views: dial,
                strings: &[],
            },
            listen: EndpointTextList {
                views: listen,
                strings: &[],
            },
            reading: as_written,
        }
    }

    /// The views of a list are written before its strings, every endpoint to dial before any to
    /// listen on, each in the rows of its role. Turned red by the strings written first, or a
    /// list written into the other role's rows.
    #[test]
    fn the_views_then_the_strings_are_written_in_the_rows_of_their_role() {
        let found = [
            String::from("tcp/10.0.0.2:7447"),
            String::from("tcp/10.0.0.3:7447"),
        ];
        let endpoints = OpenEndpoints {
            dial: EndpointTextList {
                views: &["tcp/10.0.0.1:7447"],
                strings: &found,
            },
            listen: EndpointTextList {
                views: &["tcp/0.0.0.0:7448"],
                strings: &[],
            },
            reading: as_written,
        };
        let mut rows = session_rows(3, 1);
        assert_eq!(endpoints.write_into(&mut rows), Ok(()));
        assert_eq!(rows.text(EndpointRole::Dial, 0), "tcp/10.0.0.1:7447");
        assert_eq!(rows.text(EndpointRole::Dial, 1), "tcp/10.0.0.2:7447");
        assert_eq!(rows.text(EndpointRole::Dial, 2), "tcp/10.0.0.3:7447");
        assert_eq!(rows.text(EndpointRole::Listen, 0), "tcp/0.0.0.0:7448");
    }

    /// Each text is written as the input's reading reads it. Turned red by the text written as
    /// the ABI holds it.
    #[test]
    fn each_text_is_written_as_the_reading_reads_it() {
        let endpoints = OpenEndpoints {
            reading: up_to_hash,
            ..written(&["tcp/10.0.0.1:7447#iface=lo"], &[])
        };
        let mut rows = session_rows(1, 0);
        assert_eq!(endpoints.write_into(&mut rows), Ok(()));
        assert_eq!(rows.text(EndpointRole::Dial, 0), "tcp/10.0.0.1:7447");
    }

    /// Endpoints that name none write nothing and are not refused.
    #[test]
    fn no_endpoint_writes_nothing() {
        let mut rows = session_rows(1, 1);
        assert_eq!(OpenEndpoints::NONE.write_into(&mut rows), Ok(()));
        assert_eq!(rows.text(EndpointRole::Dial, 0), "");
        assert_eq!(rows.text(EndpointRole::Listen, 0), "");
    }

    /// A text longer than a row is refused as the role it is written as: a dial's as an endpoint
    /// the session cannot reach, a listen's as one it cannot listen on. Turned red by the roles
    /// swapped in the refusal.
    #[test]
    fn a_text_longer_than_a_row_is_refused_naming_its_role() {
        let long = format!("tcp/127.0.0.1:{}", "7".repeat(MAX_LOCATOR_LEN));
        let dial = [long.as_str()];
        assert_eq!(
            written(&dial, &[]).write_into(&mut session_rows(1, 1)),
            Err(OpenError::Unreachable(EndpointRefusal::new(
                &long,
                Refusal::TextTooLong
            )))
        );
        assert_eq!(
            written(&[], &dial).write_into(&mut session_rows(1, 1)),
            Err(OpenError::Listen(EndpointRefusal::new(
                &long,
                Refusal::TextTooLong
            )))
        );
    }

    /// The first refusal ends the writing: nothing past it is written. Turned red by a text
    /// written past a refused one.
    #[test]
    fn nothing_is_written_past_the_first_refusal() {
        let long = format!("tcp/127.0.0.1:{}", "7".repeat(MAX_LOCATOR_LEN));
        let dial = [long.as_str(), "tcp/10.0.0.1:7447"];
        let mut rows = session_rows(2, 1);
        let refused = written(&dial, &["tcp/0.0.0.0:7447"]).write_into(&mut rows);
        assert!(matches!(refused, Err(OpenError::Unreachable(_))));
        assert_eq!(rows.text(EndpointRole::Dial, 0), "");
        assert_eq!(rows.text(EndpointRole::Listen, 0), "");
    }

    /// A text past the rows the open lent is refused as an arena that does not hold what the
    /// input names. Turned red by a write past the rows, or a refusal of another kind.
    #[test]
    fn a_text_past_the_last_row_is_refused_as_too_large() {
        let mut rows = session_rows(1, 0);
        let refused =
            written(&["tcp/10.0.0.1:7447", "tcp/10.0.0.2:7447"], &[]).write_into(&mut rows);
        assert_eq!(refused, Err(OpenError::Arena(ArenaRefused::TooLarge)));
        assert_eq!(rows.text(EndpointRole::Dial, 0), "tcp/10.0.0.1:7447");
    }
}
