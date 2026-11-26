// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! What an open reads its session's config from: the config, which counts the endpoints the
//! session dials and listens on, and their texts, written by the ABI in its own frame and copied
//! once into the rows the open lent for them in the session's arena
//! (`wz_runtime_coop::faces::EndpointTexts`), before anything is dialled or bound.
//!
//! A host hands the open a config that holds the texts (`CoopConfig`, whose lists are
//! `Vec<String>`): the open counts them and writes them ([`OpenSource`]). An ABI that keeps the
//! texts in a form of its own hands an input of its own: its config counts them and holds none
//! (`CoopConfig<Counted>`, a type that has no texts to hold), and it writes them from where it
//! keeps them into its [`OpenEndpoints`], so no text is a value of the heap at the open either.
//! Either way the rows are the one place the session reads an endpoint from once it is open.

use alloc::string::String;
use alloc::vec::Vec;

use wz_runtime_coop::faces::{EndpointTextRefused, EndpointTexts};
use wz_session_core::bounded::push_text;
use wz_session_core::caps;
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
/// `udp/` ones: the texts are written by the ABI into its [`OpenEndpoints`].
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

/// The most endpoints an open's input holds: every row a session may dial and listen on.
pub const OPEN_ENDPOINT_ROWS: usize = caps::MAX_STATIC_CONNECT + caps::MAX_ADMIN_LOCATORS;

/// The texts of a session's endpoints as the ABI wrote them for its open, in its own frame and
/// in the order it wrote them: the endpoints to dial first, in the order the session dials them,
/// then those to listen on. The open copies them into the rows it lends for them
/// ([`OpenInput`]), so no text of the ABI's form is read inside the engine. A text that has no
/// row is not written: the first such is kept as the refusal the open answers once it has lent
/// its rows, by the role it was written as.
pub struct OpenEndpoints {
    texts: [LocatorText; OPEN_ENDPOINT_ROWS],
    roles: [EndpointRole; OPEN_ENDPOINT_ROWS],
    len: usize,
    refused: Option<OpenError>,
}

impl Default for OpenEndpoints {
    fn default() -> Self {
        Self::new()
    }
}

impl OpenEndpoints {
    /// No endpoint written yet.
    pub const fn new() -> Self {
        Self {
            texts: [const { LocatorText::new() }; OPEN_ENDPOINT_ROWS],
            roles: [EndpointRole::Dial; OPEN_ENDPOINT_ROWS],
            len: 0,
            refused: None,
        }
    }

    /// Write the text of the next endpoint to dial; a text longer than a row,
    /// `MAX_LOCATOR_LEN` bytes, is kept as [`OpenError::Unreachable`], naming it.
    pub fn dial(&mut self, text: &str) {
        self.write(text, EndpointRole::Dial);
    }

    /// Write the text of the next endpoint to listen on; a text longer than a row is kept as
    /// [`OpenError::Listen`], naming it.
    pub fn listen(&mut self, text: &str) {
        self.write(text, EndpointRole::Listen);
    }

    /// Write `text` in the next row as an endpoint of `role`: the one body of both. Past the
    /// first refusal nothing is written, so the open answers the first.
    #[inline(never)]
    fn write(&mut self, text: &str, role: EndpointRole) {
        if self.refused.is_some() {
            return;
        }
        let why = match (self.texts.get_mut(self.len), self.roles.get_mut(self.len)) {
            (Some(row), Some(at)) => match push_text(row, text) {
                Ok(()) => {
                    *at = role;
                    self.len += 1;
                    return;
                }
                Err(_) => EndpointTextRefused::TooLong { len: text.len() },
            },
            _ => EndpointTextRefused::Full,
        };
        self.refused = Some(unwritten(text, why, role));
    }

    /// How many endpoints are written.
    pub fn len(&self) -> usize {
        self.len
    }

    /// Whether none is.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// The endpoint written `at`-th, with its role; `None` past the last.
    pub fn row(&self, at: usize) -> Option<(EndpointRole, &str)> {
        if at >= self.len {
            return None;
        }
        Some((*self.roles.get(at)?, self.texts.get(at)?.as_str()))
    }

    /// The refusal of the first text that has no row, `None` when every one has.
    pub fn refused(&self) -> Option<&OpenError> {
        self.refused.as_ref()
    }

    /// Copy the texts into `rows`, the rows the open lent, in the order they were written, or
    /// answer the refusal of the first that had none, handed over rather than copied. Every text
    /// written fits a row, as the one that did not was refused when it was written, so a row
    /// refused here is one past the rows the open lent, which its config counted. Out of line:
    /// one copy body for every engine the open is made over.
    #[inline(never)]
    pub(crate) fn copy_into(&mut self, rows: &mut EndpointTexts) -> Result<(), OpenError> {
        if let Some(refused) = self.refused.take() {
            return Err(refused);
        }
        for (text, role) in self.texts.iter().zip(&self.roles).take(self.len) {
            rows.write(*role, text.as_str())
                .map_err(|_| OpenError::Arena(ArenaRefused::TooLarge))?;
        }
        Ok(())
    }
}

/// The open's refusal of the endpoint `text` of `role` that has no row: one longer than a row is
/// refused as an endpoint to listen on or to dial, as its role is; one past the rows the open
/// lent, which its config counted, as an arena that does not hold what the source wrote.
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
    }
}

/// What an engine is opened from, a value of no type of the ABI's: the config, which counts the
/// endpoints and holds none of their texts, and the texts, which the ABI wrote in its own frame.
/// The open moves the config into the session and copies the texts into the rows it lends for
/// them before it dials or binds anything.
pub struct OpenInput<'a> {
    /// The session's config.
    pub config: CoopConfig<Counted>,
    /// Its endpoints' texts, which the open copies, and whose refusal it hands on.
    pub endpoints: &'a mut OpenEndpoints,
}

/// What a host's open reads its session's config from, once: the config, which counts the
/// endpoints and holds none of their texts, made with the texts written into `endpoints`.
pub trait OpenSource {
    /// The config, its endpoints' texts written into `endpoints`.
    fn into_input(self, endpoints: &mut OpenEndpoints) -> CoopConfig<Counted>;
}

/// A host's maker of a config that holds the texts: the open counts them, and writes them from
/// the config's lists, which are let go of here.
impl<F: FnOnce() -> CoopConfig> OpenSource for F {
    fn into_input(self, endpoints: &mut OpenEndpoints) -> CoopConfig<Counted> {
        let (config, dial, listen) = self().counted();
        for text in &dial {
            endpoints.dial(text);
        }
        for text in &listen {
            endpoints.listen(text);
        }
        config
    }
}

#[cfg(test)]
mod tests {
    use super::EndpointRole;
    use super::{OpenEndpoints, OPEN_ENDPOINT_ROWS};
    use crate::arena::ArenaRefused;
    use crate::engine::{EndpointRefusal, OpenError, Refusal};
    use alloc::format;
    use wz_session_core::caps::MAX_LOCATOR_LEN;

    /// The endpoints read back in the order they were written, each with the role it was written
    /// as. Turned red by a write that keeps a role of its own or reorders the rows.
    #[test]
    fn the_endpoints_read_in_the_order_and_role_they_were_written() {
        let mut endpoints = OpenEndpoints::new();
        endpoints.dial("tcp/10.0.0.1:7447");
        endpoints.listen("tcp/0.0.0.0:7447");
        assert_eq!(endpoints.len(), 2);
        assert_eq!(
            endpoints.row(0),
            Some((EndpointRole::Dial, "tcp/10.0.0.1:7447"))
        );
        assert_eq!(
            endpoints.row(1),
            Some((EndpointRole::Listen, "tcp/0.0.0.0:7447"))
        );
        assert_eq!(endpoints.row(2), None, "nothing past the last");
        assert!(endpoints.refused().is_none());
    }

    /// A text longer than a row is refused as the role it was written as: a dial's as an endpoint
    /// the session cannot reach, a listen's as one it cannot listen on. Turned red by the roles
    /// swapped in the refusal.
    #[test]
    fn a_text_longer_than_a_row_is_refused_naming_its_role() {
        let long = format!("tcp/127.0.0.1:{}", "7".repeat(MAX_LOCATOR_LEN));
        let mut dialled = OpenEndpoints::new();
        dialled.dial(&long);
        assert_eq!(
            dialled.refused(),
            Some(&OpenError::Unreachable(EndpointRefusal::new(
                &long,
                Refusal::TextTooLong
            )))
        );
        assert!(dialled.is_empty(), "a refused text takes no row");
        let mut listened = OpenEndpoints::new();
        listened.listen(&long);
        assert_eq!(
            listened.refused(),
            Some(&OpenError::Listen(EndpointRefusal::new(
                &long,
                Refusal::TextTooLong
            )))
        );
    }

    /// The first refusal is the one kept: what follows it is not written. Turned red by a later
    /// refusal replacing the first, or a row written past it.
    #[test]
    fn the_first_refusal_is_kept_and_nothing_is_written_past_it() {
        let long = format!("tcp/127.0.0.1:{}", "7".repeat(MAX_LOCATOR_LEN));
        let mut endpoints = OpenEndpoints::new();
        endpoints.listen(&long);
        endpoints.dial(&long);
        endpoints.dial("tcp/10.0.0.1:7447");
        assert!(matches!(endpoints.refused(), Some(OpenError::Listen(_))));
        assert!(endpoints.is_empty());
    }

    /// A text past the last row is refused as an arena that does not hold what was written.
    /// Turned red by a write past the rows, or a refusal of another kind.
    #[test]
    fn a_text_past_the_last_row_is_refused_as_too_large() {
        let mut endpoints = OpenEndpoints::new();
        for _ in 0..OPEN_ENDPOINT_ROWS {
            endpoints.dial("tcp/10.0.0.1:7447");
        }
        assert!(endpoints.refused().is_none());
        endpoints.listen("tcp/0.0.0.0:7447");
        assert_eq!(endpoints.len(), OPEN_ENDPOINT_ROWS);
        assert_eq!(
            endpoints.refused(),
            Some(&OpenError::Arena(ArenaRefused::TooLarge))
        );
    }
}
