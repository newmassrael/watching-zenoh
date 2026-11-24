// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! What an open reads its session's config from: the config, which counts the endpoints the
//! session dials and listens on, and then their texts, written once into the rows the open lent
//! for them in the session's arena (`wz_runtime_coop::faces::EndpointTexts`), after which the
//! source is let go of, before anything is dialled or bound.
//!
//! A host hands the open a config that holds the texts (`CoopConfig`, whose lists are
//! `Vec<String>`): the open counts them and writes them into the rows. An ABI that keeps the
//! texts in a form of its own hands a source of its own: its config counts them and holds none
//! (`CoopConfig<Counted>`, a type that has no texts to hold), and it writes them into the rows
//! from where it keeps them, so no text is a value of the heap at the open either. Either way the
//! rows are the one place the session reads an endpoint from once it is open.

use alloc::string::String;
use alloc::vec::Vec;

use wz_runtime_coop::faces::{EndpointRole, EndpointTextRefused, EndpointTexts};

use crate::arena::ArenaRefused;
use crate::engine::{CoopConfig, EndpointRefusal, OpenError, Refusal};

/// What a config holds of a list of endpoints: how many there are, at least.
pub trait EndpointList {
    /// How many endpoints the list names.
    fn count(&self) -> usize;
}

/// The host's form: the texts themselves.
impl EndpointList for Vec<String> {
    fn count(&self) -> usize {
        self.len()
    }
}

/// A list of endpoints of which a config holds only how many there are: the texts are written by
/// the config's source into the rows the open lent ([`OpenSource`]).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Counted(pub usize);

impl EndpointList for Counted {
    fn count(&self) -> usize {
        self.0
    }
}

/// The rows an open lent for its session's endpoints, as a source writes them: the endpoints to
/// dial first, in the order the session dials them, then those to listen on, each text refused as
/// the open refuses a config's.
pub struct EndpointWriter<'a> {
    texts: &'a mut EndpointTexts,
}

impl<'a> EndpointWriter<'a> {
    /// The writer of `texts`, the rows the open lent.
    pub(crate) fn over(texts: &'a mut EndpointTexts) -> Self {
        Self { texts }
    }

    /// Write the text of the next endpoint to dial. [`OpenError::Unreachable`] for a text longer
    /// than a row, `MAX_LOCATOR_LEN` bytes, naming it.
    pub fn dial(&mut self, text: &str) -> Result<(), OpenError> {
        self.write(text, EndpointRole::Dial)
    }

    /// Write the text of the next endpoint to listen on. [`OpenError::Listen`] for a text longer
    /// than a row, naming it.
    pub fn listen(&mut self, text: &str) -> Result<(), OpenError> {
        self.write(text, EndpointRole::Listen)
    }

    /// Write `text` in the next row of `role`: the one body of both.
    #[inline(never)]
    fn write(&mut self, text: &str, role: EndpointRole) -> Result<(), OpenError> {
        self.texts
            .write(role, text)
            .map(drop)
            .map_err(|why| unwritten(text, why, role))
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

/// What an open reads its session's config from, once: the config, which counts the endpoints and
/// holds none of their texts, and what writes the texts, which the open calls once with the rows
/// it lent for them and lets go of before it dials or binds anything.
pub trait OpenSource {
    /// The config, and the writer of its endpoints' texts.
    fn into_parts(
        self,
    ) -> (
        CoopConfig<Counted>,
        impl FnOnce(&mut EndpointWriter<'_>) -> Result<(), OpenError>,
    );
}

/// A host's maker of a config that holds the texts: the open counts them, and writes them into
/// the rows from the config's lists, which go with the writer.
impl<F: FnOnce() -> CoopConfig> OpenSource for F {
    fn into_parts(
        self,
    ) -> (
        CoopConfig<Counted>,
        impl FnOnce(&mut EndpointWriter<'_>) -> Result<(), OpenError>,
    ) {
        let (config, endpoints, listen) = self().counted();
        let write = move |writer: &mut EndpointWriter<'_>| -> Result<(), OpenError> {
            for text in &endpoints {
                writer.dial(text)?;
            }
            for text in &listen {
                writer.listen(text)?;
            }
            Ok(())
        };
        (config, write)
    }
}
