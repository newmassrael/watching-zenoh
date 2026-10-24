//
// Copyright (c) 2023 ZettaScale Technology
//
// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0, or the Apache License, Version 2.0
// which is available at https://www.apache.org/licenses/LICENSE-2.0.
//
// SPDX-License-Identifier: EPL-2.0 OR Apache-2.0
//
// Contributors:
//   ZettaScale Zenoh Team, <zenoh@zettascale.tech>
//
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
// Modified by newmassrael in 2026 for watching-zenoh. Derived from zenoh-protocol 1.10.1, file
// src/core/wire_expr.rs (https://github.com/eclipse-zenoh/zenoh, tag 1.10.1).

//! This module defines the wire representation of Key Expressions.
use alloc::{
    borrow::Cow,
    string::{String, ToString},
};
use core::{convert::TryInto, fmt, sync::atomic::AtomicU16};

use zenoh_keyexpr::{keyexpr, OwnedKeyExpr};
use zenoh_result::{bail, ZResult};

use crate::network::Mapping;

/// A numerical Id mapped to a key expression.
pub type ExprId = u16;
pub type ExprLen = u16;

pub type AtomicExprId = AtomicU16;
pub const EMPTY_EXPR_ID: ExprId = 0;

/// A zenoh **resource** is represented by a pair composed by a **key** and a
/// **value**, such as, ```(car/telemetry/speed, 320)```.  A **resource key**
/// is an arbitrary array of characters, with the exclusion of the symbols
/// ```*```, ```**```, ```?```, ```[``, ``]```, and ```#```,
/// which have special meaning in the context of zenoh.
///
/// A key including any number of the wildcard symbols, ```*``` and ```**```,
/// such as, ```/car/telemetry/*```, is called a **key expression** as it
/// denotes a set of keys. The wildcard character ```*``` expands to an
/// arbitrary string not including zenoh's reserved characters and the ```/```
/// character, while the ```**``` expands to  strings that may also include the
/// ```/``` character.
///
/// Finally, it is worth mentioning that for time and space efficiency matters,
/// zenoh will automatically map key expressions to small integers. The mapping is automatic,
/// but it can be triggered excplicily by with `zenoh::Session::declare_keyexpr()`.
///
//
//  7 6 5 4 3 2 1 0
// +-+-+-+-+-+-+-+-+
// ~      id       — if Expr: id=0
// +-+-+-+-+-+-+-+-+
// ~    suffix     ~ if flag K==1 in Message's header
// +---------------+
//
#[derive(PartialEq, Eq, Hash, Clone, Debug)]
pub struct WireExpr<'a> {
    pub scope: ExprId, // 0 marks global scope
    pub suffix: Cow<'a, str>,
    pub mapping: Mapping,
}

impl<'a> WireExpr<'a> {
    pub fn empty() -> Self {
        WireExpr {
            scope: 0,
            suffix: "".into(),
            mapping: Mapping::Sender,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.scope == 0 && self.suffix.as_ref().is_empty()
    }

    pub fn as_str(&'a self) -> &'a str {
        if self.scope == 0 {
            self.suffix.as_ref()
        } else {
            "<encoded_expr>"
        }
    }

    pub fn try_as_str(&'a self) -> ZResult<&'a str> {
        if self.scope == EMPTY_EXPR_ID {
            Ok(self.suffix.as_ref())
        } else {
            bail!("Scoped key expression")
        }
    }

    pub fn as_id(&'a self) -> ExprId {
        self.scope
    }

    pub fn try_as_id(&'a self) -> ZResult<ExprId> {
        if self.has_suffix() {
            bail!("Suffixed key expression")
        } else {
            Ok(self.scope)
        }
    }

    pub fn as_id_and_suffix(&'a self) -> (ExprId, &'a str) {
        (self.scope, self.suffix.as_ref())
    }

    pub fn has_suffix(&self) -> bool {
        !self.suffix.as_ref().is_empty()
    }

    pub fn to_owned(&self) -> WireExpr<'static> {
        WireExpr {
            scope: self.scope,
            suffix: self.suffix.to_string().into(),
            mapping: self.mapping,
        }
    }

    pub fn with_suffix(mut self, suffix: &'a str) -> Self {
        if self.suffix.is_empty() {
            self.suffix = suffix.into();
        } else {
            self.suffix += suffix;
        }
        self
    }
}

impl TryInto<String> for WireExpr<'_> {
    type Error = zenoh_result::Error;
    fn try_into(self) -> Result<String, Self::Error> {
        if self.scope == 0 {
            Ok(self.suffix.into_owned())
        } else {
            bail!("Scoped key expression")
        }
    }
}

impl TryInto<ExprId> for WireExpr<'_> {
    type Error = zenoh_result::Error;
    fn try_into(self) -> Result<ExprId, Self::Error> {
        self.try_as_id()
    }
}

impl From<ExprId> for WireExpr<'_> {
    fn from(scope: ExprId) -> Self {
        Self {
            scope,
            suffix: "".into(),
            mapping: Mapping::Sender,
        }
    }
}

impl<'a> From<&'a OwnedKeyExpr> for WireExpr<'a> {
    fn from(val: &'a OwnedKeyExpr) -> Self {
        WireExpr {
            scope: 0,
            suffix: Cow::Borrowed(val.as_str()),
            mapping: Mapping::Sender,
        }
    }
}

impl<'a> From<&'a keyexpr> for WireExpr<'a> {
    fn from(val: &'a keyexpr) -> Self {
        WireExpr {
            scope: 0,
            suffix: Cow::Borrowed(val.as_str()),
            mapping: Mapping::Sender,
        }
    }
}

impl fmt::Display for WireExpr<'_> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if self.scope == 0 {
            write!(f, "{}", self.suffix)
        } else {
            write!(f, "{}:{:?}:{}", self.scope, self.mapping, self.suffix)
        }
    }
}

impl<'a> From<&WireExpr<'a>> for WireExpr<'a> {
    #[inline]
    fn from(key: &WireExpr<'a>) -> WireExpr<'a> {
        key.clone()
    }
}

impl<'a> From<&'a str> for WireExpr<'a> {
    #[inline]
    fn from(name: &'a str) -> WireExpr<'a> {
        WireExpr {
            scope: 0,
            suffix: name.into(),
            mapping: Mapping::Sender,
        }
    }
}

impl From<String> for WireExpr<'_> {
    #[inline]
    fn from(name: String) -> WireExpr<'static> {
        WireExpr {
            scope: 0,
            suffix: name.into(),
            mapping: Mapping::Sender,
        }
    }
}

impl<'a> From<&'a String> for WireExpr<'a> {
    #[inline]
    fn from(name: &'a String) -> WireExpr<'a> {
        WireExpr {
            scope: 0,
            suffix: name.into(),
            mapping: Mapping::Sender,
        }
    }
}

impl WireExpr<'_> {
    #[cfg(feature = "test")]
    #[doc(hidden)]
    pub fn rand() -> Self {
        use rand::{
            distributions::{Alphanumeric, DistString},
            Rng,
        };

        const MIN: usize = 2;
        const MAX: usize = 64;

        let mut rng = rand::thread_rng();

        let scope: ExprId = rng.gen_range(0..20);
        let suffix: String = if rng.gen_bool(0.5) {
            let len = rng.gen_range(MIN..MAX);
            Alphanumeric.sample_string(&mut rng, len)
        } else {
            String::new()
        };

        WireExpr {
            scope,
            suffix: suffix.into(),
            mapping: Mapping::DEFAULT,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_unscoped_expression_is_its_suffix_and_a_scoped_one_is_an_id() {
        let plain: WireExpr = "a/b".into();
        assert_eq!(
            (
                plain.as_str(),
                plain.try_as_str().unwrap(),
                plain.has_suffix()
            ),
            ("a/b", "a/b", true)
        );
        assert!(plain.try_as_id().is_err() && !plain.is_empty());
        let scoped: WireExpr = 7u16.into();
        assert_eq!(
            (scoped.as_str(), scoped.as_id(), scoped.try_as_id().unwrap()),
            ("<encoded_expr>", 7, 7)
        );
        assert!(scoped.try_as_str().is_err() && !scoped.is_empty());
        assert!(WireExpr::empty().is_empty());
        assert_eq!(scoped.with_suffix("/x").as_id_and_suffix(), (7, "/x"));
        assert_eq!(WireExpr::from("a").with_suffix("/b").suffix, "a/b");
    }

    #[test]
    fn conversions_and_text() {
        let s: String = WireExpr::from("a/b").try_into().unwrap();
        assert_eq!(s, "a/b");
        assert!(TryInto::<String>::try_into(WireExpr::from(3u16)).is_err());
        assert_eq!(
            TryInto::<ExprId>::try_into(WireExpr::from(3u16)).unwrap(),
            3
        );
        let scoped = WireExpr {
            scope: 4,
            suffix: "s".into(),
            mapping: Mapping::Receiver,
        };
        assert_eq!(scoped.to_string(), "4:Receiver:s");
        assert_eq!(WireExpr::from("a").to_string(), "a");
        let owned: WireExpr<'static> = scoped.to_owned();
        assert_eq!(owned, scoped);
    }
}
