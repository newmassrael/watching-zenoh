// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! A string that is either borrowed or owned, which an empty owned string is not.

use alloc::{borrow::ToOwned, string::String};
use core::fmt::{Debug, Display, Formatter};

/// What a [`CowStr`] holds. An owned string keeps its `String` as it is: upstream keeps a boxed
/// `str` and the capacity of the string it was made from, to give the `String` back from `+`, but
/// boxing a string with spare capacity shrinks its allocation, so the capacity it then claims is
/// not the allocation's and giving the `String` back is undefined behaviour.
enum CowStrInner<'a> {
    Borrowed(&'a str),
    Owned(String),
}

pub struct CowStr<'a>(CowStrInner<'a>);

impl<'a> CowStr<'a> {
    pub(crate) const fn borrowed(s: &'a str) -> Self {
        Self(CowStrInner::Borrowed(s))
    }
    pub fn as_str(&self) -> &str {
        self
    }
}

impl<'a> From<alloc::borrow::Cow<'a, str>> for CowStr<'a> {
    fn from(value: alloc::borrow::Cow<'a, str>) -> Self {
        match value {
            alloc::borrow::Cow::Borrowed(s) => CowStr::borrowed(s),
            alloc::borrow::Cow::Owned(s) => s.into(),
        }
    }
}

impl<'a> From<&'a str> for CowStr<'a> {
    fn from(value: &'a str) -> Self {
        CowStr::borrowed(value)
    }
}

impl From<String> for CowStr<'_> {
    fn from(s: String) -> Self {
        // An empty string holds nothing worth owning.
        if s.is_empty() {
            CowStr::borrowed("")
        } else {
            Self(CowStrInner::Owned(s))
        }
    }
}

impl AsRef<str> for CowStr<'_> {
    fn as_ref(&self) -> &str {
        self
    }
}

impl core::ops::Deref for CowStr<'_> {
    type Target = str;
    fn deref(&self) -> &Self::Target {
        match &self.0 {
            CowStrInner::Borrowed(s) => s,
            CowStrInner::Owned(s) => s,
        }
    }
}

/// A clone owns its text, even if the original borrowed it.
impl Clone for CowStr<'_> {
    fn clone(&self) -> Self {
        self.as_str().to_owned().into()
    }
}

impl Debug for CowStr<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        f.write_str(self)
    }
}

impl Display for CowStr<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        f.write_str(self)
    }
}

impl PartialEq for CowStr<'_> {
    fn eq(&self, other: &Self) -> bool {
        self.as_str() == other.as_str()
    }
}

impl Eq for CowStr<'_> {}

impl core::ops::Add<&str> for CowStr<'_> {
    type Output = String;
    fn add(self, rhs: &str) -> Self::Output {
        match self.0 {
            CowStrInner::Borrowed(s) => {
                let mut ans = String::with_capacity(s.len() + rhs.len());
                ans.push_str(s);
                ans.push_str(rhs);
                ans
            }
            CowStrInner::Owned(mut s) => {
                s.push_str(rhs);
                s
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use alloc::string::ToString;

    use super::*;

    #[test]
    fn a_string_with_spare_capacity_is_added_to_without_a_reallocation_lie() {
        let mut text = String::with_capacity(64);
        text.push_str("abc");
        let owned = CowStr::from(text);
        assert_eq!((owned.as_str(), owned.len()), ("abc", 3));
        assert_eq!(owned + "def", "abcdef");
        assert_eq!(CowStr::from("x") + "y", "xy");
        assert_eq!(CowStr::from(String::new()) + "z", "z");
    }

    #[test]
    fn equal_text_is_equal_whatever_holds_it() {
        let borrowed = CowStr::from("same");
        let owned = CowStr::from("same".to_string());
        assert_eq!(borrowed, owned);
        assert_eq!(owned.clone().as_str(), "same");
        assert_eq!(format!("{borrowed} {owned:?}"), "same same");
        assert_eq!(
            CowStr::from(alloc::borrow::Cow::Borrowed("c")).as_ref(),
            "c"
        );
    }
}
