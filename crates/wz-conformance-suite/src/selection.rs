// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Selection expressions over PICS items (ISO/IEC 9646-7's selection, ISO/IEC 9646-5's test
//! selection): `T-UNICAST and not (T-MCAST or T-PATCH)`. A requirement's `applies` and a
//! conditional PICS item's `condition` are written in it, and a test purpose's selection will
//! be. `and` binds tighter than `or`; `not` binds tightest.

use std::collections::BTreeSet;

/// A parsed selection expression.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Selection {
    Item(String),
    Not(Box<Selection>),
    And(Box<Selection>, Box<Selection>),
    Or(Box<Selection>, Box<Selection>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Token {
    Item(String),
    And,
    Or,
    Not,
    Open,
    Close,
}

impl Token {
    fn describe(&self) -> String {
        match self {
            Token::Item(id) => format!("`{id}`"),
            Token::And => "`and`".to_string(),
            Token::Or => "`or`".to_string(),
            Token::Not => "`not`".to_string(),
            Token::Open => "`(`".to_string(),
            Token::Close => "`)`".to_string(),
        }
    }
}

/// Whether `word` is spelled as an item id: upper-case letters and digits in words joined by
/// single hyphens, the first word starting with a letter. That is a feature name upper-cased
/// (`crate::names`), so every id has its feature and its module parameter.
pub(crate) fn is_item_id(word: &str) -> bool {
    crate::names::is_feature_name(&word.to_ascii_lowercase())
        && !word.chars().any(|c| c.is_ascii_lowercase())
}

fn tokens(text: &str) -> Result<Vec<Token>, String> {
    let mut out = Vec::new();
    let mut rest = text;
    loop {
        rest = rest.trim_start();
        let Some(c) = rest.chars().next() else {
            return Ok(out);
        };
        if c == '(' || c == ')' {
            out.push(if c == '(' { Token::Open } else { Token::Close });
            rest = &rest[1..];
            continue;
        }
        let end = rest
            .find(|d: char| d.is_whitespace() || d == '(' || d == ')')
            .unwrap_or(rest.len());
        let word = &rest[..end];
        rest = &rest[end..];
        out.push(match word {
            "and" => Token::And,
            "or" => Token::Or,
            "not" => Token::Not,
            _ if is_item_id(word) => Token::Item(word.to_string()),
            _ => return Err(format!("`{word}` is neither an item id nor and, or, not")),
        });
    }
}

struct Parser {
    tokens: Vec<Token>,
    at: usize,
}

impl Parser {
    fn peek(&self) -> Option<&Token> {
        self.tokens.get(self.at)
    }

    fn advance(&mut self) -> Option<Token> {
        let token = self.tokens.get(self.at).cloned();
        if token.is_some() {
            self.at += 1;
        }
        token
    }

    fn or(&mut self) -> Result<Selection, String> {
        let mut left = self.and()?;
        while self.peek() == Some(&Token::Or) {
            self.at += 1;
            let right = self.and()?;
            left = Selection::Or(Box::new(left), Box::new(right));
        }
        Ok(left)
    }

    fn and(&mut self) -> Result<Selection, String> {
        let mut left = self.unary()?;
        while self.peek() == Some(&Token::And) {
            self.at += 1;
            let right = self.unary()?;
            left = Selection::And(Box::new(left), Box::new(right));
        }
        Ok(left)
    }

    fn unary(&mut self) -> Result<Selection, String> {
        match self.advance() {
            Some(Token::Not) => Ok(Selection::Not(Box::new(self.unary()?))),
            Some(Token::Open) => {
                let inner = self.or()?;
                match self.advance() {
                    Some(Token::Close) => Ok(inner),
                    Some(other) => Err(format!("{} where `)` was expected", other.describe())),
                    None => Err("a `(` is never closed".to_string()),
                }
            }
            Some(Token::Item(id)) => Ok(Selection::Item(id)),
            Some(other) => Err(format!("{} where an item was expected", other.describe())),
            None => Err("the expression ends where an item was expected".to_string()),
        }
    }
}

impl Selection {
    /// Parses `text`, refusing an empty text, an unknown word and anything left over.
    pub fn parse(text: &str) -> Result<Selection, String> {
        let mut parser = Parser {
            tokens: tokens(text)?,
            at: 0,
        };
        let selection = parser.or()?;
        match parser.advance() {
            None => Ok(selection),
            Some(extra) => Err(format!("{} after a complete expression", extra.describe())),
        }
    }

    /// The item ids the expression names.
    pub fn items(&self) -> BTreeSet<&str> {
        let mut out = BTreeSet::new();
        self.collect(&mut out);
        out
    }

    fn collect<'a>(&'a self, out: &mut BTreeSet<&'a str>) {
        match self {
            Selection::Item(id) => {
                out.insert(id.as_str());
            }
            Selection::Not(inner) => inner.collect(out),
            Selection::And(a, b) | Selection::Or(a, b) => {
                a.collect(out);
                b.collect(out);
            }
        }
    }

    /// Whether the expression holds when `support` answers each item; `None` when an item it
    /// needs is not answered.
    pub fn holds(&self, support: &dyn Fn(&str) -> Option<bool>) -> Option<bool> {
        match self {
            Selection::Item(id) => support(id),
            Selection::Not(inner) => inner.holds(support).map(|v| !v),
            Selection::And(a, b) => Some(a.holds(support)? && b.holds(support)?),
            Selection::Or(a, b) => Some(a.holds(support)? || b.holds(support)?),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn item(id: &str) -> Box<Selection> {
        Box::new(Selection::Item(id.to_string()))
    }

    #[test]
    fn and_binds_tighter_than_or_and_not_tightest() {
        let parsed = Selection::parse("T-A or not T-B and T-C").unwrap();
        let expected = Selection::Or(
            item("T-A"),
            Box::new(Selection::And(
                Box::new(Selection::Not(item("T-B"))),
                item("T-C"),
            )),
        );
        assert_eq!(parsed, expected);
    }

    #[test]
    fn parentheses_group() {
        let parsed = Selection::parse("(T-A or T-B) and T-C").unwrap();
        let expected = Selection::And(
            Box::new(Selection::Or(item("T-A"), item("T-B"))),
            item("T-C"),
        );
        assert_eq!(parsed, expected);
        assert_eq!(
            parsed.items().into_iter().collect::<Vec<_>>(),
            ["T-A", "T-B", "T-C"]
        );
    }

    #[test]
    fn malformed_expressions_are_refused() {
        for (text, needle) in [
            ("", "ends where an item was expected"),
            ("T-A and", "ends where an item was expected"),
            ("T-A T-B", "after a complete expression"),
            ("(T-A or T-B", "never closed"),
            ("T-A )", "after a complete expression"),
            ("t-lower", "neither an item id"),
            ("T-A && T-B", "neither an item id"),
            ("and T-A", "where an item was expected"),
        ] {
            let err = Selection::parse(text).unwrap_err();
            assert!(err.contains(needle), "{text:?}: {err}");
        }
    }

    #[test]
    fn holds_evaluates_and_reports_an_unanswered_item() {
        let answers = |id: &str| match id {
            "T-A" => Some(true),
            "T-B" => Some(false),
            _ => None,
        };
        let s = Selection::parse("T-A and not T-B").unwrap();
        assert_eq!(s.holds(&answers), Some(true));
        let s = Selection::parse("T-B or T-A").unwrap();
        assert_eq!(s.holds(&answers), Some(true));
        let s = Selection::parse("T-A and T-C").unwrap();
        assert_eq!(s.holds(&answers), None);
    }
}
