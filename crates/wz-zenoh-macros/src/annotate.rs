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
// Modified by newmassrael in 2026 for watching-zenoh. Derived from zenoh-macros 1.10.1, file
// src/lib.rs (https://github.com/eclipse-zenoh/zenoh, tag 1.10.1).

//! The attributes that mark an item unstable or internal, and the compiler version macro.
//!
//! An annotated item is parsed as an item, or, when it is a member of a trait (`fn f();` is no item)
//! as a trait item; the attribute is added to its list, and the item is written back.

use proc_macro2::TokenStream;
use quote::{quote, ToTokens};
use syn::{parse_quote, Attribute, Error, Item, LitStr, TraitItem};

/// What the release and the commit hash lines of `rustc -v -V` carry, as the tuple of literals
/// `rustc_version_release!` expands to.
///
/// # Panics
/// If the text has no such line, which `rustc -v -V` never lacks.
pub(crate) fn rustc_version_tokens(verbose_version: &str) -> TokenStream {
    let field = |key: &str| {
        verbose_version
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty())
            .find_map(|line| line.strip_prefix(key))
            .unwrap_or_else(|| panic!("`rustc -v -V` has no `{key}` line"))
    };
    let release = field("release: ");
    let commit = field("commit-hash: ");
    quote! {(#release, #commit)}
}

/// An item which can be annotated with `#[zenoh_macros::unstable_doc]`, `#[zenoh_macros::unstable]`
/// or `#[zenoh_macros::internal]`.
#[allow(clippy::large_enum_variant)]
enum Annotable {
    /// An item of a module.
    Item(Item),
    /// A member of a trait.
    TraitItem(TraitItem),
}

impl Annotable {
    fn parse(tokens: TokenStream) -> Result<Self, Error> {
        let item: Item = syn::parse2(tokens)?;
        if !matches!(item, Item::Verbatim(_)) {
            return Ok(Self::Item(item));
        }
        let trait_item: TraitItem = syn::parse2(item.to_token_stream())?;
        if matches!(trait_item, TraitItem::Verbatim(_)) {
            Err(Error::new_spanned(
                trait_item,
                "the `unstable` proc-macro attribute only supports items and trait items",
            ))
        } else {
            Ok(Self::TraitItem(trait_item))
        }
    }

    /// The attribute list of the item.
    fn attributes_mut(&mut self) -> Result<&mut Vec<Attribute>, Error> {
        const UNSUPPORTED: &str =
            "item is not supported by the `unstable` or `internal` proc-macro attribute";
        match self {
            Self::Item(item) => match item {
                Item::Const(item) => Ok(&mut item.attrs),
                Item::Enum(item) => Ok(&mut item.attrs),
                Item::ExternCrate(item) => Ok(&mut item.attrs),
                Item::Fn(item) => Ok(&mut item.attrs),
                Item::ForeignMod(item) => Ok(&mut item.attrs),
                Item::Impl(item) => Ok(&mut item.attrs),
                Item::Macro(item) => Ok(&mut item.attrs),
                Item::Mod(item) => Ok(&mut item.attrs),
                Item::Static(item) => Ok(&mut item.attrs),
                Item::Struct(item) => Ok(&mut item.attrs),
                Item::Trait(item) => Ok(&mut item.attrs),
                Item::TraitAlias(item) => Ok(&mut item.attrs),
                Item::Type(item) => Ok(&mut item.attrs),
                Item::Union(item) => Ok(&mut item.attrs),
                Item::Use(item) => Ok(&mut item.attrs),
                other => Err(Error::new_spanned(other, UNSUPPORTED)),
            },
            Self::TraitItem(item) => match item {
                TraitItem::Const(item) => Ok(&mut item.attrs),
                TraitItem::Fn(item) => Ok(&mut item.attrs),
                TraitItem::Type(item) => Ok(&mut item.attrs),
                TraitItem::Macro(item) => Ok(&mut item.attrs),
                other => Err(Error::new_spanned(other, UNSUPPORTED)),
            },
        }
    }

    fn to_tokens(&self) -> TokenStream {
        match self {
            Self::Item(item) => item.to_token_stream(),
            Self::TraitItem(item) => item.to_token_stream(),
        }
    }
}

/// The literal of a `#[doc = "..."]` attribute.
fn doc_text(attr: &Attribute) -> Option<&LitStr> {
    if !attr.path().is_ident("doc") {
        return None;
    }
    match &attr.meta {
        syn::Meta::NameValue(syn::MetaNameValue {
            value:
                syn::Expr::Lit(syn::ExprLit {
                    lit: syn::Lit::Str(text),
                    ..
                }),
            ..
        }) => Some(text),
        _ => None,
    }
}

/// Puts the warning that the item is unstable right after its first line of documentation, which
/// must be followed by a blank doc line: the warning is a block of HTML, and without the blank line
/// markdown would run the text after it into the block and leave its links unprocessed.
///
/// An item without documentation gets no warning.
fn add_unstable_warning(item: &mut Annotable) -> Result<(), Error> {
    let attrs = item.attributes_mut()?;
    let Some(first) = attrs.iter().position(|attr| doc_text(attr).is_some()) else {
        return Ok(());
    };
    // See: https://doc.rust-lang.org/rustdoc/how-to-write-documentation.html#adding-a-warning-block
    let message = "<div class=\"warning\">This API has been marked as <strong>unstable</strong>: it works as advertised, but it may be changed in a future release.</div>";
    let warning: Attribute = parse_quote!(#[doc = #message]);
    // The line that was second before the warning went in.
    let next = attrs[first + 1..]
        .iter()
        .find_map(|attr| doc_text(attr).map(|text| (attr, text)));
    if let Some((attr, text)) = next {
        if !text.value().trim().is_empty() {
            return Err(Error::new_spanned(
                attr,
                "documentation for `#[unstable]` items must have a blank doc line after the brief description. \
                 This blank line is critical for proper formatting: it will separate the unstable warning from the content below and ensures that \
                 markdown links (like [`Type`](path::to::Type)) are correctly processed by rustdoc. \
                 Add an empty `///` line after your brief description and before detailed explanations.",
            ));
        }
    }
    attrs.insert(first + 1, warning);
    Ok(())
}

pub(crate) fn unstable_doc(tokens: TokenStream) -> Result<TokenStream, Error> {
    let mut item = Annotable::parse(tokens)?;
    add_unstable_warning(&mut item)?;
    Ok(item.to_tokens())
}

pub(crate) fn unstable(tokens: TokenStream) -> Result<TokenStream, Error> {
    let mut item = Annotable::parse(tokens)?;
    add_unstable_warning(&mut item)?;
    let gate: Attribute = parse_quote!(#[cfg(feature = "unstable")]);
    item.attributes_mut()?.push(gate);
    Ok(item.to_tokens())
}

pub(crate) fn internal(tokens: TokenStream) -> Result<TokenStream, Error> {
    let mut item = Annotable::parse(tokens)?;
    let attrs = item.attributes_mut()?;
    let gate: Attribute = parse_quote!(#[cfg(feature = "internal")]);
    let hidden: Attribute = parse_quote!(#[doc(hidden)]);
    attrs.push(gate);
    attrs.push(hidden);
    Ok(item.to_tokens())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn text(tokens: TokenStream) -> String {
        tokens.to_string()
    }

    #[test]
    fn the_version_macro_reads_the_release_and_the_commit() {
        let verbose = "rustc 1.97.0 (abc 2026-01-01)\nbinary: rustc\ncommit-hash: deadbeef\ncommit-date: 2026-01-01\nhost: x\nrelease: 1.97.0\n";
        assert_eq!(
            text(rustc_version_tokens(verbose)),
            r#"("1.97.0" , "deadbeef")"#
        );
    }

    #[test]
    fn an_unstable_item_is_gated_and_warned_after_its_brief_line() {
        let out = unstable(quote! {
            /// Brief.
            ///
            /// Detail.
            pub fn f() {}
        })
        .unwrap();
        let out = text(out);
        let brief = out.find("Brief.").unwrap();
        let warning = out.find("marked as <strong>unstable").unwrap();
        let detail = out.find("Detail.").unwrap();
        assert!(brief < warning && warning < detail, "{out}");
        assert!(out.contains(r#"cfg (feature = "unstable")"#), "{out}");
    }

    #[test]
    fn documentation_without_a_blank_second_line_is_refused() {
        let err = unstable(quote! {
            /// Brief.
            /// Not blank.
            pub fn f() {}
        })
        .unwrap_err();
        assert!(
            err.to_string().contains("must have a blank doc line"),
            "{err}"
        );
    }

    #[test]
    fn an_undocumented_item_is_gated_without_a_warning() {
        let out = text(
            unstable(quote!(
                pub struct S;
            ))
            .unwrap(),
        );
        assert!(!out.contains("unstable</strong>"), "{out}");
        assert!(out.contains(r#"cfg (feature = "unstable")"#), "{out}");
        let doc_only = text(
            unstable_doc(quote!(
                pub struct S;
            ))
            .unwrap(),
        );
        assert!(!doc_only.contains("cfg"), "{doc_only}");
    }

    #[test]
    fn an_internal_item_is_gated_and_hidden() {
        let out = text(
            internal(quote!(
                pub fn f() {}
            ))
            .unwrap(),
        );
        assert!(out.contains(r#"cfg (feature = "internal")"#), "{out}");
        assert!(out.contains("doc (hidden)"), "{out}");
    }

    #[test]
    fn a_trait_member_is_annotated_too() {
        let out = text(
            internal(quote!(
                fn member(&self);
            ))
            .unwrap(),
        );
        assert!(out.contains(r#"cfg (feature = "internal")"#), "{out}");
        assert!(out.contains("fn member"), "{out}");
    }

    #[test]
    fn what_is_neither_an_item_nor_a_trait_member_is_refused() {
        assert!(internal(quote!(not an item)).is_err());
        assert!(internal(quote!(
            extern "C" {}
        ))
        .is_ok());
    }
}
