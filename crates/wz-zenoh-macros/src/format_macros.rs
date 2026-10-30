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
// Modified by newmassrael in 2026 for watching-zenoh. Derived from zenoh-macros 1.10.2, file
// src/lib.rs (https://github.com/eclipse-zenoh/zenoh, tag 1.10.2).

//! The key expression macros: the literals checked at compile time (`ke!`, `nonwild_ke!`) and the
//! format macros (`kedefine!`, `kewrite!`, `keformat!`).
//!
//! A format is declared once, with a literal, and `kedefine!` writes a module for it whose
//! formatter has a setter and whose parse result a getter for each field the format names. The
//! module's code is spelled with `::zenoh::` paths, as the user of the macro has `zenoh` in its
//! graph and a format module is that crate's own item.

use proc_macro2::TokenStream;
use quote::{format_ident, quote};
use syn::{punctuated::Punctuated, Token};
use zenoh_keyexpr::{
    format::{
        macro_support::{self, SegmentBuilder},
        KeFormat,
    },
    key_expr::keyexpr,
};

/// Why a macro of this module cannot expand.
pub(crate) enum Failure {
    /// The input is not what the macro takes.
    Syntax(syn::Error),
    /// A literal is not a key expression, or not a key expression format; what is reported is
    /// the text of the error that says why.
    Literal(String),
}

impl Failure {
    /// Reports the failure to the compiler: by a panic of the macro, which rustc prints as
    /// `proc macro panicked` with the text.
    pub(crate) fn raise<T>(self) -> T {
        match self {
            Failure::Syntax(error) => {
                panic!("called `Result::unwrap()` on an `Err` value: {error:?}")
            }
            Failure::Literal(text) => panic!("{text}"),
        }
    }
}

impl From<syn::Error> for Failure {
    fn from(error: syn::Error) -> Self {
        Failure::Syntax(error)
    }
}

/// The code of the module of a format: its `Format` type of size zero, its `Formatter` with a
/// setter per field, its `Parsed` with a getter per field, and the free functions over them.
fn module_body(source: &str) -> Result<TokenStream, Failure> {
    let format = KeFormat::new(source).map_err(|e| Failure::Literal(e.to_string()))?;
    // SAFETY: `specs` reads the offsets of the segments of a format built from `source`, which
    // is the format it is given.
    let specs = unsafe { macro_support::specs(&format) };
    let len = specs.len();
    let setters = specs.iter().map(|spec| {
        let id = &source[spec.spec_start..(spec.spec_start + spec.id_end as usize)];
        let set_id = format_ident!("{}", id);
        quote! {
            pub fn #set_id <S: ::core::fmt::Display>(&mut self, value: S) -> Result<&mut Self, ::zenoh::key_expr::format::FormatSetError> {
                match self.0.set(#id, value) {
                    Ok(_) => Ok(self),
                    Err(e) => Err(e)
                }
            }
        }
    });
    let getters = specs.iter().map(|spec| {
        let source = &source[spec.spec_start..spec.spec_end];
        let id = &source[..(spec.id_end as usize)];
        let get_id = format_ident!("{}", id);
        // SAFETY: the pattern of a spec of a valid format is a key expression.
        let pattern = unsafe {
            keyexpr::from_str_unchecked(if spec.pattern_end != u16::MAX {
                &source[(spec.id_end as usize + 1)..(spec.spec_start + spec.pattern_end as usize)]
            } else {
                &source[(spec.id_end as usize + 1)..]
            })
        };
        let doc = format!("Get the parsed value for `{id}`.\n\nThis value is guaranteed to be a valid key expression intersecting with `{pattern}`");
        if pattern.as_bytes() == b"**" {
            quote! {
                #[doc = #doc]
                /// Since the pattern is `**`, this may return `None` if the pattern didn't consume any chunks.
                pub fn #get_id (&self) -> Option<& ::zenoh::key_expr::keyexpr> {
                    unsafe {
                        let s =self._0.get(#id).unwrap_unchecked();
                        (!s.is_empty()).then(|| ::zenoh::key_expr::keyexpr::from_str_unchecked(s))
                    }
                }
            }
        } else {
            quote! {
                #[doc = #doc]
                pub fn #get_id (&self) -> &::zenoh::key_expr::keyexpr {
                    unsafe {::zenoh::key_expr::keyexpr::from_str_unchecked(self._0.get(#id).unwrap_unchecked())}
                }
            }
        }
    });
    let segments = specs.iter().map(|spec| {
        let SegmentBuilder {
            segment_start,
            prefix_end,
            spec_start,
            id_end,
            pattern_end,
            spec_end,
            segment_end,
        } = spec;
        quote! {
            ::zenoh::key_expr::format::macro_support::SegmentBuilder {
                segment_start: #segment_start,
                prefix_end: #prefix_end,
                spec_start: #spec_start,
                id_end: #id_end,
                pattern_end: #pattern_end,
                spec_end: #spec_end,
                segment_end: #segment_end,
            },
        }
    });

    let format_doc = format!("The `{source}` format, as a zero-sized-type.");
    let formatter_doc = format!("And instance of a formatter for `{source}`.");

    Ok(quote! {
            use ::zenoh::Result as ZResult;
            const FORMAT_INNER: ::zenoh::key_expr::format::KeFormat<'static, [::zenoh::key_expr::format::Segment<'static>; #len]> = unsafe {
                ::zenoh::key_expr::format::macro_support::const_new(#source, [#(#segments)*])
            };
            #[doc = #format_doc]
            #[derive(Copy, Clone, Hash)]
            pub struct Format;

            #[doc = #formatter_doc]
            #[derive(Clone)]
            pub struct Formatter(::zenoh::key_expr::format::KeFormatter<'static, [::zenoh::key_expr::format::Segment<'static>; #len]>);
            impl ::core::fmt::Debug for Format {
                fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
                    ::core::fmt::Debug::fmt(&FORMAT_INNER, f)
                }
            }
            impl ::core::fmt::Debug for Formatter {
                fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
                    ::core::fmt::Debug::fmt(&self.0, f)
                }
            }
            impl ::core::fmt::Display for Format {
                fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
                    ::core::fmt::Display::fmt(&FORMAT_INNER, f)
                }
            }
            impl ::core::ops::Deref for Format {
                type Target = ::zenoh::key_expr::format::KeFormat<'static, [::zenoh::key_expr::format::Segment<'static>; #len]>;
                fn deref(&self) -> &Self::Target {&FORMAT_INNER}
            }
            impl ::core::ops::Deref for Formatter {
                type Target = ::zenoh::key_expr::format::KeFormatter<'static, [::zenoh::key_expr::format::Segment<'static>; #len]>;
                fn deref(&self) -> &Self::Target {&self.0}
            }
            impl ::core::ops::DerefMut for Formatter {
                fn deref_mut(&mut self) -> &mut Self::Target {&mut self.0}
            }
            impl Formatter {
                #(#setters)*
            }
            pub struct Parsed<'s>{_0: ::zenoh::key_expr::format::Parsed<'s, [::zenoh::key_expr::format::Segment<'s>; #len]>}
            impl<'s> ::core::ops::Deref for Parsed<'s> {
                type Target = ::zenoh::key_expr::format::Parsed<'s, [::zenoh::key_expr::format::Segment<'s>; #len]>;
                fn deref(&self) -> &Self::Target {&self._0}
            }
            impl Parsed<'_> {
                #(#getters)*
            }
            impl Format {
                pub fn formatter() -> Formatter {
                    Formatter(Format.formatter())
                }
                pub fn parse<'s>(target: &'s ::zenoh::key_expr::keyexpr) -> ZResult<Parsed<'s>> {
                    Ok(Parsed{_0: Format.parse(target)?})
                }
                pub fn into_inner(self) -> ::zenoh::key_expr::format::KeFormat<'static, [::zenoh::key_expr::format::Segment<'static>; #len]> {
                    FORMAT_INNER
                }
            }
            pub fn formatter() -> Formatter {
                Format::formatter()
            }
            pub fn parse<'s>(target: &'s ::zenoh::key_expr::keyexpr) -> ZResult<Parsed<'s>> {
                Format::parse(target)
            }
    })
}

/// One declaration of `kedefine!`: `<vis> <name>: "<format>"`.
struct FormatDeclaration {
    vis: syn::Visibility,
    name: syn::Ident,
    lit: syn::LitStr,
}

impl syn::parse::Parse for FormatDeclaration {
    fn parse(input: syn::parse::ParseStream) -> syn::Result<Self> {
        let vis = input.parse()?;
        let name = input.parse()?;
        let _: Token![:] = input.parse()?;
        let lit = input.parse()?;
        Ok(FormatDeclaration { vis, name, lit })
    }
}

struct FormatDeclarations(Punctuated<FormatDeclaration, Token![,]>);

impl syn::parse::Parse for FormatDeclarations {
    fn parse(input: syn::parse::ParseStream) -> syn::Result<Self> {
        Ok(Self(
            input.parse_terminated(FormatDeclaration::parse, Token![,])?,
        ))
    }
}

pub(crate) fn kedefine(tokens: TokenStream) -> Result<TokenStream, Failure> {
    let declarations: FormatDeclarations = syn::parse2(tokens)?;
    let mut modules = Vec::new();
    for FormatDeclaration { vis, name, lit } in declarations.0 {
        let source = lit.value();
        let docstring = format!(
            r"The module associated with the `{source}` format, it contains:
- `Format`, a zero-sized type that represents your format.
- `formatter()`, a function that constructs a `Formatter` specialized for your format:
    - for every spec in your format, `Formatter` will have a method named after the spec's `id` that lets you set a value for that field of your format. These methods will return `Result<&mut Formatter, FormatError>`.
- `parse(target: &keyexpr) -> ZResult<Parsed<'_>>` will parse the provided key expression according to your format. Just like `KeFormat::parse`, parsing is lazy: each field will match the smallest subsection of your `target` that is included in its pattern.
    - like `Formatter`, `Parsed` will have a method named after each spec's `id` that returns `&keyexpr`; except for specs whose pattern was `**`, these will return an `Option<&keyexpr>`, where `None` signifies that the pattern was matched by an empty list of chunks."
        );
        let support = module_body(&source)?;
        modules.push(quote! {
            #[doc = #docstring]
            #vis mod #name{
                #support
            }
        });
    }
    Ok(quote!(#(#modules)*))
}

/// What `kewrite!` and `keformat!` take: a formatter, and the assignments to make to it, each
/// either `field = value` or `field` alone, which stands for `field = field`.
struct FormatUsage {
    id: syn::Expr,
    assigns: Vec<(syn::Expr, syn::Expr)>,
}

impl syn::parse::Parse for FormatUsage {
    fn parse(input: syn::parse::ParseStream) -> syn::Result<Self> {
        let id = input.parse()?;
        if !input.is_empty() {
            input.parse::<Token![,]>()?;
        }
        let assigns = input
            .parse_terminated(syn::Expr::parse, Token![,])?
            .into_iter()
            .map(|assign| match assign {
                syn::Expr::Assign(a) => (*a.left, *a.right),
                other => (other.clone(), other),
            })
            .collect();
        Ok(FormatUsage { id, assigns })
    }
}

pub(crate) fn kewrite(tokens: TokenStream) -> Result<TokenStream, Failure> {
    let FormatUsage { id, assigns } = syn::parse2(tokens)?;
    // `.a(x).and_then(|x| x.b(y).and_then(|x| x.c(z)))`: each setter runs only if the one before it
    // succeeded, and the result is the last setter's, or the first error.
    let mut sets = None;
    for (field, value) in assigns.iter().rev() {
        sets = Some(match sets {
            Some(rest) => quote!(.#field(#value).and_then(|x| x #rest)),
            None => quote!(.#field(#value)),
        });
    }
    Ok(quote!(#id #sets))
}

pub(crate) fn keformat(tokens: TokenStream) -> Result<TokenStream, Failure> {
    let formatted = kewrite(tokens)?;
    Ok(quote!(match #formatted {
        Ok(ok) => ok.build(),
        Err(e) => Err(e.into()),
    }))
}

/// `ke!("...")`: the key expression the literal is, built without a check at run time because it
/// was checked here.
pub(crate) fn ke(tokens: TokenStream) -> Result<TokenStream, Failure> {
    let value: syn::LitStr = syn::parse2(tokens)?;
    let ke = value.value();
    match zenoh_keyexpr::keyexpr::new(&ke) {
        // SAFETY (of the code written): `ke` was just checked.
        Ok(_) => Ok(quote!(unsafe { zenoh::key_expr::keyexpr::from_str_unchecked(#ke)})),
        Err(e) => Err(Failure::Literal(e.to_string())),
    }
}

/// `nonwild_ke!("...")`: as [`ke`], for a key expression with no wildcard.
pub(crate) fn nonwild_ke(tokens: TokenStream) -> Result<TokenStream, Failure> {
    let value: syn::LitStr = syn::parse2(tokens)?;
    let ke = value.value();
    match zenoh_keyexpr::nonwild_keyexpr::new(&ke) {
        // SAFETY (of the code written): `ke` was just checked.
        Ok(_) => Ok(quote!(unsafe { zenoh::key_expr::nonwild_keyexpr::from_str_unchecked(#ke)})),
        Err(e) => Err(Failure::Literal(e.to_string())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn raised(result: Result<TokenStream, Failure>) -> String {
        match result {
            Ok(tokens) => panic!("expanded to {tokens}"),
            Err(Failure::Literal(text)) => text,
            Err(Failure::Syntax(e)) => format!("syntax: {e}"),
        }
    }

    #[test]
    fn a_literal_that_is_a_key_expression_expands_to_its_unchecked_form() {
        let out = ke(quote!("a/b/**")).ok().unwrap().to_string();
        assert_eq!(
            out,
            r#"unsafe { zenoh :: key_expr :: keyexpr :: from_str_unchecked ("a/b/**") }"#
        );
        let out = nonwild_ke(quote!("a/b")).ok().unwrap().to_string();
        assert!(
            out.contains("nonwild_keyexpr :: from_str_unchecked"),
            "{out}"
        );
    }

    #[test]
    fn a_literal_that_is_not_one_is_refused_with_the_text_of_the_error() {
        let text = raised(ke(quote!("a//b")));
        assert!(!text.is_empty());
        assert_eq!(
            text,
            zenoh_keyexpr::keyexpr::new("a//b").unwrap_err().to_string()
        );
        let text = raised(nonwild_ke(quote!("a/*")));
        assert_eq!(
            text,
            zenoh_keyexpr::nonwild_keyexpr::new("a/*")
                .unwrap_err()
                .to_string()
        );
        assert!(raised(ke(quote!(not_a_literal))).starts_with("syntax:"));
    }

    #[test]
    fn a_write_chains_the_setters_so_the_first_error_stops_the_rest() {
        let out = kewrite(quote!(f, a = 1, b, c = x + 1))
            .ok()
            .unwrap()
            .to_string();
        assert_eq!(
            out,
            "f . a (1) . and_then (| x | x . b (b) . and_then (| x | x . c (x + 1)))"
        );
        let out = kewrite(quote!(f)).ok().unwrap().to_string();
        assert_eq!(out, "f");
    }

    #[test]
    fn a_format_builds_the_write_into_a_key_expression() {
        let out = keformat(quote!(f, a)).ok().unwrap().to_string();
        assert!(out.starts_with("match f . a (a)"), "{out}");
        assert!(out.contains("ok . build ()"), "{out}");
    }

    #[test]
    fn a_module_has_a_setter_and_a_getter_for_each_field() {
        let out = kedefine(quote!(pub robot: "robot/${id:*}/sensor/${kind:**}"))
            .ok()
            .unwrap()
            .to_string();
        assert!(out.contains("pub mod robot"), "{out}");
        for needle in [
            "pub fn id <",
            "pub fn kind <",
            "pub fn id (& self)",
            "this may return `None`",
        ] {
            assert!(out.contains(needle), "no `{needle}` in {out}");
        }
        // Two specs: the array of segments has two.
        assert_eq!(out.matches("SegmentBuilder {").count(), 2, "{out}");
    }

    #[test]
    fn a_format_that_is_not_one_is_refused() {
        let text = raised(kedefine(quote!(bad: "a/${b")));
        assert_eq!(text, KeFormat::new("a/${b").unwrap_err().to_string());
    }
}
