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

//! ⚠️ WARNING ⚠️
//!
//! This crate is intended for Zenoh's internal use.
//!
//! [Click here for Zenoh's documentation](https://docs.rs/zenoh/latest/zenoh)
//!
//! The macros are upstream's by name, signature and expansion (inventory atom `api-compat-rust`):
//! the code a macro expands to is what a crate that uses it compiles, so it is the contract and
//! is reproduced. Each macro here is a thin entry over a function on `proc_macro2` tokens, in the
//! module of its family, so that what a macro expands to can be tested without a compiler driving
//! it; `conformance/differential` compiles both crates' expansions and holds their behaviour equal.

use proc_macro::TokenStream;

mod annotate;
mod format_macros;
mod internal_trait;
mod runtime_derive;

const RUSTC_VERSION: &str = include_str!(concat!(env!("OUT_DIR"), "/version.rs"));

/// The release and the commit hash of the compiler that built this crate, as a tuple of two
/// string literals.
#[proc_macro]
pub fn rustc_version_release(_tokens: TokenStream) -> TokenStream {
    annotate::rustc_version_tokens(RUSTC_VERSION).into()
}

#[proc_macro_attribute]
/// Adds only piece of documentation about the item being unstable but no unstable attribute itself.
/// This is useful when the whole crate is supposed to be used in unstable mode only, it makes sense
/// to mention it in documentation for the crate items, but not to add `#[cfg(feature = "unstable")]` to every item.
pub fn unstable_doc(_attr: TokenStream, tokens: TokenStream) -> TokenStream {
    annotate::unstable_doc(tokens.into())
        .unwrap_or_else(syn::Error::into_compile_error)
        .into()
}

#[proc_macro_attribute]
/// Adds a `#[cfg(feature = "unstable")]` attribute to the item and appends piece of documentation about the item being unstable.
pub fn unstable(_attr: TokenStream, tokens: TokenStream) -> TokenStream {
    annotate::unstable(tokens.into())
        .unwrap_or_else(syn::Error::into_compile_error)
        .into()
}

#[proc_macro_attribute]
/// Adds a `#[cfg(feature = "internal")]` and `#[doc(hidden)]` attributes to the item.
pub fn internal(_attr: TokenStream, tokens: TokenStream) -> TokenStream {
    annotate::internal(tokens.into())
        .unwrap_or_else(syn::Error::into_compile_error)
        .into()
}

/// Create format modules from a format specification.
///
/// `kedefine!($($vis $ident: $lit),*)` will validate each `$lit` to be a valid KeFormat, and declare a module called `$ident` with `$vis` visibility at its call-site for each format.
///  The modules contain the following elements:
/// - `Format`, a zero-sized type that represents your format.
/// - `formatter()`, a function that constructs a `Formatter` specialized for your format:
///     - for every spec in your format, `Formatter` will have a method named after the spec's `id` that lets you set a value for that field of your format. These methods will return `Result<&mut Formatter, FormatError>`.
/// - `parse(target: &keyexpr) -> ZResult<Parsed<'_>>` will parse the provided key expression according to your format. Just like `KeFormat::parse`, parsing is lazy: each field will match the smallest subsection of your `target` that is included in its pattern.
///     - like `Formatter`, `Parsed` will have a method named after each spec's `id` that returns `&keyexpr`; except for specs whose pattern was `**`, these will return an `Option<&keyexpr>`, where `None` signifies that the pattern was matched by an empty list of chunks.
#[proc_macro]
pub fn kedefine(tokens: TokenStream) -> TokenStream {
    format_macros::kedefine(tokens.into())
        .unwrap_or_else(format_macros::Failure::raise)
        .into()
}

/// Write a set of values into a `Formatter`, stopping as soon as a value doesn't fit the specification for its field.
/// Contrary to `keformat` doesn't build the Formatter into a Key Expression.
///
/// `kewrite!($formatter, $($ident [= $expr]),*)` will attempt to write `$expr` into their respective `$ident` fields for `$formatter`.
/// `$formatter` must be an expression that dereferences to `&mut Formatter`.
/// `$expr` must resolve to a value that implements `core::fmt::Display`.
/// `$expr` defaults to `$ident` if omitted.
///
/// This macro always results in an expression that resolves to `Result<&mut Formatter, FormatSetError>`.
#[proc_macro]
pub fn kewrite(tokens: TokenStream) -> TokenStream {
    format_macros::kewrite(tokens.into())
        .unwrap_or_else(format_macros::Failure::raise)
        .into()
}

/// Write a set of values into a `Formatter` and then builds it into an `OwnedKeyExpr`, stopping as soon as a value doesn't fit the specification for its field.
///
/// `keformat!($formatter, $($ident [= $expr]),*)` will attempt to write `$expr` into their respective `$ident` fields for `$formatter`.
/// `$formatter` must be an expression that dereferences to `&mut Formatter`.
/// `$expr` must resolve to a value that implements `core::fmt::Display`.
/// `$expr` defaults to `$ident` if omitted.
///
/// This macro always results in an expression that resolves to `ZResult<OwnedKeyExpr>`, and leaves `$formatter` in its written state.
#[proc_macro]
pub fn keformat(tokens: TokenStream) -> TokenStream {
    format_macros::keformat(tokens.into())
        .unwrap_or_else(format_macros::Failure::raise)
        .into()
}

/// Equivalent to [`keyexpr::new`](zenoh_keyexpr::keyexpr::new), but the check is run at compile-time and will throw a compile error in case of failure.
#[proc_macro]
pub fn ke(tokens: TokenStream) -> TokenStream {
    format_macros::ke(tokens.into())
        .unwrap_or_else(format_macros::Failure::raise)
        .into()
}

/// Equivalent to [`nonwild_keyexpr::new`](zenoh_keyexpr::nonwild_keyexpr::new), but the check is run at compile-time and will throw a compile error in case of failure.
#[proc_macro]
pub fn nonwild_ke(tokens: TokenStream) -> TokenStream {
    format_macros::nonwild_ke(tokens.into())
        .unwrap_or_else(format_macros::Failure::raise)
        .into()
}

/// Make the underlying struct `Param` be generic over any `T` satisfying a generated `trait DefaultParam { fn param() -> Param; }`
/// ```rust,ignore
/// #[derive(GenericRuntimeParam)]
/// struct Param {
///    ...
/// }
/// ```
#[proc_macro_derive(GenericRuntimeParam)]
pub fn generic_runtime_param(input: TokenStream) -> TokenStream {
    runtime_derive::derive_generic_runtime_param(syn::parse_macro_input!(input))
        .unwrap_or_else(syn::Error::into_compile_error)
        .into()
}

/// Register the input `Enum` with the struct `Param` specified in the param attribute
/// ```rust,ignore
/// #[derive(RegisterParam)]
/// #[param(Param)]
/// enum Enum {
///    ...
/// }
/// ```
#[proc_macro_derive(RegisterParam, attributes(alias, param))]
pub fn register_param(input: TokenStream) -> TokenStream {
    runtime_derive::derive_register_param(syn::parse_macro_input!(input))
        .unwrap_or_else(syn::Error::into_compile_error)
        .into()
}

/// Macro `#[internal_trait]` should precede
/// `impl Trait for Struct { ... }`
///
/// This macro wraps the implementations of "internal" tratis.
///
/// These traits are used to group set of functions which should be implemented
/// together and with the same prototype. E.g. `QoSBuilderTrait` provides set of
/// setters (`congestion_control`, `priority`, `express`) and we should not
/// forget to implement all these setters for each entity which supports
/// QoS functionality.
///
/// The traits mechanism is a good way to group functions. But additional traits
/// adds extra burden to end user who have to import it every time.
///
/// The macro `internal_trait` solves this problem by adding
/// methods with same names as in trait to structure implementation itself,
/// making them available to user without additional trait import.
///
#[proc_macro_attribute]
pub fn internal_trait(_attr: TokenStream, item: TokenStream) -> TokenStream {
    internal_trait::internal_trait(item.into())
        .unwrap_or_else(syn::Error::into_compile_error)
        .into()
}

#[proc_macro_attribute]
pub fn pub_visibility_if_internal(_attr: TokenStream, tokens: TokenStream) -> TokenStream {
    internal_trait::pub_visibility_if_internal(tokens.into())
        .unwrap_or_else(syn::Error::into_compile_error)
        .into()
}

// applies zenoh_macros::internal if unstable feature is disabled, otherwise applies zenoh_macros::unstable
#[proc_macro_attribute]
pub fn internal_or_unstable(_attr: TokenStream, tokens: TokenStream) -> TokenStream {
    internal_trait::internal_or_unstable(tokens.into())
        .unwrap_or_else(syn::Error::into_compile_error)
        .into()
}
