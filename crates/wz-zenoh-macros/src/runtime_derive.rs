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
// src/zenoh_runtime_derive.rs (https://github.com/eclipse-zenoh/zenoh, tag 1.10.1).

//! The two derives that configure the pool of runtimes of `zenoh-runtime`.
//!
//! `GenericRuntimeParam` is derived on the struct of the parameters of one runtime and makes it
//! generic over a type that supplies the defaults; `RegisterParam` is derived on the enum of the
//! runtimes and, from the `#[param(..)]` of each variant (its defaults) and its
//! `#[serde(rename = ..)]` (its name in the configuration), writes the global parameter, its
//! parse from the `ZENOH_RUNTIME` variable, and the enum's `iter`, `init`, `borrow` and `Display`.
//!
//! An input a derive cannot use is a compile error that says so, where upstream's derive panics on
//! some of them (a variant attribute that is not a list, an item that is not an enum).

use proc_macro2::TokenStream;
use quote::{format_ident, quote, ToTokens};
use syn::{
    parse::{Parse, ParseStream},
    punctuated::Punctuated,
    spanned::Spanned,
    token::Comma,
    Data, DataEnum, DataStruct, DeriveInput, Expr, ExprLit, Fields, Ident, Lit, LitStr, Meta,
    MetaNameValue, Token, Variant,
};

/// The argument of `#[serde(rename = "name")]`.
struct SerdeAttribute {
    rename: LitStr,
}

impl Parse for SerdeAttribute {
    fn parse(tokens: ParseStream) -> syn::Result<Self> {
        let parsed = Punctuated::<MetaNameValue, Token![,]>::parse_terminated(tokens)?;
        for kv in parsed {
            if kv.path.is_ident("rename") {
                if let Expr::Lit(ExprLit {
                    lit: Lit::Str(str), ..
                }) = kv.value
                {
                    return Ok(SerdeAttribute { rename: str });
                }
            }
        }
        Err(syn::Error::new(
            tokens.span(),
            "Invalid rename detected, expect #[serde(rename = \"name\")]",
        ))
    }
}

/// What the variants of the enum say: their names, their names in the configuration, and the
/// field initialisers of their `#[param(..)]` (empty when there is none).
fn parse_variants(
    variants: &Punctuated<Variant, Comma>,
) -> syn::Result<(Vec<&Ident>, Vec<TokenStream>, Vec<TokenStream>)> {
    let mut names = Vec::new();
    let mut aliases = Vec::new();
    let mut params = Vec::new();

    for variant in variants {
        let serde = variant
            .attrs
            .iter()
            .find(|attr| attr.path().is_ident("serde"))
            .ok_or_else(|| {
                syn::Error::new(variant.span(), "#[serde(alias = \"name\")] is missing")
            })?;
        let alias = serde
            .parse_args::<SerdeAttribute>()?
            .rename
            .value()
            .parse::<TokenStream>()
            .map_err(|e| {
                syn::Error::new(
                    serde.span(),
                    format!("Failed to convert LitStr to Ident TokenStream: {e}"),
                )
            })?;
        let param = match variant
            .attrs
            .iter()
            .find(|attr| attr.path().is_ident("param"))
        {
            // `#[param(a = 1, b = 2)]` is the initialiser `a: 1, b: 2`.
            Some(attr) => match &attr.meta {
                Meta::List(list) => list
                    .tokens
                    .to_string()
                    .replace('=', ":")
                    .parse::<TokenStream>()
                    .map_err(|e| {
                        syn::Error::new(attr.span(), format!("Failed to parse the parameters: {e}"))
                    })?,
                _ => {
                    return Err(syn::Error::new(
                        attr.span(),
                        "Expected #[param(field = value, ..)] on a variant",
                    ))
                }
            },
            None => TokenStream::new(),
        };

        names.push(&variant.ident);
        aliases.push(alias);
        params.push(param);
    }

    Ok((names, aliases, params))
}

/// The declarations the global parameter is made of: a defaults type per variant, the helper that
/// deserializes the whole configuration, and `GlobalRuntimeParam`.
fn declare_param(
    meta_param: &Ident,
    variant_names: &[&Ident],
    aliases: &Vec<TokenStream>,
    params: &[TokenStream],
) -> TokenStream {
    let default_param_of_variant: Vec<_> = variant_names
        .iter()
        .map(|name| format_ident!("DefaultParamOf{}", name))
        .collect();
    let params_with_default = params.iter().map(|x| {
        if !x.is_empty() {
            quote!(#x, ..Default::default())
        } else {
            quote!(..Default::default())
        }
    });
    quote! {
        trait DefaultParam {
            fn param() -> #meta_param;
        }

        #(
            // Declare struct DefaultParamOf`#variant_name`
            #[derive(Debug, Clone, Copy)]
            struct #default_param_of_variant;

            // impl `DefaultParam` for `DefaultParamOf#variant_name`
            impl DefaultParam for #default_param_of_variant {
                fn param() -> #meta_param {
                    #meta_param {
                        #params_with_default
                    }
                }
            }
        )*

        // An internal helper struct for parsing the RuntimeParam
        #[derive(Deserialize, Debug, Clone, Copy)]
        #[serde(deny_unknown_fields)]
        struct AbstractRuntimeParam {
            #(
                #[serde(default)]
                #aliases: RuntimeParamHelper<#default_param_of_variant>,
            )*
        }

        // AbstractRuntimeParam => GlobalRuntimeParam, extract fields from AbstractRuntimeParam
        impl From<AbstractRuntimeParam> for GlobalRuntimeParam {
            fn from(value: AbstractRuntimeParam) -> Self {
                Self {
                    #(
                        #aliases: value.#aliases.into(),
                    )*
                }
            }
        }

        /// A global runtime parameter for zenoh runtimes
        // pub is needed within lazy_static
        pub struct GlobalRuntimeParam {
            #(
                #aliases: #meta_param,
            )*
        }

    }
}

pub(crate) fn derive_register_param(input: DeriveInput) -> Result<TokenStream, syn::Error> {
    // enum representing the runtime
    let enum_name = &input.ident;

    // Parse the parameter to register, called meta_param
    let attr = input
        .attrs
        .iter()
        .find(|attr| attr.path().is_ident("param"))
        .ok_or_else(|| {
            syn::Error::new(
                input.span(),
                "Expected attribute #[param(StructName)] is missing.",
            )
        })?;
    let meta_param = match &attr.meta {
        Meta::List(list) => syn::parse2::<Ident>(list.tokens.to_token_stream()),
        _ => Err(syn::Error::new(
            attr.span(),
            format!("Failed to parse #[param({})]", attr.to_token_stream()),
        )),
    }?;

    // Parse the variants and associated parameters of the enum
    let variants = match &input.data {
        Data::Enum(DataEnum { variants, .. }) => variants,
        _ => return Err(syn::Error::new(input.span(), "Only enum is supported.")),
    };
    let (variant_names, aliases, params) = parse_variants(variants)?;
    let declare_param_quote = declare_param(&meta_param, &variant_names, &aliases, &params);

    let tokens = quote! {

        use ron::{extensions::Extensions, options::Options};
        use #enum_name::*;

        lazy_static! {
            // We need to hold the reference of ZENOH_RUNTIME_ENV_STRING to prevent the issue of
            // "returning a value referencing data owned by the current function"
            pub static ref ZENOH_RUNTIME_ENV_STRING: String = env::var(ZENOH_RUNTIME_ENV).unwrap_or("()".to_string());
            pub static ref ZRUNTIME_PARAM: GlobalRuntimeParam = Options::default()
                .with_default_extension(Extensions::IMPLICIT_SOME)
                .from_str::<AbstractRuntimeParam>(&ZENOH_RUNTIME_ENV_STRING)
                .unwrap()
                .into();
        }

        #declare_param_quote

        impl #enum_name {
            #[doc = concat!("Create an iterator from ", stringify!(#enum_name))]
            pub fn iter() -> impl Iterator<Item = #enum_name> {
                [#(#variant_names,)*].into_iter()
            }

            #[doc = "Initialize the tokio runtime according to the given config"]
            fn init(&self) -> Result<Runtime> {
                match self {
                    #(
                        #variant_names => {
                            ZRUNTIME_PARAM.#aliases.build(#variant_names)
                        },
                    )*
                }
            }

        }

        #[doc = concat!(
            "Borrow the underlying `",
            stringify!(#meta_param),
            "` from ",
            stringify!(#enum_name)
        )]
        impl Borrow<#meta_param> for #enum_name {
            fn borrow(&self) -> &#meta_param {
                match self {
                    #(
                        #variant_names => {
                            &ZRUNTIME_PARAM.#aliases
                        },
                    )*
                }
            }
        }
        impl std::fmt::Display for #enum_name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                match self {
                    #(
                        #variant_names => {
                            write!(f, stringify!(#aliases))
                        },
                    )*

                }
            }
        }
    };
    Ok(tokens)
}

pub(crate) fn derive_generic_runtime_param(input: DeriveInput) -> Result<TokenStream, syn::Error> {
    let meta_param = &input.ident;
    let fields = match &input.data {
        Data::Struct(DataStruct {
            fields: Fields::Named(fields),
            ..
        }) => &fields.named,
        _ => {
            return Err(syn::Error::new(
                input.span(),
                "Expected a struct with named fields",
            ))
        }
    };
    let field_names: Vec<_> = fields.iter().map(|field| &field.ident).collect();
    let field_types: Vec<_> = fields.iter().map(|field| &field.ty).collect();
    let helper_name = format_ident!("{}Helper", meta_param);

    let tokens = quote! {

        use std::marker::PhantomData;

        // Declare a helper struct to be generic over any T implementing DefaultParam
        #[derive(Deserialize, Debug, Clone, Copy)]
        #[serde(deny_unknown_fields, default)]
        struct #helper_name<T>
        where
            T: DefaultParam,
        {
            #(
                #field_names: #field_types,
            )*
            #[serde(skip)]
            _phantom: PhantomData<T>,
        }

        impl<T> From<#meta_param> for #helper_name<T>
        where
            T: DefaultParam,
        {
            fn from(value: #meta_param) -> Self {
                let #meta_param { #(#field_names,)* } = value;
                Self {
                    #(#field_names,)*
                    _phantom: PhantomData,
                }
            }
        }

        impl<T> From<#helper_name<T>> for #meta_param
        where
            T: DefaultParam,
        {
            fn from(value: #helper_name<T>) -> Self {
                let #helper_name { #(#field_names,)* .. } = value;
                Self {
                    #(#field_names,)*
                }
            }
        }

        impl<T> Default for #helper_name<T>
        where
            T: DefaultParam,
        {
            fn default() -> Self {
                T::param().into()
            }
        }

    };

    Ok(tokens)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn derive_input(tokens: TokenStream) -> DeriveInput {
        syn::parse2(tokens).unwrap()
    }

    #[test]
    fn the_generic_param_derive_writes_a_helper_over_the_fields() {
        let out = derive_generic_runtime_param(derive_input(quote! {
            struct RuntimeParam { worker_threads: usize, name: String }
        }))
        .unwrap()
        .to_string();
        assert!(out.contains("struct RuntimeParamHelper < T >"), "{out}");
        assert!(out.contains("worker_threads : usize"), "{out}");
        assert!(
            out.contains("impl < T > Default for RuntimeParamHelper < T >"),
            "{out}"
        );
        assert!(derive_generic_runtime_param(derive_input(quote!(
            struct Unit;
        )))
        .is_err());
    }

    #[test]
    fn the_register_derive_names_each_variant_by_its_rename_and_applies_its_defaults() {
        let out = derive_register_param(derive_input(quote! {
            #[param(RuntimeParam)]
            enum ZRuntime {
                #[serde(rename = "app")]
                #[param(worker_threads = 1)]
                Application,
                #[serde(rename = "net")]
                Net,
            }
        }))
        .unwrap()
        .to_string();
        assert!(out.contains("struct DefaultParamOfApplication ;"), "{out}");
        assert!(
            out.contains("RuntimeParam { worker_threads : 1 , .. Default :: default () }"),
            "{out}"
        );
        assert!(
            out.contains("RuntimeParam { .. Default :: default () }"),
            "{out}"
        );
        assert!(
            out.contains(
                "pub struct GlobalRuntimeParam { app : RuntimeParam , net : RuntimeParam , }"
            ),
            "{out}"
        );
        assert!(out.contains("write ! (f , stringify ! (net))"), "{out}");
    }

    #[test]
    fn what_a_register_derive_cannot_use_is_a_compile_error_that_says_so() {
        let no_param = derive_register_param(derive_input(quote!(
            enum E {}
        )))
        .unwrap_err();
        assert!(no_param
            .to_string()
            .contains("#[param(StructName)] is missing"));
        let not_enum = derive_register_param(derive_input(quote! {
            #[param(P)] struct S;
        }))
        .unwrap_err();
        assert!(not_enum.to_string().contains("Only enum is supported"));
        let no_rename = derive_register_param(derive_input(quote! {
            #[param(P)] enum E { A }
        }))
        .unwrap_err();
        assert!(no_rename
            .to_string()
            .contains("#[serde(alias = \"name\")] is missing"));
    }
}
