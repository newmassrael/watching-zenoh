// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The attributes that shape how an item is exposed: `internal_trait` copies the methods of a trait
//! implementation onto the type, and `pub_visibility_if_internal` and `internal_or_unstable` write
//! an item twice, once as the crate sees it and once as the `internal` or the `unstable` feature
//! makes it public.

use proc_macro2::TokenStream;
use quote::{quote, ToTokens};
use syn::{parse_quote, spanned::Spanned, Attribute, Error, Item, ItemImpl};

/// `#[internal_trait] impl Trait for Type { .. }`: the implementation as written, followed by an
/// inherent `impl Type` with a method of the name and signature of each method of the trait that
/// calls the trait's, so a user of the type needs no import of the trait.
pub(crate) fn internal_trait(item: TokenStream) -> Result<TokenStream, Error> {
    let mut input: ItemImpl = syn::parse2(item)?;
    let Some((_, trait_path, _)) = input.trait_.clone() else {
        return Err(Error::new(
            input.span(),
            "`internal_trait` is for the implementation of a trait: `impl Trait for Type`",
        ));
    };
    let struct_path = input.self_ty.clone();
    let generics = input.generics.clone();

    let mut struct_methods = quote! {};
    for item_fn in input.items.iter_mut() {
        if let syn::ImplItem::Fn(method) = item_fn {
            let method_name = &method.sig.ident;
            let method_generic_params = &method.sig.generics.params;
            let method_generic_params = if method_generic_params.is_empty() {
                quote! {}
            } else {
                quote! {<#method_generic_params>}
            };
            let method_args = &method.sig.inputs;
            let method_output = &method.sig.output;
            let where_clause = &method.sig.generics.where_clause;
            let mut method_call_args = quote! {};
            for arg in method_args.iter() {
                match arg {
                    syn::FnArg::Receiver(_) => {
                        method_call_args.extend(quote! { self, });
                    }
                    syn::FnArg::Typed(pat_type) => {
                        let pat = &pat_type.pat;
                        method_call_args.extend(quote! { #pat, });
                    }
                }
            }
            let mut attributes = quote! {};
            for attr in &method.attrs {
                attributes.extend(quote! {
                    #attr
                });
            }
            // The attribute `deprecated` stays on the inherent method only: a use of the trait's own
            // would warn twice.
            method
                .attrs
                .retain(|attr| !attr.meta.path().is_ident("deprecated"));
            // call corresponding trait method from struct method
            struct_methods.extend(quote! {
                #attributes
                pub fn #method_name #method_generic_params (#method_args) #method_output #where_clause {
                    <#struct_path as #trait_path>::#method_name(#method_call_args)
                }
            });
        }
    }
    Ok(quote! {
        #input
        impl #generics #struct_path {
            #struct_methods
        }
    })
}

/// The attributes and the visibility of an item that can be written twice: a function, a struct
/// or a type alias.
fn exposed_parts<'a>(
    item: &'a mut Item,
    only: &str,
) -> Result<(&'a mut Vec<Attribute>, &'a mut syn::Visibility), Error> {
    match item {
        Item::Fn(item) => Ok((&mut item.attrs, &mut item.vis)),
        Item::Struct(item) => Ok((&mut item.attrs, &mut item.vis)),
        Item::Type(item) => Ok((&mut item.attrs, &mut item.vis)),
        other => Err(Error::new_spanned(other, only)),
    }
}

/// The item as written, with `original_gate` in front of its attributes, followed by a copy made
/// `pub` with `copy_attrs` in front of its attributes. `only` is what is said of any other item.
fn twice(
    tokens: TokenStream,
    original_gate: Attribute,
    copy_attrs: Vec<Attribute>,
    only: &str,
) -> Result<TokenStream, Error> {
    let mut original: Item = syn::parse2(tokens)?;
    // The copy is taken before the original is gated, so it carries the item's own attributes only.
    let mut copy = original.clone();
    let public = syn::Visibility::Public(syn::token::Pub(original.span()));
    let (attrs, vis) = exposed_parts(&mut copy, only)?;
    attrs.splice(0..0, copy_attrs);
    *vis = public;
    exposed_parts(&mut original, only)?
        .0
        .splice(0..0, [original_gate]);
    let mut out = original.into_token_stream();
    out.extend(copy.into_token_stream());
    Ok(out)
}

/// `#[pub_visibility_if_internal]`: the item with its own visibility unless the `internal` feature
/// is on, and `pub` and hidden from documentation if it is.
pub(crate) fn pub_visibility_if_internal(tokens: TokenStream) -> Result<TokenStream, Error> {
    twice(
        tokens,
        parse_quote!(#[cfg(not(feature = "internal"))]),
        vec![
            parse_quote!(#[cfg(feature = "internal")]),
            parse_quote!(#[doc(hidden)]),
            parse_quote!(#[allow(dead_code)]),
        ],
        "pub_visibility_if_internal only works with struct, type and fn",
    )
}

/// `#[internal_or_unstable]`: the item as `#[unstable]` when the `unstable` feature is on, and as
/// `pub` and `#[internal]` when it is off.
pub(crate) fn internal_or_unstable(tokens: TokenStream) -> Result<TokenStream, Error> {
    twice(
        tokens,
        parse_quote!(#[zenoh_macros::unstable]),
        vec![
            parse_quote!(#[cfg(not(feature = "unstable"))]),
            parse_quote!(#[zenoh_macros::internal]),
        ],
        "internal_or_unstable only works with struct, type and fn",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_trait_implementation_is_copied_onto_the_type() {
        let out = internal_trait(quote! {
            impl<T: Clone> Setters for Builder<T> {
                #[deprecated]
                fn priority<P: Into<u8>>(self, p: P) -> Self where P: Copy { self }
            }
        })
        .unwrap()
        .to_string();
        assert!(out.contains("impl < T : Clone > Builder < T >"), "{out}");
        assert!(
            out.contains("< Builder < T > as Setters > :: priority (self , p ,)"),
            "{out}"
        );
        // The deprecation is on the inherent method, and is taken off the trait's.
        assert_eq!(out.matches("deprecated").count(), 1, "{out}");
    }

    #[test]
    fn a_plain_impl_is_refused() {
        let err = internal_trait(quote!(impl Builder {})).unwrap_err();
        assert!(err.to_string().contains("impl Trait for Type"), "{err}");
    }

    #[test]
    fn the_item_is_written_twice_with_the_visibility_the_feature_gives() {
        let out = pub_visibility_if_internal(quote!(
            fn helper() {}
        ))
        .unwrap()
        .to_string();
        let original = out.find(r#"cfg (not (feature = "internal"))"#).unwrap();
        let copy = out.find(r#"cfg (feature = "internal")"#).unwrap();
        assert!(original < copy, "{out}");
        assert!(out.contains("# [doc (hidden)]"), "{out}");
        assert!(out.contains("pub fn helper"), "{out}");
        let alias = internal_or_unstable(quote!(
            struct Wrapper(u8);
        ))
        .unwrap()
        .to_string();
        assert!(alias.contains("zenoh_macros :: unstable"), "{alias}");
        assert!(alias.contains("zenoh_macros :: internal"), "{alias}");
        assert!(alias.contains("pub struct Wrapper"), "{alias}");
    }

    #[test]
    fn only_functions_structs_and_aliases_can_be_written_twice() {
        let err = pub_visibility_if_internal(quote!(
            const C: u8 = 1;
        ))
        .unwrap_err();
        assert!(err
            .to_string()
            .contains("only works with struct, type and fn"));
        assert!(internal_or_unstable(quote!(
            enum E {}
        ))
        .is_err());
    }
}
