extern crate proc_macro;
use proc_macro2::TokenStream;
use quote::{quote, quote_spanned};
use syn::{
    parse_macro_input, parse_quote, punctuated::Punctuated, spanned::Spanned, Data, DeriveInput,
    Fields, GenericParam, Generics, Ident, Type,
};

fn add_trait_bounds(mut generics: Generics, field_type: &TokenStream) -> Generics {
    for param in &mut generics.params {
        if let GenericParam::Type(ref mut type_param) = *param {
            type_param
                .bounds
                .push(parse_quote!(zk_callbacks::generic::user::UserData<#field_type>));
        }
    }
    generics
}

fn derive_userdata_and_zk(
    data: &Data,
    ft: TokenStream,
) -> (
    TokenStream,
    TokenStream,
    TokenStream,
    TokenStream,
    TokenStream,
    TokenStream,
    TokenStream,
) {
    match *data {
        Data::Struct(ref data) => match data.fields {
            Fields::Named(ref fields) => {
                let rec = fields.named.iter().map(|f| {
                    let name = &f.ident;
                    quote_spanned! {f.span() =>
                        buf.extend_from_slice(&self.#name.serialize_elements())
                    }
                });

                let rec_zk = fields.named.iter().map(|f| {
                    let name = &f.ident;
                    let ty = &f.ty;
                    quote_spanned! {f.span() =>
                        buf.extend_from_slice(<#ty as zk_callbacks::generic::user::UserData<#ft>>::serialize_in_zk(user_var.#name)?.as_slice())
                    }
                });

                let zk_fields = fields.named.iter().map(|f| {
                    let name = &f.ident;
                    let ty = &f.ty;
                    quote_spanned! {f.span() =>
                        pub #name: <#ty as zk_callbacks::generic::user::UserData<#ft>>::UserDataVar
                    }
                });

                let field_cond_select = fields.named.iter().map(|f| {
                    let name = &f.ident;
                    let ty = &f.ty;
                    quote_spanned! {f.span() =>
                        let #name = <<#ty as zk_callbacks::generic::user::UserData<#ft>>::UserDataVar as ark_r1cs_std::select::CondSelectGadget<#ft>>::conditionally_select(cond, &true_value.#name, &false_value.#name)?;
                    }
                });

                let eq_gadget = fields.named.iter().map(|f| {
                    let name = &f.ident;
                    let ty = &f.ty;
                    quote_spanned! {f.span() =>
                        b = b & <<#ty as zk_callbacks::generic::user::UserData<#ft>>::UserDataVar as ark_r1cs_std::eq::EqGadget<#ft>>::is_eq(&self.#name, &other.#name)?;
                    }
                });

                let zk_names = fields.named.iter().map(|f| {
                    let name = &f.ident;
                    quote_spanned! {f.span() => #name }
                });

                let alloc_var = fields.named.iter().map(|f| {
                    let name = &f.ident;
                    let ty = &f.ty;
                    let lit = proc_macro2::Literal::string(&(name.clone()).unwrap().to_string());
                    quote_spanned! {f.span() =>
                    let #name = <#ty as zk_callbacks::generic::user::UserData<#ft>>::UserDataVar::new_variable(ark_relations::ns!(cs, #lit), || Ok(rec.#name.clone()), mode)?
                    }
                });

                (
                    quote! {
                        #(#rec;)*
                    },
                    quote! {
                        #(#rec_zk;)*
                    },
                    quote! {
                        #(#zk_fields, )*
                    },
                    quote! {
                        #(#zk_names, )*
                    },
                    quote! {
                        #(#alloc_var;)*
                    },
                    quote! {
                        #(#field_cond_select;)*
                    },
                    quote! {
                        #(#eq_gadget;)*
                    },
                )
            }
            Fields::Unnamed(_) => {
                todo!() // TODO: macro for tuple struct
            }
            Fields::Unit => {
                todo!() // TODO: macro for unit type
            }
        },
        Data::Enum(_) => {
            todo!() // TODO: macro for enum type
        }
        Data::Union(_) => {
            todo!() // TODO: macro for union type
        }
    }
}

#[proc_macro_attribute]
pub fn zk_object(
    args: proc_macro::TokenStream,
    input: proc_macro::TokenStream,
) -> proc_macro::TokenStream {
    let ast = parse_macro_input!(input as DeriveInput);

    let args = parse_macro_input!(args with Punctuated::<Type, syn::Token![,]>::parse_terminated);

    let field_type = if !args.is_empty() {
        let x = args[0].clone();
        quote! { #x }
    } else {
        quote! { ark_bls12_381::Fr }
    };

    let noalloc = if args.len() >= 2 {
        Some(args[1].clone())
    } else {
        None
    };

    // Get the new name
    let name = ast.ident.clone();
    let mut struct_name = name.to_string().clone();

    struct_name.push_str("ZKVar");

    let zk_var_name = Ident::new(&struct_name, ast.ident.span());

    // Add trait bounds to elements in the original struct:
    let generics = add_trait_bounds(ast.generics.clone(), &field_type);
    let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();

    let (s1, s2, fields, zk_names, alloc, _fcond, _eq) =
        derive_userdata_and_zk(&ast.data, field_type.clone());
    let tok = match noalloc {
        Some(t) => {
            quote! {

                #[derive(Clone, Debug, PartialEq, Eq)]
                #ast

                impl #impl_generics zk_callbacks::generic::user::UserData<#field_type> for #name #ty_generics #where_clause {
                    type UserDataVar = #t;

                    fn serialize_elements(&self) -> Vec<zk_callbacks::generic::object::Ser<#field_type>> {
                        let mut buf: Vec<#field_type> = Vec::new();
                        #s1
                        buf
                    }

                    fn serialize_in_zk(user_var: Self::UserDataVar) -> Result<Vec<zk_callbacks::generic::object::SerVar<#field_type>>, ark_relations::r1cs::SynthesisError> {
                        let mut buf: Vec<zk_callbacks::generic::object::SerVar<#field_type>> = Vec::new();
                        #s2
                        Ok(buf)
                    }
                }
            }
        }
        None => {
            quote! {

                #[derive(Clone, Debug, PartialEq, Eq)]
                #ast

                #[derive(Clone)]
                pub struct #zk_var_name {
                    #fields
                }

                impl #impl_generics ark_r1cs_std::prelude::AllocVar<#name, #field_type> for #zk_var_name {
                    fn new_variable<T: std::borrow::Borrow<#name>>(
                        cs: impl Into<ark_relations::r1cs::Namespace<#field_type>>,
                        f: impl FnOnce() -> Result<T, ark_relations::r1cs::SynthesisError>,
                        mode: ark_r1cs_std::prelude::AllocationMode,
                    ) -> Result<Self, ark_relations::r1cs::SynthesisError> {
                        let ns = cs.into();
                        let cs = ns.cs();
                        let res = f();

                        res.and_then(|rec| {
                            let rec = rec.borrow();

                            #alloc

                            Ok(#zk_var_name { #zk_names })
                        })
                    }
                }

                impl #impl_generics zk_callbacks::generic::user::UserData<#field_type> for #name #ty_generics #where_clause {
                    type UserDataVar = #zk_var_name;

                    fn serialize_elements(&self) -> Vec<zk_callbacks::generic::object::Ser<#field_type>> {
                        let mut buf: Vec<#field_type> = Vec::new();
                        #s1
                        buf
                    }

                    fn serialize_in_zk(user_var: Self::UserDataVar) -> Result<Vec<zk_callbacks::generic::object::SerVar<#field_type>>, ark_relations::r1cs::SynthesisError> {
                        let mut buf: Vec<zk_callbacks::generic::object::SerVar<#field_type>> = Vec::new();
                        #s2
                        Ok(buf)
                    }
                }
            }
        }
    };

    tok.into()
}

#[proc_macro_attribute]
pub fn scannable_zk_object(
    args: proc_macro::TokenStream,
    input: proc_macro::TokenStream,
) -> proc_macro::TokenStream {
    let ast = parse_macro_input!(input as DeriveInput);

    let args = parse_macro_input!(args with Punctuated::<Type, syn::Token![,]>::parse_terminated);

    let field_type = if !args.is_empty() {
        let x = args[0].clone();
        quote! { #x }
    } else {
        quote! { ark_bls12_381::Fr }
    };

    let noalloc = if args.len() >= 2 {
        Some(args[1].clone())
    } else {
        None
    };

    // Get the new name
    let name = ast.ident.clone();
    let mut struct_name = name.to_string().clone();

    struct_name.push_str("ZKVar");

    let zk_var_name = Ident::new(&struct_name, ast.ident.span());

    // Add trait bounds to elements in the original struct:
    let generics = add_trait_bounds(ast.generics.clone(), &field_type);
    let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();

    let (s1, s2, fields, zk_names, alloc, fp_cond, eqg) =
        derive_userdata_and_zk(&ast.data, field_type.clone());
    let tok = match noalloc {
        Some(t) => {
            quote! {

                #[derive(Clone, Debug, PartialEq, Eq)]
                #ast

                impl #impl_generics zk_callbacks::generic::user::UserData<#field_type> for #name #ty_generics #where_clause {
                    type UserDataVar = #t;

                    fn serialize_elements(&self) -> Vec<zk_callbacks::generic::object::Ser<#field_type>> {
                        let mut buf: Vec<#field_type> = Vec::new();
                        #s1
                        buf
                    }

                    fn serialize_in_zk(user_var: Self::UserDataVar) -> Result<Vec<zk_callbacks::generic::object::SerVar<#field_type>>, ark_relations::r1cs::SynthesisError> {
                        let mut buf: Vec<zk_callbacks::generic::object::SerVar<#field_type>> = Vec::new();
                        #s2
                        Ok(buf)
                    }
                }
            }
        }
        None => {
            quote! {

                #[derive(Clone, Debug, PartialEq, Eq)]
                #ast

                #[derive(Clone)]
                pub struct #zk_var_name {
                    #fields
                }

                impl #impl_generics ark_r1cs_std::eq::EqGadget<#field_type> for #zk_var_name {
                    fn is_eq(&self, other: &Self) -> Result<ark_r1cs_std::boolean::Boolean<#field_type>, ark_relations::r1cs::SynthesisError> {
                        let mut b = ark_r1cs_std::boolean::Boolean::TRUE;
                        #eqg
                        Ok(b)
                    }
                }

                impl #impl_generics ark_r1cs_std::select::CondSelectGadget<#field_type> for #zk_var_name {
                    fn conditionally_select(
                        cond: &ark_r1cs_std::boolean::Boolean<#field_type>,
                        true_value: &Self,
                        false_value: &Self,
                    ) -> Result<Self, ark_relations::r1cs::SynthesisError> {
                        #fp_cond

                        Ok(#zk_var_name {
                            #zk_names
                        })
                    }
                }

                impl #impl_generics ark_r1cs_std::prelude::AllocVar<#name, #field_type> for #zk_var_name {
                    fn new_variable<T: std::borrow::Borrow<#name>>(
                        cs: impl Into<ark_relations::r1cs::Namespace<#field_type>>,
                        f: impl FnOnce() -> Result<T, ark_relations::r1cs::SynthesisError>,
                        mode: ark_r1cs_std::prelude::AllocationMode,
                    ) -> Result<Self, ark_relations::r1cs::SynthesisError> {
                        let ns = cs.into();
                        let cs = ns.cs();
                        let res = f();

                        res.and_then(|rec| {
                            let rec = rec.borrow();

                            #alloc

                            Ok(#zk_var_name { #zk_names })
                        })
                    }
                }

                impl #impl_generics zk_callbacks::generic::user::UserData<#field_type> for #name #ty_generics #where_clause {
                    type UserDataVar = #zk_var_name;

                    fn serialize_elements(&self) -> Vec<zk_callbacks::generic::object::Ser<#field_type>> {
                        let mut buf: Vec<#field_type> = Vec::new();
                        #s1
                        buf
                    }

                    fn serialize_in_zk(user_var: Self::UserDataVar) -> Result<Vec<zk_callbacks::generic::object::SerVar<#field_type>>, ark_relations::r1cs::SynthesisError> {
                        let mut buf: Vec<zk_callbacks::generic::object::SerVar<#field_type>> = Vec::new();
                        #s2
                        Ok(buf)
                    }
                }
            }
        }
    };

    tok.into()
}
