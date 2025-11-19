use proc_macro::TokenStream;
use quote::{ToTokens, format_ident, quote};
use syn::{
    Expr, ExprPath, FnArg, ItemFn, PatType, Token, parse_macro_input, punctuated::Punctuated,
};

#[proc_macro_attribute]
pub fn requires(attr: TokenStream, item: TokenStream) -> TokenStream {
    let req = quote! { axum_security::rbac::__requires };

    expand_inner(attr, item, req)
}

#[proc_macro_attribute]
pub fn requires_any(attr: TokenStream, item: TokenStream) -> TokenStream {
    let req = quote! { axum_security::rbac::__requires_any };

    expand_inner(attr, item, req)
}

fn expand_inner<T: ToTokens>(attr: TokenStream, item: TokenStream, auth_func: T) -> TokenStream {
    let role_exprs = parse_macro_input!(attr with Punctuated::<Expr, Token![,]>::parse_terminated);
    let input_fn = parse_macro_input!(item as ItemFn);

    let fn_vis = &input_fn.vis;
    let fn_sig = &input_fn.sig;
    let fn_name = &fn_sig.ident;
    let fn_output = &fn_sig.output;
    let fn_asyncness = &fn_sig.asyncness;
    let fn_body = &input_fn.block;

    // Extract original parameters (with patterns like Jwt(user))
    let orig_params = &fn_sig.inputs;

    // Keep inner function with original patterns
    let inner_params = orig_params.clone();

    // For outer function: extract types and create simple param names
    let outer_params_and_args: Vec<_> = orig_params
        .iter()
        .enumerate()
        .filter_map(|(i, arg)| {
            if let FnArg::Typed(PatType { ty, .. }) = arg {
                let arg_name = format_ident!("a{}", i + 1);
                Some((quote! { #arg_name: #ty }, quote! { #arg_name }))
            } else {
                None
            }
        })
        .collect();

    let rbac = match &role_exprs.first().unwrap() {
        Expr::Path(ExprPath { path, .. }) => path.segments.iter().rev().nth(1).cloned().unwrap(),
        _ => todo!(),
    };

    let outer_params = outer_params_and_args.iter().map(|(param, _)| param);
    let arg_names = outer_params_and_args.iter().map(|(_, arg)| arg);

    // Build the new function with Extension parameter prepended
    let expanded = quote! {
        #fn_vis #fn_asyncness fn #fn_name(
            roles: axum_security::rbac::RolesExtractor<#rbac>,
            #(#outer_params),*
        ) -> axum::response::Response {

            if let Some(res) = #auth_func::<#rbac>(roles, &[#role_exprs]) {
                return res;
            }

            #fn_asyncness fn inner(#inner_params) #fn_output #fn_body

            axum::response::IntoResponse::into_response(inner(#(#arg_names),*).await)
        }
    };

    TokenStream::from(expanded)
}
