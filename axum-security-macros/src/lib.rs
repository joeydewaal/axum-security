use proc_macro::TokenStream;
use quote::{ToTokens, format_ident, quote};
use syn::{
    Expr, ExprPath, FnArg, ItemFn, PatType, Token, parse_macro_input, punctuated::Punctuated,
};

#[proc_macro_attribute]
pub fn requires(attr: TokenStream, item: TokenStream) -> TokenStream {
    let req = quote! { ::axum_security::rbac::__private::__requires };
    expand_inner(attr, item, req)
}

#[proc_macro_attribute]
pub fn allows(attr: TokenStream, item: TokenStream) -> TokenStream {
    let req = quote! { ::axum_security::rbac::__private::__allows };
    expand_inner(attr, item, req)
}

fn expand_inner<T: ToTokens>(attr: TokenStream, item: TokenStream, auth_func: T) -> TokenStream {
    let role_exprs = parse_macro_input!(attr with Punctuated::<Expr, Token![,]>::parse_terminated);
    let input_fn = parse_macro_input!(item as ItemFn);

    // At least one argument required
    if role_exprs.is_empty() {
        return syn::Error::new_spanned(&input_fn.sig.ident, "requires at least one role argument")
            .to_compile_error()
            .into();
    }

    // Extract RBAC type from the first role expression
    let rbac = match role_exprs.first().unwrap() {
        Expr::Path(ExprPath { path, .. }) => match path.segments.iter().rev().nth(1) {
            Some(seg) => seg.clone(),
            None => {
                return syn::Error::new_spanned(
                    path,
                    "expected a qualified path like `Role::Variant` — \
                     write `MyRole::Admin`, not just `Admin`",
                )
                .to_compile_error()
                .into();
            }
        },
        expr => {
            return syn::Error::new_spanned(
                expr,
                "expected a role variant expression like `Role::Admin`",
            )
            .to_compile_error()
            .into();
        }
    };

    let fn_vis = &input_fn.vis;
    let fn_sig = &input_fn.sig;
    let fn_name = &fn_sig.ident;
    let fn_output = &fn_sig.output;
    let fn_asyncness = &fn_sig.asyncness;
    let fn_body = &input_fn.block;

    let orig_params = &fn_sig.inputs;
    let inner_params = orig_params.clone();

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

    let outer_params = outer_params_and_args.iter().map(|(param, _)| param);
    let arg_names = outer_params_and_args.iter().map(|(_, arg)| arg);

    let expanded = quote! {
        #fn_vis #fn_asyncness fn #fn_name(
            roles: ::axum_security::rbac::__private::RolesExtractor<#rbac>,
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
