#[cfg(feature = "macros")]
#[test]
fn rbac_macro_ui() {
    let t = trybuild::TestCases::new();
    t.compile_fail("ui/rbac/requires_no_args.rs");
    t.compile_fail("ui/rbac/requires_non_path.rs");
    t.compile_fail("ui/rbac/requires_single_segment.rs");
}
