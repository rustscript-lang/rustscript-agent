//! First load-bearing prerequisite for the remaining signed A/B acceptance.
//! This intentionally stays RED when the original leaf cannot prepare; it does
//! not count package metadata, returned text or a fake provider effect as success.

#[path = "support/signed_pinned_variants.rs"]
mod signed_pinned_variants;

#[test]
fn signed_search_variant_can_prepare_the_unchanged_production_leaf() {
    let (store, lock) = signed_pinned_variants::signed_search_variant();
    let prepared = store.prepare(&lock).unwrap_or_else(|error| {
        panic!("signed search variant must prepare the original production leaf: {error:?}")
    });
    let package_id = "org.rustscript.tools.varianta";
    assert!(prepared.program(package_id).is_some());
    assert_eq!(
        prepared.captured_source(package_id, "leaf.rss").unwrap(),
        include_bytes!("../rss/tools/search_files.rss")
    );
}
