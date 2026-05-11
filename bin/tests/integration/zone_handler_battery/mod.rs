#[macro_use]
pub mod basic;
#[macro_use]
pub mod dnssec;
#[macro_use]
pub mod dynamic_update;

pub(crate) fn fixture_path(path: &str) -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("bin crate should have a workspace parent")
        .join(path)
        .canonicalize()
        .expect("test fixture path should exist")
}
