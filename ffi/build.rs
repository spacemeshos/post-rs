extern crate cbindgen;

use std::env;

fn main() {
    let crate_dir = env::var("CARGO_MANIFEST_DIR").unwrap();

    cbindgen::Builder::new()
        .with_language(cbindgen::Language::C)
        .with_crate(crate_dir)
        .with_parse_deps(true)
        .with_parse_include(&["post-rs", "scrypt-jane", "log"])
        .generate()
        .expect("Unable to generate bindings")
        .write_to_file("prover.h");
}
