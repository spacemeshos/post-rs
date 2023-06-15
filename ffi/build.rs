extern crate cbindgen;

use std::env;

use cbindgen::Config;

fn main() {
    let crate_dir = env::var("CARGO_MANIFEST_DIR").unwrap();

    let mut config = Config::default();
    config.macro_expansion.bitflags = true;

    cbindgen::Builder::new()
        .with_config(config)
        .with_language(cbindgen::Language::C)
        .with_crate(crate_dir)
        .with_parse_deps(true)
        .with_parse_include(&["post-rs", "scrypt-jane", "log", "randomx-rs"])
        .generate()
        .expect("Unable to generate bindings")
        .write_to_file("post.h");
}
