use std::{env, path::PathBuf};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    tonic_build::configure()
        .file_descriptor_set_path(out_dir.join("post_descriptor.bin"))
        .compile(&["api/spacemesh/v1/post.proto"], &["api"])?;

    Ok(())
}
