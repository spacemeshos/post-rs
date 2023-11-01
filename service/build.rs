use std::{env, path::PathBuf};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    tonic_build::configure().compile(&["api/spacemesh/v1/post.proto"], &["api"])?;

    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    tonic_build::configure()
        .file_descriptor_set_path(out_dir.join("service_descriptor.bin"))
        .compile(&["api/post/v1/service.proto"], &["api"])?;

    Ok(())
}
