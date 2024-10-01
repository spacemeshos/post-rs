fn main() -> Result<(), Box<dyn std::error::Error>> {
    tonic_build::configure().compile_protos(&["api/spacemesh/v1/post.proto"], &["api"])?;
    Ok(())
}
