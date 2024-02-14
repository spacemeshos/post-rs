fn main() -> Result<(), Box<dyn std::error::Error>> {
    tonic_build::configure().compile(&["api/spacemesh/v1/post.proto"], &["api"])?;
    Ok(())
}
