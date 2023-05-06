pub use log::LevelFilter;

/// Configure logging for the library.
#[no_mangle]
pub extern "C" fn configure_logging(level: log::LevelFilter) {
    env_logger::Builder::new().filter_level(level).init();
}
