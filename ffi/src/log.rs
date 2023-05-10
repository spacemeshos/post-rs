pub use log::LevelFilter;
use simple_logger::SimpleLogger;

/// Configure logging for the library.
#[no_mangle]
pub extern "C" fn configure_logging(level: LevelFilter) -> i32 {
    match SimpleLogger::new().with_level(level).init() {
        Ok(_) => 0,
        Err(e) => {
            eprintln!("Failed to initialize logging: {e:?}");
            -1
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn configuring_logging() {
        assert_eq!(log::LevelFilter::Off, log::max_level());
        let result = super::configure_logging(log::LevelFilter::Info);
        assert_eq!(0, result);
        assert_eq!(log::LevelFilter::Info, log::max_level());
    }
}
