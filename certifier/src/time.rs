use std::time::{SystemTime, UNIX_EPOCH};

pub fn unix_timestamp(t: SystemTime) -> u64 {
    t.duration_since(UNIX_EPOCH)
        .expect("system time is before unix epoch")
        .as_secs()
}
