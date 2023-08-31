use regex::Regex;

const PLATFORMS_BLACKLIST_ENV: &str = "POST_OCL_PLATFORMS_BLACKLIST";
const DEVICES_BLACKLIST_ENV: &str = "POST_OCL_DEVICES_BLACKLIST";

fn create_blacklist_filter(blacklist_re: Option<&str>) -> Box<dyn Fn(&str) -> bool> {
    let Some(blacklist_re) = blacklist_re else {
        return Box::new(|_| true);
    };
    match Regex::new(blacklist_re) {
        Ok(re) => {
            log::debug!("Using blacklist filter: {}", blacklist_re);
            Box::new(move |name: &str| !re.is_match(name))
        }
        Err(e) => {
            log::error!("Invalid blacklist filter: {}", e);
            Box::new(|_| true)
        }
    }
}

pub(crate) fn create_platform_filter() -> Box<dyn Fn(&str) -> bool> {
    create_blacklist_filter(std::env::var(PLATFORMS_BLACKLIST_ENV).ok().as_deref())
}

pub(crate) fn create_device_filter() -> Box<dyn Fn(&str) -> bool> {
    create_blacklist_filter(std::env::var(DEVICES_BLACKLIST_ENV).ok().as_deref())
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_create_filter() {
        let filter = super::create_blacklist_filter(Some("foo"));

        assert!(!filter("foo"));
        assert!(filter("bar"));
        assert!(filter(""));
    }

    #[test]
    fn test_regex_filter() {
        let filter = super::create_blacklist_filter(Some("foo|bar"));
        assert!(!filter("foo"));
        assert!(!filter("bar"));
        assert!(filter("baz"));
    }

    #[test]
    fn test_invalid_regex_filter() {
        let filter = super::create_blacklist_filter(Some("fo(o"));
        assert!(filter("foo"));
    }

    #[test]
    fn test_device_filter_env_set() {
        std::env::set_var(super::DEVICES_BLACKLIST_ENV, "foo");
        let filter = super::create_device_filter();
        assert!(!filter("foo"));
        assert!(filter("bar"));
    }

    #[test]
    fn test_platform_filter_env_set() {
        std::env::set_var(super::PLATFORMS_BLACKLIST_ENV, "foo");
        let filter = super::create_platform_filter();
        assert!(!filter("foo"));
        assert!(filter("bar"));
    }
}
