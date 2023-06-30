use regex::Regex;

const PLATFORMS_BLACKLIST_ENV: &str = "POST_OCL_PLATFORMS_BLACKLIST";
const DEVICES_BLACKLIST_ENV: &str = "POST_OCL_DEVICES_BLACKLIST";

fn create_blacklist_filter(blacklist_re: Option<&str>) -> Box<dyn Fn(&str) -> bool> {
    blacklist_re
        .and_then(|re| -> Option<Box<dyn Fn(&str) -> bool>> {
            match Regex::new(re) {
                Ok(re) => Some(Box::new(move |name| !re.is_match(name))),
                Err(e) => {
                    log::warn!("Invalid blacklist regex: ({e})");
                    None
                }
            }
        })
        .unwrap_or(Box::new(|_| true))
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
        assert_eq!(filter("foo"), false);
        assert_eq!(filter("bar"), true);
        assert_eq!(filter(""), true);
    }

    #[test]
    fn test_regex_filter() {
        let filter = super::create_blacklist_filter(Some("foo|bar"));
        assert_eq!(filter("foo"), false);
        assert_eq!(filter("bar"), false);
        assert_eq!(filter("baz"), true);
    }

    #[test]
    fn test_invalid_regex_filter() {
        let filter = super::create_blacklist_filter(Some("fo(o"));
        assert_eq!(filter("foo"), true);
        assert_eq!(filter("bar"), true);
    }

    #[test]
    fn test_device_filter_env_not_set() {
        let filter = super::create_device_filter();
        assert_eq!(filter("foo"), true);
    }

    #[test]
    fn test_device_filter_env_set() {
        std::env::set_var(super::DEVICES_BLACKLIST_ENV, "foo");
        let filter = super::create_device_filter();
        assert_eq!(filter("foo"), false);
        assert_eq!(filter("bar"), true);
    }

    #[test]
    fn test_platform_filter_env_set() {
        std::env::set_var(super::PLATFORMS_BLACKLIST_ENV, "foo");
        let filter = super::create_platform_filter();
        assert_eq!(filter("foo"), false);
        assert_eq!(filter("bar"), true);
    }
}
