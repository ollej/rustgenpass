use regex::Regex;
use rustgenpass::get_hostname;

#[test]
fn passes_through_input() {
    let url = "https://www.example.com/foo/bar.html";
    assert_eq!(url, get_hostname(url, true, false).unwrap());
}

#[test]
fn returns_error_with_empty_string() {
    let url = "";
    assert!(get_hostname(url, false, false).is_err());
}

#[test]
fn returns_string() {
    let url = "%invalid_url%";
    assert_eq!("%invalid_url%", get_hostname(url, false, false).unwrap());
}

#[test]
fn returns_ip_address() {
    let url = "https://127.0.0.1/foo/bar.html";
    assert_eq!("127.0.0.1", get_hostname(url, false, false).unwrap());
}

#[test]
fn keep_subdomains_flag() {
    let url = "https://foo.bar.example.com/foo/bar.html";
    assert_eq!(
        "foo.bar.example.com",
        get_hostname(url, false, true).unwrap()
    );
}

#[test]
fn removes_subdomains() {
    let url = "https://foo.bar.example.com/foo/bar.html";
    assert_eq!("example.com", get_hostname(url, false, false).unwrap());
}

#[test]
fn keeps_cc_tld() {
    let url = "https://foo.bar.example.co.uk/foo/bar.html";
    assert_eq!("example.co.uk", get_hostname(url, false, false).unwrap());
}

#[test]
fn returns_single_hostname_as_is() {
    let url = "https://localhost/foo/bar.html";
    assert_eq!("localhost", get_hostname(url, false, false).unwrap());
}

#[test]
fn ignores_port() {
    let url = "https://localhost:4711/foo/bar.html";
    assert_eq!("localhost", get_hostname(url, false, false).unwrap());
}

#[test]
fn ignores_username_and_password() {
    let url = "https://foo:bar@localhost/foo/bar.html";
    assert_eq!("localhost", get_hostname(url, false, false).unwrap());
}

#[test]
fn test_regex_without_match() {
    let url = "";
    let re_domain = Regex::new(r"^(?i)(?:[a-z]+://)?(?:[^/@]+@)?([^/:]+)").unwrap();
    let captures = re_domain.captures(url.as_ref());
    assert!(captures.is_none());
}

#[test]
fn test_regex() {
    let url = "https://127.0.0.1/foo/bar.html";
    let re_domain = Regex::new(r"^(?i)(?:[a-z]+://)?(?:[^/@]+@)?([^/:]+)").unwrap();
    let captures = re_domain.captures(url.as_ref()).unwrap();
    assert_eq!(Some("127.0.0.1"), captures.get(1).map(|m| m.as_str()));
}
