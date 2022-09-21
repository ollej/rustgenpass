#[macro_use]
extern crate lazy_static;
use clap::Parser;
use md5::{Digest, Md5};
use regex::Regex;

lazy_static! {
    static ref RE_STARTS_WITH_LOWERCASE_LETTER: Regex = Regex::new(r"^[a-z]").unwrap();
    static ref RE_CONTAINS_UPPERCASE_LETTER: Regex = Regex::new(r"[A-Z]").unwrap();
    static ref RE_CONATINS_NUMERAL: Regex = Regex::new(r"[0-9]").unwrap();
    static ref RE_DOMAIN: Regex = Regex::new(r"^(?:[a-zA-Z]+://)?(?:[^/@]+@)?([^/:]+)").unwrap();
    static ref RE_IP_ADDRESS: Regex = Regex::new(r"^\d{1,3}\.\d{1,3}.\d{1,3}\.\d{1,3}$").unwrap();
    static ref TLD_LIST: Vec<String> = include_str!("tldlist.txt")
        .lines()
        .map(String::from)
        .collect();
}

pub fn get_hostname<S: Into<String>>(
    domain: S,
    passthrough: bool,
    keep_subdomains: bool,
) -> Result<String, String> {
    let domain = domain.into();
    if passthrough {
        return Ok(domain);
    }
    let hostname = match RE_DOMAIN.captures(domain.as_ref()) {
        Some(hostname) => hostname.get(1).unwrap().as_str(),
        None => return Err(format!("URL is invalid: {}", domain)),
    };
    if RE_IP_ADDRESS.is_match(hostname) || keep_subdomains {
        return Ok(hostname.to_string());
    }
    Ok(remove_subdomain(hostname.to_string()))
}

/// Remove subdomains while respecting a number of secondary ccTLDs.
fn remove_subdomain<S: Into<String>>(hostname: S) -> String {
    let hostname = hostname.into().to_lowercase();
    let parts = hostname.split(".").collect::<Vec<&str>>();

    // A hostname with less than three parts is as short as it will get.
    if parts.len() < 2 {
        return hostname;
    }

    // Try to find a match in the list of ccTLDs.
    if let Some(cc_tld) = TLD_LIST
        .iter()
        .find(|&subdomain| hostname.ends_with(subdomain))
    {
        // Get one extra part from the hostname.
        let part_count = cc_tld.matches('.').count() + 1;
        return parts[(parts.len() - part_count)..].join(".");
    }

    // If no ccTLDs were matched, return the final two parts of the hostname.
    parts.as_slice()[parts.len() - 2..].join(".")
}

fn strong_enough<S: AsRef<str>>(password: S) -> bool {
    RE_STARTS_WITH_LOWERCASE_LETTER.is_match(password.as_ref())
        && RE_CONATINS_NUMERAL.is_match(password.as_ref())
        && RE_CONTAINS_UPPERCASE_LETTER.is_match(password.as_ref())
}

fn b64_md5<S: AsRef<str>>(hash: S) -> String {
    let mut hasher = Md5::new();
    hasher.update(hash.as_ref());
    let digest = hasher.finalize();
    let b64_md5 = base64::encode(digest);
    b64_md5
        .chars()
        .map(|x| match x {
            '=' => 'A',
            '+' => '9',
            '/' => '8',
            _ => x,
        })
        .collect()
}

pub fn generate<S: AsRef<str>>(
    password: S,
    domain: S,
    secret: Option<String>,
    length: u8,
    hash_rounds: u8,
) -> String {
    let length = length as usize;
    let mut hash: String = format!(
        "{}{}:{}",
        password.as_ref(),
        secret.unwrap_or("".to_string()),
        domain.as_ref()
    );

    let mut i = 0;
    while i < hash_rounds || !strong_enough(&hash[..length]) {
        hash = b64_md5(hash);
        i += 1;
    }

    hash[..length].to_string()
}

#[derive(Parser)]
#[clap(author, version, about, long_about = None)]
pub struct Cli {
    /// Master password, if not given, reads from stdin
    #[clap(short, long, value_parser)]
    pub password: Option<String>,

    /// Secret added to the master password
    #[clap(short, long, value_parser)]
    pub secret: Option<String>,

    /// Domain / URL
    #[clap(short, long, value_parser)]
    pub domain: String,

    /// Length of password, min: 4, max: 24
    #[clap(short, long, default_value_t = 10, value_parser = clap::value_parser!(u8).range(4..=24))]
    pub length: u8,

    /// Number of hash rounds
    #[clap(short, long, default_value_t = 10)]
    pub rounds: u8,

    /// Don't remove subdomain from domain
    #[clap(short, long, action)]
    pub keep_subdomains: bool,

    /// Passthrough domain unmodified to hash function
    #[clap(short = 'P', long, action)]
    pub passthrough: bool,
}

#[cfg(test)]
mod strong_enough {
    use super::*;

    #[test]
    fn validates_minimal_example() {
        assert!(strong_enough("aB9"));
    }

    #[test]
    fn requires_an_uppercase_letter() {
        assert_eq!(false, strong_enough("a"));
    }

    #[test]
    fn requires_password_to_start_with_lowercase_letter() {
        assert_eq!(false, strong_enough("A"));
    }

    #[test]
    fn requires_a_number() {
        assert_eq!(false, strong_enough("aA"));
    }
}
