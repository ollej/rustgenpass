//! An implementation in Rust of the [SuperGenPass](https://chriszarate.github.io/supergenpass/) utility.
//!
//! Hash a master password into unique, complex passwords specific for each
//! website.
//!
//! # Examples
//!
//! ## Use default to parse domain from URL and strip subdomains
//! ```
//! use rustgenpass::generate_with_url;
//! let generated_password = generate_with_url("masterpassword", "http://www.example.com/foo/bar.html");
//! assert_eq!("jHMOHn7bRs", generated_password);
//! ```
//!
//! ## With configuration matching defaults
//! ```rust
//! use rustgenpass::{ generate_with_config, HashAlgorithm };
//! let generated_password = generate_with_config("masterpassword", "example.com", None, 10, 10, HashAlgorithm::MD5);
//! assert_eq!("jHMOHn7bRs", generated_password);
//! ```
//!
//! ## With configuration matching defaults
//! ```rust
//! use rustgenpass::{ generate_with_config, HashAlgorithm };
//! let generated_password = generate_with_config("masterpassword", "example.com", Some("secret".to_string()), 24, 50, HashAlgorithm::MD5);
//! assert_eq!("izHhm22SMfZeg8Q3t2BrZgAA", generated_password);
//! ```
//!
//! ## Full example with hostname isolation from URL
//! ```rust
//! use rustgenpass::{ get_hostname, generate_with_config, HashAlgorithm };
//! let domain = get_hostname("https://www.example.com/foo/bar.html").unwrap();
//! let generated_password = generate_with_config("masterpassword", &domain, Some("secret".to_string()), 24, 50, HashAlgorithm::MD5);
//! assert_eq!("izHhm22SMfZeg8Q3t2BrZgAA", generated_password);
//! ```
//!
//! ## Full example using SHA512 hashing
//! ```rust
//! use rustgenpass::{ get_hostname, generate_with_config, HashAlgorithm };
//! let domain = get_hostname("https://www.example.com/foo/bar.html").unwrap();
//! let generated_password = generate_with_config("masterpassword", &domain, Some("secret".to_string()), 24, 50, HashAlgorithm::SHA512);
//! assert_eq!("awqhRUhYQSj48FIp678e84LO", generated_password);
//! ```
//!
//! ## Full example with passthrough of URL
//! ```rust
//! use rustgenpass::{ get_hostname_with_config, generate_with_config, HashAlgorithm };
//! let domain = get_hostname_with_config("https://www.example.com/foo/bar.html", true, false).unwrap();
//! let generated_password = generate_with_config("masterpassword", &domain, None, 24, 50, HashAlgorithm::MD5);
//! assert_eq!("ufLehPcQ8FgvRZX8ZHOg5wAA", generated_password);
//! ```

#[macro_use]
extern crate lazy_static;
use clap::Parser;
use md5::Md5;
use regex::Regex;
use sha2::{Digest, Sha512};

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

/// Generate a hashed password from URL with default options.
///
/// # Arguments
///
/// * `password` - Master password to generate hashed password from
/// * `url` - URL to generate password for, will be stripped to domain
///
/// # Examples
///
/// ```
/// use rustgenpass::generate_with_url;
/// let generated_password = generate_with_url("masterpassword", "https://www.example.com/foo/bar.html");
/// assert_eq!("jHMOHn7bRs", generated_password);
/// ```
pub fn generate_with_url<S: Into<String>>(password: S, url: S) -> String {
    let domain = get_hostname(url).expect("Couldn't parse URL");
    generate_with_config(password.into(), domain, None, 10, 10, HashAlgorithm::MD5)
}

/// Generate a hashed password with default options.
///
/// # Arguments
///
/// * `password` - Master password to generate hashed password from
/// * `domain` - Domain / URL to generate password for
///
/// # Examples
///
/// ```
/// use rustgenpass::generate;
/// let generated_password = generate("masterpassword", "example.com");
/// assert_eq!("jHMOHn7bRs", generated_password);
/// ```
pub fn generate<S: Into<String>>(password: S, domain: S) -> String {
    generate_with_config(password, domain, None, 10, 10, HashAlgorithm::MD5)
}

/// Generate a hashed password with given options.
///
/// # Arguments
///
/// * `password` - Master password to generate hashed password from
/// * `domain` - Domain / URL to generate password for
/// * `secret` - Secret added to the master password
/// * `length` - Length of generated password, min: 4, max: 24
/// * `hash_rounds` - Number of hash rounds
/// * `hash_algorithm` - Hashing algorithm to use
///
/// # Examples
///
/// ```
/// use rustgenpass::{generate_with_config, HashAlgorithm};
/// let generated_password = generate_with_config("masterpassword", "example.com", Some("secret".to_string()), 10, 10, HashAlgorithm::MD5);
/// assert_eq!("fqProIJ38f", generated_password);
/// ```
pub fn generate_with_config<S: Into<String>>(
    password: S,
    domain: S,
    secret: Option<String>,
    length: u8,
    hash_rounds: u8,
    hash_algorithm: HashAlgorithm,
) -> String {
    let length = length as usize;
    let mut hash: String = format!(
        "{}{}:{}",
        password.into(),
        secret.unwrap_or("".to_string()),
        domain.into()
    );

    // Hash the input for the requested number of rounds, then continue hashing
    // until the password policy is satisfied.
    let mut i = 0;
    while i < hash_rounds || !validate_password(&hash[..length]) {
        hash = match hash_algorithm {
            HashAlgorithm::MD5 => base64_md5(hash),
            HashAlgorithm::SHA512 => base64_sha512(hash),
        };
        i += 1;
    }

    hash[..length].to_string()
}

/// Isolate the domain name of a URL with default config.
///
/// # Arguments
///
/// * `domain` - Domain / URL to get base hostname for
///
/// # Examples
///
/// ```
/// use rustgenpass::get_hostname;
/// let hostname = get_hostname("https://user:pass@www.example.com:4711/path/file.html");
/// assert_eq!("example.com", hostname.unwrap());
/// ```
pub fn get_hostname<S: Into<String>>(domain: S) -> Result<String, String> {
    get_hostname_with_config(domain, false, false)
}

/// Isolate the domain name of a URL.
///
/// # Arguments
///
/// * `domain` - Domain / URL to get base hostname for
/// * `passthrough` -  Passthrough domain unmodified to hash function
/// * `keep_subdomains` - Don't remove subdomains from domain
///
/// # Examples
///
/// ```
/// use rustgenpass::get_hostname_with_config;
/// let hostname = get_hostname_with_config("https://user:pass@www.example.com:4711/path/file.html", false, false);
/// assert_eq!("example.com", hostname.unwrap());
/// ```
pub fn get_hostname_with_config<S: Into<String>>(
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

    // If the hostname is an IP address, no further processing can be done.
    if RE_IP_ADDRESS.is_match(hostname) || keep_subdomains {
        return Ok(hostname.to_string());
    }

    // Return the hostname with subdomains removed, if requested.
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

fn validate_password<S: Into<String>>(password: S) -> bool {
    let password = password.into();
    RE_STARTS_WITH_LOWERCASE_LETTER.is_match(&password)
        && RE_CONATINS_NUMERAL.is_match(&password)
        && RE_CONTAINS_UPPERCASE_LETTER.is_match(&password)
}

fn base64_md5<S: Into<String>>(hash: S) -> String {
    let mut hasher = Md5::new();
    hasher.update(hash.into());
    let digest = hasher.finalize();
    base64_encode(&digest)
}

fn base64_sha512<S: Into<String>>(hash: S) -> String {
    let mut hasher = Sha512::new();
    hasher.update(hash.into());
    let digest = hasher.finalize();
    base64_encode(&digest)
}

fn base64_encode(digest: &[u8]) -> String {
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

#[derive(Clone, clap::ArgEnum)]
/// Supported hashing algorithms
pub enum HashAlgorithm {
    MD5,
    SHA512,
}

#[derive(Parser)]
#[clap(author, version, about, long_about = None)]
/// Options parsed from command line used by the binary
pub struct Cli {
    /// Master password, if not given, reads from stdin
    #[clap(short, long, value_parser)]
    pub password: Option<String>,

    /// Secret added to the master password
    #[clap(short, long, value_parser)]
    pub secret: Option<String>,

    /// Domain / URL to generate password for
    #[clap(short, long, value_parser)]
    pub domain: String,

    /// Length of generated password, min: 4, max: 24
    #[clap(short, long, default_value_t = 10, value_parser = clap::value_parser!(u8).range(4..=24))]
    pub length: u8,

    /// Number of hash rounds
    #[clap(short, long, default_value_t = 10)]
    pub rounds: u8,

    /// Don't remove subdomains from domain
    #[clap(short, long, action)]
    pub keep_subdomains: bool,

    /// Passthrough domain unmodified to hash function
    #[clap(short = 'P', long, action)]
    pub passthrough: bool,

    /// Hashing method to use
    #[clap(short = 'H', long, arg_enum, default_value_t = HashAlgorithm::MD5)]
    pub hash: HashAlgorithm,
}

#[cfg(test)]
mod test_validate_password {
    use super::*;

    #[test]
    fn validates_minimal_example() {
        assert!(validate_password("aB9"));
    }

    #[test]
    fn requires_an_uppercase_letter() {
        assert_eq!(false, validate_password("a"));
    }

    #[test]
    fn requires_password_to_start_with_lowercase_letter() {
        assert_eq!(false, validate_password("A"));
    }

    #[test]
    fn requires_a_number() {
        assert_eq!(false, validate_password("aA"));
    }
}
