#[macro_use]
extern crate lazy_static;
use md5::{Digest, Md5};
use regex::Regex;

lazy_static! {
    static ref RE_STARTS_WITH_LOWERCASE_LETTER: Regex = Regex::new(r"^[a-z]").unwrap();
    static ref RE_CONTAINS_UPPERCASE_LETTER: Regex = Regex::new(r"[A-Z]").unwrap();
    static ref RE_CONATINS_NUMERAL: Regex = Regex::new(r"[0-9]").unwrap();
    static ref RE_URI_MATCH: Regex = Regex::new(
        r"^(?:http|https|ftp|ftps|webdav|gopher|rtsp|irc|nntp|pop|imap|smtp):\/\/([^\/:]+)"
    )
    .unwrap();
    static ref RE_IP_MATCH: Regex =
        Regex::new(r"^([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})$").unwrap();
    static ref TLD_LIST: Vec<String> = include_str!("tldlist.txt")
        .lines()
        .map(String::from)
        .collect();
}

fn get_top_domain(domain: &str) -> &str {
    domain
}

fn strong_enough(password: &str) -> bool {
    RE_STARTS_WITH_LOWERCASE_LETTER.is_match(password)
        && RE_CONATINS_NUMERAL.is_match(password)
        && RE_CONTAINS_UPPERCASE_LETTER.is_match(password)
}

fn b64_md5(hash: String) -> String {
    let mut hasher = Md5::new();
    hasher.update(hash);
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

fn generate(password: &str, domain: &str) -> String {
    let length = 10;
    let hash_rounds = 10;
    let domain = get_top_domain(domain);
    let mut hash: String = format!("{password}:{domain}");

    let mut i = 0;
    while i < hash_rounds || !strong_enough(&hash[..=length]) {
        hash = b64_md5(hash);
        i += 1;
    }

    hash[..=length].to_string()
}

fn main() {
    println!("generated hash: {}", generate("test", "example"));
}
