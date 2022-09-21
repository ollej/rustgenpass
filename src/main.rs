#[macro_use]
extern crate lazy_static;
use clap::Parser;
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

fn get_top_domain<S: AsRef<str>>(domain: S) -> S {
    domain
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

fn generate<S: AsRef<str>>(password: S, domain: S) -> String {
    let length = 10;
    let hash_rounds = 10;
    let domain = get_top_domain(domain);
    let mut hash: String = format!("{}:{}", password.as_ref(), domain.as_ref());

    let mut i = 0;
    while i < hash_rounds || !strong_enough(&hash[..=length]) {
        hash = b64_md5(hash);
        i += 1;
    }

    hash[..=length].to_string()
}

#[derive(Parser)]
#[clap(author, version, about, long_about = None)]
struct Cli {
    /// Master password, if not given, reads from stdin
    #[clap(short, long, value_parser)]
    password: Option<String>,

    /// Domain / URL
    #[clap(short, long, value_parser)]
    domain: Option<String>,

    /// Length of password
    #[clap(short, long, default_value_t = 10)]
    length: u8,

    /// Number of hash rounds
    #[clap(short, long, default_value_t = 10)]
    rounds: u8,

    /// Don't remove subdomain from domain
    #[clap(short, long, action)]
    keep_subdomains: bool,

    /// Passthrough domain unmodified to hash function
    #[clap(short = 'P', long, action)]
    passthrough: bool,
}

fn main() {
    /* TODO:
     * Add tests
     * Implement get_top_domain
     * Support length
     * Support hash_rounds
     * Support not stripping domain
     */
    let cli = Cli::parse();
    let password = cli.password.unwrap_or_else(|| {
        rpassword::prompt_password("Enter master password: ").expect("You must enter a password.")
    });
    let generated_password = generate(password, cli.domain.unwrap_or("".to_string()));
    println!("{}", generated_password);
}
