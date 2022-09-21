use clap::Parser;
use rustgenpass::{generate, get_hostname, Cli};

fn main() -> Result<(), String> {
    /* TODO:
     * Add tests
     * Support secret
     * Support sha512 hashing
     * Write documentation
     */
    let cli = Cli::parse();
    let password = cli.password.unwrap_or_else(|| {
        rpassword::prompt_password("Enter master password: ").expect("You must enter a password.")
    });
    let domain = get_hostname(cli.domain, cli.keep_subdomains, cli.passthrough)?;
    let generated_password = generate(password, domain, cli.secret, cli.length, cli.rounds);
    println!("{}", generated_password);
    Ok(())
}
