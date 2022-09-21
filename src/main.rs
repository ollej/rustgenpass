use clap::Parser;
use rustgenpass::{generate_with_config, get_hostname, Cli};

fn main() -> Result<(), String> {
    /* TODO:
     * Support sha512 hashing
     * Builder interface for library
     */
    let cli = Cli::parse();
    let password = cli.password.unwrap_or_else(|| {
        rpassword::prompt_password("Enter master password: ").expect("You must enter a password.")
    });
    let domain = get_hostname(cli.domain, cli.keep_subdomains, cli.passthrough)?;
    let generated_password =
        generate_with_config(password, domain, cli.secret, cli.length, cli.rounds);
    println!("{}", generated_password);
    Ok(())
}
