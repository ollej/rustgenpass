use clap::Parser;
use rustgenpass::{generate, get_hostname, Cli};

fn main() -> Result<(), String> {
    /* TODO:
     * Add tests
     * Implement get_top_domain
     * Support length
     * Support hash_rounds
     * Support not stripping domain
     * Support secret
     * Make into library
     * Write documentation
     */
    let cli = Cli::parse();
    let password = cli.password.unwrap_or_else(|| {
        rpassword::prompt_password("Enter master password: ").expect("You must enter a password.")
    });
    let domain = get_hostname(cli.domain, cli.keep_subdomains, cli.passthrough)?;
    let generated_password = generate(password, domain, cli.length);
    println!("{}", generated_password);
    Ok(())
}
