use clap::Parser;
use rustgenpass::{generate_with_config, get_hostname_with_config, Cli};

fn main() -> Result<(), String> {
    let cli = Cli::parse();
    let password = cli.password.unwrap_or_else(|| {
        rpassword::prompt_password("Enter master password: ").expect("You must enter a password.")
    });
    let domain = get_hostname_with_config(cli.domain, cli.keep_subdomains, cli.passthrough)?;
    let generated_password = generate_with_config(
        password, domain, cli.secret, cli.length, cli.rounds, cli.hash,
    );
    println!("{}", generated_password);
    Ok(())
}
