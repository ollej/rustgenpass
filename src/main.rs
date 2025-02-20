use rustgenpass::{Cli, generate_with_config, get_hostname_with_config};
use {
    clap::Parser,
    dialoguer::{Input, Password},
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    let input_domain = if let Some(domain) = cli.domain.clone() {
        domain
    } else {
        Input::new().with_prompt("Domain").interact()?
    };
    let password = if let Some(password) = cli.password.clone() {
        password
    } else {
        Password::new()
            .with_prompt("Enter master password")
            .interact()?
    };
    let domain = get_hostname_with_config(input_domain, cli.clone().into())?;
    let generated_password = generate_with_config(password, domain, cli.into());
    println!("{}", generated_password);
    Ok(())
}
