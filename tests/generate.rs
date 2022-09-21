use rustgenpass::generate;

#[test]
fn generate_password_length() {
    assert_eq!(
        "xe4X3",
        generate("masterpassword", "example.com", None, 5, 10)
    );
    assert_eq!(
        "jHMOHn7bRs",
        generate("masterpassword", "example.com", None, 10, 10)
    );
    assert_eq!(
        "jHMOHn7bRszh9PiXKswZEwAA",
        generate("masterpassword", "example.com", None, 24, 10)
    );
}

#[test]
fn generate_password_rounds() {
    assert_eq!(
        "lZKJ9s3A1o",
        generate("masterpassword", "example.com", None, 10, 1)
    );
    assert_eq!(
        "jHMOHn7bRs",
        generate("masterpassword", "example.com", None, 10, 10)
    );
    assert_eq!(
        "v7txjtuTvz",
        generate("masterpassword", "example.com", None, 10, 50)
    );
}

#[test]
fn generate_password_with_secret() {
    let secret = Some("secret".to_string());
    assert_eq!(
        "h9Rh",
        generate("masterpassword", "example.com", secret.clone(), 4, 10)
    );
    assert_eq!(
        "fqProIJ38f",
        generate("masterpassword", "example.com", secret.clone(), 10, 10)
    );
    assert_eq!(
        "fqProIJ38f5wZrTJM3QRwwAA",
        generate("masterpassword", "example.com", secret.clone(), 24, 10)
    );
}
