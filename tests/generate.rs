use rustgenpass::generate;

#[test]
fn generate_password_length() {
    assert_eq!("xe4X3", generate("masterpassword", "example.com", 5, 10));
    assert_eq!(
        "jHMOHn7bRs",
        generate("masterpassword", "example.com", 10, 10)
    );
    assert_eq!(
        "jHMOHn7bRszh9PiXKswZEwAA",
        generate("masterpassword", "example.com", 24, 10)
    );
}

#[test]
fn generate_password_rounds() {
    assert_eq!(
        "lZKJ9s3A1o",
        generate("masterpassword", "example.com", 10, 1)
    );
    assert_eq!(
        "jHMOHn7bRs",
        generate("masterpassword", "example.com", 10, 10)
    );
    assert_eq!(
        "v7txjtuTvz",
        generate("masterpassword", "example.com", 10, 50)
    );
}
