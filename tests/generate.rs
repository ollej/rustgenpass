use rustgenpass::generate;

#[test]
fn generate_password() {
    assert_eq!("xe4X3", generate("masterpassword", "example.com", 5));
    assert_eq!("jHMOHn7bRs", generate("masterpassword", "example.com", 10));
    assert_eq!(
        "jHMOHn7bRszh9PiXKswZEwAA",
        generate("masterpassword", "example.com", 24)
    );
}
