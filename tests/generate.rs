use rustgenpass::generate;

#[test]
fn generate_password() {
    assert_eq!("jHMOHn7bRs", generate("masterpassword", "example.com"));
}
