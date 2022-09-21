#[cfg(test)]
mod test_generate {
    use rustgenpass::{generate, generate_with_config};

    #[test]
    fn generate_works_like_generate_with_config() {
        assert_eq!("jHMOHn7bRs", generate("masterpassword", "example.com"));
        assert_eq!(
            generate_with_config("masterpassword", "example.com", None, 10, 10),
            generate("masterpassword", "example.com")
        );
    }
}

#[cfg(test)]
mod test_generate_with_config {
    use rustgenpass::generate_with_config;

    #[test]
    fn with_length() {
        assert_eq!(
            "xe4X3",
            generate_with_config("masterpassword", "example.com", None, 5, 10)
        );
        assert_eq!(
            "jHMOHn7bRs",
            generate_with_config("masterpassword", "example.com", None, 10, 10)
        );
        assert_eq!(
            "jHMOHn7bRszh9PiXKswZEwAA",
            generate_with_config("masterpassword", "example.com", None, 24, 10)
        );
    }

    #[test]
    fn with_hash_rounds() {
        assert_eq!(
            "lZKJ9s3A1o",
            generate_with_config("masterpassword", "example.com", None, 10, 1)
        );
        assert_eq!(
            "jHMOHn7bRs",
            generate_with_config("masterpassword", "example.com", None, 10, 10)
        );
        assert_eq!(
            "v7txjtuTvz",
            generate_with_config("masterpassword", "example.com", None, 10, 50)
        );
    }

    #[test]
    fn with_secret() {
        let secret = Some("secret".to_string());
        assert_eq!(
            "h9Rh",
            generate_with_config("masterpassword", "example.com", secret.clone(), 4, 10)
        );
        assert_eq!(
            "fqProIJ38f",
            generate_with_config("masterpassword", "example.com", secret.clone(), 10, 10)
        );
        assert_eq!(
            "fqProIJ38f5wZrTJM3QRwwAA",
            generate_with_config("masterpassword", "example.com", secret.clone(), 24, 10)
        );
    }
}
