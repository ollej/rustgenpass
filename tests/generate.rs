#[cfg(test)]
mod test_generate_with_url {
    use rustgenpass::{GenerateConfig, generate_with_config, generate_with_url};

    #[test]
    fn generate_with_url_works_like_generate_with_config() {
        assert_eq!(
            "jHMOHn7bRs",
            generate_with_url("masterpassword", "https://www.example.com/foo/bar.html")
        );
        assert_eq!(
            generate_with_config("masterpassword", "example.com", GenerateConfig::default()),
            generate_with_url("masterpassword", "https://www.example.com/foo/bar.html")
        );
    }
}

#[cfg(test)]
mod test_generate {
    use rustgenpass::{GenerateConfig, generate, generate_with_config};

    #[test]
    fn generate_works_like_generate_with_config() {
        assert_eq!("jHMOHn7bRs", generate("masterpassword", "example.com"));
        assert_eq!(
            generate_with_config("masterpassword", "example.com", GenerateConfig::default()),
            generate("masterpassword", "example.com")
        );
    }
}

#[cfg(test)]
mod test_generate_with_config {
    use rustgenpass::{GenerateConfig, HashAlgorithm, generate_with_config};

    #[test]
    fn with_length() {
        assert_eq!(
            "xe4X3",
            generate_with_config(
                "masterpassword",
                "example.com",
                GenerateConfig {
                    length: 5,
                    ..GenerateConfig::default()
                }
            )
        );
        assert_eq!(
            "jHMOHn7bRs",
            generate_with_config("masterpassword", "example.com", GenerateConfig::default())
        );
        assert_eq!(
            "jHMOHn7bRszh9PiXKswZEwAA",
            generate_with_config(
                "masterpassword",
                "example.com",
                GenerateConfig {
                    length: 24,
                    ..GenerateConfig::default()
                }
            )
        );
    }

    #[test]
    fn with_hash_rounds() {
        assert_eq!(
            "lZKJ9s3A1o",
            generate_with_config(
                "masterpassword",
                "example.com",
                GenerateConfig {
                    hash_rounds: 1,
                    ..GenerateConfig::default()
                }
            )
        );
        assert_eq!(
            "jHMOHn7bRs",
            generate_with_config(
                "masterpassword",
                "example.com",
                GenerateConfig {
                    hash_rounds: 10,
                    ..GenerateConfig::default()
                }
            )
        );
        assert_eq!(
            "v7txjtuTvz",
            generate_with_config(
                "masterpassword",
                "example.com",
                GenerateConfig {
                    hash_rounds: 50,
                    ..GenerateConfig::default()
                }
            )
        );
    }

    #[test]
    fn with_secret() {
        let secret = Some("secret".to_string());
        assert_eq!(
            "h9Rh",
            generate_with_config(
                "masterpassword",
                "example.com",
                GenerateConfig {
                    secret: secret.clone(),
                    length: 4,
                    ..GenerateConfig::default()
                }
            )
        );
        assert_eq!(
            "fqProIJ38f",
            generate_with_config(
                "masterpassword",
                "example.com",
                GenerateConfig {
                    secret: secret.clone(),
                    ..GenerateConfig::default()
                }
            )
        );
        assert_eq!(
            "fqProIJ38f5wZrTJM3QRwwAA",
            generate_with_config(
                "masterpassword",
                "example.com",
                GenerateConfig {
                    secret: secret.clone(),
                    length: 24,
                    ..GenerateConfig::default()
                }
            )
        );
    }

    #[test]
    fn hashing_with_sha512() {
        let secret = Some("secret".to_string());
        assert_eq!(
            "pAF9",
            generate_with_config(
                "masterpassword",
                "example.com",
                GenerateConfig {
                    secret: secret.clone(),
                    length: 4,
                    hash_algorithm: HashAlgorithm::SHA512,
                    ..GenerateConfig::default()
                }
            )
        );
        assert_eq!(
            "wqSjM4Vrmz",
            generate_with_config(
                "masterpassword",
                "example.com",
                GenerateConfig {
                    secret: secret.clone(),
                    hash_algorithm: HashAlgorithm::SHA512,
                    ..GenerateConfig::default()
                }
            )
        );
        assert_eq!(
            "wqSjM4Vrmzjrpz2MyMHcpHBY",
            generate_with_config(
                "masterpassword",
                "example.com",
                GenerateConfig {
                    secret: secret.clone(),
                    length: 24,
                    hash_algorithm: HashAlgorithm::SHA512,
                    ..GenerateConfig::default()
                }
            )
        );
    }
}
