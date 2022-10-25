RustGenPass
===========

[![Cross-compile](https://github.com/ollej/rustgenpass/actions/workflows/crosscompile.yml/badge.svg)](https://github.com/ollej/rustgenpass/actions/workflows/crosscompile.yml) [![Crates.io](https://img.shields.io/crates/v/rustgenpass)](https://crates.io/crates/rustgenpass) [![docs.rs](https://img.shields.io/docsrs/rustgenpass)](https://docs.rs/rustgenpass/latest/rustgenpass/) [![Crates.io](https://img.shields.io/crates/l/rustgenpass)](https://opensource.org/licenses/MIT)

An implementation in Rust of the [SuperGenPass](https://chriszarate.github.io/supergenpass/) utility.

Hash a master password into unique, complex passwords specific for each
website.

[Documentation](https://docs.rs/rustgenpass/latest/rustgenpass/) on docs.rs

Usage
-----

```
rustgenpass 0.5.0
Generate a hashed password similar to SuperGenPass.

USAGE:
    rgp [OPTIONS] --domain <DOMAIN>

OPTIONS:
  -p, --password <PASSWORD>  Master password, if not given, reads from stdin
  -s, --secret <SECRET>      Secret added to the master password
  -d, --domain <DOMAIN>      Domain / URL to generate password for
  -l, --length <LENGTH>      Length of generated password, min: 4, max: 24 [default: 10]
  -r, --rounds <ROUNDS>      Number of hash rounds [default: 10]
  -k, --keep-subdomains      Don't remove subdomains from domain
  -P, --passthrough          Passthrough domain unmodified to hash function
  -H, --hash <HASH>          Hashing method to use [default: md5] [possible values: md5, sha512]
  -h, --help                 Print help information
  -V, --version              Print version information
```

License
-------

Copyright 2022 Olle Wreede

Released under the [MIT license](https://opensource.org/licenses/MIT).
