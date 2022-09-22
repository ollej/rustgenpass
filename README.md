RustGenPass
===========

[![Cross-compile](https://github.com/ollej/rustgenpass/actions/workflows/crosscompile.yml/badge.svg)](https://github.com/ollej/rustgenpass/actions/workflows/crosscompile.yml)

An implementation in Rust of the [SuperGenPass](https://chriszarate.github.io/supergenpass/) utility.

Hash a master password into unique, complex passwords specific for each
website.

Usage
-----

```
rustgenpass 0.4.0
Generate a hashed password similar to SuperGenPass.

USAGE:
    rgp [OPTIONS] --domain <DOMAIN>

OPTIONS:
    -d, --domain <DOMAIN>        Domain / URL to generate password for
    -h, --help                   Print help information
    -H, --hash <HASH>            Hashing method to use [default: md5] [possible values: md5, sha512]
    -k, --keep-subdomains        Don't remove subdomains from domain
    -l, --length <LENGTH>        Length of generated password, min: 4, max: 24 [default: 10]
    -p, --password <PASSWORD>    Master password, if not given, reads from stdin
    -P, --passthrough            Passthrough domain unmodified to hash function
    -r, --rounds <ROUNDS>        Number of hash rounds [default: 10]
    -s, --secret <SECRET>        Secret added to the master password
    -V, --version                Print version informationrustgenpass 0.4.0
```

License
-------

Copyright 2022 Olle Wreede

Released under the [MIT license](https://opensource.org/licenses/MIT).
