RustGenPass
===========

An implementation in Rust of the SuperGenPass utility.

https://chriszarate.github.io/supergenpass/

Usage
-----

```
rustgenpass 0.1.0
Generate a hashed password similar to SuperGenPass.

USAGE:
    rustgenpass [OPTIONS] --domain <DOMAIN>

OPTIONS:
    -d, --domain <DOMAIN>        Domain / URL
    -h, --help                   Print help information
    -k, --keep-subdomains        Don't remove subdomain from domain
    -l, --length <LENGTH>        Length of password, min: 4, max: 24 [default: 10]
    -p, --password <PASSWORD>    Master password, if not given, reads from stdin
    -P, --passthrough            Passthrough domain unmodified to hash function
    -r, --rounds <ROUNDS>        Number of hash rounds [default: 10]
    -s, --secret <SECRET>        Secret added to the master password
    -V, --version                Print version information
```

License
-------

Copyright 2022 Olle Wreede

Released under the [MIT license](https://opensource.org/licenses/MIT).
